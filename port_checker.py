import csv
import ipaddress
import json
import socket
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent
TARGETS_FILE = BASE_DIR / "targets.txt"
PORTS_FILE = BASE_DIR / "ports.txt"
OUTPUT_DIR = BASE_DIR / "output"

TIMEOUT = 1.0
BANNER_BYTES = 1024
HTTP_PORTS = {18080}
BANNER_PORTS = {19090, 20001}

APPROVED_TARGETS = {"127.0.0.1"}


def load_lines(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f
                    if line.strip() and not line.strip().startswith("#")]
    except FileNotFoundError:
        print(f"[ERROR] File not found: {path}")
        return []


def is_allowed_target(target):
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return False, "not a valid IP address"
    if not ip.is_loopback:
        return False, "not a local (loopback) address"
    if target not in APPROVED_TARGETS:
        return False, "not on the approved target list"
    return True, "ok"


def load_targets(path):
    targets = []
    for t in load_lines(path):
        ok, reason = is_allowed_target(t)
        if ok:
            targets.append(t)
        else:
            print(f"[BLOCKED] Target '{t}' rejected: {reason}")
    return targets


def load_ports(path):
    ports = []
    for line in load_lines(path):
        try:
            port = int(line)
        except ValueError:
            print(f"[SKIP] Invalid port value: '{line}'")
            continue
        if 1 <= port <= 65535:
            ports.append(port)
        else:
            print(f"[SKIP] Port out of range: {port}")
    return ports


def check_port(target, port):
    try:
        with socket.create_connection((target, port), timeout=TIMEOUT):
            return "OPEN", "connection accepted"
    except ConnectionRefusedError:
        return "CLOSED", "connection refused"
    except socket.timeout:
        return "CLOSED", "timed out"
    except OSError as e:
        return "CLOSED", f"error: {e}"


def grab_banner(target, port):
    try:
        with socket.create_connection((target, port), timeout=TIMEOUT) as s:
            data = s.recv(BANNER_BYTES)
            return data.decode("utf-8", errors="replace").strip() or None
    except OSError:
        return None


def http_get(target, port):
    request = (f"GET / HTTP/1.1\r\nHost: {target}:{port}\r\n"
               f"Connection: close\r\n\r\n").encode()
    try:
        with socket.create_connection((target, port), timeout=TIMEOUT) as s:
            s.sendall(request)
            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
    except OSError as e:
        return {"error": str(e)}

    head, _, body = response.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    status_parts = lines[0].split(" ", 2) if lines else []
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {
        "status_code": int(status_parts[1]) if len(status_parts) > 1 else None,
        "content_type": headers.get("content-type"),
        "server": headers.get("server"),
        "body_preview": body.decode("utf-8", errors="replace").strip()[:80],
    }


def scan(targets, ports):
    results = []
    for target in targets:
        for port in ports:
            state, note = check_port(target, port)
            row = {"target": target, "port": port, "state": state,
                   "note": note, "banner": None, "http": None}
            if state == "OPEN" and port in BANNER_PORTS:
                row["banner"] = grab_banner(target, port)
            if state == "OPEN" and port in HTTP_PORTS:
                row["http"] = http_get(target, port)
            results.append(row)
            print(f"{target}:{port:<6} {state:<7} {note}")
    return results


def interpret(row):
    if row["state"] == "CLOSED":
        return "Nothing listening. No exposure on this port."
    if row["http"] and "status_code" in row["http"]:
        return ("Web service answering. Check what it serves and who "
                "can reach it.")
    if row["banner"]:
        return ("Service reveals a banner (name/version). This helps an "
                "attacker fingerprint it.")
    return "Open but quiet. Identify which program owns this port."


def summarise(results):
    open_count = sum(1 for r in results if r["state"] == "OPEN")
    return {"total": len(results), "open": open_count,
            "closed": len(results) - open_count}


def save_reports(results, summary):
    OUTPUT_DIR.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(OUTPUT_DIR / "results.json", "w", encoding="utf-8") as f:
        json.dump({"scan_time": stamp, "summary": summary,
                   "results": results}, f, indent=2)

    with open(OUTPUT_DIR / "results.csv", "w", newline="",
              encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["target", "port", "state", "note", "banner",
                    "http_status", "content_type"])
        for r in results:
            h = r["http"] or {}
            w.writerow([r["target"], r["port"], r["state"], r["note"],
                        r["banner"] or "", h.get("status_code", ""),
                        h.get("content_type", "")])

    lines = [
        "COMP H2702 - Local Network Exposure Report",
        f"Scan time: {stamp}",
        f"Timeout per port: {TIMEOUT}s",
        "",
        f"Ports checked: {summary['total']}   "
        f"OPEN: {summary['open']}   CLOSED: {summary['closed']}",
        "",
        "Findings",
        "--------",
    ]
    for r in results:
        lines.append(f"{r['target']}:{r['port']}  {r['state']}  ({r['note']})")
        if r["banner"]:
            lines.append(f"    Banner: {r['banner']}")
        if r["http"]:
            h = r["http"]
            if "error" in h:
                lines.append(f"    HTTP error: {h['error']}")
            else:
                lines.append(f"    HTTP {h['status_code']}  "
                             f"Content-Type: {h['content_type']}")
        lines.append(f"    Exposure: {interpret(r)}")
    lines += [
        "",
        "Note: an open port only means a program is listening. It is not a",
        "vulnerability by itself. Risk depends on what the service is, its",
        "version, its config, and who can reach it.",
    ]
    with open(OUTPUT_DIR / "report.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"\nReports saved to: {OUTPUT_DIR}")


def main():
    print("COMP H2702 - Local Network Exposure Checker\n")
    targets = load_targets(TARGETS_FILE)
    ports = load_ports(PORTS_FILE)
    if not targets or not ports:
        print("[ERROR] No valid targets or ports. Nothing to scan.")
        return

    results = scan(targets, ports)
    summary = summarise(results)
    print(f"\nSummary: {summary['open']} OPEN, {summary['closed']} CLOSED "
          f"out of {summary['total']}")
    save_reports(results, summary)


if __name__ == "__main__":
    main()
