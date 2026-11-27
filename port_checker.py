# COMP H2702 scenario D: checks which ports are open on localhost only,
# then saves a report. Standard library only.
import csv
import ipaddress
import json
import socket
from datetime import datetime
from pathlib import Path

# Input and output locations, relative to this script
BASE_DIR = Path(__file__).parent
TARGETS_FILE = BASE_DIR / "targets.txt"
PORTS_FILE = BASE_DIR / "ports.txt"
OUTPUT_DIR = BASE_DIR / "output"

# Settings: seconds to wait per connection, max banner bytes to read,
# which ports get an HTTP request and which get a banner read
TIMEOUT = 1.0
BANNER_BYTES = 1024
HTTP_PORTS = {18080}
BANNER_PORTS = {19090, 20001}

# The only targets the script will touch
APPROVED_TARGETS = {"127.0.0.1"}


def load_lines(path):
    # Read a text file, skipping blank lines and lines starting with #.
    # A missing file gives an error message and an empty list, not a crash.
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f
                    if line.strip() and not line.strip().startswith("#")]
    except FileNotFoundError:
        print(f"[ERROR] File not found: {path}")
        return []


def is_allowed_target(target):
    # Safety check: the target must be a real IP, a loopback address and on
    # the approved list. Returns (True/False, reason).
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
    # Keep only the targets that pass the safety check, and say why any are blocked
    targets = []
    for t in load_lines(path):
        ok, reason = is_allowed_target(t)
        if ok:
            targets.append(t)
        else:
            print(f"[BLOCKED] Target '{t}' rejected: {reason}")
    return targets


def load_ports(path):
    # Keep only valid port numbers (1 to 65535), skipping anything else
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
    # Try a TCP connection. If it connects the port is OPEN, otherwise it is
    # CLOSED and the reason is returned (refused, timed out or another error).
    # Windows shows a closed port as "timed out" instead of "refused".
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
    # Connect and read the first message the service sends, if it sends one
    try:
        with socket.create_connection((target, port), timeout=TIMEOUT) as s:
            data = s.recv(BANNER_BYTES)
            return data.decode("utf-8", errors="replace").strip() or None
    except OSError:
        return None


def http_get(target, port):
    # Send a plain HTTP GET over a socket and read the whole reply
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

    # Split the reply into headers and body, then pull out the status code and
    # the headers we care about
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
    # Check every port on every target. Open ports also get a banner read or
    # an HTTP request, depending on the settings at the top.
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
    # Short plain explanation of what each result means for exposure
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
    # Count how many ports are open and closed
    open_count = sum(1 for r in results if r["state"] == "OPEN")
    return {"total": len(results), "open": open_count,
            "closed": len(results) - open_count}


def save_reports(results, summary):
    # Write the same results three ways: JSON, CSV and a readable text report
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

    # Build the text report line by line
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
    # Load the input, scan, print a summary and save the reports
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
