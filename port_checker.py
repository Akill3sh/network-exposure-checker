# COMP H2702 scenario D. Checks which ports are open on my own machine
# and saves a report. Only uses the Python standard library.
import csv
import ipaddress
import json
import socket
from datetime import datetime
from pathlib import Path

# Where the input files are and where the output goes, relative to this script
BASE_DIR = Path(__file__).parent
TARGETS_FILE = BASE_DIR / "targets.txt"
PORTS_FILE = BASE_DIR / "ports.txt"
OUTPUT_DIR = BASE_DIR / "output"

# How long to wait on each connection, how much of a banner to read, and
# which ports get an HTTP request instead of a banner read
TIMEOUT = 1.0
BANNER_BYTES = 1024
HTTP_PORTS = {18080}
BANNER_PORTS = {19090, 20001}

# The script will only ever touch this address
APPROVED_TARGETS = {"127.0.0.1"}


def load_lines(path):
    # Reads a text file and gives back the real lines: no blanks, no comments.
    # If the file isn't there, this prints an error and returns an empty list
    # instead of crashing.
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f
                    if line.strip() and not line.strip().startswith("#")]
    except FileNotFoundError:
        print(f"[ERROR] File not found: {path}")
        return []


def is_allowed_target(target):
    # Makes sure a target is actually usable: a valid IP, loopback, and on
    # my approved list. Gives back True/False plus the reason why.
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
    # Filters targets.txt down to the ones that pass is_allowed_target,
    # and prints why anything else got blocked
    targets = []
    for t in load_lines(path):
        ok, reason = is_allowed_target(t)
        if ok:
            targets.append(t)
        else:
            print(f"[BLOCKED] Target '{t}' rejected: {reason}")
    return targets


def load_ports(path):
    # Same idea for ports.txt. Anything that isn't a number from 1 to 65535
    # gets skipped and printed, not silently dropped.
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
    # The actual connection attempt. If it connects, the port is OPEN.
    # Otherwise it's CLOSED, and I keep the reason (refused, timed out, or
    # something else). On my Windows PC a closed port shows up as "timed
    # out" rather than "connection refused".
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
    # Connects and reads whatever the service sends first, if anything
    try:
        with socket.create_connection((target, port), timeout=TIMEOUT) as s:
            data = s.recv(BANNER_BYTES)
            return data.decode("utf-8", errors="replace").strip() or None
    except OSError:
        return None


def http_get(target, port):
    # Builds a plain HTTP GET by hand and sends it over the socket, then
    # reads the full reply back
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

    # Splits headers from the body, then pulls the status code and the
    # couple of headers I actually care about
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
    # Runs check_port on every target/port pair. If a port comes back OPEN
    # and it's in BANNER_PORTS or HTTP_PORTS, I follow up with a banner read
    # or an HTTP request.
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
    # Turns one result into a plain-English note on what it means for exposure
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
    # Just counts OPEN vs CLOSED across everything scanned
    open_count = sum(1 for r in results if r["state"] == "OPEN")
    return {"total": len(results), "open": open_count,
            "closed": len(results) - open_count}


def save_reports(results, summary):
    # Writes the same results three times over: JSON, CSV, and a readable
    # text report
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

    # Building the text report one line at a time
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
    # Loads the inputs, runs the scan, prints a summary, and saves everything
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
