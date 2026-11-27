# Local Network Exposure Checker

COMP H2702 Scripting for Cybersecurity, individual project, scenario D.

This is a Python script that checks a few ports on my own computer and tells me which ones are open. For the open ones it also reads the banner or sends a web request, then it saves a report.

## Scope

The script only checks 127.0.0.1 and the ports in `ports.txt`. If a target is not a local address on my approved list, it gets rejected. I didn't build it to scan other networks and it shouldn't be used that way.

## Files

- `port_checker.py`: my script.
- `local_test_services.py`: starts the safe test services. The lecturer supplied it.
- `targets.txt` and `ports.txt`: the target (127.0.0.1) and the four ports. Also supplied.
- `output/`: made when the script runs. It holds `report.txt`, `results.csv` and `results.json`.

## What you need

Python 3.8 or newer. There is nothing to install because the script only uses the standard library.

## How to run it

Open two terminals in this folder.

Terminal 1 starts the test services. Leave it running:

```
python local_test_services.py
```

Terminal 2 runs my checker:

```
python port_checker.py
```

With the test services running, I get this:

| Port | State | What it shows |
|------|-------|---------------|
| 18080 | OPEN | HTTP 200, Content-Type text/plain |
| 19090 | OPEN | Banner: COMP H2702 Banner Service v1.0 |
| 20001 | OPEN | Banner: COMP H2702 Generic TCP Service |
| 20002 | CLOSED | Connection refused |

## How it works

1. It reads the target and the ports from `targets.txt` and `ports.txt`, so none of the results are hard-coded. Blank lines and lines starting with `#` are skipped.
2. It checks the input. A target is blocked if it isn't a valid IP, isn't a loopback address, or isn't in `APPROVED_TARGETS`. A port is skipped if it isn't a number or is outside 1 to 65535, and the script prints a message for each one.
3. For every port it tries a TCP connection with a 1 second timeout. If the connection works the port is OPEN. If it is refused, times out or fails some other way, the port is CLOSED and the reason is saved.
4. On open ports 19090 and 20001 it reads the banner the service sends. On open port 18080 it sends a normal HTTP GET and saves the status code, the content type and the start of the page.
5. It prints how many ports are open and closed, then saves three files. `report.txt` is the readable report with a short exposure note for each port. `results.csv` has one row per port. `results.json` has everything.

## Error handling

The script keeps going when something goes wrong. It handles:

- a missing `targets.txt` or `ports.txt`
- ports that are not numbers or are out of range
- targets that are not allowed
- refused connections, timeouts and other socket errors
- a test service that isn't running. If I forget to start terminal 1, every port just shows as CLOSED.

## Settings

These are at the top of `port_checker.py`.

| Setting | Default | What it does |
|---------|---------|--------------|
| `TIMEOUT` | 1.0 | Seconds to wait for each connection |
| `BANNER_BYTES` | 1024 | Most bytes to read for a banner |
| `HTTP_PORTS` | {18080} | Ports that get an HTTP GET |
| `BANNER_PORTS` | {19090, 20001} | Ports where a banner is read |
| `APPROVED_TARGETS` | {"127.0.0.1"} | The only targets allowed |

## What an open port means

An open port means a program is listening and accepts connections. That alone is not a vulnerability. What matters is:

- what the service is, and whether it is meant to be there
- its version and settings, for example an old version or no login
- who can reach it. A service on 127.0.0.1 can only be reached from the same computer, but the same service on 0.0.0.0 can be reached from the network
- what it gives away. A banner like `Banner Service v1.0` shows the software and version, which helps an attacker look up known problems

A closed port has nothing listening, so it adds no exposure.
