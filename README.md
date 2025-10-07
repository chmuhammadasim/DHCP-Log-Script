## DHCP_Logs.py — Ultimate DHCP sniffer & Internet DHCP analysis

This repository contains a single advanced Python script, `DHCP_Logs.py`, which is an "ultimate" DHCP sniffer designed to capture and analyze DHCP traffic, fingerprint devices, detect anomalies and potential threats, and persist detailed logs (PCAP, JSONL, and human-readable text). It includes enhanced features such as geolocation lookups, vendor fingerprinting, DNS-tunneling heuristics, and performance monitoring.

This README explains prerequisites, installation steps, and a comprehensive set of PowerShell example commands that exercise all major modes and options supported by the script.

## Files in this folder

- `DHCP_Logs.py` — main script (capture and analysis). Keep this file in the workspace root.
- `requirements.txt` — Python dependencies for the script (use a virtualenv).

## What this script does (high level)

- Listens for DHCP-related network traffic (standard DHCP/BOOTP ports and DHCPv6) using Scapy.
- Parses and extracts ALL DHCP options and tries to canonicalize them.
- Produces multiple outputs: PCAP file, JSONL event file, pretty text logs, raw analysis dump, statistics file, and a threat analysis log.
- Performs enhanced analysis: device/vendor fingerprinting, hostname resolution (optional), geolocation (optional via external web services), anomaly detection and basic threat scoring.
- Can operate on a live interface or read an existing PCAP.

## Requirements

- Python 3.8+ (3.10/3.11 recommended)
- Administrator/root privileges for live capture (Windows: run PowerShell as Administrator)
- Recommended Python packages (see `requirements.txt`):
  - scapy
  - psutil (optional, used for performance monitoring)

Notes:
- The script calls external tools (e.g., `curl`, `arp`, `avahi-resolve`, `getent`) for certain features. Those tools are typical on Linux/macOS. On Windows:
  - Recent Windows 10/11 include `curl` and `nslookup` by default. `arp -a` works on Windows but parsing differs from Linux output.
  - Linux-specific helper utilities such as `avahi-resolve` and `getent` are not available on stock Windows and those code paths will simply skip or log debug messages.

## Installation (PowerShell)

Open PowerShell as Administrator and run the commands below to create and activate a virtual environment, then install dependencies.

```powershell
# change to the project directory
Set-Location -Path "C:\Users\Muhammad Asim\Documents\DHCP Logs"

# create a venv
python -m venv .venv

# activate the venv (PowerShell)
.\.venv\Scripts\Activate.ps1

# upgrade pip and install requirements
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If you cannot use a virtual environment, you can install packages globally (not recommended):

```powershell
pip install scapy psutil
```

## Windows notes and capabilities

- Live capture requires Administrator privileges.
- Some features that rely on Linux-only tools (AVAHI, getent, Linux arp parsing) will be skipped on Windows. Hostname resolution still uses Python's `socket` functions which work cross-platform.
- Geolocation uses public web APIs via `curl`. Windows 10+ includes a `curl` binary; if your system doesn't have `curl`, either install it or modify `DHCP_Logs.py` to use Python's `requests` library.

## Quick sanity check (verify Python imports)

Run the following to confirm Scapy is importable and dependencies are installed:

```powershell
python -c "import scapy.all as scapy; print('scapy', scapy.__version__)"
python -c "import psutil; print('psutil', psutil.__version__)"  # optional
```

## How to run `DHCP_Logs.py`

Important: for live capture you must specify an interface via `-i` / `--interface`. To get a list of available interfaces, run with `--list-interfaces`.

General usage:

```powershell
python .\DHCP_Logs.py -i <interface> [options]
```

If you don't need live capture you can analyze a PCAP file:

```powershell
python .\DHCP_Logs.py --read-pcap path\to\capture.pcap
```

## All important example commands (PowerShell, Windows)

Below is a comprehensive set of commands that exercise the script's options. Replace placeholders (like `<iface>` and paths) with real values.

- List network interfaces (no capture):

```powershell
python .\DHCP_Logs.py --list-interfaces
```

- Test hostname resolution (offline test mode):

```powershell
python .\DHCP_Logs.py --test-hostnames
```

- Read and analyze an existing pcap file (safe, no root required):

```powershell
python .\DHCP_Logs.py --read-pcap .\example_capture.pcap --json output_events.jsonl --txt output_log.txt --pcap output_append.pcap
```

- Live capture (minimum required):

```powershell
# Run as Administrator
python .\DHCP_Logs.py -i "Ethernet" -v
```

- Live capture with verbose diagnostic mode (very chatty):

```powershell
python .\DHCP_Logs.py -i "Ethernet" -v -d
```

- Live capture, enable hostname resolution (may slow down processing):

```powershell
python .\DHCP_Logs.py -i "Ethernet" --enable-hostname-resolution --geo-lookup --threat-detection --performance-monitor
```

- Capture ALL UDP traffic (non-filtered) — use caution (lots of data):

```powershell
python .\DHCP_Logs.py -i "Ethernet" --capture-all --no-filter
```

- Internet focus (attempt to highlight DHCP traffic that involves non-private IPs):

```powershell
python .\DHCP_Logs.py -i "Ethernet" --internet-focus --threat-detection --geo-lookup
```

- Increase thread pool for higher throughput (modify `--max-threads` as needed):

```powershell
python .\DHCP_Logs.py -i "Ethernet" --max-threads 16 --performance-monitor
```

- Change output filenames and batch/flush parameters:

```powershell
python .\DHCP_Logs.py -i "Ethernet" --pcap my_capture.pcap --json events.jsonl --txt events.txt --batch-size 5 --flush-interval 10
```

- Run in diagnostic + deep analysis mode (for debugging and development):

```powershell
python .\DHCP_Logs.py -i "Ethernet" -d --deep-analysis --diagnostic --verbose
```

- Read PCAP, generate final enhanced report & threat log (read-only run):

```powershell
python .\DHCP_Logs.py --read-pcap .\captures\big_capture.pcap --json analysis_events.jsonl --threat-log threats.json
```

## Example: Full-feature capture command (recommended for research)

Run this as Administrator and be prepared for a lot of output and network/Internet lookups:

```powershell
python .\DHCP_Logs.py -i "Ethernet" --pcap dhcp_capture.pcap --json dhcp_events.jsonl --txt dhcp_log.txt --raw-dump raw_dhcp.json --stats-file dhcp_stats.json --threat-log dhcp_threats.json --geo-cache geo_cache.json -b 10 -f 5 --internet-focus --threat-detection --geo-lookup --performance-monitor --enable-hostname-resolution --max-threads 12 -v
```

## Output files generated by the script

- `dhcp_capture.pcap` (default): appended raw packets captured
- `log.json` (default): line-delimited JSON events
- `log.txt` (default): human-readable formatted events
- `raw_dhcp_dump.txt` (default): raw JSON analyses of packets
- `dhcp_stats.json`: computed statistics and summaries
- `threat_analysis.json`: threat events and summaries
- `*_comprehensive_report.json`: generated at graceful shutdown

## Troubleshooting

- Permission denied / sniff failed: Run PowerShell as Administrator. Windows requires elevated privileges to capture packets.
- Scapy import failed: ensure Python and pip installed and install `scapy` from the `requirements.txt`.
- curl not found: install curl or modify the code to use Python `requests` for geolocation lookups.
- Missing Linux-specific tools: The script gracefully falls back for many of these functions; hostname and geolocation features still work with Python standard libs and web APIs.

## CLI argument reference (concise)

The script accepts many flags. Here is a concise reference matching the `argparse` options in `DHCP_Logs.py`:

- `-i, --interface` — Interface name for live capture (required for live mode).
- `--list-interfaces` — Print available interfaces and exit.
- `--test-hostnames` — Run offline hostname resolution tests and exit.
- `--pcap` — PCAP output filename (default: dhcp_capture.pcap).
- `--json` — JSONL events output file (default: log.json).
- `--txt` — Human-readable text log (default: log.txt).
- `--summary` — Summary JSON file name.
- `--raw-dump` — Raw packet analysis dump (default: raw_dhcp_dump.txt).
- `--stats-file` — Statistics output file (default: dhcp_stats.json).
- `--threat-log` — Threat analysis log filename.
- `--geo-cache` — Geolocation cache file.
- `-b, --batch-size` — Number of packets/events to buffer before writing to disk.
- `-f, --flush-interval` — Seconds between automatic flushes of buffers.
- `--read-pcap` — Read and analyze an existing PCAP (no live capture).
- `-v, --verbose` — Verbose logging.
- `-d, --diagnostic` — Diagnostic mode (extra debug prints).
- `--no-filter` — Capture all packets (no BPF filter).
- `--promisc` — Enable promiscuous mode on the interface.
- `--capture-all` — Capture all DHCP-like traffic, including malformed.
- `--deep-analysis` — Enable deeper analysis routines.
- `--internet-focus` — Focus on DHCP traffic involving public/internet IPs.
- `--threat-detection` — Enable threat detection features.
- `--geo-lookup` — Enable geolocation lookups for public IPs.
- `--performance-monitor` — Enable background performance monitoring (psutil required).
- `--max-threads` — Maximum worker threads for analysis (default 8).
- `--enable-hostname-resolution` — Enable reverse DNS/hostname resolution (slower).

For a complete list and short help text, run:

```powershell
python .\DHCP_Logs.py -h
```

## Output format & examples

This section gives examples of the main output types so you know what to expect.

- JSONL events (`--json` or default `log.json`): each line is a JSON object describing a DHCP event. A minimal example event looks like:

```json
{
  "time": "2025-10-07T12:34:56.789+00:00",
  "message_type": "OFFER",
  "message_type_code": 2,
  "chaddr": "00:11:22:33:44:55",
  "yiaddr": "192.168.1.101",
  "server_id": "192.168.1.1",
  "raw_options": {"53": "02", "1": "ffffff00"}
}
```

- Human-readable text log (`--txt` or default `log.txt`): contains formatted blocks produced by the `pretty_line()` function in the script. It includes CLIENT INFO, SERVER INFO, IP ASSIGNMENT, FINGERPRINT INFO, RAW DHCP OPTIONS and more. Expect multi-page human-friendly entries.

- PCAP (`--pcap`): standard packet capture file that can be opened with Wireshark or tcpdump.

- Raw analyses (`--raw-dump`): JSON serialized results of deep packet inspection for each packet analyzed — useful for programmatic post-processing.

- Statistics (`--stats-file`): a JSON snapshot containing counters (packets, unique vendors, option frequency, etc.).

### Example pretty text snippet (truncated)

```
================================================================================
[2025-10-07T12:34:56.789+00:00] DHCP OFFER
--------------------------------------------------------------------------------
CLIENT INFO:
  MAC Address:      00:11:22:33:44:55
  DHCP Hostname:    client-host
  Client IP:        0.0.0.0
  Source MAC:       00:11:22:33:44:55
  Source IP:        192.168.1.101

SERVER INFO:
  Server ID:        192.168.1.1
  Server IP:        192.168.1.1

RAW DHCP OPTIONS:
  [ 53] message-type             = 2
  [  1] subnet_mask              = ffffff00
  ...
================================================================================
```

## Windows: Npcap / WinPcap installation (required for live capture)

For live packet capture on Windows you need Npcap installed. Steps:

1. Download Npcap from https://nmap.org/npcap/ (use the latest stable installer).
2. Run the installer as Administrator and enable the "Install Npcap in WinPcap API-compatible mode" option if you need older software compatibility.
3. Reboot if the installer recommends it.
4. Run PowerShell as Administrator and run the capture command (e.g., `--list-interfaces` then `-i <Your Interface>`).

If you see permission or device errors when running `sniff()` in Scapy, ensure Npcap is installed and that PowerShell was launched with Administrator privileges.

## Simulating DHCP packets for testing (offline)

If you don't have live DHCP traffic, create a small test pcap or use Scapy to craft packets and then run `--read-pcap`:

```powershell
# Example: create a tiny pcap using a Python snippet
python - <<'PY'
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, wrpcap
pkt = Ether()/IP(src='192.168.1.2',dst='192.168.1.1')/UDP(sport=68,dport=67)/BOOTP(chaddr=b'\x00\x11\x22\x33\x44\x55')/DHCP(options=[('message-type', 'discover'), ('end', b'')])
wrpcap('test_dhcp.pcap', [pkt])
print('wrote test_dhcp.pcap')
PY

python .\DHCP_Logs.py --read-pcap .\test_dhcp.pcap
```

## Automated sanity tests (quick checks)

Use these fast one-liners to validate environment and imports before a live capture:

```powershell
# scapy import
python -c "import scapy.all as scapy; print('scapy OK', getattr(scapy, '__version__', 'unknown'))"

# psutil (optional)
python -c "import psutil; print('psutil OK', psutil.virtual_memory().percent)"

# curl availability (for geo lookups)
curl --version
```

## FAQ and common errors (expanded)

- Q: "I get PermissionError / can't sniff" — A: Run PowerShell as Administrator and ensure Npcap is installed. Also close other applications that may bind to network devices.

- Q: "Geolocation lookups fail or are slow" — A: The script uses `curl` to query third-party APIs. If `curl` is missing, install it or request that I replace the code to use `requests` (included in `requirements.txt`). Also consider disabling `--geo-lookup` for large captures.

- Q: "Hostname resolution is slow and times out" — A: Don't run with `--enable-hostname-resolution` on high-traffic captures. Use `--diagnostic` only for low-volume debugging.

- Q: "The script writes nothing to disk" — A: Check the output directory permissions and validate the file paths you provided. By default the script attempts to create the output files on startup; any failure is logged and the script exits.

- Q: "I see a lot of UDP packets but no DHCP events" — A: Use `--capture-all` to capture non-standard DHCP traffic, or confirm the interface is correct. Also ensure no firewall rules are blocking UDP 67/68 visibility.

## Suggested next improvements (optional tasks)

- Replace `curl` subprocess calls with Python `requests` for cross-platform geolocation lookups and better error handling. (I can do this change and run a local test.)
- Add a small unit test suite for parsing functions (e.g., `dhcp_options_to_dict`) and run them automatically.
- Add a small Windows-specific module to parse `arp -a` output and map IP->hostnames more reliably.

---

## Security, Privacy & Ethics

- This tool captures network traffic; use it only on networks you own or have explicit permission to monitor.
- Geolocation and threat lookups may send IP addresses to 3rd-party services; be mindful of privacy and compliance requirements.

## Contributing / Extending

- If you want to add platform-specific features (Windows support for ARP parsing, using WinPcap/Npcap APIs), modify `DHCP_Logs.py` accordingly.
- To replace `curl` calls with `requests` for cross-platform compatibility, add `requests` to `requirements.txt` and update the geolocation functions.

## Status & Notes

- This README and the `requirements.txt` provide a quick-start and full command matrix to exercise the script. Some advanced features (e.g., avahi, getent, Linux ARP parsing) are platform-specific and will not run on Windows without changes. The script includes many defensive checks and will continue to run even if optional utilities are missing.

---

If you want, I can also:
- Run one example command in your PowerShell terminal here (you must confirm which one and accept elevated permissions), or
- Replace `curl` calls with Python `requests` for cross-platform compatibility and update `requirements.txt`.
