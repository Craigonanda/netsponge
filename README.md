# netsponge — Network Recon & Scan Tool

**netsponge** is a small interactive terminal network scanning tool built with [Rich] for a clean TUI.  
It automates interface detection and offers discovery/scan actions (nmap, arp-scan, ping sweep, masscan, tcpdump hooks).

> ⚠️ Only use netsponge on networks you own or are authorized to test.

## Features
- Auto-detect primary interface and network
- `nmap -sn` discovery, `arp-scan`, ping sweep
- Top-ports scans and full aggressive `nmap` scans
- Optional `masscan` integration
- Live `ip monitor` and `tcpdump` capture (streamed)
- Save discovery results to CSV

## Requirements
- Python 3.8+
- `pip` packages:
  - `rich`
- Recommended system tools (for full functionality):
  - `nmap`, `arp-scan`, `masscan`, `tcpdump`

### Install
```bash
pip3 install -r requirements.txt
