#!/usr/bin/env python3
"""
NETSPONGE - Network Scan Tool (fixed)

Interactive terminal tool using Rich. Features:
- persistent logging to ~/network_scans/netsponge.log
- colorized alerts when new hosts are discovered compared to the last run
- a simple banner animation (netbot eye blink) on startup
- scanning features: nmap -sn, arp-scan, ping sweep, top ports, full scan,
  masscan, ip monitor, tcpdump, and save to CSV

Requirements:
    python3
    pip3 install rich
    nmap, arp-scan, masscan, tcpdump (optional but recommended)

Only use on networks you own or are authorized to test.
"""

from __future__ import annotations
import os
import shlex
import subprocess
import sys
import csv
import time
import logging
from datetime import datetime
from typing import List, Dict, Tuple, Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt
    from rich.align import Align
    from rich.layout import Layout
    from rich.live import Live
    from rich import box
    from rich.text import Text
except Exception:
    print("\nMissing dependency 'rich'. Install with: pip3 install rich\n")
    raise

# --------- configuration ----------------------------------------------------
console = Console()
OUTPUT_DIR = os.path.expanduser("~/network_scans")
os.makedirs(OUTPUT_DIR, exist_ok=True)
LOGFILE = os.path.join(OUTPUT_DIR, "netsponge.log")

# set up Python logging (file + console)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(LOGFILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("netsponge")

ASCII_BOT = r"""
             █████████████████████████
   ███▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀███
  ███    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄     ███
 ███    ▐   ▄████████▄   ▌     ███
 ███     ▐   ▀██████▀    ▌     ███
 ███      ▀▄    ▀▀▀    ▄▀      ███
  ███      ▄▄▄▄ ▄▄▄▄ ▄▄▄▄      ███
   ███    ▐ ▓▓  ▄▄▄▄  ▓▓ ▌    ███
    ███    ▀▄▓▓████▓▓▄▀       ███
     ███▄     ▀████▀        ▄███
      ████▄               ▄████
       ██████▄    ▄▄▄   ▄█████
         ███████████████████
          ███   ▄████▄   ███
          ███    ▀▀▀▀    ███
           ███▄▄▄▄▄▄▄▄▄▄███
             ▀██████████▀
                ▀▀▀▀▀▀
"""

# ------------------ Utilities -------------------------------------------------


def run_cmd(cmd: str, sudo: bool = False, stream: bool = False) -> Tuple[int, str, str]:
    """Run a shell command. If sudo=True and not root, prefix with sudo.
    If stream=True, stream output live.
    """
    if sudo and os.name != "nt":
        try:
            if os.geteuid() != 0:
                cmd = "sudo " + cmd
        except AttributeError:
            # os.geteuid may not exist on Windows
            pass
    logger.info(f"$ {cmd}")
    console.log(f"[bold cyan]$ {cmd}[/]")
    if stream:
        proc = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            for line in proc.stdout:
                console.print(line.rstrip())
        except KeyboardInterrupt:
            proc.terminate()
            console.print("[bold yellow]\n[!] Stopped by user[/]")
            return proc.returncode or 1, "", ""
        proc.wait()
        return proc.returncode or 0, "", ""

    proc = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = proc.communicate()
    return proc.returncode, (out or "").strip(), (err or "").strip()


def check_tool(name: str) -> bool:
    rc, out, err = run_cmd(f"which {name}")
    return rc == 0 and out != ""


def detect_primary_interface() -> Tuple[str, str]:
    iface = "eth0"
    net = "10.0.2.0/24"
    rc, out, err = run_cmd("ip route show default")
    if rc == 0 and out:
        parts = out.split()
        if "dev" in parts:
            try:
                iface = parts[parts.index("dev") + 1]
            except Exception:
                pass
    rc, out, err = run_cmd(f"ip -o -f inet addr show {iface}")
    if rc == 0 and out:
        try:
            tokens = out.split()
            if "inet" in tokens:
                idx = tokens.index("inet")
                cidr = tokens[idx + 1]
                if cidr.endswith("/24"):
                    base = cidr.split("/")[0].rsplit('.', 1)[0]
                    net = f"{base}.0/24"
                else:
                    net = cidr
        except Exception:
            pass
    return iface, net


# ------------------ Parsers ---------------------------------------------------


def parse_nmap_sn(output: str) -> List[Dict[str, str]]:
    hosts: List[Dict[str, str]] = []
    cur: Dict[str, str] = {}
    for line in (output or "").splitlines():
        line = line.strip()
        if line.startswith("Nmap scan report for"):
            if cur:
                hosts.append(cur)
            cur = {"ip": "", "hostname": "", "mac": "", "vendor": ""}
            if "(" in line and ")" in line:
                try:
                    name = line.split("Nmap scan report for", 1)[1].strip()
                    host, ip = name.split("(", 1)
                    cur["hostname"] = host.strip()
                    cur["ip"] = ip.replace(")", "").strip()
                except Exception:
                    parts = line.split()
                    cur["ip"] = parts[-1]
            else:
                parts = line.split()
                cur["ip"] = parts[-1]
        elif line.startswith("MAC Address:"):
            try:
                tail = line.split("MAC Address:", 1)[1].strip()
                mac, rest = tail.split(" ", 1)
                cur["mac"] = mac.strip()
                if "(" in rest and ")" in rest:
                    cur["vendor"] = rest.split("(", 1)[1].rsplit(")", 1)[0].strip()
                else:
                    cur["vendor"] = rest.strip()
            except Exception:
                pass
    if cur:
        hosts.append(cur)
    return hosts


# ------------------ Persistence & alerts ------------------------------------

LAST_HOSTS_FILE = os.path.join(OUTPUT_DIR, "last_hosts.txt")


def load_last_hosts() -> List[str]:
    if not os.path.exists(LAST_HOSTS_FILE):
        return []
    with open(LAST_HOSTS_FILE, "r") as f:
        return [l.strip() for l in f if l.strip()]


def save_last_hosts(ips: List[str]):
    with open(LAST_HOSTS_FILE, "w") as f:
        f.write("\n".join(ips))


def alert_new_hosts(found_hosts: List[Dict[str, str]]):
    """Compare found hosts to previous run and colorize alerts for new ones."""
    prev = set(load_last_hosts())
    found_ips = [h["ip"] for h in found_hosts if h.get("ip")]
    new = [ip for ip in found_ips if ip not in prev]
    if new:
        logger.info(f"New hosts discovered: {', '.join(new)}")
        table = Table(title="New Hosts Detected", box=box.ROUNDED)
        table.add_column("IP", style="bold red")
        table.add_column("MAC")
        table.add_column("Vendor")
        for h in found_hosts:
            if h.get("ip") in new:
                table.add_row(h.get("ip", ""), h.get("mac", ""), h.get("vendor", ""))
        console.print(Panel(table, title="[bold red]ALERT[/]", border_style="red"))
    else:
        console.print(Panel("No new hosts since last run.", title="Status", border_style="green"))
    save_last_hosts(found_ips)


# ------------------ Actions ---------------------------------------------------


def show_local_ip(iface: str):
    rc, out, err = run_cmd(f"ip -br addr show dev {iface}")
    if rc != 0:
        console.print("[red]Failed to get interface info. Check interface name.[/]")
        if err:
            console.print(err)
    else:
        console.print(Panel(out, title=f"Interface: {iface}", subtitle="ip -br addr"))


def discover_nmap_sn(target_net: str) -> List[Dict[str, str]]:
    console.print(f"[bold]Running nmap -sn on {target_net}[/]")
    cmd = f"nmap -sn {target_net}"
    rc, out, err = run_cmd(cmd)
    if rc != 0:
        console.print("[red]nmap returned non-zero exit code[/]")
        if err:
            console.print(err)
    hosts = parse_nmap_sn(out)
    table = Table(title=f"Hosts in {target_net}", box=box.SIMPLE)
    table.add_column("IP")
    table.add_column("Hostname")
    table.add_column("MAC")
    table.add_column("Vendor")
    for h in hosts:
        table.add_row(h.get("ip", ""), h.get("hostname", ""), h.get("mac", ""), h.get("vendor", ""))
    console.print(table)
    alert_new_hosts(hosts)
    return hosts


def arp_scan(iface: str) -> List[Dict[str, str]]:
    if not check_tool("arp-scan"):
        console.print("[yellow]arp-scan not installed. Install with: sudo apt install arp-scan[/]")
        return []
    cmd = f"arp-scan --interface={iface} --localnet"
    rc, out, err = run_cmd(cmd, sudo=True)
    hosts: List[Dict[str, str]] = []
    for line in (out or "").splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0].count(".") == 3 and parts[1].count(":") == 5:
            hosts.append({"ip": parts[0], "mac": parts[1], "vendor": " ".join(parts[2:])})
    table = Table(title="ARP Scan Results", box=box.SIMPLE)
    table.add_column("IP")
    table.add_column("MAC")
    table.add_column("Vendor")
    for h in hosts:
        table.add_row(h["ip"], h["mac"], h["vendor"])
    console.print(table)
    alert_new_hosts(hosts)
    return hosts


def ping_sweep(base_cidr: str) -> List[Dict[str, str]]:
    console.print(f"[bold]Ping sweep on {base_cidr} (may take a while)[/]")
    alive: List[Dict[str, str]] = []
    base = base_cidr.split("/")[0].rsplit(".", 1)[0]
    for i in range(1, 255):
        ip = f"{base}.{i}"
        proc = subprocess.Popen(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        res = proc.wait()
        if res == 0:
            alive.append({"ip": ip})
            console.print(f"alive: {ip}")
    console.print(f"[green]Ping sweep finished: {len(alive)} hosts alive[/]")
    alert_new_hosts(alive)
    return alive


def top_ports_scan(target: str, top: int = 200):
    console.print(f"[bold]Scanning {target} (top {top} ports) with nmap[/]")
    outfile = os.path.join(OUTPUT_DIR, f"top{top}-{target.replace('/', '_')}.txt")
    cmd = f"nmap -sS -Pn -T4 --top-ports {top} {target} -oN {outfile}"
    run_cmd(cmd, sudo=True, stream=True)
    console.print(f"[green]Saved output to {outfile}[/]")


def full_aggressive_scan(target: str):
    console.print("[bold red]Aggressive scan (noisy & slow):[/]")
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = os.path.join(OUTPUT_DIR, f"full-{target.replace('/', '_')}-{ts}")
    cmd = f"nmap -A -p- -T4 {target} -oA {base}"
    run_cmd(cmd, sudo=True, stream=True)
    console.print(f"[green]Saved outputs to {base}.*[/]")


def run_masscan(target: str):
    if not check_tool("masscan"):
        console.print("[yellow]masscan not installed. Install with: sudo apt install masscan[/]")
        return
    rate = Prompt.ask("Rate (packets/sec)", default="10000")
    out = os.path.join(OUTPUT_DIR, f"masscan-{target.replace('/', '_')}.log")
    cmd = f"masscan {target} -p1-65535 --rate {rate} -oL {out}"
    run_cmd(cmd, sudo=True, stream=True)
    console.print(f"[green]Masscan output: {out}[/]")


def ip_monitor():
    console.print("[bold]ip monitor (Ctrl+C to stop)[/]")
    run_cmd("ip monitor all", sudo=True, stream=True)


def tcpdump_capture(iface: str):
    console.print("[bold]tcpdump live capture (Ctrl+C to stop)[/]")
    run_cmd(f"tcpdump -n -i {iface}", sudo=True, stream=True)


def save_hosts_csv(hosts: List[Dict[str, str]], filename: Optional[str] = None) -> str:
    if not filename:
        filename = os.path.join(OUTPUT_DIR, f"hosts-{int(time.time())}.csv")
    keys = ["ip", "hostname", "mac", "vendor"]
    with open(filename, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for h in hosts:
            w.writerow({k: h.get(k, "") for k in keys})
    console.print(f"[green]Saved {len(hosts)} hosts to {filename}[/]")
    logger.info(f"Saved {len(hosts)} hosts to {filename}")
    return filename


# ------------------ UI / Main -----------------------------------------------


def banner_animation(duration: float = 2.0):
    """Simple startup animation: netbot eye blink using Rich's Live"""
    frames = [
        ASCII_BOT,
        ASCII_BOT.replace("███", "█-█"),
        ASCII_BOT,
    ]
    with Live(Align.center(Text("", justify="center")), refresh_per_second=4, console=console) as live:
        start = time.time()
        i = 0
        while time.time() - start < duration:
            t = Text()
            t.append(frames[i % len(frames)] + "\n", style="bold green")
            t.append("NETSPONGE - NetBot (eye patch)\n", style="bold white on blue")
            live.update(Panel(Align.center(t), border_style="bright_magenta"))
            time.sleep(0.35)
            i += 1


def header_panel() -> Panel:
    text = Text()
    text.append(ASCII_BOT + "\n", style="bold green")
    text.append("NETSPONGE - Network Recon & Scan Tool\n", style="bold white on blue")
    text.append("\nA friendly bot with an eyepatch. Use responsibly.\n", style="italic")
    return Panel(Align.center(text), border_style="bright_magenta", title="netsponge")


def menu_panel(iface: str, net: str) -> Panel:
    menu = Table.grid(padding=1)
    menu.add_column(justify="left")
    menu.add_column(justify="left")
    menu.add_row("[1] Show local IP / interface info", f"Interface: {iface}")
    menu.add_row("[2] Discover hosts (nmap -sn)", f"Network: {net}")
    menu.add_row("[3] ARP scan (arp-scan)", "Requires arp-scan")
    menu.add_row("[4] Ping sweep", "Slow but simple")
    menu.add_row("[5] Top ports scan (nmap --top-ports)", "Fast service scan")
    menu.add_row("[6] Full aggressive scan (nmap -A -p-)", "Noisy")
    menu.add_row("[7] Masscan (if installed)", "Very fast")
    menu.add_row("[8] ip monitor (live)", "Event stream")
    menu.add_row("[9] Tcpdump live capture", "Requires sudo")
    menu.add_row("[10] Save last discovery to CSV", "")
    menu.add_row("[0] Exit", "")
    return Panel(menu, title="Main Menu", border_style="cyan")


def main():
    banner_animation(duration=1.8)
    iface_detected, net_detected = detect_primary_interface()
    iface = Prompt.ask("Interface", default=iface_detected)
    net = Prompt.ask("Target network (CIDR)", default=net_detected)

    last_discovery: List[Dict[str, str]] = []

    while True:
        layout = Layout()
        layout.split_column(
            Layout(header_panel(), name="header", size=12),
            Layout(menu_panel(iface, net), name="menu", ratio=2),
        )
        console.clear()
        console.print(layout)
        choice = Prompt.ask("Choose an option (number)")
        if choice == "1":
            show_local_ip(iface)
        elif choice == "2":
            hosts = discover_nmap_sn(net)
            last_discovery = hosts
        elif choice == "3":
            hosts = arp_scan(iface)
            last_discovery = hosts
        elif choice == "4":
            hosts = ping_sweep(net)
            last_discovery = hosts
        elif choice == "5":
            target = Prompt.ask("Target (IP or CIDR)", default=net)
            top = Prompt.ask("Top ports to scan (number)", default="200")
            try:
                top_ports_scan(target, int(top))
            except ValueError:
                console.print("[red]Invalid number for top ports[/]")
        elif choice == "6":
            target = Prompt.ask("Target IP (single host preferred)", default=net)
            full_aggressive_scan(target)
        elif choice == "7":
            target = Prompt.ask("Target (CIDR)", default=net)
            run_masscan(target)
        elif choice == "8":
            ip_monitor()
        elif choice == "9":
            tcpdump_capture(iface)
        elif choice == "10":
            if not last_discovery:
                console.print("[yellow]No discovery results in memory. Run option 2 or 3 first.[/]")
            else:
                fname = Prompt.ask("Filename (optional)")
                if not fname:
                    save_hosts_csv(last_discovery)
                else:
                    save_hosts_csv(last_discovery, filename=os.path.expanduser(fname))
        elif choice == "0":
            console.print("[bold green]Goodbye![/]")
            break
        else:
            console.print("[red]Invalid choice[/]")
        Prompt.ask("Press Enter to continue")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Interrupted. Exiting.[/]")
        sys.exit(0)
