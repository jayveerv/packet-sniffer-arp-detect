"""Basic Packet Sniffer + ARP Spoofing Detector - command line.

Examples:
    python sniff.py --make-samples samples                 build the sample pcaps
    python sniff.py --pcap samples/arp_spoof.pcap          analyse a capture file
    python sniff.py --pcap samples/normal_traffic.pcap --proto tcp --port 80
    python sniff.py --pcap file.pcap --report report.html --alerts-json alerts.json --alerts-csv alerts.csv
    python sniff.py --pcap file.pcap --proto dns --save-pcap dns_only.pcap
    python sniff.py --list-ifaces
    python sniff.py --iface "Wi-Fi" --count 500 --timeout 60 --save-pcap capture.pcap   (live, admin + Npcap)
"""

import argparse
import os
import sys
import time

from pkt import MITRE_ID, MITRE_NAME, __version__
from pkt.analyzer import Analysis, analyse_pcap
from pkt.arp_detector import parse_whitelist
from pkt.capture import capture_status, list_interfaces, live_capture
from pkt.export import alerts_csv, alerts_json, html_report, save_pcap, write_text
from pkt.samples import SAMPLES, build_samples

if os.name == "nt":
    os.system("")  # turns on colour support in the Windows console

SEV = {"High": "\033[91m", "Medium": "\033[93m", "Low": "\033[94m"}
END = "\033[0m"


def c(text, sev):
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    return SEV.get(sev, "") + text + END


def row(r):
    src = r["src"] or r["src_mac"] or "-"
    dst = r["dst"] or r["dst_mac"] or "-"
    if r["sport"] is not None:
        src, dst = f"{src}:{r['sport']}", f"{dst}:{r['dport']}"
    flag = c(" <-- " + r["alert"], r["alert"]) if r.get("alert") else ""
    return f"{r['no']:>6} {r['rel']:>10.3f}  {src:<22} {dst:<22} {r['proto']:<5} {r['len']:>5}  {r['info'][:60]}{flag}"


def report(a, args, records):
    if not args.quiet:
        print(f"{'No.':>6} {'Time':>10}  {'Source':<22} {'Destination':<22} {'Proto':<5} {'Len':>5}  Info")
        shown = records if args.limit == 0 else records[:args.limit]
        for r in shown:
            print(row(r))
        if len(shown) < len(records):
            print(f"   ... {len(records) - len(shown)} more (use --limit 0 to show all)")
    s = a.stats()
    print(f"\n{s['packets']} packets ({len(records)} after filters), {s['bytes']:,} bytes, {s['duration']} s, "
          f"avg {s['avg_pps']} pkt/s, peak {s['peak_pps']} pkt/s")
    print("Protocols:", ", ".join(f"{p} {n}" for p, n in s["protocols"]))
    print("Top talkers:", ", ".join(f"{h} ({p})" for h, p, _ in s["top_talkers"][:5]))
    alerts = a.alerts
    summ = a.detector.summary()
    print(f"\nARP alerts: {len(alerts)}  (High {summ['High']}, Medium {summ['Medium']}, Low {summ['Low']})  "
          f"MITRE ATT&CK {MITRE_ID} {MITRE_NAME}")
    for al in alerts:
        print("  " + c(f"[{al['severity']:<6}]", al["severity"]) + f" {al['type']}: {al['detail']} (x{al['count']}, first at packet {al['packet']})")
    if args.report:
        print("HTML report :", write_text(html_report(a, f"Packet capture report: {args.title}"), args.report))
    if args.alerts_json:
        print("Alerts JSON :", write_text(alerts_json(alerts), args.alerts_json))
    if args.alerts_csv:
        print("Alerts CSV  :", write_text(alerts_csv(alerts), args.alerts_csv))
    if args.save_pcap:
        print("Saved pcap  :", save_pcap(a.packets_for(records), args.save_pcap), f"({len(records)} packets)")
    return 1 if summ["High"] else 0


def main(argv=None):
    p = argparse.ArgumentParser(description="Basic Packet Sniffer + ARP Spoofing Detector (detection only)")
    p.add_argument("--version", action="version", version=__version__)
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="read packets from a .pcap/.pcapng file")
    src.add_argument("--iface", nargs="?", const="", help="live capture from an interface (admin + Npcap on Windows)")
    src.add_argument("--list-ifaces", action="store_true", help="list network interfaces")
    src.add_argument("--make-samples", metavar="FOLDER", help="build the sample pcaps (offline, nothing is sent)")
    p.add_argument("--count", type=int, default=0, help="live: stop after N packets (0 = no limit)")
    p.add_argument("--timeout", type=int, default=30, help="live: stop after N seconds")
    p.add_argument("--proto", help="filter: ARP, IP, TCP, UDP, ICMP, DNS, DHCP, HTTP")
    p.add_argument("--ip", help="filter: source or destination IP")
    p.add_argument("--port", type=int, help="filter: source or destination port")
    p.add_argument("--limit", type=int, default=40, help="packets to print (0 = all)")
    p.add_argument("--quiet", action="store_true", help="do not print the packet table")
    p.add_argument("--whitelist", default="", help="trusted IP=MAC pairs, comma separated")
    p.add_argument("--garp-threshold", type=int, default=20, help="gratuitous ARPs per window that count as a flood")
    p.add_argument("--garp-window", type=float, default=1.0, help="flood window in seconds")
    p.add_argument("--report", help="write an HTML report to this path")
    p.add_argument("--alerts-json", help="write alerts as JSON")
    p.add_argument("--alerts-csv", help="write alerts as CSV")
    p.add_argument("--save-pcap", help="save the (filtered) packets to a .pcap file")
    args = p.parse_args(argv)

    if args.make_samples:
        for path in build_samples(args.make_samples):
            print(f"  {path:<40} {SAMPLES[os.path.basename(path)][0]}")
        return 0
    if args.list_ifaces:
        ok, msg = capture_status()
        print("Live capture:", "available" if ok else "not available", "-", msg)
        for i in list_interfaces():
            print(f"  {i['name']:<30} {i['ip']:<16} {i['mac']:<18} {i['description']}")
        return 0
    try:
        whitelist = parse_whitelist(args.whitelist)
    except ValueError as exc:
        p.error(str(exc))
    opts = dict(whitelist=whitelist, flood_threshold=args.garp_threshold, flood_window=args.garp_window)
    print(f"Basic Packet Sniffer + ARP Spoofing Detector v{__version__} (detection only)\n")
    if args.pcap:
        if not os.path.exists(args.pcap):
            print("error: file not found:", args.pcap)
            return 2
        a = analyse_pcap(args.pcap, **opts)
        args.title = os.path.basename(args.pcap)
    else:
        a = Analysis(**opts)
        live = []

        def on_packet(pkt):
            rec = a.add(pkt)
            live.append(rec)
            if not args.quiet:
                print(row(rec))
        print(f"Capturing on {args.iface or 'default interface'} for {args.timeout}s (Ctrl+C to stop)...")
        try:
            live_capture(args.iface or None, args.count, args.timeout, on_packet)
        except PermissionError as exc:
            print("Live capture is not available:", exc)
            return 2
        except KeyboardInterrupt:
            pass
        args.quiet = True
        args.title = f"live capture {time.strftime('%Y-%m-%d %H:%M')}"
    records = a.filtered(args.proto, args.ip, args.port)
    return report(a, args, records)


if __name__ == "__main__":
    sys.exit(main())
