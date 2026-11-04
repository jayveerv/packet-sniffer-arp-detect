"""Exports: .pcap, alerts as JSON / CSV, and a self-contained HTML report."""

import csv
import html
import io
import json
import os
import time

from scapy.utils import wrpcap

from . import MITRE_ID, MITRE_NAME, __version__

ALERT_FIELDS = ["time", "severity", "type", "ip", "mac", "old_mac", "count", "packet", "mitre", "detail"]
SEV_COLOR = {"High": "#f0506e", "Medium": "#f5b83d", "Low": "#60a5fa"}
PROTO_COLOR = {"TCP": "#22d3ee", "HTTP": "#a78bfa", "UDP": "#34d399", "DNS": "#4ade80", "ARP": "#f5b83d",
               "ICMP": "#fb923c", "DHCP": "#2dd4bf", "IPv6": "#94a3b8", "IP": "#64748b", "Other": "#475569"}


def _ts(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t)) + f".{int((t % 1) * 1000):03d}"


def save_pcap(packets, path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    wrpcap(path, packets)
    return path


def alerts_json(alerts):
    return json.dumps({"tool": "Basic Packet Sniffer + ARP Spoofing Detector", "version": __version__,
                       "mitre": {"id": MITRE_ID, "name": MITRE_NAME},
                       "alerts": [dict(a, time_utc=_ts(a["time"])) for a in alerts]}, indent=2)


def alerts_csv(alerts):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=ALERT_FIELDS, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for a in alerts:
        w.writerow(dict(a, time=_ts(a["time"])))
    return buf.getvalue()


def write_text(text, path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    return path


def svg_bars(items, width=520, row=22, color_map=None):
    if not items:
        return "<p>No data</p>"
    mx = max(v for _, v in items) or 1
    h = row * len(items) + 6
    out = [f'<svg viewBox="0 0 {width} {h}" width="100%" role="img" aria-label="bar chart">']
    for i, (label, v) in enumerate(items):
        y = i * row + 3
        bw = (width - 190) * v / mx
        col = (color_map or {}).get(label, "#22d3ee")
        out.append(f'<text x="0" y="{y + 14}" fill="#9fb3c6" font-size="12">{html.escape(str(label))}</text>'
                   f'<rect x="110" y="{y + 3}" width="{max(bw, 1):.1f}" height="14" rx="3" fill="{col}"/>'
                   f'<text x="{116 + bw:.1f}" y="{y + 14}" fill="#d6e2ee" font-size="12">{v}</text>')
    out.append("</svg>")
    return "".join(out)


def svg_line(values, width=520, height=150):
    if not values:
        return "<p>No data</p>"
    mx = max(values) or 1
    n = max(len(values) - 1, 1)
    pts = " ".join(f"{30 + (width - 40) * i / n:.1f},{height - 22 - (height - 40) * v / mx:.1f}" for i, v in enumerate(values))
    return (f'<svg viewBox="0 0 {width} {height}" width="100%" role="img" aria-label="packets per second">'
            f'<line x1="30" y1="{height - 22}" x2="{width - 10}" y2="{height - 22}" stroke="#1e3347"/>'
            f'<text x="0" y="22" fill="#9fb3c6" font-size="11">{mx}</text><text x="0" y="{height - 22}" fill="#9fb3c6" font-size="11">0</text>'
            f'<polyline points="{pts}" fill="none" stroke="#22d3ee" stroke-width="2"/>'
            f'<text x="30" y="{height - 5}" fill="#9fb3c6" font-size="11">0 s</text>'
            f'<text x="{width - 10}" y="{height - 5}" fill="#9fb3c6" font-size="11" text-anchor="end">{len(values) - 1} s</text></svg>')


def html_report(analysis, title="Packet capture report", max_rows=500):
    e = html.escape
    s = analysis.stats()
    alerts = analysis.alerts
    summ = analysis.detector.summary()
    arows = "".join(
        f'<tr><td>{_ts(a["time"])}</td><td><b style="color:{SEV_COLOR[a["severity"]]}">{a["severity"]}</b></td>'
        f'<td>{e(a["type"])}</td><td>{e(a["ip"])}</td><td class="m">{e(a["mac"])}</td><td>{a["count"]}</td>'
        f'<td>{e(a["detail"])}</td></tr>' for a in alerts) or '<tr><td colspan="7">No ARP alerts.</td></tr>'
    prow = "".join(
        f'<tr><td>{r["no"]}</td><td>{r["rel"]:.3f}</td><td>{e(r["src"] or "")}</td><td>{e(r["dst"] or "")}</td>'
        f'<td>{e(r["proto"])}</td><td>{r["len"]}</td><td>{e(r["info"])}</td></tr>' for r in analysis.records[:max_rows])
    talkers = "".join(f"<tr><td>{e(h)}</td><td>{p}</td><td>{b:,}</td></tr>" for h, p, b in s["top_talkers"])
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title><style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#0b1622;color:#d6e2ee;margin:0;padding:24px}}h1{{margin:0;font-size:22px}}h2{{font-size:16px;margin:0 0 10px}}
.sub{{color:#8aa0b5;font-size:13px;margin:4px 0 18px}}.g{{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));margin-bottom:14px}}
.c{{background:#101e2c;border:1px solid #1e3347;border-radius:10px;padding:14px 16px}}.k{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}}
.k div{{background:#101e2c;border:1px solid #1e3347;border-radius:10px;padding:10px 16px}}.k b{{display:block;font-size:22px}}
table{{width:100%;border-collapse:collapse;font-size:12.5px}}th,td{{text-align:left;padding:5px 6px;border-bottom:1px solid #172a3c;vertical-align:top}}th{{color:#8aa0b5}}
.m{{font-family:Consolas,monospace}}
</style></head><body><h1>{e(title)}</h1><div class="sub">Basic Packet Sniffer + ARP Spoofing Detector v{__version__} &middot; generated {time.strftime('%Y-%m-%d %H:%M:%S')} &middot; MITRE ATT&amp;CK {MITRE_ID} {MITRE_NAME}</div>
<div class="k"><div><b>{s['packets']:,}</b>packets</div><div><b>{s['bytes']:,}</b>bytes</div><div><b>{s['duration']}</b>seconds</div><div><b>{s['avg_pps']}</b>avg pkt/s</div>
<div style="color:#f0506e"><b>{summ['High']}</b>High</div><div style="color:#f5b83d"><b>{summ['Medium']}</b>Medium</div><div style="color:#60a5fa"><b>{summ['Low']}</b>Low</div></div>
<div class="c" style="margin-bottom:14px"><h2>ARP alerts</h2><table><tr><th>Time (UTC)</th><th>Severity</th><th>Type</th><th>IP</th><th>MAC</th><th>Count</th><th>Detail</th></tr>{arows}</table></div>
<div class="g"><div class="c"><h2>Protocols</h2>{svg_bars(s['protocols'], color_map=PROTO_COLOR)}</div><div class="c"><h2>Packets per second</h2>{svg_line(s['pps'])}</div></div>
<div class="c" style="margin-bottom:14px"><h2>Top talkers</h2><table><tr><th>Host</th><th>Packets</th><th>Bytes</th></tr>{talkers}</table></div>
<div class="c"><h2>Packets{' (first ' + str(max_rows) + ')' if len(analysis.records) > max_rows else ''}</h2><table><tr><th>No.</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th><th>Info</th></tr>{prow}</table></div>
</body></html>"""
