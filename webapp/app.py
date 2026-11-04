"""Basic Packet Sniffer + ARP Spoofing Detector - Flask dashboard.

Works online without live capture: it analyses the bundled sample pcaps or a pcap you upload.
Live capture is only offered when running locally with the right permissions (never on the hosted demo).
"""

import io
import os
import secrets
import shutil
import sys
import threading
import time
from collections import OrderedDict

from flask import (Flask, Response, abort, flash, redirect, render_template, request, send_file, session, url_for)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scapy.layers.l2 import ARP  # noqa: E402
from scapy.utils import hexdump, wrpcap  # noqa: E402

from pkt import MITRE_ID, MITRE_NAME, __version__  # noqa: E402
from pkt.analyzer import analyse_pcap  # noqa: E402
from pkt.arp_detector import parse_whitelist  # noqa: E402
from pkt.capture import capture_status, list_interfaces, live_capture  # noqa: E402
from pkt.export import PROTO_COLOR, alerts_csv, alerts_json, html_report, svg_bars, svg_line  # noqa: E402
from pkt.filters import PROTOCOLS  # noqa: E402
from pkt.samples import SAMPLES, build_samples  # noqa: E402

SAMPLE_DIR = os.path.join(ROOT, "samples")
DATA = os.environ.get("PS_DATA_DIR", os.path.join(ROOT, "webapp_data"))
PUBLIC_MODE = os.environ.get("PUBLIC_MODE", "0") not in ("", "0", "false", "no")
RETENTION_H = float(os.environ.get("RETENTION_HOURS", "24"))
MAX_MB = int(os.environ.get("MAX_UPLOAD_MB", "10"))
MAX_PACKETS = int(os.environ.get("MAX_PACKETS", "50000"))
PAGE = 100
PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}
DEFAULT_DS = "s-arp_spoof.pcap"

app = Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
                  MAX_CONTENT_LENGTH=MAX_MB * 1024 * 1024)

if not all(os.path.exists(os.path.join(SAMPLE_DIR, n)) for n in SAMPLES):
    build_samples(SAMPLE_DIR)

_cache = OrderedDict()
_lock = threading.Lock()
_last_cleanup = [0.0]


def visitor_dir():
    vid = session.get("vid")
    if not vid or not vid.isalnum():
        vid = session["vid"] = secrets.token_hex(8)
    d = os.path.join(DATA, "visitors", vid)
    os.makedirs(d, exist_ok=True)
    return d


def dataset_path(dsid):
    if dsid.startswith("s-") and dsid[2:] in SAMPLES:
        return os.path.join(SAMPLE_DIR, dsid[2:]), dsid[2:]
    if dsid.startswith("u-") and dsid[2:].isalnum():
        p = os.path.join(visitor_dir(), dsid[2:] + ".pcap")
        if os.path.exists(p):
            names = session.get("names", {})
            return p, names.get(dsid, "uploaded.pcap")
    abort(404)


def settings():
    s = session.get("settings") or {}
    return {"threshold": int(s.get("threshold", 20)), "window": float(s.get("window", 1.0)),
            "whitelist": s.get("whitelist", "")}


def get_analysis(dsid):
    path, name = dataset_path(dsid)
    st = settings()
    key = (path, os.path.getmtime(path), st["threshold"], st["window"], st["whitelist"])
    with _lock:
        if key in _cache:
            _cache.move_to_end(key)
            return _cache[key], name
    a = analyse_pcap(path, limit=MAX_PACKETS, whitelist=parse_whitelist(st["whitelist"]),
                     flood_threshold=st["threshold"], flood_window=st["window"])
    with _lock:
        _cache[key] = a
        while len(_cache) > 12:
            _cache.popitem(last=False)
    return a, name


def current_filters():
    proto = request.args.get("proto") or None
    ip = (request.args.get("ip") or "").strip() or None
    port = request.args.get("port") or None
    if port is not None and not port.isdigit():
        port = None
    return proto, ip, port


@app.before_request
def cleanup():
    if not PUBLIC_MODE or time.time() - _last_cleanup[0] < 600:
        return
    _last_cleanup[0] = time.time()
    root = os.path.join(DATA, "visitors")
    if os.path.isdir(root):
        for vid in os.listdir(root):
            p = os.path.join(root, vid)
            if time.time() - os.path.getmtime(p) > RETENTION_H * 3600:
                shutil.rmtree(p, ignore_errors=True)


@app.context_processor
def inject():
    return {"version": __version__, "public_mode": PUBLIC_MODE, "retention": int(RETENTION_H), "max_mb": MAX_MB,
            "mitre_id": MITRE_ID, "mitre_name": MITRE_NAME, "samples": SAMPLES}


@app.template_filter("utc")
def utc(t):
    return time.strftime("%H:%M:%S", time.gmtime(t)) + f".{int((t % 1) * 1000):03d}"


@app.get("/")
def index():
    return redirect(url_for("dashboard", dsid=session.get("ds", DEFAULT_DS)))


@app.get("/d/<dsid>")
def dashboard(dsid):
    a, name = get_analysis(dsid)
    session["ds"] = dsid
    proto, ip, port = current_filters()
    rows = a.filtered(proto, ip, port)
    page = max(int(request.args.get("page", 1) or 1), 1)
    pages = max((len(rows) + PAGE - 1) // PAGE, 1)
    page = min(page, pages)
    s = a.stats()
    uploads = [(k, v) for k, v in session.get("names", {}).items()]
    return render_template(
        "dashboard.html", dsid=dsid, name=name, stats=s, alerts=a.alerts, summary=a.detector.summary(),
        rows=rows[(page - 1) * PAGE: page * PAGE], total_rows=len(rows), page=page, pages=pages,
        proto=proto or "", ip=ip or "", port=port or "", protocols=PROTOCOLS, st=settings(), uploads=uploads,
        proto_chart=svg_bars(s["protocols"], color_map=PROTO_COLOR), pps_chart=svg_line(s["pps"][:600]),
        arp_table=sorted(a.detector.table.items()))


@app.get("/d/<dsid>/packet/<int:no>")
def packet(dsid, no):
    a, name = get_analysis(dsid)
    if not 1 <= no <= len(a.records):
        abort(404)
    pkt = a.packets[no - 1]
    rec = a.records[no - 1]
    detail = pkt.show(dump=True)
    hx = hexdump(pkt, dump=True)
    related = [al for al in a.alerts if al["packet"] == no or (ARP in pkt and al["ip"] == pkt[ARP].psrc and al["mac"] == pkt[ARP].hwsrc.lower())]
    return render_template("packet.html", dsid=dsid, name=name, r=rec, detail=detail, hexd=hx, related=related, total=len(a.records))


@app.get("/d/<dsid>/export/<kind>")
def export(dsid, kind):
    a, name = get_analysis(dsid)
    base = os.path.splitext(name)[0]
    if kind == "alerts.json":
        return Response(alerts_json(a.alerts), mimetype="application/json",
                        headers={"Content-Disposition": f"attachment; filename={base}_alerts.json"})
    if kind == "alerts.csv":
        return Response(alerts_csv(a.alerts), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={base}_alerts.csv"})
    if kind == "report.html":
        return html_report(a, f"Packet capture report: {name}")
    if kind == "packets.pcap":
        proto, ip, port = current_filters()
        tmp = os.path.join(visitor_dir(), "export_" + secrets.token_hex(4) + ".pcap")
        wrpcap(tmp, a.packets_for(a.filtered(proto, ip, port)))
        with open(tmp, "rb") as fh:
            buf = io.BytesIO(fh.read())
        os.remove(tmp)
        return send_file(buf, mimetype="application/vnd.tcpdump.pcap", as_attachment=True,
                         download_name=f"{base}_filtered.pcap")
    abort(404)


@app.post("/upload")
def upload():
    f = request.files.get("file")
    if not f or not f.filename:
        flash("Choose a .pcap or .pcapng file first.", "error")
        return redirect(url_for("index"))
    token = secrets.token_hex(6)
    path = os.path.join(visitor_dir(), token + ".pcap")
    f.save(path)
    with open(path, "rb") as fh:
        magic = fh.read(4)
    valid = magic in PCAP_MAGIC
    if valid:
        try:
            from scapy.utils import PcapReader
            with PcapReader(path) as r:
                next(iter(r), None)
        except Exception:
            valid = False
    if not valid:
        try:
            os.remove(path)
        except OSError:
            pass
        flash("That file is not a valid pcap / pcapng capture.", "error")
        return redirect(url_for("index"))
    names = session.get("names", {})
    names["u-" + token] = os.path.basename(f.filename)[:80]
    session["names"] = names
    return redirect(url_for("dashboard", dsid="u-" + token))


@app.post("/settings")
def save_settings():
    try:
        wl = request.form.get("whitelist", "").strip()
        parse_whitelist(wl)
        th = max(1, min(int(request.form.get("threshold", 20)), 10000))
        win = max(0.1, min(float(request.form.get("window", 1.0)), 60.0))
    except ValueError as exc:
        flash(f"Settings not saved: {exc}", "error")
    else:
        session["settings"] = {"threshold": th, "window": win, "whitelist": wl}
        flash("Detection settings saved and applied.", "ok")
    return redirect(request.form.get("back") or url_for("index"))


@app.route("/live", methods=["GET", "POST"])
def live():
    ok, msg = (False, "Live capture is disabled on the hosted demo. Run the project on your own computer.") if PUBLIC_MODE else capture_status()
    ifaces = list_interfaces() if ok else []
    if request.method == "POST" and ok:
        seconds = max(1, min(int(request.form.get("seconds", 15)), 120))
        iface = request.form.get("iface") or None
        try:
            pkts = live_capture(iface, 0, seconds)
        except Exception as exc:
            flash(f"Capture failed: {exc}", "error")
            return redirect(url_for("live"))
        token = secrets.token_hex(6)
        wrpcap(os.path.join(visitor_dir(), token + ".pcap"), pkts)
        names = session.get("names", {})
        names["u-" + token] = f"live_{time.strftime('%H%M%S')}.pcap"
        session["names"] = names
        return redirect(url_for("dashboard", dsid="u-" + token))
    return render_template("live.html", ok=ok, msg=msg, ifaces=ifaces)


@app.get("/about")
def about():
    return render_template("about.html", st=settings())


@app.errorhandler(413)
def too_large(_):
    flash(f"File too large. The limit is {MAX_MB} MB.", "error")
    return redirect(url_for("index"))


@app.get("/healthz")
def healthz():
    return {"ok": True, "version": __version__}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")
    print(f"\n  Packet Sniffer + ARP Spoofing Detector v{__version__}\n  Open http://127.0.0.1:{port}/\n")
    try:
        from waitress import serve
        serve(app, host=host, port=port, threads=8)
    except ImportError:
        app.run(host=host, port=port)
