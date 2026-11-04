import io
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------- CLI ----------------

def cli(*args, cwd=None):
    return subprocess.run([sys.executable, os.path.join(ROOT, "sniff.py"), *args], cwd=cwd, capture_output=True,
                          text=True, timeout=120, env=dict(os.environ, NO_COLOR="1"))


def test_cli_samples_and_analysis(tmp_path):
    assert cli("--make-samples", str(tmp_path / "s")).returncode == 0
    out = cli("--pcap", str(tmp_path / "s" / "arp_spoof.pcap"), "--report", str(tmp_path / "r.html"),
              "--alerts-json", str(tmp_path / "a.json"), "--alerts-csv", str(tmp_path / "a.csv"),
              "--proto", "arp", "--save-pcap", str(tmp_path / "arp.pcap"))
    assert out.returncode == 1  # high alerts found
    assert "IP-MAC conflict" in out.stdout and "T1557.002" in out.stdout
    for f in ["r.html", "a.json", "a.csv", "arp.pcap"]:
        assert (tmp_path / f).stat().st_size > 0
    clean = cli("--pcap", str(tmp_path / "s" / "normal_traffic.pcap"), "--proto", "tcp", "--port", "80", "--limit", "3")
    assert clean.returncode == 0 and "HTTP" in clean.stdout and "more (use --limit 0" in clean.stdout


def test_cli_errors(tmp_path):
    assert cli("--pcap", str(tmp_path / "missing.pcap")).returncode == 2
    assert cli("--pcap", "x.pcap", "--whitelist", "bad").returncode == 2


# ---------------- web app ----------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PS_DATA_DIR", str(tmp_path / "data"))
    import importlib
    import webapp.app as appmod
    appmod = importlib.reload(appmod)
    appmod.app.config["TESTING"] = True
    return appmod.app.test_client()


def test_index_redirects_to_default_sample(client):
    r = client.get("/")
    assert r.status_code == 302 and "/d/s-arp_spoof.pcap" in r.headers["Location"]


@pytest.mark.parametrize("name", ["normal_traffic.pcap", "arp_spoof.pcap", "garp_flood.pcap", "dhcp_benign.pcap"])
def test_every_sample_dashboard(client, name):
    page = client.get(f"/d/s-{name}").get_data(as_text=True)
    assert name in page and "Protocols" in page and "<svg" in page


def test_dashboard_content(client):
    spoof = client.get("/d/s-arp_spoof.pcap").get_data(as_text=True)
    assert "IP-MAC conflict" in spoof and "de:ad:be:ef:00:66" in spoof
    normal = client.get("/d/s-normal_traffic.pcap").get_data(as_text=True)
    assert "No ARP spoofing detected" in normal


def test_filters_and_pagination(client):
    page = client.get("/d/s-normal_traffic.pcap?proto=HTTP").get_data(as_text=True)
    assert "10 of 148 packets" in page
    page = client.get("/d/s-garp_flood.pcap?page=2").get_data(as_text=True)
    assert "Page 2 of" in page


def test_packet_detail(client):
    page = client.get("/d/s-arp_spoof.pcap/packet/59").get_data(as_text=True)
    assert "Packet #59" in page and "IP-MAC conflict" in page and "Hex dump" in page
    assert client.get("/d/s-arp_spoof.pcap/packet/99999").status_code == 404


def test_exports(client):
    assert client.get("/d/s-arp_spoof.pcap/export/alerts.json").json["alerts"]
    assert "IP-MAC conflict" in client.get("/d/s-arp_spoof.pcap/export/alerts.csv").get_data(as_text=True)
    assert "<!DOCTYPE html>" in client.get("/d/s-arp_spoof.pcap/export/report.html").get_data(as_text=True)
    r = client.get("/d/s-arp_spoof.pcap/export/packets.pcap?proto=ARP")
    assert r.status_code == 200 and r.data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4")
    assert client.get("/d/s-arp_spoof.pcap/export/nope").status_code == 404


def test_upload_pcap_and_reject_bad_file(client, tmp_path):
    from pkt.samples import arp_spoof
    from scapy.utils import wrpcap
    p = tmp_path / "mine.pcap"
    wrpcap(str(p), arp_spoof())
    r = client.post("/upload", data={"file": (open(p, "rb"), "mine.pcap")}, content_type="multipart/form-data")
    assert r.status_code == 302
    page = client.get(r.headers["Location"]).get_data(as_text=True)
    assert "mine.pcap" in page and "IP-MAC conflict" in page
    bad = client.post("/upload", data={"file": (io.BytesIO(b"not a pcap"), "x.pcap")},
                      content_type="multipart/form-data", follow_redirects=True)
    assert "not a valid pcap" in bad.get_data(as_text=True)


def test_uploads_are_private(tmp_path, monkeypatch):
    monkeypatch.setenv("PS_DATA_DIR", str(tmp_path / "data"))
    import importlib
    import webapp.app as appmod
    appmod = importlib.reload(appmod)
    from pkt.samples import normal_traffic
    from scapy.utils import wrpcap
    p = tmp_path / "a.pcap"
    wrpcap(str(p), normal_traffic())
    a, b = appmod.app.test_client(), appmod.app.test_client()
    loc = a.post("/upload", data={"file": (open(p, "rb"), "a.pcap")}, content_type="multipart/form-data").headers["Location"]
    assert a.get(loc).status_code == 200 and b.get(loc).status_code == 404


def test_settings_change_detection(client):
    r = client.post("/settings", data={"threshold": "1000", "window": "1", "whitelist": "", "back": "/d/s-garp_flood.pcap"})
    assert r.status_code == 302
    assert "Gratuitous ARP flood" not in client.get("/d/s-garp_flood.pcap").get_data(as_text=True)
    client.post("/settings", data={"threshold": "20", "window": "1", "whitelist": "192.168.1.1=00:11:22:33:44:01"})
    assert "Whitelisted MAC mismatch" in client.get("/d/s-arp_spoof.pcap").get_data(as_text=True)
    bad = client.post("/settings", data={"threshold": "20", "window": "1", "whitelist": "oops"}, follow_redirects=True)
    assert "Settings not saved" in bad.get_data(as_text=True)


def test_live_disabled_in_public_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("PS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PUBLIC_MODE", "1")
    import importlib
    import webapp.app as appmod
    appmod = importlib.reload(appmod)
    c = appmod.app.test_client()
    page = c.get("/live").get_data(as_text=True)
    assert "disabled on the hosted demo" in page
    assert "disabled on the hosted demo" in c.post("/live", data={"seconds": "5"}).get_data(as_text=True)


def test_other_pages(client):
    for url in ["/about", "/healthz", "/live"]:
        assert client.get(url).status_code == 200
    assert client.get("/d/s-unknown.pcap").status_code == 404
    assert client.get("/d/u-..").status_code == 404
