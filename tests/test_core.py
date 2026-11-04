import json
import os

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import rdpcap

from pkt import MITRE_ID
from pkt.analyzer import analyse_pcap
from pkt.arp_detector import ArpDetector, parse_whitelist
from pkt.export import alerts_csv, alerts_json, html_report, save_pcap
from pkt.filters import apply, matches
from pkt.parser import parse_packet
from pkt.samples import SAMPLES
from pkt.stats import compute

GW, GW_MAC = "192.168.1.1", "00:11:22:33:44:01"
PC, PC_MAC = "192.168.1.10", "3c:52:82:aa:10:10"
EVIL = "de:ad:be:ef:00:66"


E = dict(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
I = dict(src="10.0.0.1", dst="10.0.0.2")


def stamp(pkt, t=100.0):
    pkt.time = t
    return pkt


# ---------------- parsing ----------------

def test_parse_arp_request_and_reply():
    r = parse_packet(stamp(Ether(src=PC_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=PC_MAC, psrc=PC, pdst=GW)))
    assert r["proto"] == "ARP" and r["src"] == PC and r["dst"] == GW and r["src_mac"] == PC_MAC
    assert r["info"] == f"Who has {GW}? Tell {PC}"
    r = parse_packet(stamp(Ether(**E) / ARP(op=2, hwsrc=GW_MAC, psrc=GW, pdst=PC)))
    assert r["info"] == f"{GW} is at {GW_MAC}"
    r = parse_packet(stamp(Ether(**E) / ARP(op=2, hwsrc=GW_MAC, psrc=GW, pdst=GW)))
    assert "gratuitous" in r["info"]


def test_parse_tcp_http_tls():
    r = parse_packet(stamp(Ether(**E) / IP(src=PC, dst="1.2.3.4") / TCP(sport=5000, dport=80, flags="S")))
    assert (r["proto"], r["sport"], r["dport"]) == ("TCP", 5000, 80) and "SYN" in r["info"]
    r = parse_packet(stamp(Ether(**E) / IP(src=PC, dst="1.2.3.4") / TCP(sport=5000, dport=80, flags="PA") / Raw(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n")))
    assert r["proto"] == "HTTP" and r["info"] == "GET /a HTTP/1.1"
    r = parse_packet(stamp(Ether(**E) / IP(**I) / TCP(sport=5000, dport=443, flags="PA") / Raw(b"\x17\x03\x03abc")))
    assert r["proto"] == "TCP" and "TLS" in r["info"]


def test_parse_dns_query_and_response():
    q = parse_packet(stamp(Ether(**E) / IP(**I) / UDP(sport=4000, dport=53) / DNS(qd=DNSQR(qname="example.com"))))
    assert q["proto"] == "DNS" and q["info"] == "Query A example.com"
    pkt = Ether(**E) / IP(**I) / UDP(sport=53, dport=4000) / DNS(qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata="93.184.216.34"))
    r = parse_packet(stamp(Ether(bytes(pkt))))
    assert r["info"] == "Response example.com -> 93.184.216.34"


def test_parse_icmp_udp_and_times():
    r = parse_packet(stamp(Ether(**E) / IP(**I) / ICMP(type=8), 105.5), 7, 100.0)
    assert r["proto"] == "ICMP" and r["info"] == "Echo request" and r["no"] == 7 and r["rel"] == 5.5
    r = parse_packet(stamp(Ether(**E) / IP(**I) / UDP(sport=1, dport=2) / Raw(b"x")))
    assert r["proto"] == "UDP" and r["len"] > 0


# ---------------- filters ----------------

RECS = [
    {"proto": "HTTP", "src": "1.1.1.1", "dst": "2.2.2.2", "sport": 5000, "dport": 80},
    {"proto": "DNS", "src": "1.1.1.1", "dst": "8.8.8.8", "sport": 4000, "dport": 53},
    {"proto": "ARP", "src": "1.1.1.1", "dst": "1.1.1.254", "sport": None, "dport": None},
]


def test_filters_protocol_family_ip_port():
    assert [r["proto"] for r in apply(RECS, proto="tcp")] == ["HTTP"]
    assert [r["proto"] for r in apply(RECS, proto="UDP")] == ["DNS"]
    assert len(apply(RECS, proto="IP")) == 2
    assert [r["proto"] for r in apply(RECS, ip="8.8.8.8")] == ["DNS"]
    assert [r["proto"] for r in apply(RECS, port=80)] == ["HTTP"]
    assert apply(RECS, proto="tcp", port=53) == []
    assert matches(RECS[2], proto="arp", ip="1.1.1.254")


# ---------------- ARP detector ----------------

def arp(op, hwsrc, psrc, pdst):
    return ARP(op=op, hwsrc=hwsrc, psrc=psrc, pdst=pdst)


def test_normal_request_reply_raises_nothing():
    d = ArpDetector()
    d.process(arp(1, PC_MAC, PC, GW), 0)
    assert d.process(arp(2, GW_MAC, GW, PC), 0.01) == []
    assert d.alerts == [] and d.table[GW]["mac"] == GW_MAC


def test_mac_change_is_high_and_mapped_to_mitre():
    d = ArpDetector()
    d.process(arp(1, PC_MAC, PC, GW), 0)
    d.process(arp(2, GW_MAC, GW, PC), 0.01)
    hits = d.process(arp(2, EVIL, GW, PC), 5)
    types = {h["type"]: h for h in hits}
    assert types["IP-MAC conflict"]["severity"] == "High"
    assert types["IP-MAC conflict"]["old_mac"] == GW_MAC and types["IP-MAC conflict"]["mitre"] == MITRE_ID
    assert types["Unsolicited ARP reply"]["severity"] == "Medium"
    assert d.table[GW]["mac"] == GW_MAC  # the trusted first mapping is kept


def test_unsolicited_reply_without_change_is_low():
    d = ArpDetector()
    hits = d.process(arp(2, GW_MAC, GW, PC), 0)
    assert [(h["type"], h["severity"]) for h in hits] == [("Unsolicited ARP reply", "Low")]


def test_repeated_alerts_are_grouped():
    d = ArpDetector()
    d.process(arp(2, GW_MAC, GW, PC), 0)
    for i in range(5):
        d.process(arp(2, EVIL, GW, PC), 1 + i)
    conflict = [a for a in d.alerts if a["type"] == "IP-MAC conflict"]
    assert len(conflict) == 1 and conflict[0]["count"] == 5


def test_gratuitous_flood_threshold():
    d = ArpDetector(flood_threshold=10, flood_window=1.0)
    for i in range(10):
        d.process(arp(2, EVIL, f"10.0.0.{i}", f"10.0.0.{i}"), i * 0.05)
    assert d.alerts == []
    d.process(arp(2, EVIL, "10.0.0.99", "10.0.0.99"), 0.6)
    flood = [a for a in d.alerts if a["type"] == "Gratuitous ARP flood"]
    assert len(flood) == 1 and flood[0]["severity"] == "High" and flood[0]["ip"] == "multiple"


def test_slow_gratuitous_arps_are_not_a_flood():
    d = ArpDetector(flood_threshold=5, flood_window=1.0)
    for i in range(20):
        d.process(arp(2, PC_MAC, PC, PC), i * 2.0)
    assert d.alerts == []


def test_whitelist_mismatch():
    d = ArpDetector(whitelist={GW: GW_MAC})
    assert d.process(arp(1, GW_MAC, GW, PC), 0) == []
    hits = d.process(arp(1, EVIL, GW, PC), 1)
    assert hits[0]["type"] == "Whitelisted MAC mismatch" and hits[0]["old_mac"] == GW_MAC


def test_stale_ip_reuse_is_low():
    d = ArpDetector(stale_after=300)
    d.process(arp(2, "00:00:00:00:00:01", "10.0.0.50", "10.0.0.50"), 0)
    hits = d.process(arp(2, "00:00:00:00:00:02", "10.0.0.50", "10.0.0.50"), 1000)
    assert [(h["type"], h["severity"]) for h in hits] == [("IP reassigned", "Low")]
    assert d.table["10.0.0.50"]["mac"] == "00:00:00:00:00:02"


def test_arp_probe_is_ignored():
    d = ArpDetector()
    assert d.process(arp(1, PC_MAC, "0.0.0.0", "10.0.0.7"), 0) == [] and d.table == {}


def test_parse_whitelist():
    assert parse_whitelist("192.168.1.1=AA:BB:CC:DD:EE:FF, 10.0.0.1=00:00:00:00:00:01") == {
        "192.168.1.1": "aa:bb:cc:dd:ee:ff", "10.0.0.1": "00:00:00:00:00:01"}
    for bad in ["192.168.1.1", "1.1.1.1=zz"]:
        with pytest.raises(ValueError):
            parse_whitelist(bad)


# ---------------- samples, end to end ----------------

def test_samples_exist_and_are_offline(sample_dir):
    assert sorted(os.listdir(sample_dir)) == sorted(SAMPLES)


def test_normal_sample_has_no_alerts(sample_dir):
    a = analyse_pcap(str(sample_dir / "normal_traffic.pcap"))
    protos = dict(a.stats()["protocols"])
    assert a.alerts == []
    for p in ["ARP", "DNS", "HTTP", "TCP", "ICMP", "UDP"]:
        assert protos.get(p), p


def test_spoof_sample_detected(sample_dir):
    a = analyse_pcap(str(sample_dir / "arp_spoof.pcap"))
    high = [x for x in a.alerts if x["severity"] == "High"]
    assert {x["ip"] for x in high} == {"192.168.1.1", "192.168.1.10"}
    assert all(x["mac"] == EVIL for x in high)
    assert any(r.get("alert") == "High" for r in a.records)


def test_flood_sample_detected(sample_dir):
    a = analyse_pcap(str(sample_dir / "garp_flood.pcap"))
    assert [x["type"] for x in a.alerts if x["severity"] == "High"] == ["Gratuitous ARP flood"]


def test_flood_threshold_is_configurable(sample_dir):
    a = analyse_pcap(str(sample_dir / "garp_flood.pcap"), flood_threshold=1000)
    assert not [x for x in a.alerts if x["type"] == "Gratuitous ARP flood"]


def test_dhcp_benign_has_no_high_or_medium(sample_dir):
    a = analyse_pcap(str(sample_dir / "dhcp_benign.pcap"))
    s = a.detector.summary()
    assert s["High"] == 0 and s["Medium"] == 0
    assert any(r["proto"] == "DHCP" for r in a.records)


def test_whitelist_on_spoof_sample(sample_dir):
    a = analyse_pcap(str(sample_dir / "arp_spoof.pcap"), whitelist={"192.168.1.1": GW_MAC})
    assert any(x["type"] == "Whitelisted MAC mismatch" for x in a.alerts)


# ---------------- stats and export ----------------

def test_stats(sample_dir):
    s = analyse_pcap(str(sample_dir / "normal_traffic.pcap")).stats()
    assert s["packets"] == sum(n for _, n in s["protocols"]) == sum(s["pps"])
    assert s["top_talkers"][0][0] == "192.168.1.10"
    assert s["peak_pps"] >= s["avg_pps"] > 0
    assert compute([])["packets"] == 0


def test_exports(sample_dir, tmp_path):
    a = analyse_pcap(str(sample_dir / "arp_spoof.pcap"))
    doc = json.loads(alerts_json(a.alerts))
    assert doc["mitre"]["id"] == MITRE_ID and len(doc["alerts"]) == len(a.alerts)
    lines = alerts_csv(a.alerts).strip().splitlines()
    assert lines[0].startswith("time,severity,type") and len(lines) == len(a.alerts) + 1
    html = html_report(a, "t")
    assert "<!DOCTYPE html>" in html and "IP-MAC conflict" in html and "<svg" in html
    arp_only = a.filtered(proto="ARP")
    out = save_pcap(a.packets_for(arp_only), str(tmp_path / "x" / "arp.pcap"))
    back = rdpcap(out)
    assert len(back) == len(arp_only) and all(ARP in p for p in back)


def test_html_report_escapes(tmp_path):
    from pkt.analyzer import Analysis
    a = Analysis()
    a.add(stamp(Ether(**E) / IP(**I) / TCP(sport=1, dport=80, flags="PA") / Raw(b"GET /<script>alert(1)</script> HTTP/1.1\r\n\r\n")))
    html = html_report(a)
    assert "<script>alert" not in html and "&lt;script&gt;" in html
