"""Sample capture files, built offline with Scapy and written straight to .pcap.

Nothing here sends a packet: every packet is created in memory and saved to a file,
so the web demo and the tests work without a network or admin rights.

Lab network: 192.168.1.0/24
  gateway  192.168.1.1   00:11:22:33:44:01
  laptop   192.168.1.10  3c:52:82:aa:10:10
  printer  192.168.1.20  00:1b:a9:bb:20:20
  attacker 192.168.1.66  de:ad:be:ef:00:66   (spoof samples only)
"""

import os
import random

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

BASE_T = 1_793_000_000.0  # fixed start time so samples are identical on every run
GW, GW_MAC = "192.168.1.1", "00:11:22:33:44:01"
PC, PC_MAC = "192.168.1.10", "3c:52:82:aa:10:10"
PR, PR_MAC = "192.168.1.20", "00:1b:a9:bb:20:20"
ATK, ATK_MAC = "192.168.1.66", "de:ad:be:ef:00:66"
BCAST = "ff:ff:ff:ff:ff:ff"
WEB = "93.184.216.34"
DNS_SRV = "1.1.1.1"


class _Builder:
    def __init__(self, seed=1):
        self.pkts = []
        self.rnd = random.Random(seed)

    def add(self, t, pkt):
        pkt.time = BASE_T + t
        self.pkts.append(pkt)

    def arp_req(self, t, smac, sip, tip):
        self.add(t, Ether(src=smac, dst=BCAST) / ARP(op=1, hwsrc=smac, psrc=sip, pdst=tip))

    def arp_rep(self, t, smac, sip, dmac, dip):
        self.add(t, Ether(src=smac, dst=dmac) / ARP(op=2, hwsrc=smac, psrc=sip, hwdst=dmac, pdst=dip))

    def garp(self, t, smac, sip):
        self.add(t, Ether(src=smac, dst=BCAST) / ARP(op=2, hwsrc=smac, psrc=sip, hwdst=BCAST, pdst=sip))

    def dns(self, t, name, answer, sport):
        q = Ether(src=PC_MAC, dst=GW_MAC) / IP(src=PC, dst=DNS_SRV) / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=name))
        r = Ether(src=GW_MAC, dst=PC_MAC) / IP(src=DNS_SRV, dst=PC) / UDP(sport=53, dport=sport) / \
            DNS(id=q[DNS].id, qr=1, rd=1, ra=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, rdata=answer, ttl=300))
        self.add(t, q)
        self.add(t + 0.018, r)

    def http(self, t, sport, path="/"):
        c = dict(src=PC, dst=WEB)
        s = dict(src=WEB, dst=PC)
        e1, e2 = Ether(src=PC_MAC, dst=GW_MAC), Ether(src=GW_MAC, dst=PC_MAC)
        seq, ack = self.rnd.randint(1000, 9_999_999), self.rnd.randint(1000, 9_999_999)
        req = f"GET {path} HTTP/1.1\r\nHost: example.com\r\nUser-Agent: lab-browser/1.0\r\n\r\n".encode()
        body = b"<html><body>Example Domain</body></html>"
        resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        self.add(t, e1 / IP(**c) / TCP(sport=sport, dport=80, flags="S", seq=seq))
        self.add(t + 0.03, e2 / IP(**s) / TCP(sport=80, dport=sport, flags="SA", seq=ack, ack=seq + 1))
        self.add(t + 0.031, e1 / IP(**c) / TCP(sport=sport, dport=80, flags="A", seq=seq + 1, ack=ack + 1))
        self.add(t + 0.032, e1 / IP(**c) / TCP(sport=sport, dport=80, flags="PA", seq=seq + 1, ack=ack + 1) / Raw(req))
        self.add(t + 0.07, e2 / IP(**s) / TCP(sport=80, dport=sport, flags="PA", seq=ack + 1, ack=seq + 1 + len(req)) / Raw(resp))
        self.add(t + 0.071, e1 / IP(**c) / TCP(sport=sport, dport=80, flags="FA", seq=seq + 1 + len(req), ack=ack + 1 + len(resp)))

    def https(self, t, sport, n=6):
        e1, e2 = Ether(src=PC_MAC, dst=GW_MAC), Ether(src=GW_MAC, dst=PC_MAC)
        for i in range(n):
            pl = Raw(b"\x17\x03\x03" + self.rnd.randbytes(120))
            if i % 2 == 0:
                self.add(t + i * 0.05, e1 / IP(src=PC, dst="142.250.183.14") / TCP(sport=sport, dport=443, flags="PA") / pl)
            else:
                self.add(t + i * 0.05, e2 / IP(src="142.250.183.14", dst=PC) / TCP(sport=443, dport=sport, flags="PA") / pl)

    def ping(self, t, seq):
        self.add(t, Ether(src=PC_MAC, dst=GW_MAC) / IP(src=PC, dst="8.8.8.8") / ICMP(type=8, id=1, seq=seq) / Raw(b"x" * 32))
        self.add(t + 0.012, Ether(src=GW_MAC, dst=PC_MAC) / IP(src="8.8.8.8", dst=PC) / ICMP(type=0, id=1, seq=seq) / Raw(b"x" * 32))

    def printer(self, t):
        self.add(t, Ether(src=PC_MAC, dst=PR_MAC) / IP(src=PC, dst=PR) / UDP(sport=50000, dport=161) / Raw(b"\x30\x26snmp-status"))
        self.add(t + 0.004, Ether(src=PR_MAC, dst=PC_MAC) / IP(src=PR, dst=PC) / UDP(sport=161, dport=50000) / Raw(b"\x30\x2aready"))

    def normal(self, start=0.0, seconds=30, sport0=51000):
        """A normal working LAN: ARP resolution, DNS, HTTP, HTTPS, ping and printer traffic."""
        self.arp_req(start + 0.0, PC_MAC, PC, GW)
        self.arp_rep(start + 0.002, GW_MAC, GW, PC_MAC, PC)
        sites = [("example.com", WEB), ("www.google.com", "142.250.183.14"), ("github.com", "140.82.112.3")]
        for k in range(seconds // 3):
            t = start + 0.5 + k * 3
            name, ans = sites[k % len(sites)]
            self.dns(t, name, ans, 40000 + k)
            if k % 2 == 0:
                self.http(t + 0.2, sport0 + k, "/" if k % 4 == 0 else "/index.html")
            self.https(t + 0.5, sport0 + 100 + k)
            self.ping(t + 1.2, k + 1)
            if k % 3 == 0:
                self.printer(t + 1.8)
            if k % 5 == 4:  # periodic legitimate ARP refresh
                self.arp_req(t + 2.2, PC_MAC, PC, GW)
                self.arp_rep(t + 2.202, GW_MAC, GW, PC_MAC, PC)
                self.arp_req(t + 2.4, PC_MAC, PC, PR)
                self.arp_rep(t + 2.402, PR_MAC, PR, PC_MAC, PC)


def normal_traffic():
    b = _Builder(1)
    b.normal(0, 30)
    return b.pkts


def arp_spoof():
    """An attacker poisons both the laptop and the gateway (classic man-in-the-middle)."""
    b = _Builder(2)
    b.normal(0, 12)
    for i in range(10):
        t = 12 + i * 2
        b.arp_rep(t, ATK_MAC, GW, PC_MAC, PC)        # tells the laptop: "the gateway is at my MAC"
        b.arp_rep(t + 0.001, ATK_MAC, PC, GW_MAC, GW)  # tells the gateway: "the laptop is at my MAC"
    b.normal(12.5, 18, sport0=52000)
    return sorted(b.pkts, key=lambda p: p.time)


def garp_flood():
    """A burst of gratuitous ARPs from one MAC claiming many addresses."""
    b = _Builder(3)
    b.normal(0, 6)
    for i in range(250):
        t = 6 + i * 0.008
        b.garp(t, ATK_MAC, f"192.168.1.{100 + i % 50}")
    b.normal(8.5, 6, sport0=53000)
    return sorted(b.pkts, key=lambda p: p.time)


def dhcp_benign():
    """Normal events that must NOT raise a high alert: a DHCP lease with its gratuitous
    announcement, and an old address reused by a new device after a long silence."""
    b = _Builder(4)
    old_mac, new_mac, phone_mac, ip = "00:aa:bb:cc:50:01", "00:aa:bb:cc:50:02", "f0:99:bf:12:34:56", "192.168.1.50"
    b.arp_req(0, PC_MAC, PC, ip)
    b.arp_rep(0.002, old_mac, ip, PC_MAC, PC)
    b.normal(1, 9)
    # a phone joins: DHCP discover / offer / request / ack, then announces itself once
    xid = 0x3903F326
    opts = lambda mt: [("message-type", mt), ("server_id", GW), ("lease_time", 86400), ("subnet_mask", "255.255.255.0"), "end"]
    b.add(12, Ether(src=phone_mac, dst=BCAST) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) /
          BOOTP(chaddr=bytes.fromhex(phone_mac.replace(":", "")), xid=xid) / DHCP(options=[("message-type", "discover"), "end"]))
    b.add(12.01, Ether(src=GW_MAC, dst=BCAST) / IP(src=GW, dst="255.255.255.255") / UDP(sport=67, dport=68) /
          BOOTP(op=2, yiaddr="192.168.1.77", chaddr=bytes.fromhex(phone_mac.replace(":", "")), xid=xid) / DHCP(options=opts("offer")))
    b.add(12.02, Ether(src=phone_mac, dst=BCAST) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) /
          BOOTP(chaddr=bytes.fromhex(phone_mac.replace(":", "")), xid=xid) / DHCP(options=[("message-type", "request"), ("requested_addr", "192.168.1.77"), "end"]))
    b.add(12.03, Ether(src=GW_MAC, dst=BCAST) / IP(src=GW, dst="255.255.255.255") / UDP(sport=67, dport=68) /
          BOOTP(op=2, yiaddr="192.168.1.77", chaddr=bytes.fromhex(phone_mac.replace(":", "")), xid=xid) / DHCP(options=opts("ack")))
    b.add(12.2, Ether(src=phone_mac, dst=BCAST) / ARP(op=1, hwsrc=phone_mac, psrc="0.0.0.0", pdst="192.168.1.77"))  # ARP probe
    b.garp(12.5, phone_mac, "192.168.1.77")
    # 15 minutes later the old device is gone and DHCP gives 192.168.1.50 to a new laptop
    b.garp(912, new_mac, ip)
    b.arp_req(912.5, PC_MAC, PC, ip)
    b.arp_rep(912.502, new_mac, ip, PC_MAC, PC)
    b.normal(913, 6, sport0=54000)
    return sorted(b.pkts, key=lambda p: p.time)


SAMPLES = {
    "normal_traffic.pcap": ("Normal LAN traffic: ARP, DNS, HTTP, HTTPS, ICMP, printer", normal_traffic),
    "arp_spoof.pcap": ("Simulated ARP spoofing (man-in-the-middle between laptop and gateway)", arp_spoof),
    "garp_flood.pcap": ("Simulated gratuitous ARP flood (250 announcements in 2 seconds)", garp_flood),
    "dhcp_benign.pcap": ("Benign DHCP lease and IP reuse: must NOT raise a high alert", dhcp_benign),
}


def build_samples(folder):
    os.makedirs(folder, exist_ok=True)
    paths = []
    for name, (_, make) in SAMPLES.items():
        p = os.path.join(folder, name)
        wrpcap(p, make())
        paths.append(p)
    return paths
