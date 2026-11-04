"""Turn Scapy packets into simple, readable records."""

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"HTTP/1.")
ICMP_TYPES = {0: "Echo reply", 3: "Destination unreachable", 5: "Redirect", 8: "Echo request", 11: "Time exceeded"}
TCP_FLAGS = [("S", "SYN"), ("F", "FIN"), ("R", "RST"), ("P", "PSH"), ("A", "ACK"), ("U", "URG")]
BROADCAST = "ff:ff:ff:ff:ff:ff"


def _name(x):
    if isinstance(x, bytes):
        x = x.decode("utf-8", "replace")
    return str(x).rstrip(".")


def _list(field):
    if field is None:
        return []
    if isinstance(field, list):
        return field
    try:
        return list(field)
    except TypeError:
        return [field]


def is_gratuitous(arp):
    """A gratuitous ARP announces the sender's own IP (sender IP == target IP)."""
    return arp.psrc == arp.pdst


def dns_info(d):
    qs = _list(d.qd)
    qname = _name(qs[0].qname) if qs else "?"
    if d.qr == 0:
        qtype = qs[0].sprintf("%qtype%") if qs else ""
        return f"Query {qtype} {qname}"
    answers = []
    for rr in _list(d.an):
        rdata = getattr(rr, "rdata", None)
        if rdata is not None:
            answers.append(_name(rdata))
    return f"Response {qname} -> {', '.join(answers) or 'no answer'}"


def http_info(payload):
    line = payload.split(b"\r\n", 1)[0][:120]
    return line.decode("latin-1", "replace")


def parse_packet(pkt, no=1, t0=None):
    t = float(pkt.time)
    rec = {"no": no, "time": t, "rel": round(t - (t0 if t0 is not None else t), 6), "len": len(pkt),
           "src_mac": None, "dst_mac": None, "src": None, "dst": None, "sport": None, "dport": None,
           "proto": "Other", "info": ""}
    if Ether in pkt:
        rec["src_mac"], rec["dst_mac"] = pkt[Ether].src, pkt[Ether].dst
    if ARP in pkt:
        a = pkt[ARP]
        rec.update(proto="ARP", src=a.psrc, dst=a.pdst)
        if a.op == 1:
            rec["info"] = f"Who has {a.pdst}? Tell {a.psrc}"
        elif a.op == 2:
            rec["info"] = f"{a.psrc} is at {a.hwsrc}"
        else:
            rec["info"] = f"ARP op {a.op}"
        if is_gratuitous(a):
            rec["info"] += " (gratuitous)"
        return rec
    ip = pkt[IP] if IP in pkt else pkt[IPv6] if IPv6 in pkt else None
    if ip is None:
        if Ether in pkt:
            rec["info"] = f"EtherType 0x{pkt[Ether].type:04x}"
        return rec
    rec.update(src=ip.src, dst=ip.dst, proto="IPv6" if IPv6 in pkt and IP not in pkt else "IP")
    if TCP in pkt:
        tcp = pkt[TCP]
        flags = "/".join(n for f, n in TCP_FLAGS if f in str(tcp.flags))
        rec.update(proto="TCP", sport=tcp.sport, dport=tcp.dport, info=f"{tcp.sport} -> {tcp.dport} [{flags}]")
        payload = bytes(tcp.payload) if tcp.payload else b""
        if payload.startswith(HTTP_METHODS):
            rec.update(proto="HTTP", info=http_info(payload))
        elif payload and 443 in (tcp.sport, tcp.dport):
            rec["info"] += " TLS (encrypted)"
    elif UDP in pkt:
        udp = pkt[UDP]
        rec.update(proto="UDP", sport=udp.sport, dport=udp.dport, info=f"{udp.sport} -> {udp.dport}")
        if DNS in pkt:
            rec.update(proto="DNS", info=dns_info(pkt[DNS]))
        elif 67 in (udp.sport, udp.dport) or 68 in (udp.sport, udp.dport):
            rec.update(proto="DHCP", info="DHCP " + ("request" if udp.dport == 67 else "reply"))
    elif ICMP in pkt:
        ic = pkt[ICMP]
        rec.update(proto="ICMP", info=ICMP_TYPES.get(ic.type, f"Type {ic.type}"))
    elif Raw in pkt:
        rec["info"] = f"{len(pkt[Raw].load)} bytes payload"
    return rec
