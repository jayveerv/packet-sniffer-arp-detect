"""Filters for parsed packet records: by protocol, IP and port (combinable)."""

PROTOCOLS = ["ARP", "IP", "TCP", "UDP", "ICMP", "DNS", "DHCP", "HTTP", "IPv6", "Other"]
# A protocol filter also matches the protocols carried inside it (e.g. "TCP" includes HTTP).
FAMILY = {"TCP": {"TCP", "HTTP"}, "UDP": {"UDP", "DNS", "DHCP"},
          "IP": {"IP", "TCP", "UDP", "ICMP", "DNS", "DHCP", "HTTP"}}


def matches(rec, proto=None, ip=None, port=None):
    if proto:
        want = proto.upper() if proto.lower() != "ipv6" else "IPv6"
        if rec["proto"] not in FAMILY.get(want, {want}):
            return False
    if ip and ip not in (rec.get("src"), rec.get("dst")):
        return False
    if port not in (None, ""):
        port = int(port)
        if port not in (rec.get("sport"), rec.get("dport")):
            return False
    return True


def apply(records, proto=None, ip=None, port=None):
    return [r for r in records if matches(r, proto, ip, port)]
