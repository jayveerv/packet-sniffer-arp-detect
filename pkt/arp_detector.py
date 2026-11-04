"""ARP spoofing detection.

Checks:
  * IP-MAC conflict      the same IP is suddenly claimed by a different MAC        (High)
  * Gateway MAC mismatch a whitelisted IP is claimed by a MAC not in the whitelist (High)
  * Gratuitous ARP flood more than `flood_threshold` gratuitous ARPs from one MAC
                         within `flood_window` seconds                              (High)
  * Unsolicited ARP reply an "is-at" reply nobody asked for                        (Low, Medium if
                                                                                    it also changes a mapping)
  * IP reassigned        a different MAC takes an IP that was silent for longer than
                         `stale_after` seconds (normal DHCP reuse)                  (Low)

All alerts are mapped to MITRE ATT&CK T1557.002 (ARP Cache Poisoning).
False positives are reduced with a trusted IP-MAC whitelist, configurable thresholds,
the stale-mapping rule above, and by ignoring a single gratuitous announcement.
"""

from collections import defaultdict, deque

from . import MITRE_ID, MITRE_NAME

SEVERITY_ORDER = {"High": 3, "Medium": 2, "Low": 1}


class ArpDetector:
    def __init__(self, whitelist=None, flood_threshold=20, flood_window=1.0, reply_window=2.0,
                 stale_after=300.0, dedupe_seconds=10.0):
        self.whitelist = {ip: mac.lower() for ip, mac in (whitelist or {}).items()}
        self.flood_threshold = flood_threshold
        self.flood_window = flood_window
        self.reply_window = reply_window
        self.stale_after = stale_after
        self.dedupe_seconds = dedupe_seconds
        self.table = {}                 # ip -> {"mac", "first", "last"}
        self.alerts = []
        self._requests = {}             # target ip -> time of last who-has
        self._garp = defaultdict(deque)  # mac -> times of gratuitous ARPs
        self._last = {}                 # dedupe key -> alert
        self._hits = []

    def _alert(self, t, kind, severity, ip, mac, detail, no, old_mac=None):
        key = (kind, ip, mac)
        prev = self._last.get(key)
        if prev and t - prev["last_seen"] <= self.dedupe_seconds:
            prev["count"] += 1
            prev["last_seen"] = t
            prev["detail"] = detail
            self._hits.append(prev)
            return prev
        a = {"time": t, "last_seen": t, "type": kind, "severity": severity, "ip": ip, "mac": mac,
             "old_mac": old_mac, "detail": detail, "packet": no, "count": 1,
             "mitre": MITRE_ID, "technique": MITRE_NAME}
        self.alerts.append(a)
        self._last[key] = a
        self._hits.append(a)
        return a

    def process(self, arp, t, no=0):
        """Feed one ARP layer (Scapy ARP) seen at time t. Returns the alerts this packet raised or updated."""
        self._hits = []
        ip, mac = arp.psrc, (arp.hwsrc or "").lower()
        if not ip or ip == "0.0.0.0":  # ARP probes (RFC 5227) carry no sender IP
            if arp.op == 1:
                self._requests[arp.pdst] = t
            return []
        gratuitous = arp.psrc == arp.pdst

        if arp.op == 1 and not gratuitous:
            self._requests[arp.pdst] = t

        if gratuitous:
            q = self._garp[mac]
            q.append((t, ip))
            while q and t - q[0][0] > self.flood_window:
                q.popleft()
            if len(q) > self.flood_threshold:
                ips = {x[1] for x in q}
                target = ip if len(ips) == 1 else "multiple"
                self._alert(t, "Gratuitous ARP flood", "High", target, mac,
                            f"{len(q)} gratuitous ARPs from {mac} within {self.flood_window:g}s "
                            f"(threshold {self.flood_threshold}), claiming {len(ips)} address(es)", no)

        changed = False
        trusted = self.whitelist.get(ip)
        if trusted and trusted != mac:
            changed = True
            self._alert(t, "Whitelisted MAC mismatch", "High", ip, mac,
                        f"{ip} is trusted as {trusted} but is now claimed by {mac}", no, trusted)
        entry = self.table.get(ip)
        if entry and entry["mac"] != mac and not trusted:
            if t - entry["last"] > self.stale_after:
                self._alert(t, "IP reassigned", "Low", ip, mac,
                            f"{ip} moved from {entry['mac']} to {mac} after {t - entry['last']:.0f}s of silence "
                            "(normal for DHCP)", no, entry["mac"])
            else:
                changed = True
                self._alert(t, "IP-MAC conflict", "High", ip, mac,
                            f"{ip} was at {entry['mac']} and is now claimed by {mac}", no, entry["mac"])

        if arp.op == 2 and not gratuitous:
            asked = self._requests.get(ip)
            if asked is None or t - asked > self.reply_window:
                self._alert(t, "Unsolicited ARP reply", "Medium" if changed else "Low", ip, mac,
                            f"{mac} announced {ip} is-at {mac} without a matching request", no)
            else:
                self._requests.pop(ip, None)

        if not trusted or trusted == mac:
            if entry and entry["mac"] == mac:
                entry["last"] = t
            elif not changed:
                self.table[ip] = {"mac": mac, "first": t, "last": t}
            elif entry is None:
                self.table[ip] = {"mac": mac, "first": t, "last": t}
            # a conflicting claim does not overwrite the first-seen (trusted) mapping
        return self._hits

    def summary(self):
        out = {"High": 0, "Medium": 0, "Low": 0}
        for a in self.alerts:
            out[a["severity"]] += 1
        return out

    def sorted_alerts(self):
        return sorted(self.alerts, key=lambda a: (-SEVERITY_ORDER[a["severity"]], a["time"]))


def parse_whitelist(text):
    """Parse 'ip=mac' pairs separated by commas, spaces or new lines."""
    out = {}
    for part in (text or "").replace(",", " ").split():
        if "=" not in part:
            raise ValueError(f"whitelist entry {part!r} must look like 192.168.1.1=aa:bb:cc:dd:ee:ff")
        ip, mac = part.split("=", 1)
        if len(mac.split(":")) != 6:
            raise ValueError(f"bad MAC address {mac!r}")
        out[ip.strip()] = mac.strip().lower()
    return out
