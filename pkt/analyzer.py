"""Glue: parse packets, run the ARP detector and compute statistics."""

from scapy.layers.l2 import ARP

from . import filters, stats
from .arp_detector import SEVERITY_ORDER, ArpDetector
from .capture import read_pcap
from .parser import parse_packet

MAX_PACKETS = 200_000


class Analysis:
    def __init__(self, whitelist=None, flood_threshold=20, flood_window=1.0, stale_after=300.0, keep_packets=True):
        self.detector = ArpDetector(whitelist, flood_threshold, flood_window, stale_after=stale_after)
        self.records = []
        self.packets = [] if keep_packets else None
        self._t0 = None

    def add(self, pkt):
        if self._t0 is None:
            self._t0 = float(pkt.time)
        no = len(self.records) + 1
        rec = parse_packet(pkt, no, self._t0)
        self.records.append(rec)
        if self.packets is not None:
            self.packets.append(pkt)
        if ARP in pkt:
            hits = self.detector.process(pkt[ARP], float(pkt.time), no)
            if hits:
                rec["alert"] = max((h["severity"] for h in hits), key=lambda s: SEVERITY_ORDER[s])
                rec["alert_types"] = sorted({h["type"] for h in hits})
        return rec

    @property
    def alerts(self):
        return self.detector.sorted_alerts()

    def stats(self):
        return stats.compute(self.records)

    def filtered(self, proto=None, ip=None, port=None):
        return filters.apply(self.records, proto, ip, port)

    def packets_for(self, records):
        nos = {r["no"] for r in records}
        return [p for i, p in enumerate(self.packets or [], 1) if i in nos]


def analyse_pcap(path, limit=MAX_PACKETS, **kwargs):
    a = Analysis(**kwargs)
    for pkt in read_pcap(path, limit):
        a.add(pkt)
    return a
