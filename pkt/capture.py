"""Packet sources: .pcap files and live capture (local only, needs admin rights / Npcap)."""

import os
import socket
import sys

from scapy.utils import PcapReader


def read_pcap(path, limit=None):
    """Yield packets from a pcap/pcapng file."""
    with PcapReader(path) as reader:
        for i, pkt in enumerate(reader):
            if limit and i >= limit:
                break
            yield pkt


def capture_status():
    """Can this machine capture live traffic? Returns (ok, message)."""
    if sys.platform.startswith("win"):
        npcap = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap")
        if not os.path.isdir(npcap):
            return False, ("Npcap is not installed. Install it from https://npcap.com (tick 'WinPcap API-compatible "
                           "mode'), then run as Administrator. Until then, use --pcap files.")
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                return False, "Live capture needs Administrator rights: right-click run.bat and choose 'Run as administrator'."
        except Exception:
            pass
        return True, "Npcap found."
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        s.close()
        return True, "Raw sockets available."
    except (PermissionError, OSError, AttributeError):
        return False, "Live capture needs root (sudo) or the CAP_NET_RAW capability. Use --pcap files instead."


def list_interfaces():
    from scapy.interfaces import get_working_ifaces
    out = []
    for iface in get_working_ifaces():
        out.append({"name": iface.name, "description": getattr(iface, "description", "") or "",
                    "ip": getattr(iface, "ip", "") or "", "mac": getattr(iface, "mac", "") or ""})
    return out


def live_capture(iface=None, count=0, timeout=None, callback=None, bpf=None):
    """Capture live packets. Calls callback(pkt) for each packet and returns the list.

    Detection only: nothing is ever sent on the network.
    """
    from scapy.sendrecv import sniff
    ok, msg = capture_status()
    if not ok:
        raise PermissionError(msg)
    return list(sniff(iface=iface, count=count, timeout=timeout, prn=callback, filter=bpf, store=True))
