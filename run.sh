#!/usr/bin/env bash
# Packet Sniffer + ARP Spoofing Detector - Linux / macOS launcher
set -e
cd "$(dirname "$0")"
command -v python3 >/dev/null || { echo "Python 3.10+ is required"; exit 1; }
[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate
pip install -q -r requirements-dev.txt
case "${1:-web}" in
  web)     python webapp/app.py ;;
  demo)    python sniff.py --pcap samples/arp_spoof.pcap --proto arp ;;
  live)    sudo -E .venv/bin/python sniff.py --iface ${2:-} --timeout 30 --save-pcap live_capture.pcap ;;
  test)    python -m pytest -q ;;
  *)       python sniff.py "$@" ;;
esac
