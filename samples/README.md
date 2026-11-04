# Sample captures

These four .pcap files are built **offline** by `pkt/samples.py` with Scapy and written straight to disk. No packet was ever sent on a network. Rebuild them any time with:

```
python sniff.py --make-samples samples
```

Lab network `192.168.1.0/24`: gateway `.1` (00:11:22:33:44:01), laptop `.10` (3c:52:82:aa:10:10), printer `.20`, simulated attacker `.66` (de:ad:be:ef:00:66).

| File | What it contains | Expected result |
|---|---|---|
| normal_traffic.pcap | ARP, DNS, HTTP, HTTPS, ICMP and printer traffic for 30 s | No alerts |
| arp_spoof.pcap | Normal traffic, then the attacker tells the laptop it is the gateway and the gateway it is the laptop, every 2 s | 2 High (IP-MAC conflict), 2 Medium (unsolicited reply) |
| garp_flood.pcap | 250 gratuitous ARPs in 2 s from one MAC claiming 50 addresses | 1 High (gratuitous ARP flood, counted 230 times) |
| dhcp_benign.pcap | A phone joins with DHCP and announces itself; 15 min later an old IP is reused by a new device | No High or Medium, 1 Low (IP reassigned) |
