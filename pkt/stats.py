"""Traffic statistics: protocol counts, top talkers, packets per second."""

from collections import Counter, defaultdict


def compute(records):
    if not records:
        return {"packets": 0, "bytes": 0, "duration": 0.0, "avg_pps": 0.0, "peak_pps": 0,
                "protocols": [], "top_talkers": [], "pps": [], "conversations": []}
    protos = Counter(r["proto"] for r in records)
    talkers = defaultdict(lambda: {"packets": 0, "bytes": 0})
    convs = defaultdict(lambda: {"packets": 0, "bytes": 0})
    for r in records:
        for host in {r["src"], r["dst"]} - {None}:
            talkers[host]["packets"] += 1
            talkers[host]["bytes"] += r["len"]
        if r["src"] and r["dst"]:
            key = tuple(sorted((r["src"], r["dst"])))
            convs[key]["packets"] += 1
            convs[key]["bytes"] += r["len"]
    t0 = records[0]["time"]
    duration = max(r["time"] for r in records) - t0
    buckets = Counter(int(r["time"] - t0) for r in records)
    seconds = int(duration) + 1
    pps = [buckets.get(s, 0) for s in range(seconds)]
    return {
        "packets": len(records),
        "bytes": sum(r["len"] for r in records),
        "duration": round(duration, 3),
        "avg_pps": round(len(records) / max(duration, 1.0), 2),
        "peak_pps": max(pps) if pps else 0,
        "protocols": protos.most_common(),
        "top_talkers": sorted(((h, v["packets"], v["bytes"]) for h, v in talkers.items()), key=lambda x: (-x[1], x[0]))[:10],
        "conversations": sorted(((a, b, v["packets"], v["bytes"]) for (a, b), v in convs.items()), key=lambda x: -x[2])[:10],
        "pps": pps,
    }
