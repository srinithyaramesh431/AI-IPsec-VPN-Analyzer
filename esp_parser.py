"""
esp_parser.py
-------------
ESP (protocol 50) payloads are encrypted by design, so this module
NEVER attempts to decrypt or guess payload contents. It extracts only
what is legitimately observable on the wire:

  - SPI (Security Parameter Index) — plaintext in the ESP header
  - Sequence number — plaintext in the ESP header
  - Packet length / inter-arrival timing — visible at the IP layer
  - IP version (v4/v6) — visible at the IP layer

These metadata features are what feed the ML traffic-type classifier
(app/ml). Every field is tagged "Observed" since it is read directly
from the capture, not inferred.
"""
from app.config import SOURCE_OBSERVED, SOURCE_UNAVAILABLE


def parse_esp_packets(cap):
    flows = {}  # keyed by SPI
    packet_records = []

    for pkt in cap:
        if not hasattr(pkt, "esp"):
            continue
        esp = pkt.esp
        spi = getattr(esp, "spi", None)
        seq = getattr(esp, "sequence", None)

        ip_version = "IPv6" if hasattr(pkt, "ipv6") else (
            "IPv4" if hasattr(pkt, "ip") else SOURCE_UNAVAILABLE)

        length = int(getattr(pkt, "length", 0)) if getattr(pkt, "length", None) else None
        ts = getattr(pkt, "sniff_timestamp", None)

        rec = {
            "spi": spi or SOURCE_UNAVAILABLE,
            "sequence": seq or SOURCE_UNAVAILABLE,
            "ip_version": ip_version,
            "length": length,
            "timestamp": float(ts) if ts else None,
            "source": SOURCE_OBSERVED,
        }
        packet_records.append(rec)

        if spi:
            flows.setdefault(spi, {
                "spi": spi,
                "ip_version": ip_version,
                "packet_count": 0,
                "total_bytes": 0,
                "lengths": [],
                "timestamps": [],
                "source": SOURCE_OBSERVED,
            })
            flow = flows[spi]
            flow["packet_count"] += 1
            if length:
                flow["total_bytes"] += length
                flow["lengths"].append(length)
            if ts:
                flow["timestamps"].append(float(ts))

    # Derive simple per-flow statistics (used as ML features)
    flow_summaries = []
    for spi, flow in flows.items():
        lengths = flow["lengths"]
        timestamps = sorted(flow["timestamps"])
        inter_arrivals = [
            round(timestamps[i + 1] - timestamps[i], 6)
            for i in range(len(timestamps) - 1)
        ] if len(timestamps) > 1 else []

        flow_summaries.append({
            "spi": spi,
            "ip_version": flow["ip_version"],
            "packet_count": flow["packet_count"],
            "total_bytes": flow["total_bytes"],
            "avg_packet_size": round(sum(lengths) / len(lengths), 2) if lengths else None,
            "min_packet_size": min(lengths) if lengths else None,
            "max_packet_size": max(lengths) if lengths else None,
            "avg_inter_arrival_sec": round(sum(inter_arrivals) / len(inter_arrivals), 6)
                if inter_arrivals else None,
            "duration_sec": round(timestamps[-1] - timestamps[0], 3)
                if len(timestamps) > 1 else 0,
            "source": SOURCE_OBSERVED,
        })

    return {"flows": flow_summaries, "packet_count": len(packet_records)}
