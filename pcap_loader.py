"""
pcap_loader.py
--------------
Loads a .pcap file with pyshark and runs both the IKE and ESP parsers
over it. This is the single entry point the FastAPI routes call.

Design note: pyshark opens two passes (one filtered for isakmp, one
for esp) because mixing display filters mid-iteration is unreliable.
For large pcaps this is the simplest robust approach for an academic
demo; a production system would parse once with scapy for speed.
"""
import os
import pyshark

from app.analyzer.ike_parser import parse_ike_packets
from app.analyzer.esp_parser import parse_esp_packets
from app.config import SOURCE_UNAVAILABLE


def analyze_pcap(pcap_path: str) -> dict:
    if not os.path.isfile(pcap_path):
        raise FileNotFoundError(pcap_path)

    ike_result = {"sa_summary": {}, "exchanges": []}
    esp_result = {"flows": [], "packet_count": 0}

    # --- IKE pass ---
    try:
        ike_cap = pyshark.FileCapture(pcap_path, display_filter="isakmp")
        ike_result = parse_ike_packets(ike_cap)
        ike_cap.close()
    except Exception as e:
        ike_result = {
            "sa_summary": {"error": str(e), "source": SOURCE_UNAVAILABLE},
            "exchanges": [],
        }

    # --- ESP pass ---
    try:
        esp_cap = pyshark.FileCapture(pcap_path, display_filter="esp")
        esp_result = parse_esp_packets(esp_cap)
        esp_cap.close()
    except Exception as e:
        esp_result = {"error": str(e), "flows": [], "packet_count": 0}

    detected_ip_versions = set()
    for flow in esp_result.get("flows", []):
        if flow.get("ip_version") not in (None, SOURCE_UNAVAILABLE):
            detected_ip_versions.add(flow["ip_version"])

    return {
        "pcap_file": os.path.basename(pcap_path),
        "ike": ike_result,
        "esp": esp_result,
        "ip_versions_detected": sorted(detected_ip_versions) or [SOURCE_UNAVAILABLE],
    }
