"""
ike_parser.py
-------------
Parses IKE (ISAKMP, UDP 500/4500) packets from a pcap using pyshark
(which shells out to tshark's dissectors). We only report fields that
tshark's ISAKMP dissector actually exposes on the wire. Anything that
cannot be dissected (e.g. because it's IKEv2 with the SK payload
encrypted after IKE_AUTH) is explicitly marked UNAVAILABLE rather than
guessed.

Everything returned by this module has provenance = "Observed" because
it is read directly off captured packets — never fabricated.
"""
from collections import defaultdict

from app.config import SOURCE_OBSERVED, SOURCE_UNAVAILABLE

# Wireshark ISAKMP transform-type/value maps used to translate numeric
# codes into human-readable crypto names when tshark doesn't already
# resolve them as strings.
ENCR_ALGO_MAP = {
    "1": "DES-CBC", "2": "IDEA-CBC", "3": "Blowfish-CBC", "5": "3DES-CBC",
    "7": "AES-CBC", "8": "AES-CTR", "18": "AES-GCM-16", "20": "AES-GCM-16",
    "28": "ChaCha20-Poly1305",
}
DH_GROUP_MAP = {
    "1": "MODP768", "2": "MODP1024", "5": "MODP1536", "14": "MODP2048",
    "15": "MODP3072", "16": "MODP4096", "19": "ECP256", "20": "ECP384",
    "21": "ECP521", "31": "Curve25519",
}
INTEGRITY_MAP = {
    "1": "HMAC-MD5", "2": "HMAC-SHA1", "12": "HMAC-SHA2-256",
    "13": "HMAC-SHA2-384", "14": "HMAC-SHA2-512",
}


def _get(pkt_layer, *field_names, default=None):
    """Try several possible tshark field name variants; return first hit."""
    for name in field_names:
        val = getattr(pkt_layer, name, None)
        if val is not None:
            return str(val)
    return default


def parse_ike_packets(cap):
    """
    cap: an open pyshark.FileCapture (already filtered/iterable)
    Returns: dict with per-SA observations plus a flat list of per-packet
    observations, each tagged with provenance.
    """
    exchanges = []
    sa_summary = {
        "ike_version": SOURCE_UNAVAILABLE,
        "mode": SOURCE_UNAVAILABLE,
        "proposed_encryption": [],
        "proposed_integrity": [],
        "proposed_dh_groups": [],
        "proposed_prf": [],
        "initiator_spi": SOURCE_UNAVAILABLE,
        "responder_spi": SOURCE_UNAVAILABLE,
        "packet_count": 0,
        "source": SOURCE_OBSERVED,
    }

    exchange_type_seen = set()

    for pkt in cap:
        if not hasattr(pkt, "isakmp"):
            continue
        isakmp = pkt.isakmp
        sa_summary["packet_count"] += 1

        version_major = _get(isakmp, "version_major", "majorversion")
        version_minor = _get(isakmp, "version_minor", "minorversion")
        if version_major:
            sa_summary["ike_version"] = f"IKEv{version_major}"

        exch_type = _get(isakmp, "exchangetype", "exchange_type")
        if exch_type:
            exchange_type_seen.add(exch_type)

        init_spi = _get(isakmp, "icookie", "ispi")
        resp_spi = _get(isakmp, "rcookie", "rspi")
        if init_spi:
            sa_summary["initiator_spi"] = init_spi
        if resp_spi and resp_spi != "0000000000000000":
            sa_summary["responder_spi"] = resp_spi

        # Transform payload fields (present during SA negotiation packets)
        encr = _get(isakmp, "enc_algo", "trans_encr", "ike_attr_id_enc")
        dh = _get(isakmp, "trans_dh", "ike_attr_group_desc")
        integ = _get(isakmp, "trans_auth", "ike_attr_auth")
        prf = _get(isakmp, "trans_prf", "ike_attr_prf")

        if encr:
            name = ENCR_ALGO_MAP.get(encr, encr)
            if name not in sa_summary["proposed_encryption"]:
                sa_summary["proposed_encryption"].append(name)
        if dh:
            name = DH_GROUP_MAP.get(dh, dh)
            if name not in sa_summary["proposed_dh_groups"]:
                sa_summary["proposed_dh_groups"].append(name)
        if integ:
            name = INTEGRITY_MAP.get(integ, integ)
            if name not in sa_summary["proposed_integrity"]:
                sa_summary["proposed_integrity"].append(name)
        if prf:
            if prf not in sa_summary["proposed_prf"]:
                sa_summary["proposed_prf"].append(prf)

        exchanges.append({
            "frame_number": _get(pkt, "number") or getattr(pkt, "number", None),
            "timestamp": getattr(pkt, "sniff_time", None).isoformat()
                if getattr(pkt, "sniff_time", None) else SOURCE_UNAVAILABLE,
            "exchange_type": exch_type or SOURCE_UNAVAILABLE,
            "src_ip": _get(getattr(pkt, "ip", None), "src") if hasattr(pkt, "ip")
                else _get(getattr(pkt, "ipv6", None), "src") if hasattr(pkt, "ipv6")
                else SOURCE_UNAVAILABLE,
            "dst_ip": _get(getattr(pkt, "ip", None), "dst") if hasattr(pkt, "ip")
                else _get(getattr(pkt, "ipv6", None), "dst") if hasattr(pkt, "ipv6")
                else SOURCE_UNAVAILABLE,
            "source": SOURCE_OBSERVED,
        })

    # Detect aggressive vs main mode heuristically from exchange type codes
    # seen (IKEv1: 2 = Identity Protection/Main, 4 = Aggressive).
    if "2" in exchange_type_seen:
        sa_summary["mode"] = "Main"
    elif "4" in exchange_type_seen:
        sa_summary["mode"] = "Aggressive"
    elif sa_summary["ike_version"] == "IKEv2":
        sa_summary["mode"] = "N/A (IKEv2 has no main/aggressive distinction)"

    if not sa_summary["proposed_encryption"]:
        sa_summary["proposed_encryption"] = [SOURCE_UNAVAILABLE]
    if not sa_summary["proposed_dh_groups"]:
        sa_summary["proposed_dh_groups"] = [SOURCE_UNAVAILABLE]
    if not sa_summary["proposed_integrity"]:
        sa_summary["proposed_integrity"] = [SOURCE_UNAVAILABLE]

    return {"sa_summary": sa_summary, "exchanges": exchanges}
