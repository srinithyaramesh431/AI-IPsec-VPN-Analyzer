"""
pipeline.py
-----------
Ties every module together in the documented project flow:

    Capture -> Identify -> Infer -> Assess -> Score -> Recommend

  Capture   : the .pcap file already on disk (uploaded via /api/upload)
  Identify  : analyzer.pcap_loader (IKE + ESP parsing)
  Infer     : ml.predict (traffic-type classification from ESP metadata)
  Assess    : security.scorer (rule-based checks)
  Score     : security.scorer (composite 0-100 score + risk level)
  Recommend : security.recommendations (explanations + fixes)

An optional `known_config` dict (parsed from an uploaded strongSwan
label/config JSON) can supply Configuration-Supplied values for fields
IKEv2 does not expose on the wire (e.g. key lifetime, PFS, replay
window) — these are merged in and explicitly tagged with their source
so the frontend can distinguish them from Observed packet data.
"""
from app.analyzer.pcap_loader import analyze_pcap
from app.ml.predict import predict_traffic_types
from app.security.scorer import assess_configuration
from app.security.recommendations import build_recommendations
from app.config import SOURCE_OBSERVED, SOURCE_CONFIG_SUPPLIED, SOURCE_UNAVAILABLE


def _build_observed_config(ike_sa_summary: dict, known_config: dict | None) -> dict:
    known_config = known_config or {}

    def cfg_or_observed(key, observed_val, observed_source=SOURCE_OBSERVED):
        if observed_val not in (None, [], SOURCE_UNAVAILABLE, [SOURCE_UNAVAILABLE]):
            return observed_val, observed_source
        if key in known_config:
            return known_config[key], SOURCE_CONFIG_SUPPLIED
        return None, SOURCE_UNAVAILABLE

    ike_version = ike_sa_summary.get("ike_version")
    if ike_version in (None, SOURCE_UNAVAILABLE) and "ike_version" in known_config:
        ike_version = known_config["ike_version"]

    mode, mode_source = cfg_or_observed("mode", ike_sa_summary.get("mode"))
    encryption, encryption_source = cfg_or_observed(
        "encryption", ike_sa_summary.get("proposed_encryption"))
    dh_groups, dh_groups_source = cfg_or_observed(
        "dh_groups", ike_sa_summary.get("proposed_dh_groups"))

    # These are rarely visible on the wire (esp. IKEv2), so they usually
    # come from known_config if supplied at all.
    pfs_enabled, pfs_source = cfg_or_observed("pfs_enabled", None)
    replay_protection, replay_source = cfg_or_observed("replay_protection", None)
    key_lifetime_seconds, key_lifetime_source = cfg_or_observed("key_lifetime_seconds", None)

    return {
        "ike_version": ike_version,
        "mode": mode, "mode_source": mode_source,
        "encryption": encryption if isinstance(encryption, list) else
            ([encryption] if encryption else None),
        "encryption_source": encryption_source,
        "dh_groups": dh_groups if isinstance(dh_groups, list) else
            ([dh_groups] if dh_groups else None),
        "dh_groups_source": dh_groups_source,
        "pfs_enabled": pfs_enabled, "pfs_source": pfs_source,
        "replay_protection": replay_protection, "replay_source": replay_source,
        "key_lifetime_seconds": key_lifetime_seconds,
        "key_lifetime_source": key_lifetime_source,
    }


def run_pipeline(pcap_path: str, known_config: dict | None = None) -> dict:
    # 1. Identify (IKE + ESP parsing)
    parsed = analyze_pcap(pcap_path)
    ike_sa_summary = parsed["ike"].get("sa_summary", {})
    esp_flows = parsed["esp"].get("flows", [])

    # 2. Infer (ML traffic-type classification)
    ml_predictions = predict_traffic_types(esp_flows)
    confidences = [p["confidence"] for p in ml_predictions if p.get("confidence") is not None]
    ai_confidence = round(sum(confidences) / len(confidences), 4) if confidences else None

    # 3 & 4. Assess + Score
    observed_config = _build_observed_config(ike_sa_summary, known_config)
    assessment = assess_configuration(observed_config)

    # 5. Recommend
    recommendations = build_recommendations(assessment["checks"])

    return {
        "pcap_file": parsed["pcap_file"],
        "ike": parsed["ike"],
        "esp": parsed["esp"],
        "ip_versions_detected": parsed["ip_versions_detected"],
        "observed_config": observed_config,
        "ml_predictions": ml_predictions,
        "ai_confidence": ai_confidence,
        "security_assessment": assessment,
        "recommendations": recommendations,
    }
