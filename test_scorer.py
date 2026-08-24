"""
test_scorer.py
---------------
Run with:  pytest backend/tests/test_scorer.py
(from the backend/ directory, venv activated, PYTHONPATH=. or run via
`python -m pytest tests/`)
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.security.scorer import assess_configuration


def test_strong_configuration_scores_high():
    cfg = {
        "ike_version": "IKEv2",
        "mode": "N/A (IKEv2 has no main/aggressive distinction)",
        "mode_source": "Observed",
        "encryption": ["aes256gcm16"], "encryption_source": "Observed",
        "dh_groups": ["ecp384"], "dh_groups_source": "Observed",
        "pfs_enabled": True, "pfs_source": "Configuration-Supplied",
        "replay_protection": True, "replay_source": "Configuration-Supplied",
        "key_lifetime_seconds": 3600, "key_lifetime_source": "Configuration-Supplied",
    }
    result = assess_configuration(cfg)
    assert result["security_score"] >= 85
    assert result["risk_level"] == "Low"
    assert result["threat_matrix"] == []


def test_weak_configuration_scores_low():
    cfg = {
        "ike_version": "IKEv1",
        "mode": "Aggressive", "mode_source": "Observed",
        "encryption": ["3DES-CBC"], "encryption_source": "Observed",
        "dh_groups": ["MODP1024"], "dh_groups_source": "Observed",
        "pfs_enabled": False, "pfs_source": "Configuration-Supplied",
        "replay_protection": False, "replay_source": "Configuration-Supplied",
        "key_lifetime_seconds": 172800, "key_lifetime_source": "Configuration-Supplied",
    }
    result = assess_configuration(cfg)
    assert result["security_score"] < 40
    assert result["risk_level"] == "Critical"
    factors = {t["factor"] for t in result["threat_matrix"]}
    assert "mode" in factors
    assert "encryption" in factors
    assert "dh_group" in factors


def test_unavailable_fields_are_not_penalized_to_critical():
    cfg = {"ike_version": "IKEv2"}  # everything else unavailable
    result = assess_configuration(cfg)
    # Neutral midpoint scoring should land roughly in the Medium band,
    # not get crushed to Critical just because data is missing.
    assert result["security_score"] > 40
    assert result["unavailable_checks"] >= 4


if __name__ == "__main__":
    test_strong_configuration_scores_high()
    test_weak_configuration_scores_low()
    test_unavailable_fields_are_not_penalized_to_critical()
    print("All tests passed.")
