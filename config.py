"""
Central configuration for the backend. Keep magic numbers / paths here
so the scoring rubric and file locations are easy to audit and tune.
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
PCAP_DIR = os.path.join(DATA_DIR, "incoming_pcaps")
MODEL_DIR = os.path.join(DATA_DIR, "models")
DB_PATH = os.path.join(DATA_DIR, "ipsec_analyzer.db")

os.makedirs(PCAP_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

TRAFFIC_MODEL_PATH = os.path.join(MODEL_DIR, "traffic_classifier.joblib")
TRAFFIC_MODEL_META_PATH = os.path.join(MODEL_DIR, "traffic_classifier_meta.json")

# CORS origins for the Vite dev server
FRONTEND_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

# Data-provenance tags used everywhere in analyzer output.
# These are the ONLY allowed values for any "source" field returned
# by the analyzer/security engine — never fabricate a fifth category.
SOURCE_OBSERVED = "Observed"                # read directly off the wire
SOURCE_INFERRED = "Inferred"                # produced by the ML module
SOURCE_CONFIG_SUPPLIED = "Configuration-Supplied"  # from ipsec.conf / label file
SOURCE_UNAVAILABLE = "Unavailable"          # could not be determined
