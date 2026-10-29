import os

# PBKDF2 iterations (OWASP 2023 recommends >= 600000)
PBKDF2_ITERATIONS = 600000

# Avalanche test trials
AVALANCHE_TRIALS = 5

# NIST SP 800-22 significance level
NIST_ALPHA = 0.01

# PCA minimum samples
PCA_MIN_SAMPLES = 2

# Default metric weights
DEFAULT_WEIGHTS = {"h": 0.25, "sac": 0.25, "uni": 0.15, "mono": 0.10, "runs": 0.10, "diff": 0.15}

# File paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
HISTORY_FILE = os.path.join(PROJECT_DIR, "crypto_history.csv")
MODEL_FILE = os.path.join(PROJECT_DIR, "cipher_classifier.joblib")

# SMTP defaults
SMTP_DEFAULT_SERVER = "smtp.gmail.com"
SMTP_DEFAULT_PORT = 587

# Fernet key regex for validation
FERNET_KEY_PATTERN = r'^[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+$'

# Session state keys
STATE_KEYS = [
    "key", "last_enc", "u_text", "license_code",
    "metrics_cache", "history", "rf_model", "key_visible",
    "qr_visible", "cipher_mode", "ecdh_priv", "ecdh_pub"
]

DEFAULT_STATE = {
    "key": None,
    "last_enc": None,
    "u_text": "",
    "license_code": "",
    "metrics_cache": {},
    "history": None,
    "rf_model": None,
    "key_visible": False,
    "qr_visible": False,
    "cipher_mode": "Fernet (AES-128-CBC + HMAC)",
}
