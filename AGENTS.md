# AGENTS.md — Guidelines for AI Developers

## Project Overview

Master Crypto Lab is a Streamlit-based cryptography analysis and education tool.
It provides 10 cipher modes, 10 key derivation methods, NIST SP 800-22 statistical
tests (7), LSB steganography, and a full ML pipeline for 10-class cipher
identification using 19 extracted features (RF + MLP + IsolationForest).

## Architecture

```
Cryptography.py          # Main Streamlit entry point (UI only, ~640 lines)
crypto_lab/              # Package with all business logic
├── __init__.py          # Public API exports
├── config.py            # Constants and configuration
├── crypto_engine.py     # CIPHER_REGISTRY (10 modes), KEY_METHODS (10 methods)
│                        #   encrypt_with(), decrypt_with(), derive_key()
├── steganography.py     # LSB image steganography
├── nist_suite.py        # NIST SP 800-22 (7 tests), entropy, diffusion, avalanche
│                        #   autocorrelation, compression_ratio, byte_chi_square
│                        #   _unpackbits_cached() via lru_cache
├── ml_models.py         # CipherMLClassifier: RF + MLP + IsolationForest,
│                        #   10-class prediction, 19 features, PCA/t-SNE,
│                        #   permutation importance, confusion matrix,
│                        #   learning curve, HPO, active learning, drift tracking
├── email_service.py     # SMTP zero-knowledge email with env var support
└── utils.py             # Session state, history persistence (CSV), validation
```

## Code Conventions

- **Language**: All docstrings and comments in English.
- **Types**: Use type hints for all function parameters and return values.
- **Imports**: Standard library first, then third-party, then local.
- **Error handling**: Use specific exception types; provide actionable error messages.
- **Streamlit**: Keep UI logic in `Cryptography.py`; business logic in `crypto_lab/`.

## Cipher Registry System

Ciphers are registered in `CIPHER_REGISTRY` dict in `crypto_engine.py`:

```python
CIPHER_REGISTRY["AES-256-GCM"] = {
    "key_size": 32,
    "generate_key": callable,     # () -> bytes
    "encrypt": callable,          # (key, plaintext) -> ciphertext
    "decrypt": callable,          # (key, ciphertext) -> plaintext
    "key_to_str": callable,       # (key) -> display string
    "str_to_key": callable,       # (string) -> key bytes
    "ciphertext_format": "hex"/"base64",
    "educational": bool,
    "description": str,
}
```

To add a new cipher mode:
1. Create the encrypt/decrypt functions in `crypto_engine.py`.
2. Add an entry to `CIPHER_REGISTRY`.
3. It automatically appears in the Streamlit UI dropdown.

## Key Method Registry System

Key derivation methods are registered in `KEY_METHODS` list:

```python
_register_key_method("name", needs_passphrase, needs_additional_input, derive_fn)
```

The `derive_fn` signature: `(cipher_mode, passphrase, additional_input) -> (key_bytes, info_msg)`.

The `_key_for_mode(raw, mode)` helper converts raw derived bytes to the format
expected by the cipher mode (e.g., base64-urlsafe for Fernet).

## Testing

- Run `streamlit run Cryptography.py` to launch the app.
- No automated tests are configured yet.

## Common Tasks

### Adding a new NIST test
1. Add the test method to `crypto_lab/nist_suite.py` in `CryptoScientificLibrary`.
2. Use `_unpackbits_cached()` for bit conversion (lru_cache optimized).
3. Add it to `run_full_suite()` (returns dict with key matching `FEATURE_NAMES` in `ml_models.py`).
4. Add a UI card in Tab 4 of `Cryptography.py`.

### Adding a new cipher mode
1. Create encrypt/decrypt functions in `crypto_engine.py`.
2. Register in `CIPHER_REGISTRY` with all required fields.
3. Set `"educational": True` to show a warning badge in the UI.
4. No changes needed in `Cryptography.py` — the UI auto-discovers from the registry.

### Adding a new key derivation method
1. Create a derive function in `crypto_engine.py`.
2. Call `_register_key_method()` to add it to `KEY_METHODS`.
3. Use `_key_for_mode()` at the end to ensure format compatibility.
4. No changes needed in `Cryptography.py` — the UI auto-discovers from the list.

### Model retraining
The ML model is auto-trained on startup and saved to `cipher_classifier.joblib`.
Delete this file to force retraining on next startup.

The `train()` method accepts:
- `X, y`: optional real data (uses synthetic benchmark if None)
- `do_hpo=False`: run GridSearchCV for RF hyperparameter tuning
- `do_learning_curve=False`: compute learning curve (15 fits — slow, use on-demand)

Use `retrain_with_history(history)` to merge real encryption history with
synthetic benchmark data (gradual replacement of hardcoded values).

Call `compute_learning_curve()` separately for on-demand LC (cached in
`model._learning_curve`; UI shows button to trigger).

### ML model details
- **3 classifiers**: RandomForestClassifier(100 trees), MLPClassifier(64,32), IsolationForest
- **19 features**: see `FEATURE_NAMES` in `ml_models.py`
- **10 classes**: see `CIPHER_CLASSES` in `ml_models.py`
- **HPO**: GridSearchCV over n_estimators, max_depth, min_samples_split
- **Learning curve**: cached in `_learning_curve`, computed on demand
- **Active learning**: `add_training_sample()`, `get_training_data_from_history()`, `retrain_with_history()`
- **Drift tracking**: `_feature_importance_history` list, accessible via `get_drift_df()`

## Environment Variables

| Variable | Purpose |
|---|---|
| `SMTP_SERVER` | SMTP server hostname (default: smtp.gmail.com) |
| `SMTP_PORT` | SMTP server port (default: 587) |
| `SMTP_EMAIL` | SMTP sender email |
| `SMTP_PASSWORD` | SMTP app password |

## Key Files Reference

| File | Key Exports |
|---|---|
| `crypto_engine.py` | `get_available_ciphers()`, `get_cipher_info()`, `encrypt_with()`, `decrypt_with()`, `get_available_key_methods()`, `derive_key()`, `CIPHER_REGISTRY`, `KEY_METHODS` |
| `nist_suite.py` | `CryptoScientificLibrary` (all static methods), `_unpackbits_cached()`, `FEATURE_NAMES` (exported via `ml_models`) |
| `ml_models.py` | `CipherMLClassifier` (train, predict, predict_all_probas, compute_pca, compute_tsne, compute_learning_curve, detect_anomaly, retrain_with_history, get_drift_df, save, load), `FEATURE_NAMES`, `CIPHER_CLASSES` |
| `utils.py` | `init_session_state()`, `splash_screen()`, `append_to_history()`, `make_weights_sliders()` |

## Known LSP False Positives

- `os.urandom()` → `Optional[bytes]` in Python 3.14 (never None at runtime)
- `permutation_importance().importances_mean` — stub says `dict`, returns `Bunch`
- `classification_report(zero_division=0)` — stub expects `str`, accepts `int`
- `IsolationForest(contamination=0.1)` — stub expects `str`, accepts `float`
- `st.selectbox` → can return `None` per stub (never does at runtime)
- `qrcode.save(buf, format="PNG")` — stub missing `format` param
- Learning curve `lc_result[0]` indexed access (stub says 5 values, returns 3)
