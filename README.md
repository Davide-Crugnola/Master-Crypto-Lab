# Master Crypto Lab v8.1 🔬

An interactive cryptography analysis and education tool built with Streamlit.
Combines 18 cipher modes, 10 key derivation methods, LSB steganography,
NIST SP 800-22 statistical testing (7 tests), and an ML pipeline for
10-class cipher identification with 19 extracted features.

## Features

### 10 Cipher Modes
| Mode | Type | Auth | Educational |
|---|---|---|---|
| Fernet (AES-128-CBC + HMAC) | Symmetric | ✅ HMAC-SHA256 | |
| AES-256-GCM | Symmetric | ✅ AEAD | |
| ChaCha20-Poly1305 | Symmetric | ✅ AEAD | |
| AES-256-CBC + HMAC-SHA256 | Symmetric | ✅ Encrypt-then-MAC | |
| AES-128-GCM | Symmetric | ✅ AEAD | |
| AES-128-CBC + HMAC-SHA256 | Symmetric | ✅ Encrypt-then-MAC | |
| TripleDES | Symmetric | ❌ | ⚠️ |
| Blowfish | Symmetric | ❌ | ⚠️ |
| XOR + HMAC | Symmetric | ✅ HMAC-SHA256 | ⚠️ |
| Vigenère | Classical | ❌ | ⚠️ |
| AES-256-CTR | Symmetric | ❌ | |
| AES-256-OFB | Symmetric | ❌ | |
| AES-256-CFB | Symmetric | ❌ | |
| ChaCha20 (stream) | Symmetric | ❌ | |
| Hybrid RSA-OAEP + AES-GCM | Hybrid | ✅ AEAD | |
| AES-256-XTS | Symmetric | ❌ | |
| Salsa20 | Symmetric stream | ❌ | ⚠️ |
| RSA-2048-OAEP | Asymmetric | ❌ | |

### 10 Key Derivation Methods
| Method | Type | Notes |
|---|---|---|
| Random Key | — | `os.urandom()` |
| PBKDF2 (SHA-256) | Passphrase | 600k iterations (OWASP 2023) |
| PBKDF2 (SHA-512) | Passphrase | 600k iterations, stronger hash |
| scrypt | Passphrase | Memory-hard, N=2¹⁷ |
| HKDF from IKM | Raw material | HKDF-SHA256 |
| ECDH X25519 | Key agreement | X25519 + HKDF |
| Argon2id | Passphrase | OWASP #1 (requires `argon2-cffi`) |
| HMAC-SHA256 from Seed | Seed string | HMAC counter expansion |
| SHA-256 Direct Hash | Text | No stretching (educational) |
| Layered KDF (PBKDF2 + scrypt) | Passphrase | Hybrid approach |

### ML Pipeline — 19 Features, 10 Classes
- **3 classifiers**: Random Forest (100 trees), MLP (64,32), Isolation Forest
- **19 features**: Shannon entropy, SAC avalanche, byte uniformity, monobit (stat + p), block freq (stat + p), runs (stat + p), FFT (stat + p), diffusion, cumulative sums p, serial test p1/p2, approx entropy p, chi-square, autocorrelation, compression ratio
- **10-class cipher identification** – predicts which cipher mode was used
- **Dimensionality reduction**: PCA (2D) + t-SNE (2D) projections
- **Feature importance**: Random Forest built-in + permutation importance (sklearn.inspection)
- **Confusion matrix**: 10×10 heatmap via Plotly
- **Learning curve**: on-demand computation with caching (button-triggered, 15 fits)
- **Hyperparameter optimization**: GridSearchCV (n_estimators, max_depth, min_samples_split)
- **Anomaly detection**: Isolation Forest with anomaly score
- **Active learning**: retrain with real encryption history (merged with synthetic benchmark)
- **Feature importance drift**: tracked over multiple training runs, displayed as line chart
- **Model persistence**: auto-saved to `cipher_classifier.joblib`, loaded on startup

### NIST SP 800-22 Suite (7 tests)
| Test | Method |
|---|---|
| 1. Monobit Frequency | `nist_monobit_test` |
| 2. Block Frequency (m=8) | `nist_block_frequency_test` |
| 3. Runs Test | `nist_runs_test` |
| 4. Discrete Fourier (FFT) | `nist_spectral_fft_test` |
| 5. Cumulative Sums (Cusum) | `nist_cumulative_sums_test` |
| 6. Serial Test (m=2) | `nist_serial_test` |
| 7. Approximate Entropy (m=2) | `nist_approximate_entropy_test` |

### Auxiliary Features (3)
- **Autocorrelation** at lag 1
- **Compression ratio** via gzip
- **Chi-square byte distribution**

### Other Features
- **Steganography**: LSB image steganography for ciphertext hiding
- **Zero-Knowledge Email**: Send ciphertext via SMTP (env vars or manual config)
- **Persistent History**: CSV-based log of all encryption operations
- **QR Code**: On-demand QR code for out-of-band key exchange
- **Security Index**: Weighted composite score from 6 normalized metrics
- **PKCS#7 padding visualization**: educational block breakdown
- **IV/Nonce inspector**: structure + nonce-reuse warnings for AEAD

## Installation

```bash
# Clone the repository
git clone <repo-url>
cd FINALE

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Optional: install argon2 for Argon2id key derivation
pip install argon2-cffi

# Run the app
streamlit run Cryptography.py
# Or double-click run.bat (Windows)
```

## Usage

1. **Select a Cipher Mode** in the sidebar (10 available)
2. **Choose a Key Derivation Method** (10 available)
3. **Generate/Derive a key** and encrypt your plaintext in Tab 1
4. **Analyze** the ciphertext with the full NIST suite + 19 features in Tab 4
5. **Classify** the cipher mode with ML (10 classes) in Tab 5
6. **Hide** the ciphertext in an image via steganography in Tab 3

## Project Structure

```
├── Cryptography.py          # Main entry point (Streamlit UI, ~640 lines)
├── crypto_lab/              # Business logic package
│   ├── __init__.py          # Public API exports
│   ├── config.py            # Constants (PBKDF2 iterations, file paths, defaults)
│   ├── crypto_engine.py     # CIPHER_REGISTRY (10 modes), KEY_METHODS (10 methods)
│   │                        #   encrypt_with(), decrypt_with(), derive_key()
│   ├── steganography.py     # LSB image steganography
│   ├── nist_suite.py        # NIST SP 800-22 (7 tests), entropy, diffusion,
│   │                        #   avalanche, autocorrelation, compression, chi-square
│   │                        #   _unpackbits_cached() via lru_cache
│   ├── ml_models.py         # CipherMLClassifier (RF + MLP + IsolationForest),
│   │                        #   10-class prediction, 19 features, PCA/t-SNE,
│   │                        #   permutation importance, confusion matrix,
│   │                        #   learning curve, HPO, active learning, drift
│   ├── email_service.py     # SMTP zero-knowledge email (env var support)
│   └── utils.py             # Session state, history persistence (CSV), validation
├── requirements.txt
├── run.bat                  # Windows launcher
├── AGENTS.md                # AI developer guidelines
├── LICENSE                  # MIT
└── README.md
```

## Security Notes

- The master key is never stored or transmitted by the application.
- PBKDF2 uses 600,000 iterations per OWASP 2023 recommendations.
- AES-256-GCM and ChaCha20-Poly1305 provide authenticated encryption.
- Educational ciphers (TripleDES, Blowfish, XOR, Vigenère) display clear warnings.
- SMTP credentials can be set via environment variables to avoid UI entry.
- The "Zero-Knowledge Email" sends only the ciphertext; the key must be
  exchanged out-of-band.
- Key visibility is hidden by default; toggle "Show key in sidebar" to reveal.

## Performance

- PBKDF2 and scrypt may take a few seconds (intentional security cost).
- NIST tests use `@functools.lru_cache` on bit conversions for speed.
- ML model is trained once on startup and persisted to `cipher_classifier.joblib`.
- MLP converges faster with `early_stopping=True`, `n_iter_no_change=5`, `tol=1e-3`.
- Learning curve is on-demand only (button click, 15 fits over 5 train sizes).
- Avalanche test uses 5 trials (configurable in `AVALANCHE_TRIALS` in `config.py`).

## Known Issues

- Python 3.14 `os.urandom()` LSP false positive: return type shown as `Optional[bytes]`
  (never None at runtime).
- cryptography 46.0.5 removed DES entirely; TripleDES in `decrepit` module, Blowfish
  used as DES replacement.
- sklearn stubs: `permutation_importance` returns a `Bunch` but stub says `dict` —
  `.importances_mean` access triggers false positive LSP error.
- Vigenère name displays with encoding artifact in cp1252 console (fine in Streamlit UI).

## License

MIT


## Enterprise features (v8.1)

- Workflow bar: KEY → ENCRYPT → ANALYZE → EXPORT
- Demo presets + guided tour in sidebar
- Tab **07 ENTERPRISE**: compliance checklist, multi-cipher benchmark, evidence ZIP/PDF, case files
- ML feature contribution explanation + model card
- Local API: `uvicorn crypto_lab.api_server:app --port 8765` (requires fastapi)
- PQC educational lab (toy KEM + NIST algorithm map)

### Evidence pack
After analysis, open **07 ENTERPRISE** → Build evidence pack (ZIP) for audit-style export.
