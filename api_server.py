"""
Local REST API for Master Crypto Lab (P3).

Run:
  uvicorn crypto_lab.api_server:app --host 127.0.0.1 --port 8765

Endpoints are intentionally local-only oriented for enterprise lab integration.
"""
from __future__ import annotations

from typing import Optional

try:
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel, Field
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    FastAPI = None  # type: ignore


if HAS_FASTAPI:
    from .crypto_engine import CIPHER_REGISTRY, encrypt_with, decrypt_with, get_available_ciphers
    from .nist_suite import CryptoScientificLibrary
    from .enterprise import run_cipher_benchmark, compliance_checklist

    app = FastAPI(
        title="Master Crypto Lab API",
        version="8.0",
        description="Local analytic API — encrypt, metrics, benchmark",
    )

    class EncryptRequest(BaseModel):
        mode: str
        key_hex: str
        plaintext: str

    class DecryptRequest(BaseModel):
        mode: str
        key_hex: str
        ciphertext_hex: str

    class MetricsRequest(BaseModel):
        ciphertext_hex: str
        plaintext: str = ""
        key_hex: str = ""
        mode: str = "AES-256-GCM"

    @app.get("/health")
    def health():
        return {"status": "ok", "ciphers": len(CIPHER_REGISTRY)}

    @app.get("/ciphers")
    def ciphers():
        return {"ciphers": get_available_ciphers()}

    @app.post("/encrypt")
    def api_encrypt(req: EncryptRequest):
        if req.mode not in CIPHER_REGISTRY:
            raise HTTPException(400, f"Unknown mode: {req.mode}")
        try:
            key = bytes.fromhex(req.key_hex)
            ct = encrypt_with(req.mode, key, req.plaintext.encode())
            return {"ciphertext_hex": ct.hex(), "length": len(ct)}
        except Exception as e:
            raise HTTPException(400, str(e))

    @app.post("/decrypt")
    def api_decrypt(req: DecryptRequest):
        if req.mode not in CIPHER_REGISTRY:
            raise HTTPException(400, f"Unknown mode: {req.mode}")
        try:
            key = bytes.fromhex(req.key_hex)
            pt = decrypt_with(req.mode, key, bytes.fromhex(req.ciphertext_hex))
            return {"plaintext": pt.decode("utf-8", errors="replace")}
        except Exception as e:
            raise HTTPException(400, str(e))

    @app.post("/metrics")
    def api_metrics(req: MetricsRequest):
        try:
            ct = bytes.fromhex(req.ciphertext_hex)
            key = bytes.fromhex(req.key_hex) if req.key_hex else b"\x00" * 32

            def _enc(p: bytes) -> bytes:
                return encrypt_with(req.mode, key, p)

            metrics = CryptoScientificLibrary.run_full_suite(
                ct, req.plaintext or "A", key, encrypt_fn=_enc if req.key_hex else None
            )
            return {"metrics": metrics}
        except Exception as e:
            raise HTTPException(400, str(e))

    @app.post("/benchmark")
    def api_benchmark(plaintext: str = "Master Crypto Lab benchmark payload"):
        return {"rows": run_cipher_benchmark(plaintext)}

else:
    app = None  # type: ignore
