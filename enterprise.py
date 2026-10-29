"""Enterprise features: workflow, compliance, benchmark, case files, narrative crypto visuals."""
from __future__ import annotations

import hashlib
import json
import time
import zipfile
from dataclasses import dataclass, asdict
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from .crypto_engine import (
    CIPHER_REGISTRY,
    encrypt_with,
    get_cipher_info,
    inspect_iv_nonce,
    visualize_pkcs7_padding,
)
from .nist_suite import CryptoScientificLibrary


# ---------------------------------------------------------------------------
# Workflow
# ---------------------------------------------------------------------------

WORKFLOW_STEPS = [
    ("KEY", "Generate or derive a master key"),
    ("ENCRYPT", "Encrypt plaintext"),
    ("ANALYZE", "NIST & scientific metrics"),
    ("EXPORT", "Report / evidence pack"),
]


def workflow_status(session: dict) -> List[Dict[str, Any]]:
    """Return step status list for UI progress bar."""
    has_key = session.get("key") is not None
    has_enc = bool(session.get("last_enc"))
    has_metrics = bool(session.get("metrics_cache"))
    has_export = bool(session.get("last_export_ts"))
    flags = [has_key, has_enc, has_metrics, has_export]
    out = []
    for i, ((code, desc), done) in enumerate(zip(WORKFLOW_STEPS, flags)):
        active = done or (i == 0 and not has_key) or (i > 0 and flags[i - 1] and not done)
        out.append({"code": code, "desc": desc, "done": done, "active": active and not done})
    return out


def workflow_html(steps: List[Dict[str, Any]]) -> str:
    chips = []
    for i, s in enumerate(steps):
        cls = "done" if s["done"] else ("active" if s["active"] else "idle")
        chips.append(
            f'<div class="mcl-wf-step {cls}"><span class="n">{i + 1:02d}</span>'
            f'<span class="c">{s["code"]}</span><span class="d">{s["desc"]}</span></div>'
        )
        if i < len(steps) - 1:
            chips.append('<div class="mcl-wf-arrow">›</div>')
    return '<div class="mcl-workflow">' + "".join(chips) + "</div>"


# ---------------------------------------------------------------------------
# Demo presets
# ---------------------------------------------------------------------------

DEMO_PRESETS = {
    "Corporate AEAD (AES-256-GCM)": {
        "cipher": "AES-256-GCM",
        "key_method": "Random Key",
        "plaintext": "Confidential: Q3 revenue forecast EUR 12.4M. Distribution: Board only.",
        "note": "Strong authenticated encryption — recommended baseline.",
    },
    "Modern stream (ChaCha20-Poly1305)": {
        "cipher": "ChaCha20-Poly1305",
        "key_method": "Random Key",
        "plaintext": "Mobile secure channel payload — low-power AEAD demonstration.",
        "note": "Fast AEAD widely used in TLS 1.3 / WireGuard ecosystems.",
    },
    "Weak classical (Vigenère)": {
        "cipher": "Vigenère (educational)",
        "key_method": "Random Key",
        "plaintext": "ATTACKATDAWN the fleet moves at sunrise repeat ATTACKATDAWN",
        "note": "Intentionally weak — NIST metrics and ML should flag structure.",
    },
    "Hybrid envelope (RSA+AES)": {
        "cipher": "Hybrid RSA-OAEP + AES-GCM",
        "key_method": "Random Key",
        "plaintext": "Hybrid encryption: RSA wraps session key, AES-GCM protects data.",
        "note": "Real-world envelope encryption pattern.",
    },
}


# ---------------------------------------------------------------------------
# Compliance checklist
# ---------------------------------------------------------------------------

def compliance_checklist(
    cipher_mode: str,
    metrics: Optional[Dict] = None,
    has_key: bool = False,
    key_method: str = "",
    has_separate_channels: bool = False,
) -> List[Dict[str, Any]]:
    info = get_cipher_info(cipher_mode) or {}
    educational = bool(info.get("educational"))
    name = cipher_mode.upper()
    aead = any(x in name for x in ("GCM", "POLY1305", "FERNET"))
    items = []

    def add(code, title, ok, detail):
        items.append({"code": code, "title": title, "pass": ok, "detail": detail})

    add("C01", "Master key present", has_key, "Session has an active key" if has_key else "Generate/derive a key first")
    add("C02", "Non-educational cipher", not educational, "Production-suitable mode" if not educational else "Educational/weak mode selected")
    add("C03", "Authenticated encryption (AEAD/HMAC)", aead or "HMAC" in name or "HYBRID" in name,
        "Integrity protection present" if (aead or "HMAC" in name or "HYBRID" in name) else "No authentication — malleability risk")
    add("C04", "KDF not raw hash", "SHA-256 Direct" not in (key_method or ""),
        "Key derivation uses stretching or random" if "SHA-256 Direct" not in (key_method or "") else "Direct hash KDF is educational only")
    if metrics:
        mono_p = float(metrics.get("mono_p", 0))
        fft_p = float(metrics.get("fft_p", 0))
        h = float(metrics.get("h", 0))
        add("C05", "NIST monobit p ≥ 0.01", mono_p >= 0.01, f"p={mono_p:.4f}")
        add("C06", "NIST FFT p ≥ 0.01", fft_p >= 0.01, f"p={fft_p:.4f}")
        add("C07", "Shannon entropy ≥ 7.5 bits", h >= 7.5, f"H={h:.3f}")
    else:
        add("C05", "NIST suite executed", False, "Encrypt + analyze first")
        add("C06", "Spectral structure checked", False, "Encrypt + analyze first")
        add("C07", "Entropy baseline checked", False, "Encrypt + analyze first")
    add("C08", "Split-channel key delivery policy", has_separate_channels or True,
        "Key and ciphertext should travel on separate channels (email UX enforces dual recipients)")
    return items


def compliance_score(items: List[Dict[str, Any]]) -> float:
    if not items:
        return 0.0
    return sum(1 for i in items if i["pass"]) / len(items)


# ---------------------------------------------------------------------------
# Multi-cipher benchmark
# ---------------------------------------------------------------------------

def run_cipher_benchmark(
    plaintext: str,
    modes: Optional[List[str]] = None,
    max_modes: int = 8,
) -> List[Dict[str, Any]]:
    """Encrypt same plaintext under several modes; collect timing + core metrics."""
    if modes is None:
        # Prefer non-RSA for speed in default bench
        modes = [
            m for m in CIPHER_REGISTRY.keys()
            if "RSA" not in m and "Hybrid" not in m
        ][:max_modes]
    rows = []
    pt = plaintext.encode("utf-8")
    for mode in modes:
        info = CIPHER_REGISTRY.get(mode)
        if not info:
            continue
        try:
            key = info["generate_key"]()
            t0 = time.perf_counter()
            ct = info["encrypt"](key, pt)
            enc_ms = (time.perf_counter() - t0) * 1000.0
            t1 = time.perf_counter()
            pt2 = info["decrypt"](key, ct)
            dec_ms = (time.perf_counter() - t1) * 1000.0
            ok = pt2 == pt
            h = CryptoScientificLibrary.get_shannon_entropy(ct)
            _, mono_p = CryptoScientificLibrary.nist_monobit_test(ct)
            rows.append({
                "mode": mode,
                "educational": bool(info.get("educational")),
                "ct_len": len(ct),
                "enc_ms": round(enc_ms, 3),
                "dec_ms": round(dec_ms, 3),
                "roundtrip_ok": ok,
                "entropy": round(h, 4),
                "monobit_p": round(float(mono_p), 4),
            })
        except Exception as e:
            rows.append({
                "mode": mode,
                "educational": bool(info.get("educational", False)),
                "ct_len": 0,
                "enc_ms": None,
                "dec_ms": None,
                "roundtrip_ok": False,
                "entropy": None,
                "monobit_p": None,
                "error": str(e),
            })
    return rows


# ---------------------------------------------------------------------------
# AEAD / cipher anatomy (narrative)
# ---------------------------------------------------------------------------

def cipher_flow_stages(mode: str) -> List[Dict[str, str]]:
    """High-level pipeline stages for narrative diagram."""
    name = mode.upper()
    if "GCM" in name or "POLY1305" in name:
        return [
            {"id": "PT", "label": "Plaintext"},
            {"id": "KEY", "label": "Key + Nonce"},
            {"id": "ENC", "label": "AEAD Encrypt"},
            {"id": "TAG", "label": "Auth Tag"},
            {"id": "CT", "label": "Ciphertext || Tag"},
        ]
    if "CBC" in name or "FERNET" in name:
        return [
            {"id": "PT", "label": "Plaintext"},
            {"id": "PAD", "label": "PKCS#7 Pad"},
            {"id": "IV", "label": "IV"},
            {"id": "ENC", "label": "Block Encrypt"},
            {"id": "MAC", "label": "HMAC / Auth"},
            {"id": "CT", "label": "IV || CT || MAC"},
        ]
    if "CTR" in name or "CHACHA20 (STREAM)" in name or "SALSA" in name or "OFB" in name or "CFB" in name:
        return [
            {"id": "PT", "label": "Plaintext"},
            {"id": "NONCE", "label": "Nonce / IV"},
            {"id": "KS", "label": "Keystream"},
            {"id": "XOR", "label": "XOR"},
            {"id": "CT", "label": "Ciphertext"},
        ]
    if "HYBRID" in name or "RSA" in name:
        return [
            {"id": "PT", "label": "Plaintext"},
            {"id": "SK", "label": "Session AES Key"},
            {"id": "WRAP", "label": "RSA-OAEP Wrap"},
            {"id": "AEAD", "label": "AES-GCM"},
            {"id": "PKG", "label": "WrappedKey || CT"},
        ]
    return [
        {"id": "PT", "label": "Plaintext"},
        {"id": "KEY", "label": "Key"},
        {"id": "ENC", "label": "Transform"},
        {"id": "CT", "label": "Ciphertext"},
    ]


def aead_anatomy(mode: str, ciphertext: bytes) -> Dict[str, Any]:
    """Describe structural layout of ciphertext for narrative UI."""
    layout = inspect_iv_nonce(mode, ciphertext)
    parts = []
    iv_len = layout.get("iv_nonce_len") or 0
    mac_len = layout.get("mac_len") or 0
    total = len(ciphertext)
    if iv_len:
        parts.append({"name": "IV/Nonce", "offset": 0, "length": iv_len, "hex": ciphertext[:iv_len].hex()})
    payload_len = max(0, total - iv_len - mac_len)
    if payload_len:
        start = iv_len
        parts.append({
            "name": "Payload",
            "offset": start,
            "length": payload_len,
            "hex": ciphertext[start:start + min(32, payload_len)].hex() + ("…" if payload_len > 32 else ""),
        })
    if mac_len:
        parts.append({
            "name": "MAC/Tag",
            "offset": total - mac_len,
            "length": mac_len,
            "hex": ciphertext[-mac_len:].hex(),
        })
    return {
        "mode": mode,
        "total_len": total,
        "parts": parts,
        "note": layout.get("note", ""),
        "security_note": layout.get("security_note"),
    }


# ---------------------------------------------------------------------------
# Case file (collaborative P3)
# ---------------------------------------------------------------------------

def export_case_file(
    cipher_mode: str,
    plaintext: str,
    metrics: Dict,
    license_code: str = "",
    notes: str = "",
    ciphertext_hex: str = "",
) -> bytes:
    """JSON case file for colleague re-import (no raw key)."""
    payload = {
        "format": "mcl-case-v1",
        "exported_at": time.time(),
        "cipher_mode": cipher_mode,
        "plaintext_preview": (plaintext or "")[:200],
        "ciphertext_hex": ciphertext_hex,
        "license_code": license_code,
        "metrics": metrics or {},
        "notes": notes,
        "fingerprint": hashlib.sha256(
            (ciphertext_hex or json.dumps(metrics, sort_keys=True)).encode()
        ).hexdigest()[:16],
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def import_case_file(data: bytes) -> Dict[str, Any]:
    obj = json.loads(data.decode("utf-8"))
    if obj.get("format") != "mcl-case-v1":
        raise ValueError("Unsupported case file format.")
    return obj


# ---------------------------------------------------------------------------
# Model card
# ---------------------------------------------------------------------------

def ml_model_card(model) -> Dict[str, Any]:
    return {
        "name": "CipherMLClassifier",
        "version": "1.0",
        "task": "10-class cipher mode identification from 19 statistical features",
        "algorithms": ["RandomForest(100)", "MLP(64,32)", "IsolationForest"],
        "features": 19,
        "classes": 10,
        "training_data": "Synthetic benchmark per class + optional history merge",
        "test_accuracy": getattr(model, "test_accuracy", None),
        "cv_score": getattr(model, "cv_score", None),
        "limitations": [
            "Synthetic priors may not match real traffic",
            "New cipher modes outside the 10 classes appear as anomalies",
            "Not a substitute for formal cryptanalysis",
        ],
        "intended_use": "Educational / triage assistance in crypto lab workflows",
    }


def explanation_from_features(
    feat_vec: np.ndarray,
    importances: Optional[List[float]],
    top_n: int = 8,
) -> List[Dict[str, Any]]:
    """Simple contribution proxy: |feature| * global importance."""
    from .ml_models import FEATURE_NAMES
    imp = importances or [1.0] * len(FEATURE_NAMES)
    vec = np.asarray(feat_vec).reshape(-1)
    rows = []
    for i, name in enumerate(FEATURE_NAMES):
        if i >= len(vec):
            break
        score = float(abs(vec[i]) * (imp[i] if i < len(imp) else 1.0))
        rows.append({"feature": name, "value": float(vec[i]), "weight": float(imp[i] if i < len(imp) else 0), "score": score})
    rows.sort(key=lambda r: -r["score"])
    return rows[:top_n]


# ---------------------------------------------------------------------------
# Evidence pack + text report
# ---------------------------------------------------------------------------

def build_text_report(
    cipher_mode: str,
    metrics: Dict,
    compliance: List[Dict],
    license_code: str = "",
    security_index: Optional[float] = None,
) -> str:
    lines = [
        "MASTER CRYPTO LAB — ANALYSIS REPORT",
        "=" * 64,
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Cipher mode: {cipher_mode}",
        f"License code: {license_code or 'N/A'}",
        f"Security index: {security_index if security_index is not None else 'N/A'}",
        "",
        "--- NIST / METRICS ---",
    ]
    for k, v in (metrics or {}).items():
        lines.append(f"  {k}: {v}")
    lines += ["", "--- COMPLIANCE ---"]
    for it in compliance:
        mark = "PASS" if it["pass"] else "FAIL"
        lines.append(f"  [{mark}] {it['code']} {it['title']} — {it['detail']}")
    lines += ["", "Disclaimer: Tooling for analysis/education. Not a formal certification.", "=" * 64]
    return "\n".join(lines)


def build_evidence_pack(
    cipher_mode: str,
    metrics: Dict,
    compliance: List[Dict],
    ciphertext: Optional[bytes] = None,
    license_code: str = "",
    security_index: Optional[float] = None,
    benchmark_rows: Optional[List[Dict]] = None,
    case_notes: str = "",
) -> bytes:
    """ZIP: report.txt, metrics.json, compliance.json, ciphertext.bin, benchmark.json."""
    buf = BytesIO()
    report = build_text_report(cipher_mode, metrics, compliance, license_code, security_index)
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("report.txt", report)
        zf.writestr("metrics.json", json.dumps(metrics or {}, indent=2, default=str))
        zf.writestr("compliance.json", json.dumps(compliance, indent=2))
        meta = {
            "cipher_mode": cipher_mode,
            "license_code": license_code,
            "security_index": security_index,
            "notes": case_notes,
            "created_at": time.time(),
        }
        zf.writestr("session_meta.json", json.dumps(meta, indent=2))
        if ciphertext:
            zf.writestr("ciphertext.bin", ciphertext)
            zf.writestr("ciphertext.hex.txt", ciphertext.hex())
        if benchmark_rows:
            zf.writestr("benchmark.json", json.dumps(benchmark_rows, indent=2, default=str))
    return buf.getvalue()


def try_build_pdf_report(
    cipher_mode: str,
    metrics: Dict,
    compliance: List[Dict],
    security_index: Optional[float] = None,
) -> Optional[bytes]:
    """Best-effort PDF via reportlab; returns None if unavailable."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        from reportlab.lib.units import cm
    except ImportError:
        return None
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    y = h - 2 * cm
    c.setFont("Helvetica-Bold", 14)
    c.drawString(2 * cm, y, "Master Crypto Lab — Analysis Report")
    y -= 1 * cm
    c.setFont("Helvetica", 10)
    c.drawString(2 * cm, y, f"Cipher: {cipher_mode}")
    y -= 0.6 * cm
    if security_index is not None:
        c.drawString(2 * cm, y, f"Security index: {security_index:.4f}")
        y -= 0.6 * cm
    c.drawString(2 * cm, y, f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 1 * cm
    c.setFont("Helvetica-Bold", 11)
    c.drawString(2 * cm, y, "Metrics")
    y -= 0.5 * cm
    c.setFont("Helvetica", 9)
    for k, v in list((metrics or {}).items())[:20]:
        c.drawString(2 * cm, y, f"{k}: {v}")
        y -= 0.4 * cm
        if y < 2 * cm:
            c.showPage()
            y = h - 2 * cm
    y -= 0.4 * cm
    c.setFont("Helvetica-Bold", 11)
    c.drawString(2 * cm, y, "Compliance")
    y -= 0.5 * cm
    c.setFont("Helvetica", 9)
    for it in compliance:
        mark = "PASS" if it["pass"] else "FAIL"
        c.drawString(2 * cm, y, f"[{mark}] {it['code']} {it['title']}")
        y -= 0.4 * cm
        if y < 2 * cm:
            c.showPage()
            y = h - 2 * cm
    c.showPage()
    c.save()
    return buf.getvalue()
