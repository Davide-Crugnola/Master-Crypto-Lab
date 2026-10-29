"""
Mission Tour — 5-step guided experience for Master Crypto Lab.

Steps:
  1 BRIEF   — mission briefing overlay
  2 ARM     — strong AEAD key generation
  3 ENCRYPT — encrypt demo plaintext (AES-256-GCM)
  4 CONTRAST— weak Vigenère vs strong metrics side-by-side
  5 EXPORT  — compliance + evidence pack CTA
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import streamlit as st

from .crypto_engine import CIPHER_REGISTRY, derive_key, encrypt_with
from .nist_suite import CryptoScientificLibrary
from .enterprise import (
    compliance_checklist,
    compliance_score,
    build_evidence_pack,
    try_build_pdf_report,
    build_text_report,
    cipher_flow_stages,
    aead_anatomy,
)


TOUR_STEPS = [
    {
        "id": 1,
        "code": "BRIEF",
        "title": "MISSION BRIEFING",
        "subtitle": "Randomness under fire",
        "body": (
            "Objective: verify whether an encrypted channel withstands statistical analysis. "
            "Two constructions. One verdict. Four minutes."
        ),
        "action_label": "INITIATE MISSION",
    },
    {
        "id": 2,
        "code": "ARM",
        "title": "ARM THE SESSION",
        "subtitle": "Strong AEAD baseline",
        "body": (
            "Select AES-256-GCM and materialize a random session key. "
            "Header status must reach SYSTEM ARMED before proceeding."
        ),
        "action_label": "GENERATE KEY (AES-256-GCM)",
    },
    {
        "id": 3,
        "code": "ENCRYPT",
        "title": "COMMIT CIPHERTEXT",
        "subtitle": "Authenticated encryption",
        "body": (
            "Encrypt the mission payload under AES-256-GCM. "
            "Observe the AEAD pipeline and packet anatomy (nonce · payload · tag)."
        ),
        "action_label": "ENCRYPT PAYLOAD",
    },
    {
        "id": 4,
        "code": "CONTRAST",
        "title": "STATISTICAL CONTRAST",
        "subtitle": "Strong vs classical weak",
        "body": (
            "Same secret intent, opposite constructions: AES-256-GCM versus Vigenère. "
            "Compare Security Index, entropy and monobit p-value side by side."
        ),
        "action_label": "RUN CONTRAST (GCM vs VIGENÈRE)",
    },
    {
        "id": 5,
        "code": "EXPORT",
        "title": "SEAL EVIDENCE",
        "subtitle": "Audit-ready artefact",
        "body": (
            "Review compliance score and download an evidence pack. "
            "You leave with a file — not only a screenshot."
        ),
        "action_label": "BUILD EVIDENCE PACK",
    },
]

MISSION_PLAINTEXT = (
    "MISSION PAYLOAD — Board distribution only. "
    "Q3 forecast EUR 12.4M. Do not forward outside secure channel."
)

DEFAULT_WEIGHTS = {"h": 0.25, "sac": 0.25, "uni": 0.15, "mono": 0.10, "runs": 0.10, "diff": 0.15}


def init_tour_state() -> None:
    defaults = {
        "tour_active": False,
        "tour_step": 0,  # 0 = inactive; 1..5 = steps
        "tour_strong_metrics": None,
        "tour_weak_metrics": None,
        "tour_strong_index": None,
        "tour_weak_index": None,
        "tour_completed": False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def start_tour() -> None:
    st.session_state.tour_active = True
    st.session_state.tour_step = 1
    st.session_state.tour_completed = False
    st.session_state.tour_strong_metrics = None
    st.session_state.tour_weak_metrics = None
    st.session_state.tour_strong_index = None
    st.session_state.tour_weak_index = None


def end_tour() -> None:
    st.session_state.tour_active = False
    st.session_state.tour_step = 0
    st.session_state.tour_completed = True


def skip_tour() -> None:
    end_tour()


def next_step() -> None:
    step = int(st.session_state.get("tour_step", 0))
    if step >= 5:
        end_tour()
    else:
        st.session_state.tour_step = step + 1


def prev_step() -> None:
    step = int(st.session_state.get("tour_step", 0))
    if step > 1:
        st.session_state.tour_step = step - 1


def current_step_meta() -> Optional[Dict[str, Any]]:
    step = int(st.session_state.get("tour_step", 0))
    if not st.session_state.get("tour_active") or step < 1 or step > 5:
        return None
    return TOUR_STEPS[step - 1]


def tour_css() -> str:
    return """
<style>
.mcl-tour-panel {
  border: 1px solid rgba(0,229,255,0.45);
  border-radius: 10px;
  background: linear-gradient(145deg, rgba(8,12,20,0.98), rgba(12,18,30,0.95));
  box-shadow: 0 0 40px rgba(0,229,255,0.18), inset 0 1px 0 rgba(0,229,255,0.15);
  padding: 1.1rem 1.25rem 1rem;
  margin: 0.4rem 0 1rem 0;
  position: relative;
  overflow: hidden;
}
.mcl-tour-panel::before {
  content: "";
  position: absolute; left: 0; top: 0; bottom: 0; width: 4px;
  background: linear-gradient(180deg, #00e5ff, #b388ff, #69f0ae);
}
.mcl-tour-kicker {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.68rem;
  letter-spacing: 0.22em;
  color: #8b9bb4;
  text-transform: uppercase;
  margin-bottom: 0.35rem;
}
.mcl-tour-title {
  font-family: Orbitron, sans-serif;
  font-weight: 800;
  letter-spacing: 0.14em;
  color: #00e5ff;
  font-size: 1.15rem;
  text-shadow: 0 0 18px rgba(0,229,255,0.45);
  margin: 0 0 0.2rem 0;
}
.mcl-tour-sub {
  font-family: 'JetBrains Mono', monospace;
  color: #69f0ae;
  font-size: 0.75rem;
  letter-spacing: 0.08em;
  margin-bottom: 0.55rem;
}
.mcl-tour-body {
  font-family: Inter, system-ui, sans-serif;
  color: #c5d0e0;
  font-size: 0.92rem;
  line-height: 1.45;
  margin-bottom: 0.85rem;
  max-width: 52rem;
}
.mcl-tour-progress {
  display: flex; gap: 0.35rem; margin-bottom: 0.75rem; flex-wrap: wrap;
}
.mcl-tour-dot {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.62rem;
  letter-spacing: 0.1em;
  padding: 0.22rem 0.5rem;
  border-radius: 3px;
  border: 1px solid rgba(0,229,255,0.2);
  color: #8b9bb4;
}
.mcl-tour-dot.on {
  color: #00e5ff;
  border-color: rgba(0,229,255,0.55);
  background: rgba(0,229,255,0.1);
  box-shadow: 0 0 12px rgba(0,229,255,0.2);
}
.mcl-tour-dot.done {
  color: #69f0ae;
  border-color: rgba(105,240,174,0.45);
  background: rgba(105,240,174,0.08);
}
.mcl-contrast-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.75rem;
  margin: 0.75rem 0;
}
@media (max-width: 900px) {
  .mcl-contrast-grid { grid-template-columns: 1fr; }
}
.mcl-contrast-card {
  border: 1px solid rgba(0,229,255,0.25);
  border-radius: 8px;
  padding: 0.85rem 1rem;
  background: rgba(10,14,23,0.9);
}
.mcl-contrast-card.weak {
  border-color: rgba(255,82,82,0.45);
}
.mcl-contrast-card.strong {
  border-color: rgba(105,240,174,0.45);
}
.mcl-contrast-card h4 {
  font-family: Orbitron, sans-serif;
  letter-spacing: 0.1em;
  font-size: 0.85rem;
  margin: 0 0 0.5rem 0;
}
.mcl-contrast-card.strong h4 { color: #69f0ae; }
.mcl-contrast-card.weak h4 { color: #ff5252; }
.mcl-contrast-metric {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.78rem;
  color: #c5d0e0;
  margin: 0.2rem 0;
}
.mcl-tour-verdict {
  font-family: Orbitron, sans-serif;
  letter-spacing: 0.12em;
  text-align: center;
  padding: 0.65rem;
  margin-top: 0.5rem;
  border-radius: 6px;
  border: 1px solid rgba(255,215,64,0.45);
  color: #ffd740;
  background: rgba(255,215,64,0.08);
}
</style>
"""


def _progress_html(step: int) -> str:
    dots = []
    for s in TOUR_STEPS:
        cls = "done" if s["id"] < step else ("on" if s["id"] == step else "")
        dots.append(f'<span class="mcl-tour-dot {cls}">{s["id"]:02d} {s["code"]}</span>')
    return '<div class="mcl-tour-progress">' + "".join(dots) + "</div>"


def _encrypt_suite(mode: str, key: bytes, plaintext: str) -> Tuple[bytes, Dict]:
    def _enc(pt: bytes) -> bytes:
        return encrypt_with(mode, key, pt)

    ct = _enc(plaintext.encode("utf-8"))
    metrics = CryptoScientificLibrary.run_full_suite(ct, plaintext, key, encrypt_fn=_enc)
    return ct, metrics


def _run_arm() -> Tuple[bool, str]:
    mode = "AES-256-GCM"
    st.session_state.cipher_mode = mode
    try:
        key, msg = derive_key("Random Key", mode)
        st.session_state.key = key
        st.session_state.last_key_method = "Random Key"
        return True, msg or "Random AEAD key generated."
    except Exception as e:
        return False, str(e)


def _run_encrypt_strong() -> Tuple[bool, str]:
    mode = "AES-256-GCM"
    key = st.session_state.get("key")
    if key is None:
        return False, "No key armed."
    st.session_state.cipher_mode = mode
    try:
        ct, metrics = _encrypt_suite(mode, key, MISSION_PLAINTEXT)
        st.session_state.last_enc = ct
        st.session_state.u_text = MISSION_PLAINTEXT
        st.session_state.metrics_cache = metrics
        st.session_state.tour_strong_metrics = metrics
        idx = CryptoScientificLibrary.compute_security_index(metrics, DEFAULT_WEIGHTS)
        st.session_state.tour_strong_index = idx
        # license-like code (compact)
        hx = ct.hex().upper()
        st.session_state.license_code = "-".join(hx[i:i + 5] for i in range(0, min(40, len(hx)), 5))
        return True, f"Payload encrypted ({len(ct)} bytes). Security index={idx:.3f}"
    except Exception as e:
        return False, str(e)


def _run_contrast() -> Tuple[bool, str]:
    """Encrypt same plaintext under Vigenère; keep strong metrics from step 3."""
    mode_w = "Vigenère (educational)"
    try:
        if mode_w not in CIPHER_REGISTRY:
            return False, "Vigenère mode not available."
        key_w, _ = derive_key("Random Key", mode_w)
        ct_w, metrics_w = _encrypt_suite(mode_w, key_w, MISSION_PLAINTEXT)
        st.session_state.tour_weak_metrics = metrics_w
        idx_w = CryptoScientificLibrary.compute_security_index(metrics_w, DEFAULT_WEIGHTS)
        st.session_state.tour_weak_index = idx_w
        # restore strong session as primary so lab tabs stay on GCM story
        if st.session_state.get("tour_strong_metrics"):
            st.session_state.metrics_cache = st.session_state.tour_strong_metrics
            st.session_state.cipher_mode = "AES-256-GCM"
        return True, f"Contrast ready. Weak security index={idx_w:.3f}"
    except Exception as e:
        return False, str(e)


def _contrast_cards_html() -> str:
    sm = st.session_state.get("tour_strong_metrics") or {}
    wm = st.session_state.get("tour_weak_metrics") or {}
    si = st.session_state.get("tour_strong_index")
    wi = st.session_state.get("tour_weak_index")

    def card(title, cls, metrics, idx):
        h = metrics.get("h", float("nan"))
        mono_p = metrics.get("mono_p", float("nan"))
        fft_p = metrics.get("fft_p", float("nan"))
        sac = metrics.get("sac", float("nan"))
        idx_s = f"{idx:.3f}" if idx is not None else "n/a"
        return f"""
<div class="mcl-contrast-card {cls}">
  <h4>{title}</h4>
  <div class="mcl-contrast-metric">Security Index · <b>{idx_s}</b></div>
  <div class="mcl-contrast-metric">Entropy H · <b>{h:.3f}</b> bit</div>
  <div class="mcl-contrast-metric">Monobit p · <b>{mono_p:.4f}</b></div>
  <div class="mcl-contrast-metric">FFT p · <b>{fft_p:.4f}</b></div>
  <div class="mcl-contrast-metric">SAC avalanche · <b>{sac:.1f}%</b></div>
</div>"""

    return (
        '<div class="mcl-contrast-grid">'
        + card("AES-256-GCM (STRONG)", "strong", sm, si)
        + card("VIGENÈRE (WEAK)", "weak", wm, wi)
        + "</div>"
        + '<div class="mcl-tour-verdict">VERDICT — Same payload. Opposite statistical posture.</div>'
    )


def render_mission_tour(weights: Optional[Dict[str, float]] = None) -> None:
    """Render the active mission panel and execute step actions."""
    init_tour_state()
    if not st.session_state.get("tour_active"):
        return

    meta = current_step_meta()
    if not meta:
        return

    weights = weights or DEFAULT_WEIGHTS
    step = meta["id"]

    st.markdown(tour_css(), unsafe_allow_html=True)
    st.markdown(
        f"""
<div class="mcl-tour-panel">
  <div class="mcl-tour-kicker">MISSION TOUR · STEP {step:02d} / 05</div>
  {_progress_html(step)}
  <div class="mcl-tour-title">{meta['title']}</div>
  <div class="mcl-tour-sub">{meta['subtitle']}</div>
  <div class="mcl-tour-body">{meta['body']}</div>
</div>
""",
        unsafe_allow_html=True,
    )

    c1, c2, c3, c4 = st.columns([2, 1, 1, 1])
    with c1:
        primary = st.button(meta["action_label"], key=f"tour_primary_{step}", type="primary")
    with c2:
        if step > 1:
            if st.button("← PREV", key=f"tour_prev_{step}"):
                prev_step()
                st.rerun()
    with c3:
        if step < 5 and step != 1:
            # allow skip ahead only after briefing
            if st.button("SKIP STEP", key=f"tour_skipstep_{step}"):
                next_step()
                st.rerun()
    with c4:
        if st.button("ABORT TOUR", key=f"tour_abort_{step}"):
            skip_tour()
            st.rerun()

    # --- Step actions ---
    if step == 1 and primary:
        next_step()
        st.rerun()

    if step == 2 and primary:
        ok, msg = _run_arm()
        if ok:
            st.success(msg)
            next_step()
            st.rerun()
        else:
            st.error(msg)

    if step == 3:
        if st.session_state.get("key") is None:
            st.warning("Key not armed — go back to step 02.")
        if primary:
            ok, msg = _run_encrypt_strong()
            if ok:
                st.success(msg)
                stages = cipher_flow_stages("AES-256-GCM")
                st.caption(" → ".join(s["label"] for s in stages))
                if st.session_state.get("last_enc"):
                    an = aead_anatomy("AES-256-GCM", st.session_state.last_enc)
                    st.caption(an.get("note") or "")
                next_step()
                st.rerun()
            else:
                st.error(msg)

    if step == 4:
        if st.session_state.get("tour_strong_metrics") is None:
            st.warning("Strong metrics missing — complete ENCRYPT step first.")
        if primary:
            with st.spinner("Running weak construction + contrast metrics..."):
                ok, msg = _run_contrast()
            if ok:
                st.success(msg)
            else:
                st.error(msg)
        if st.session_state.get("tour_weak_metrics") and st.session_state.get("tour_strong_metrics"):
            st.markdown(_contrast_cards_html(), unsafe_allow_html=True)
            if st.button("CONTINUE TO EXPORT →", key="tour_contrast_next"):
                next_step()
                st.rerun()

    if step == 5:
        metrics = st.session_state.get("tour_strong_metrics") or st.session_state.get("metrics_cache") or {}
        mode = "AES-256-GCM"
        items = compliance_checklist(
            mode,
            metrics=metrics if metrics else None,
            has_key=st.session_state.get("key") is not None,
            key_method=st.session_state.get("last_key_method", "Random Key"),
        )
        score = compliance_score(items)
        st.metric("Compliance score (strong path)", f"{score:.0%}")
        for it in items[:6]:
            mark = "PASS" if it["pass"] else "FAIL"
            st.caption(f"[{mark}] {it['code']} {it['title']}")

        if primary:
            pack = build_evidence_pack(
                mode,
                metrics,
                items,
                ciphertext=st.session_state.get("last_enc"),
                license_code=st.session_state.get("license_code", ""),
                security_index=st.session_state.get("tour_strong_index"),
                case_notes="Mission tour — Randomness under fire",
            )
            st.session_state.last_export_ts = __import__("time").time()
            st.download_button(
                "DOWNLOAD EVIDENCE PACK (ZIP)",
                data=pack,
                file_name="mcl_mission_evidence.zip",
                mime="application/zip",
                key="tour_dl_pack",
            )
            pdf = try_build_pdf_report(
                mode, metrics, items,
                security_index=st.session_state.get("tour_strong_index"),
            )
            if pdf:
                st.download_button(
                    "DOWNLOAD PDF REPORT",
                    data=pdf,
                    file_name="mcl_mission_report.pdf",
                    mime="application/pdf",
                    key="tour_dl_pdf",
                )
            else:
                txt = build_text_report(
                    mode, metrics, items,
                    st.session_state.get("license_code", ""),
                    st.session_state.get("tour_strong_index"),
                )
                st.download_button(
                    "DOWNLOAD TEXT REPORT",
                    data=txt.encode(),
                    file_name="mcl_mission_report.txt",
                    mime="text/plain",
                    key="tour_dl_txt",
                )
            st.success("Evidence sealed. Mission complete.")
            if st.button("CLOSE MISSION", key="tour_close"):
                end_tour()
                st.rerun()
