import io
import base64
import time
import re

import streamlit as st
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    qrcode = None
    HAS_QRCODE = False
from PIL import Image
from cryptography.hazmat.primitives.asymmetric import x25519

from crypto_lab import (
    get_available_ciphers, get_cipher_info,
    encrypt_with, decrypt_with,
    get_available_key_methods, get_key_method_info, derive_key,
    AdvancedCryptoEngine,
    CryptoScientificLibrary,
    LSBSteganography,
    CipherMLClassifier, FEATURE_NAMES, CIPHER_CLASSES,
    send_zero_knowledge_email, send_key_email, send_ciphertext_email,
    get_smtp_config_from_env,
    init_session_state, splash_screen,
    append_to_history, save_history_to_csv,
    check_key_active, make_weights_sliders,
    MODEL_FILE,
    estimate_password_strength,
    visualize_pkcs7_padding, inspect_iv_nonce,
    workflow_status, workflow_html, DEMO_PRESETS,
    compliance_checklist, compliance_score,
    run_cipher_benchmark, cipher_flow_stages, aead_anatomy,
    export_case_file, import_case_file, ml_model_card, explanation_from_features,
    build_text_report, build_evidence_pack, try_build_pdf_report,
    PQC_ALGORITHMS, toy_hash_kem_keypair, toy_hash_kem_encaps, toy_hash_kem_decaps,
    migration_checklist,
    init_tour_state, start_tour, render_mission_tour, skip_tour,
)


def _make_encrypt_fn(mode_name: str, key: bytes):
    def _enc(plaintext: bytes) -> bytes:
        return encrypt_with(mode_name, key, plaintext)
    return _enc


def _key_to_display(key: bytes, mode_name: str) -> str:
    info = get_cipher_info(mode_name)
    if info is None:
        return key.hex()
    return info["key_to_str"](key)


def _is_educational(mode_name: str) -> bool:
    info = get_cipher_info(mode_name)
    return info["educational"] if info else False


def inject_console_theme() -> None:
    """Professional cyber-ops console skin — hides default Streamlit chrome."""
    st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Orbitron:wght@500;700;900&family=Inter:wght@400;500;600&display=swap');

:root {
  --bg-0: #05070b;
  --bg-1: #0a0e17;
  --bg-2: #0f1520;
  --bg-3: #151c2c;
  --border: rgba(0, 229, 255, 0.18);
  --border-hot: rgba(0, 229, 255, 0.55);
  --cyan: #00e5ff;
  --cyan-dim: #00b8d4;
  --green: #69f0ae;
  --amber: #ffd740;
  --red: #ff5252;
  --violet: #b388ff;
  --text: #e8eef7;
  --text-dim: #8b9bb4;
  --glow: 0 0 20px rgba(0, 229, 255, 0.25);
}

/* ===== Global ===== */
html, body, [data-testid="stAppViewContainer"], .stApp {
  background: var(--bg-0) !important;
  color: var(--text) !important;
  font-family: 'Inter', system-ui, sans-serif !important;
}

/* Soften Streamlit chrome but KEEP sidebar toggle accessible */
[data-testid="stHeader"] {
  background: rgba(5,7,11,0.65) !important;
  backdrop-filter: blur(8px);
}
[data-testid="stToolbar"] { opacity: 0.35; }
[data-testid="stToolbar"]:hover { opacity: 1; }
#MainMenu { visibility: hidden; }
footer { visibility: hidden; height: 0; }
[data-testid="stDecoration"] { display: none !important; }
.block-container {
  padding-top: 1.2rem !important;
  padding-bottom: 3rem !important;
  max-width: 1400px !important;
}

/* Particle canvas behind everything */
#mcl-particles {
  position: fixed; inset: 0;
  width: 100vw; height: 100vh;
  z-index: 0; pointer-events: none;
}
[data-testid="stAppViewContainer"] > .main,
[data-testid="stSidebar"] {
  position: relative;
  z-index: 1;
}

/* Grid + scanline overlays (do not block clicks) */
.stApp::before {
  content: "";
  position: fixed; inset: 0; pointer-events: none; z-index: 0;
  background:
    linear-gradient(rgba(0,229,255,0.025) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,229,255,0.025) 1px, transparent 1px);
  background-size: 48px 48px;
  mask-image: radial-gradient(ellipse at center, black 20%, transparent 70%);
}
.stApp::after {
  content: "";
  position: fixed; inset: 0; pointer-events: none; z-index: 2;
  background: repeating-linear-gradient(
    0deg, transparent, transparent 2px, rgba(0,0,0,0.025) 3px);
  opacity: 0.35;
}

/* ===== SIDEBAR — forced visible, full contrast ===== */
section[data-testid="stSidebar"],
[data-testid="stSidebar"] {
  background: linear-gradient(180deg, #070b12 0%, #0a101a 55%, #0c121c 100%) !important;
  border-right: 1px solid var(--border) !important;
  z-index: 100 !important;
  opacity: 1 !important;
}
/* Streamlit sidebar open state — do not force transform (breaks collapse) */
section[data-testid="stSidebar"][aria-expanded="true"] {
  visibility: visible !important;
}
[data-testid="stSidebar"] > div {
  background: transparent !important;
}
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
  color: var(--text-dim) !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 0.8rem !important;
}
[data-testid="stSidebar"] label {
  color: #b0c0d8 !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 0.78rem !important;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3 {
  font-family: 'Orbitron', sans-serif !important;
  color: var(--cyan) !important;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  font-size: 0.95rem !important;
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.4rem;
  visibility: visible !important;
}
/* Sidebar collapse control always visible */

/* Ensure collapsed-control (hamburger) is always visible and styled */
[data-testid="collapsedControl"],
[data-testid="stSidebarCollapsedControl"] {
  visibility: visible !important;
  display: flex !important;
  opacity: 1 !important;
  background: rgba(10,14,23,0.9) !important;
  border: 1px solid rgba(0,229,255,0.4) !important;
  border-radius: 0 6px 6px 0 !important;
  color: #00e5ff !important;
  z-index: 1000 !important;
}
/* Never fully hide the sidebar section */
section[data-testid="stSidebar"][aria-expanded="false"] {
  /* still allow collapse, but keep toggle */
}

[data-testid="stSidebarCollapsedControl"],
button[kind="header"] {
  visibility: visible !important;
  opacity: 1 !important;
  color: var(--cyan) !important;
}
/* Select / inputs inside sidebar */
[data-testid="stSidebar"] .stSelectbox,
[data-testid="stSidebar"] .stTextInput,
[data-testid="stSidebar"] .stButton,
[data-testid="stSidebar"] .stCheckbox,
[data-testid="stSidebar"] .stSlider,
[data-testid="stSidebar"] .stExpander {
  visibility: visible !important;
  opacity: 1 !important;
}

/* ===== Typography ===== */
h1, h2, h3, h4 {
  font-family: 'Orbitron', sans-serif !important;
  color: var(--cyan) !important;
  letter-spacing: 0.08em;
  text-shadow: 0 0 18px rgba(0,229,255,0.35);
}
.stCaption, [data-testid="stCaptionContainer"] {
  color: var(--text-dim) !important;
  font-family: 'JetBrains Mono', monospace !important;
  letter-spacing: 0.06em;
}

/* ===== Metrics as HUD panels ===== */
[data-testid="stMetric"] {
  background: linear-gradient(145deg, rgba(15,21,32,0.95), rgba(10,14,23,0.98));
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.85rem 1rem !important;
  box-shadow: inset 0 0 30px rgba(0,229,255,0.04), var(--glow);
  position: relative;
  overflow: hidden;
}
[data-testid="stMetric"]::before {
  content: "";
  position: absolute; top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, transparent, var(--cyan), transparent);
}
[data-testid="stMetricLabel"] {
  font-family: 'JetBrains Mono', monospace !important;
  color: var(--text-dim) !important;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  font-size: 0.7rem !important;
}
[data-testid="stMetricValue"] {
  font-family: 'Orbitron', sans-serif !important;
  color: var(--cyan) !important;
  font-weight: 700 !important;
  text-shadow: 0 0 12px rgba(0,229,255,0.5);
}
[data-testid="stMetricDelta"] {
  font-family: 'JetBrains Mono', monospace !important;
}

/* ===== Buttons ===== */
.stButton > button {
  background: linear-gradient(180deg, rgba(0,229,255,0.12), rgba(0,229,255,0.04)) !important;
  color: var(--cyan) !important;
  border: 1px solid var(--border-hot) !important;
  border-radius: 4px !important;
  font-family: 'Orbitron', sans-serif !important;
  font-weight: 600 !important;
  letter-spacing: 0.14em !important;
  text-transform: uppercase !important;
  font-size: 0.75rem !important;
  padding: 0.55rem 1.2rem !important;
  transition: all 0.2s ease !important;
  box-shadow: 0 0 12px rgba(0,229,255,0.15) !important;
}
.stButton > button:hover {
  background: linear-gradient(180deg, rgba(0,229,255,0.28), rgba(0,229,255,0.1)) !important;
  box-shadow: 0 0 24px rgba(0,229,255,0.4) !important;
  border-color: var(--cyan) !important;
  transform: translateY(-1px);
}
.stButton > button:active {
  transform: translateY(0);
}

/* ===== Inputs ===== */
.stTextInput input, .stTextArea textarea, .stSelectbox > div > div,
[data-baseweb="select"] > div, .stNumberInput input {
  background: var(--bg-2) !important;
  color: var(--text) !important;
  border: 1px solid var(--border) !important;
  border-radius: 4px !important;
  font-family: 'JetBrains Mono', monospace !important;
}
.stTextInput input:focus, .stTextArea textarea:focus {
  border-color: var(--cyan) !important;
  box-shadow: 0 0 0 1px var(--cyan), 0 0 16px rgba(0,229,255,0.2) !important;
}

/* ===== Tabs as console segments ===== */
.stTabs [data-baseweb="tab-list"] {
  gap: 4px;
  background: var(--bg-1);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 4px;
}
.stTabs [data-baseweb="tab"] {
  font-family: 'Orbitron', sans-serif !important;
  font-size: 0.7rem !important;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--text-dim) !important;
  background: transparent !important;
  border-radius: 4px !important;
  padding: 0.55rem 0.9rem !important;
}
.stTabs [aria-selected="true"] {
  background: linear-gradient(180deg, rgba(0,229,255,0.2), rgba(0,229,255,0.06)) !important;
  color: var(--cyan) !important;
  box-shadow: inset 0 0 12px rgba(0,229,255,0.15);
}
.stTabs [data-baseweb="tab-highlight"],
.stTabs [data-baseweb="tab-border"] {
  display: none !important;
}

/* ===== Code / pre ===== */
code, pre, .stCode {
  font-family: 'JetBrains Mono', monospace !important;
  background: var(--bg-1) !important;
  border: 1px solid var(--border) !important;
  border-radius: 4px !important;
  color: var(--green) !important;
}

/* ===== Alerts ===== */
.stAlert {
  border-radius: 6px !important;
  border-left-width: 3px !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 0.85rem !important;
}
[data-testid="stSuccess"] {
  background: rgba(105,240,174,0.08) !important;
  border-color: var(--green) !important;
}
[data-testid="stWarning"] {
  background: rgba(255,215,64,0.08) !important;
  border-color: var(--amber) !important;
}
[data-testid="stError"] {
  background: rgba(255,82,82,0.08) !important;
  border-color: var(--red) !important;
}
[data-testid="stInfo"] {
  background: rgba(0,229,255,0.06) !important;
  border-color: var(--cyan) !important;
}

/* ===== Expander / divider ===== */
.streamlit-expanderHeader {
  font-family: 'Orbitron', sans-serif !important;
  color: var(--cyan-dim) !important;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  font-size: 0.8rem !important;
}
hr { border-color: var(--border) !important; opacity: 0.6; }

/* ===== Progress / slider ===== */
.stProgress > div > div > div {
  background: linear-gradient(90deg, var(--cyan-dim), var(--cyan)) !important;
  box-shadow: 0 0 10px rgba(0,229,255,0.5);
}
[data-testid="stSlider"] [data-baseweb="slider"] div[role="slider"] {
  background: var(--cyan) !important;
  box-shadow: 0 0 8px var(--cyan);
}

/* ===== Dataframe ===== */
[data-testid="stDataFrame"] {
  border: 1px solid var(--border);
  border-radius: 6px;
  overflow: hidden;
}

/* ===== Plotly containers ===== */
[data-testid="stPlotlyChart"] {
  border: 1px solid var(--border);
  border-radius: 8px;
  background: rgba(10,14,23,0.6);
  padding: 4px;
  box-shadow: inset 0 0 40px rgba(0,229,255,0.03);
}

/* ===== Custom header HUD ===== */
.mcl-header {
  display: flex; align-items: stretch; gap: 0;
  margin-bottom: 1.4rem;
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
  background: linear-gradient(135deg, rgba(10,14,23,0.98), rgba(15,21,32,0.95));
  box-shadow: 0 0 40px rgba(0,229,255,0.08), inset 0 1px 0 rgba(0,229,255,0.12);
}
.mcl-header-accent {
  width: 5px;
  background: linear-gradient(180deg, var(--cyan), var(--violet), var(--green));
  box-shadow: 0 0 20px var(--cyan);
}
.mcl-header-body {
  flex: 1; padding: 1.1rem 1.5rem 1rem;
  position: relative;
}
.mcl-header-body::after {
  content: "CLASSIFIED // ANALYTICS NODE";
  position: absolute; top: 10px; right: 18px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.65rem; letter-spacing: 0.18em;
  color: var(--text-dim); opacity: 0.7;
}
.mcl-title {
  font-family: 'Orbitron', sans-serif;
  font-weight: 900;
  font-size: 1.55rem;
  letter-spacing: 0.16em;
  color: var(--cyan);
  text-shadow: 0 0 24px rgba(0,229,255,0.55);
  margin: 0 0 0.25rem 0;
  line-height: 1.2;
}
.mcl-sub {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.72rem;
  letter-spacing: 0.12em;
  color: var(--text-dim);
  text-transform: uppercase;
}
.mcl-status-row {
  display: flex; gap: 1.2rem; margin-top: 0.75rem; flex-wrap: wrap;
}
.mcl-chip {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.68rem;
  letter-spacing: 0.08em;
  padding: 0.28rem 0.65rem;
  border-radius: 3px;
  border: 1px solid var(--border);
  color: var(--text-dim);
  background: rgba(0,0,0,0.35);
}
.mcl-chip.on {
  color: var(--green);
  border-color: rgba(105,240,174,0.45);
  box-shadow: 0 0 12px rgba(105,240,174,0.2);
}
.mcl-chip.warn {
  color: var(--amber);
  border-color: rgba(255,215,64,0.4);
}
.mcl-chip.live::before {
  content: "● ";
  animation: pulse 1.4s ease-in-out infinite;
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.35; }
}

/* armed banner */
.mcl-armed {
  font-family: 'Orbitron', sans-serif;
  letter-spacing: 0.2em;
  text-align: center;
  padding: 0.5rem;
  margin: 0.5rem 0;
  border: 1px solid rgba(105,240,174,0.5);
  background: rgba(105,240,174,0.08);
  color: var(--green);
  border-radius: 4px;
  text-shadow: 0 0 10px rgba(105,240,174,0.5);
  animation: pulse 2s ease-in-out infinite;
}

/* scrollbar */
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: var(--bg-1); }
::-webkit-scrollbar-thumb {
  background: rgba(0,229,255,0.25);
  border-radius: 4px;
}
::-webkit-scrollbar-thumb:hover { background: rgba(0,229,255,0.45); }

/* Workflow progress */
.mcl-workflow {
  display: flex; align-items: stretch; gap: 0.35rem; flex-wrap: wrap;
  margin: 0.6rem 0 1.2rem 0; padding: 0.6rem 0.75rem;
  border: 1px solid var(--border); border-radius: 8px;
  background: rgba(10,14,23,0.85);
}
.mcl-wf-step {
  display: flex; flex-direction: column; gap: 0.15rem;
  padding: 0.45rem 0.7rem; border-radius: 6px;
  border: 1px solid transparent; min-width: 7rem;
  font-family: 'JetBrains Mono', monospace;
}
.mcl-wf-step .n { color: var(--text-dim); font-size: 0.65rem; letter-spacing: 0.12em; }
.mcl-wf-step .c { color: var(--text-dim); font-family: Orbitron, sans-serif; font-size: 0.78rem; letter-spacing: 0.1em; }
.mcl-wf-step .d { color: var(--text-dim); font-size: 0.62rem; opacity: 0.85; }
.mcl-wf-step.done { border-color: rgba(105,240,174,0.45); background: rgba(105,240,174,0.08); }
.mcl-wf-step.done .c { color: var(--green); }
.mcl-wf-step.active { border-color: rgba(0,229,255,0.55); background: rgba(0,229,255,0.1); box-shadow: 0 0 16px rgba(0,229,255,0.15); }
.mcl-wf-step.active .c { color: var(--cyan); }
.mcl-wf-arrow { display: flex; align-items: center; color: var(--text-dim); font-size: 1.2rem; opacity: 0.5; }
.mcl-flow {
  display: flex; flex-wrap: wrap; gap: 0.4rem; align-items: center; margin: 0.5rem 0 1rem;
}
.mcl-flow .node {
  font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; letter-spacing: 0.06em;
  padding: 0.45rem 0.7rem; border-radius: 4px;
  border: 1px solid var(--border); color: var(--cyan);
  background: rgba(0,229,255,0.06);
}
.mcl-flow .sep { color: var(--text-dim); opacity: 0.5; }

</style>
""", unsafe_allow_html=True)



    st.markdown("""
<canvas id="mcl-particles"></canvas>
<script>
(function(){
  function boot(){
    var canvas = document.getElementById('mcl-particles');
    if (!canvas) {
      canvas = document.createElement('canvas');
      canvas.id = 'mcl-particles';
      document.body.appendChild(canvas);
    }
    if (canvas.dataset.booted === '1') return;
    canvas.dataset.booted = '1';
    var ctx = canvas.getContext('2d');
    var w, h, particles, raf;
    var N = 80;
    var LINK = 130;
    var COLOR = '0, 229, 255';

    function resize(){
      w = canvas.width = window.innerWidth;
      h = canvas.height = window.innerHeight;
    }
    function spawn(){
      particles = [];
      for (var i = 0; i < N; i++) {
        particles.push({
          x: Math.random() * w,
          y: Math.random() * h,
          vx: (Math.random() - 0.5) * 0.4,
          vy: (Math.random() - 0.5) * 0.4,
          r: Math.random() * 1.8 + 0.4
        });
      }
    }
    function step(){
      ctx.clearRect(0, 0, w, h);
      for (var i = 0; i < particles.length; i++) {
        var p = particles[i];
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > w) p.vx *= -1;
        if (p.y < 0 || p.y > h) p.vy *= -1;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(' + COLOR + ', 0.75)';
        ctx.fill();
        for (var j = i + 1; j < particles.length; j++) {
          var q = particles[j];
          var dx = p.x - q.x, dy = p.y - q.y;
          var d = Math.sqrt(dx * dx + dy * dy);
          if (d < LINK) {
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(q.x, q.y);
            ctx.strokeStyle = 'rgba(' + COLOR + ', ' + (0.2 * (1 - d / LINK)) + ')';
            ctx.lineWidth = 0.7;
            ctx.stroke();
          }
        }
      }
      raf = requestAnimationFrame(step);
    }
    resize();
    spawn();
    step();
    window.addEventListener('resize', resize);
  }
  // Streamlit re-runs: delay slightly so DOM is ready
  setTimeout(boot, 80);
  setTimeout(boot, 400);
})();
</script>
""", unsafe_allow_html=True)


def render_console_header(armed: bool = False, ml_ready: bool = False) -> None:
    status_armed = '<span class="mcl-chip on live">SYSTEM ARMED</span>' if armed else '<span class="mcl-chip warn">AWAITING KEY</span>'
    status_ml = '<span class="mcl-chip on">ML ONLINE</span>' if ml_ready else '<span class="mcl-chip">ML STANDBY</span>'
    st.markdown(f"""
<div class="mcl-header">
  <div class="mcl-header-accent"></div>
  <div class="mcl-header-body">
    <div class="mcl-title">MASTER CRYPTO LAB</div>
    <div class="mcl-sub">v8.0 &nbsp;//&nbsp; 18 cipher modes &nbsp;//&nbsp; NIST SP 800-22 &nbsp;//&nbsp; 19-feature ML pipeline</div>
    <div class="mcl-status-row">
      {status_armed}
      {status_ml}
      <span class="mcl-chip">NODE: ANALYTIC</span>
      <span class="mcl-chip">CHANNEL: SECURE</span>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)


def main():
    st.set_page_config(
        page_title="MASTER CRYPTO LAB // v8.0",
        layout="wide",
        page_icon="⬡",
        initial_sidebar_state="expanded",
    )
    inject_console_theme()
    splash_screen()
    init_session_state()
    init_tour_state()

    # ---- ML Model initialization ----
    if st.session_state.rf_model is None:
        model = CipherMLClassifier.load(MODEL_FILE)
        if model is None:
            with st.spinner("Initializing ML core on synthetic benchmark..."):
                model = CipherMLClassifier()
                result = model.train(do_hpo=False, do_learning_curve=False)
                model.save(MODEL_FILE)
                st.sidebar.caption(
                    f"ML  acc={result['test_accuracy']:.3f}  "
                    f"cv={result['cv_mean_accuracy']:.3f}  "
                    f"{result['n_classes']}cls/{result['n_features']}feat"
                )
        st.session_state.rf_model = model

    armed = st.session_state.get("key") is not None
    ml_ready = st.session_state.rf_model is not None and getattr(st.session_state.rf_model, "is_trained", False)
    render_console_header(armed=armed, ml_ready=ml_ready)

    # --- WORKFLOW (P0) ---
    wf = workflow_status(dict(st.session_state))
    st.markdown(workflow_html(wf), unsafe_allow_html=True)

    # --- SIDEBAR ---
    with st.sidebar:
        st.header("KEY OPS")
        st.caption("CIPHER · KDF · ARMING")

        with st.expander("Demo presets", expanded=False):
            preset_name = st.selectbox("Load scenario", ["—"] + list(DEMO_PRESETS.keys()), key="demo_preset")
            if preset_name != "—" and st.button("APPLY PRESET", key="btn_preset"):
                pr = DEMO_PRESETS[preset_name]
                st.session_state.cipher_mode = pr["cipher"]
                st.session_state["_preset_plaintext"] = pr["plaintext"]
                st.session_state["_preset_note"] = pr["note"]
                st.success(f"Preset ready: {preset_name}")
                st.caption(pr["note"])

        st.markdown("##### Mission tour")
        if st.session_state.get("tour_active"):
            st.caption(f"Active · step {st.session_state.get('tour_step', 0)}/5")
            if st.button("ABORT MISSION", key="sidebar_abort_tour"):
                skip_tour()
                st.rerun()
        else:
            if st.button("START MISSION TOUR", key="sidebar_start_tour", type="primary"):
                start_tour()
                st.rerun()
            st.caption("5 steps · strong AEAD vs weak classical · evidence pack")

        cipher_modes = get_available_ciphers()
        default_mode = st.session_state.get("cipher_mode", cipher_modes[0])
        if default_mode not in cipher_modes:
            default_mode = cipher_modes[0]
        cipher_mode = st.selectbox("Cipher Mode", cipher_modes,
                                   index=cipher_modes.index(default_mode))
        info = get_cipher_info(cipher_mode)
        if info and info.get("description"):
            st.caption(info["description"])
        if info and info["educational"]:
            st.warning("⚠️ **Educational cipher** — do NOT use for real security.", icon="⚠️")
        st.session_state.cipher_mode = cipher_mode

        key_methods = get_available_key_methods()
        key_gen_method = st.selectbox("Key Generation Method", key_methods)
        method_info = get_key_method_info(key_gen_method)

        if method_info:
            st.markdown(f"**{key_gen_method}**")
            if key_gen_method == "Random Key":
                if st.button("Generate Random Key"):
                    key, msg = derive_key(key_gen_method, cipher_mode)
                    st.session_state.key = key
                    st.session_state.last_key_method = key_gen_method
                    st.success(msg)
            elif key_gen_method == "ECDH X25519 Key Agreement":
                if "ecdh_priv" not in st.session_state:
                    priv, pub = AdvancedCryptoEngine.generate_ecdh_keypair()
                    st.session_state.ecdh_priv = priv
                    st.session_state.ecdh_pub = pub
                pub_bytes = st.session_state.ecdh_pub.public_bytes_raw()
                st.code(base64.b64encode(pub_bytes).decode(), language="text")
                st.caption("Your public key (share with peer)")
                peer_pub_input = st.text_input("Peer Public Key (Base64)")
                if st.button("Compute Shared Key"):
                    if peer_pub_input.strip():
                        try:
                            peer_raw = base64.b64decode(peer_pub_input.strip())
                            peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_raw)
                            shared_secret = st.session_state.ecdh_priv.exchange(peer_pub)
                            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
                            from cryptography.hazmat.primitives import hashes
                            hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None,
                                        info=b'ECDH Key Agreement')
                            raw = hkdf.derive(shared_secret)
                            from crypto_lab import CIPHER_REGISTRY
                            info_c = CIPHER_REGISTRY[cipher_mode]
                            ks = info_c["key_size"]
                            if cipher_mode == "Fernet (AES-128-CBC + HMAC)":
                                st.session_state.key = base64.urlsafe_b64encode(raw[:ks])
                            elif ks:
                                st.session_state.key = raw[:ks]
                            else:
                                st.session_state.key = raw[:32]
                            st.success("ECDH shared key derived!")
                        except Exception as ex:
                            st.error(f"ECDH error: {str(ex)}")
                    else:
                        st.error("Paste the peer's public key first.")
            elif method_info.get("needs_passphrase", False):
                pp = st.text_input("Passphrase", type="password")
                if pp:
                    strength = estimate_password_strength(pp)
                    st.progress(strength["score"] / 5.0)
                    st.caption(
                        f"Password strength: **{strength['label']}** "
                        f"({strength['entropy_bits']} bits entropy)"
                    )
                if st.button("Derive Key"):
                    if pp:
                        try:
                            with st.spinner("Deriving key..."):
                                key, msg = derive_key(key_gen_method, cipher_mode, passphrase=pp)
                            st.session_state.key = key
                            st.session_state.last_key_method = key_gen_method
                            st.info(msg)
                        except ImportError as e:
                            st.error(str(e))
                        except Exception as e:
                            st.error(f"Key derivation failed: {str(e)}")
                    else:
                        st.error("Enter a passphrase.")
            elif method_info.get("needs_additional_input", False):
                extra_label = "Input Material" if key_gen_method != "ECDH X25519 Key Agreement" else "Peer Public Key (Base64)"
                extra = st.text_input(extra_label, type="password" if key_gen_method != "ECDH X25519 Key Agreement" else "default")
                if st.button("Derive Key"):
                    if extra.strip():
                        try:
                            with st.spinner("Deriving key..."):
                                key, msg = derive_key(key_gen_method, cipher_mode, additional_input=extra)
                            st.session_state.key = key
                            st.session_state.last_key_method = key_gen_method
                            st.info(msg)
                        except ImportError as e:
                            st.error(str(e))
                        except Exception as e:
                            st.error(f"Key derivation failed: {str(e)}")
                    else:
                        st.error("Enter the required input.")

        if check_key_active():
            st.markdown('<div class="mcl-armed">◆ SYSTEM ARMED — KEY ACTIVE ◆</div>', unsafe_allow_html=True)
            st.checkbox("Show key in sidebar", key="key_visible")
            if st.session_state.key_visible:
                st.code(_key_to_display(st.session_state.key, cipher_mode), language="text")
            if HAS_QRCODE:
                if st.button("Show QR Code"):
                    st.session_state.qr_visible = not st.session_state.qr_visible
                if st.session_state.qr_visible:
                    key_str = _key_to_display(st.session_state.key, cipher_mode)
                    qr_img = qrcode.make(key_str)
                    buf = io.BytesIO()
                    qr_img.save(buf, format="PNG")
                    st.image(buf.getvalue(), caption="QR Code Key (Out-of-Band)", width=170)
            else:
                st.caption("QR Code disabled — install with: pip install qrcode")
            st.divider()
            weights = make_weights_sliders()
            st.divider()
            st.subheader("SECURE MAIL")
            st.caption("KEY CHANNEL ≠ CIPHERTEXT CHANNEL")
            env_config = get_smtp_config_from_env()
            with st.expander("SMTP Configuration", expanded=not bool(env_config)):
                if env_config:
                    st.info("SMTP loaded from environment variables.")
                    smtp_server = env_config.get("server", "smtp.gmail.com")
                    smtp_port = int(env_config.get("port", 587))
                    sender_email = env_config.get("email", "")
                    sender_password = env_config.get("password", "")
                    st.caption(f"Server: {smtp_server}:{smtp_port} · From: {sender_email}")
                else:
                    st.warning("Set env vars or enter SMTP credentials below.")
                    smtp_server = st.text_input("SMTP Server", value="smtp.gmail.com", key="smtp_server")
                    smtp_port = int(st.number_input("SMTP Port", value=587, key="smtp_port"))
                    sender_email = st.text_input("Sender Email", key="smtp_from")
                    sender_password = st.text_input("App Password", type="password", key="smtp_pass")

            # --- Channel 1: KEY ---
            with st.expander("① Send KEY via Email", expanded=False):
                st.caption("Out-of-band key delivery. Use a different recipient than ciphertext.")
                key_receiver = st.text_input("Key recipient email", key="email_key_to")
                if st.button("SEND KEY", key="btn_send_key"):
                    if not check_key_active():
                        st.error("No active key to send.")
                    elif not key_receiver.strip():
                        st.error("Enter key recipient email.")
                    elif not sender_email or not sender_password:
                        st.error("Configure SMTP credentials first.")
                    else:
                        key_str = _key_to_display(st.session_state.key, cipher_mode)
                        with st.spinner("Sending key channel..."):
                            ok, msg = send_key_email(
                                smtp_server, smtp_port, sender_email, sender_password,
                                key_receiver.strip(), key_str, cipher_mode=cipher_mode,
                            )
                        st.success(msg) if ok else st.error(msg)

            # --- Channel 2: CIPHERTEXT ---
            with st.expander("② Send CIPHERTEXT via Email", expanded=False):
                st.caption("Ciphertext only — key must travel on a separate channel.")
                ct_receiver = st.text_input("Ciphertext recipient email", key="email_ct_to")
                if st.button("SEND CIPHERTEXT", key="btn_send_ct"):
                    if not st.session_state.last_enc:
                        st.error("Encrypt a message in Tab 01 first.")
                    elif not ct_receiver.strip():
                        st.error("Enter ciphertext recipient email.")
                    elif not sender_email or not sender_password:
                        st.error("Configure SMTP credentials first.")
                    else:
                        enc = st.session_state.last_enc
                        fmt = get_cipher_info(cipher_mode)
                        if fmt and fmt.get("ciphertext_format") == "base64":
                            try:
                                ct_str = enc.decode() if isinstance(enc, (bytes, bytearray)) else str(enc)
                            except Exception:
                                ct_str = base64.b64encode(enc).decode()
                        else:
                            ct_str = enc.hex() if isinstance(enc, (bytes, bytearray)) else str(enc)
                        with st.spinner("Sending ciphertext channel..."):
                            ok, msg = send_ciphertext_email(
                                smtp_server, smtp_port, sender_email, sender_password,
                                ct_receiver.strip(), ct_str,
                                license_code=st.session_state.get("license_code", ""),
                                cipher_mode=cipher_mode,
                            )
                        st.success(msg) if ok else st.error(msg)
        else:
            weights = {"h": 0.25, "sac": 0.25, "uni": 0.15, "mono": 0.10, "runs": 0.10, "diff": 0.15}
            st.warning("Enable a Master Key to begin.")

    # --- MISSION TOUR PANEL (after sidebar so key/weights available) ---
    render_mission_tour(weights)

    # --- MAIN PANEL TABS ---
    t1, t2, t3, t4, t5, t6, t7 = st.tabs([
        "01  ENCRYPT", "02  DECRYPT", "03  STEGO",
        "04  NIST LAB", "05  ML CORE", "06  HISTORY",
        "07  ENTERPRISE",
    ])

    # ======== TAB 1: ENCRYPTION ========
    with t1:
        st.subheader("Encrypt Plaintext")
        _default_pt = st.session_state.pop("_preset_plaintext", None) or "Artificial intelligence is an extension of formal logic."
        u_input = st.text_area(
            "Plaintext Input",
            value=_default_pt,
            height=120,
        )
        if st.session_state.get("_preset_note"):
            st.caption(st.session_state["_preset_note"])

        if st.button("Encrypt"):
            if not check_key_active():
                st.error("Generate or derive a key in the sidebar first.")
            elif not u_input.strip():
                st.error("Enter some plaintext to encrypt.")
            else:
                mode = st.session_state.cipher_mode
                key = st.session_state.key
                enc_fn = _make_encrypt_fn(mode, key)
                with st.spinner(f"Encrypting with {mode} and computing full 19-feature suite..."):
                    try:
                        enc_bytes = enc_fn(u_input.encode())
                    except Exception as e:
                        st.error(f"Encryption failed: {str(e)}")
                        st.stop()
                st.session_state.last_enc = enc_bytes
                st.session_state.u_text = u_input

                b64 = base64.b64encode(enc_bytes).decode().replace("=", "").upper()
                clean_b64 = re.sub(r"[^A-Z0-9]", "X", b64)
                license_code = "-".join([clean_b64[i:i + 5] for i in range(0, min(40, len(clean_b64)), 5)])
                st.session_state.license_code = license_code

                with st.spinner("Running full feature extraction (19 features)..."):
                    metrics = CryptoScientificLibrary.run_full_suite(enc_bytes, u_input, key, encrypt_fn=enc_fn)
                st.session_state.metrics_cache = metrics

                col1, col2 = st.columns(2)
                with col1:
                    st.subheader("License Code")
                    st.code(license_code, language="text")
                with col2:
                    fmt = get_cipher_info(mode)
                    label = "Ciphertext (Base64)" if not fmt or fmt["ciphertext_format"] == "base64" else "Ciphertext (Hex)"
                    display_ct = enc_bytes.decode() if not fmt or fmt["ciphertext_format"] == "base64" else enc_bytes.hex()
                    st.subheader(label)
                    st.code(display_ct, language="text")

                sec_idx = CryptoScientificLibrary.compute_security_index(metrics, weights)
                entry = {
                    "timestamp": time.time(),
                    "CipherMode": mode,
                    "Entropy": metrics["h"], "SAC": metrics["sac"],
                    "Uniformity": metrics["uni"],
                    "Monobit": metrics["mono"], "Monobit_PValue": metrics["mono_p"],
                    "BlockFreq_PValue": metrics["block_p"],
                    "Runs": metrics["runs"], "Runs_PValue": metrics["runs_p"],
                    "FFT_PValue": metrics["fft_p"], "Diffusion": metrics["diff"],
                    "CumulativeSums_P": metrics.get("cum_p", 0.5),
                    "Serial_P1": metrics.get("ser_p1", 0.5),
                    "Serial_P2": metrics.get("ser_p2", 0.5),
                    "ApproxEntropy_P": metrics.get("ap_p", 0.5),
                    "ChiSquare": metrics.get("chi2", 0),
                    "Autocorrelation": metrics.get("autocorr", 0),
                    "CompressionRatio": metrics.get("compress", 1.0),
                    "SecurityIndex": sec_idx,
                }
                st.session_state.last_entry = entry
                append_to_history(entry)
                st.success("Encryption and full 19-feature analysis complete.")

                # Narrative: cipher flow + AEAD anatomy (P1)
                stages = cipher_flow_stages(mode)
                flow_html = '<div class="mcl-flow">' + ''.join(
                    (f'<span class="node">{s["label"]}</span>' + ('<span class="sep">→</span>' if i < len(stages)-1 else ''))
                    for i, s in enumerate(stages)
                ) + '</div>'
                st.markdown("##### Cipher pipeline")
                st.markdown(flow_html, unsafe_allow_html=True)
                anatomy = aead_anatomy(mode, enc_bytes)
                with st.expander("Ciphertext anatomy (IV / payload / tag)", expanded=False):
                    st.caption(anatomy.get("note") or "")
                    for part in anatomy.get("parts", []):
                        st.code(f"{part['name']} @ {part['offset']} (+{part['length']} B): {part['hex']}", language="text")
                    if anatomy.get("security_note"):
                        st.warning(anatomy["security_note"])


                # --- Padding visualization (educational) ---
                st.markdown("---")
                st.markdown("### 🧱 PKCS#7 Padding Visualization")
                block_sz = 8 if "TripleDES" in mode or "Blowfish" in mode else 16
                pad_info = visualize_pkcs7_padding(u_input.encode(), block_size=block_sz)
                pc1, pc2, pc3 = st.columns(3)
                pc1.metric("Original length", pad_info["original_len"])
                pc2.metric("Padded length", pad_info["padded_len"])
                pc3.metric("Pad bytes", pad_info["pad_len"])
                st.caption(pad_info["description"])
                with st.expander("Show padded blocks (hex)"):
                    for i, blk in enumerate(pad_info["blocks"]):
                        st.code(f"Block {i}: {blk}", language="text")

                # --- IV / Nonce inspection ---
                st.markdown("### 🔑 IV / Nonce Structure")
                iv_info = inspect_iv_nonce(mode, enc_bytes)
                st.caption(iv_info["note"])
                if iv_info.get("security_note"):
                    st.warning(iv_info["security_note"])
                ic1, ic2, ic3 = st.columns(3)
                ic1.metric("IV/Nonce length", iv_info["iv_nonce_len"])
                ic2.metric("Payload length", iv_info["payload_len"])
                ic3.metric("MAC length", iv_info["mac_len"])
                if iv_info.get("iv_nonce_hex"):
                    st.code(f"IV/Nonce: {iv_info['iv_nonce_hex']}", language="text")
                if iv_info.get("mac_hex"):
                    st.code(f"MAC/Tag:  {iv_info['mac_hex']}", language="text")
                if iv_info.get("warning"):
                    st.error(iv_info["warning"])


        # Persistent IV/Nonce + padding panel when ciphertext available
        if st.session_state.last_enc and st.session_state.get("u_text"):
            with st.expander("🧱 Padding & IV/Nonce inspector (last encryption)", expanded=False):
                mode_p = st.session_state.cipher_mode
                pt = st.session_state.u_text.encode()
                block_sz = 8 if "TripleDES" in mode_p or "Blowfish" in mode_p else 16
                pad_info = visualize_pkcs7_padding(pt, block_size=block_sz)
                st.markdown(f"**{pad_info['description']}**")
                st.code(" | ".join(pad_info["blocks"][:8]) + (" ..." if len(pad_info["blocks"]) > 8 else ""), language="text")
                iv_info = inspect_iv_nonce(mode_p, st.session_state.last_enc)
                st.markdown(f"**Structure:** {iv_info['note']}")
                if iv_info.get("iv_nonce_hex"):
                    st.code(f"IV/Nonce ({iv_info['iv_nonce_len']} B): {iv_info['iv_nonce_hex']}")
                if iv_info.get("mac_hex"):
                    st.code(f"MAC ({iv_info['mac_len']} B): {iv_info['mac_hex']}")
                if iv_info.get("security_note"):
                    st.warning(iv_info["security_note"])

    # ======== TAB 2: DECRYPTION ========
    with t2:
        st.subheader("🔓 Decrypt Message / Ciphertext")
        cipher_mode_dec = st.selectbox("Cipher Mode", get_available_ciphers(), key="decrypt_cipher_mode")
        info_dec = get_cipher_info(cipher_mode_dec)
        if info_dec and info_dec["educational"]:
            st.warning("⚠️ Educational cipher selected.", icon="⚠️")
        fmt = info_dec["ciphertext_format"] if info_dec else "hex"
        key_label = "Master Key (Fernet format)" if fmt == "base64" else "Master Key (hex)"
        ct_label = "Paste Ciphertext (Base64)" if fmt == "base64" else "Paste Ciphertext (hex)"
        input_key = st.text_input(key_label, type="password")
        input_ct = st.text_area(ct_label)
        if st.button("Decrypt"):
            if not input_key.strip() or not input_ct.strip():
                st.error("Both key and ciphertext are required.")
            else:
                try:
                    key = info_dec["str_to_key"](input_key.strip())
                    ct = base64.b64decode(input_ct.strip()) if fmt == "base64" else bytes.fromhex(input_ct.strip())
                    decrypted = decrypt_with(cipher_mode_dec, key, ct)
                    st.success("Decryption successful!")
                    st.info(decrypted.decode("utf-8"))
                except Exception as exc:
                    err_msg = str(exc)
                    if "hex" in err_msg or "binascii" in type(exc).__module__:
                        st.error("Invalid format. Check the key or ciphertext encoding.")
                    else:
                        st.error(f"Decryption failed: {err_msg}")

    # ======== TAB 3: STEGANOGRAPHY ========
    with t3:
        st.subheader("🖼️ LSB Steganography")
        steg_mode = st.radio("Operation", ["Hide Ciphertext", "Extract & Decrypt"])
        if steg_mode == "Hide Ciphertext":
            uploaded_img = st.file_uploader("Upload Image (PNG/BMP)", type=["png", "bmp"])
            if uploaded_img and st.session_state.last_enc:
                cover_image = Image.open(uploaded_img)
                if st.button("Inject Data into Image"):
                    try:
                        steg_image = LSBSteganography.encode_message(cover_image, st.session_state.last_enc)
                        out_buf = io.BytesIO()
                        steg_image.save(out_buf, format="PNG")
                        st.download_button("Download Steganographic Image", out_buf.getvalue(), file_name="stego_carrier.png")
                        st.success("Data hidden successfully.")
                    except ValueError as e:
                        st.error(f"Image too small: {str(e)}")
            elif uploaded_img:
                st.warning("Encrypt a message first (Tab 1) to have ciphertext to hide.")
        elif steg_mode == "Extract & Decrypt":
            steg_file = st.file_uploader("Upload Stego Image (.png)", type=["png"])
            steg_key_input = st.text_input("Master Key", type="password")
            steg_cipher_mode = st.selectbox("Cipher Mode", get_available_ciphers(), key="steg_cipher_mode")
            info_steg = get_cipher_info(steg_cipher_mode)
            if steg_file and steg_key_input and st.button("Extract"):
                try:
                    img = Image.open(steg_file)
                    extracted = LSBSteganography.decode_message(img)
                    key = info_steg["str_to_key"](steg_key_input.strip())
                    decrypted = decrypt_with(steg_cipher_mode, key, extracted)
                    st.success("Extraction and decryption successful!")
                    st.info(decrypted.decode("utf-8"))
                except ValueError as e:
                    st.error(str(e))
                except Exception:
                    st.error("Extraction/decryption failed. Check image, key, and cipher mode.")

    # ======== TAB 4: NIST SUITE & SCIENTIFIC GRAPHICS ========
    with t4:
        st.subheader("📊 NIST SP 800-22 Suite & Scientific Visualizations")
        if st.session_state.last_enc and st.session_state.metrics_cache:
            m = st.session_state.metrics_cache
            ct = st.session_state.last_enc
            sec_idx = CryptoScientificLibrary.compute_security_index(m, weights)
            hn, sacn, unin, monon, runsn, diffn = CryptoScientificLibrary.normalize_metrics(
                m["h"], m["sac"], m["uni"], m["mono"], m["runs"], m["diff"]
            )
            mode = st.session_state.cipher_mode
            key = st.session_state.key
            enc_fn = _make_encrypt_fn(mode, key) if key is not None else None

            c0a, c0b = st.columns([1, 1])
            with c0a:
                st.metric("Weighted Security Index", f"{sec_idx:.3f}")
                fig_radar = go.Figure()
                theta = ["Entropy", "SAC", "Uniformity", "Monobit", "Runs", "Diffusion"]
                fig_radar.add_trace(go.Scatterpolar(
                    r=[1] * 6, theta=theta, fill="none",
                    line=dict(color="gray", dash="dash"), name="Ideal",
                ))
                fig_radar.add_trace(go.Scatterpolar(
                    r=[hn, sacn, unin, monon, runsn, diffn], theta=theta,
                    fill="toself", line=dict(color="#00E5FF"), name="Current",
                ))
                fig_radar.update_layout(
                    polar=dict(radialaxis=dict(visible=True, range=[0, 1])),
                    title="Normalized Metrics Radar", height=320, margin=dict(t=40, b=20),
                    template="plotly_dark",
                )
                st.plotly_chart(fig_radar, use_container_width=True)
            with c0b:
                st.markdown("##### NIST SP 800-22 Test Battery (α = 0.01)")
                nist_tests = [
                    ("1. Monobit Frequency", m["mono_p"]),
                    ("2. Block Frequency", m["block_p"]),
                    ("3. Runs Test", m["runs_p"]),
                    ("4. Discrete Fourier (FFT)", m["fft_p"]),
                    ("5. Cumulative Sums", m.get("cum_p", 0.5)),
                    ("6. Serial p1", m.get("ser_p1", 0.5)),
                    ("7. Approximate Entropy", m.get("ap_p", 0.5)),
                ]
                for name, pval in nist_tests:
                    passed = float(pval) >= 0.01
                    st.metric(
                        f"{name} p-value", f"{float(pval):.4f}",
                        delta="PASS" if passed else "FAIL",
                        delta_color="normal" if passed else "inverse",
                    )

            st.markdown("---")
            st.markdown("### 🔬 p-value Radar (NIST + Serial)")
            pv = CryptoScientificLibrary.pvalue_radar_data(m)
            labels = list(pv.keys())
            values = list(pv.values())
            fig_pv = go.Figure()
            fig_pv.add_trace(go.Scatterpolar(
                r=[0.01] * len(labels), theta=labels,
                fill="none", line=dict(color="#FF5252", dash="dash"), name="α = 0.01",
            ))
            fig_pv.add_trace(go.Scatterpolar(
                r=values + [values[0]], theta=labels + [labels[0]],
                fill="toself", line=dict(color="#69F0AE"), name="p-values",
            ))
            fig_pv.update_layout(
                polar=dict(radialaxis=dict(visible=True, range=[0, 1])),
                title="NIST p-values (closer to 0.5 = more random)",
                height=380, template="plotly_dark",
            )
            st.plotly_chart(fig_pv, use_container_width=True)

            st.markdown("---")
            st.markdown("### 🟦 Ciphertext Bitstream Heatmap")
            heat_w = st.slider("Heatmap width (bytes/row)", 16, 64, 32, 8, key="heat_w")
            mat = CryptoScientificLibrary.bitstream_matrix(ct, width=heat_w)
            fig_heat = px.imshow(
                mat, color_continuous_scale="viridis",
                labels=dict(x="Byte column", y="Row", color="Value"),
                title=f"Ciphertext byte map ({len(ct)} bytes)",
                aspect="auto",
            )
            fig_heat.update_layout(height=min(500, 40 + mat.shape[0] * 8), template="plotly_dark")
            st.plotly_chart(fig_heat, use_container_width=True)

            st.markdown("---")
            st.markdown("### ⚡ Avalanche Effect (1-bit flip)")
            if enc_fn and st.session_state.u_text:
                aval = CryptoScientificLibrary.avalanche_detail(
                    st.session_state.u_text, key, encrypt_fn=enc_fn, trials=10,
                )
                ca1, ca2 = st.columns(2)
                with ca1:
                    st.metric("Mean Hamming distance %", f"{aval['mean']:.2f}%")
                    st.metric("Std", f"{aval['std']:.2f}%")
                    if aval["trials"]:
                        fig_av = go.Figure()
                        fig_av.add_trace(go.Scatter(
                            y=aval["trials"], mode="lines+markers",
                            name="Trial %", line=dict(color="#FFD740"),
                        ))
                        fig_av.add_hline(y=50, line_dash="dash", line_color="#69F0AE",
                                         annotation_text="Ideal 50%")
                        fig_av.update_layout(
                            title="Avalanche trials (SAC)",
                            yaxis_title="% bits flipped", xaxis_title="Trial",
                            height=300, template="plotly_dark",
                        )
                        st.plotly_chart(fig_av, use_container_width=True)
                with ca2:
                    bd = aval.get("bitdiff")
                    if bd is not None and len(bd) > 0:
                        step = max(1, len(bd) // 512)
                        bd_ds = bd[::step]
                        fig_bd = go.Figure()
                        fig_bd.add_trace(go.Bar(
                            y=bd_ds, marker_color=np.where(bd_ds > 0.5, "#FF5252", "#00E5FF"),
                            name="Bit flipped",
                        ))
                        fig_bd.update_layout(
                            title="Bit difference map (last trial, downsampled)",
                            yaxis_title="Flipped (1/0)", height=300, template="plotly_dark",
                            showlegend=False,
                        )
                        st.plotly_chart(fig_bd, use_container_width=True)
            else:
                st.info("Avalanche requires active key and plaintext from Tab 1.")

            st.markdown("---")
            col_re, col_fft = st.columns(2)
            with col_re:
                st.markdown("### 📈 Rolling Shannon Entropy")
                win = st.select_slider("Window size", options=[32, 64, 128, 256], value=64, key="ent_win")
                pos, ent = CryptoScientificLibrary.rolling_entropy(ct, window=win)
                fig_re = go.Figure()
                fig_re.add_trace(go.Scatter(
                    x=pos, y=ent, mode="lines", name="Entropy",
                    line=dict(color="#E040FB", width=2),
                ))
                fig_re.add_hline(y=8.0, line_dash="dash", line_color="#69F0AE",
                                 annotation_text="Max 8 bit")
                fig_re.update_layout(
                    xaxis_title="Byte position", yaxis_title="Entropy (bits)",
                    height=320, template="plotly_dark", yaxis=dict(range=[0, 8.5]),
                )
                st.plotly_chart(fig_re, use_container_width=True)
            with col_fft:
                st.markdown("### 🌊 FFT Power Spectrum")
                spec = CryptoScientificLibrary.fft_spectrum_data(ct)
                if len(spec["freqs"]) > 0:
                    step = max(1, len(spec["freqs"]) // 1000)
                    fig_fft = go.Figure()
                    fig_fft.add_trace(go.Scatter(
                        x=spec["freqs"][::step], y=spec["magnitude"][::step],
                        mode="lines", name="|FFT|", line=dict(color="#40C4FF", width=1),
                    ))
                    fig_fft.add_hline(
                        y=spec["threshold"], line_dash="dash", line_color="#FF5252",
                        annotation_text="NIST threshold",
                    )
                    fig_fft.update_layout(
                        xaxis_title="Frequency bin", yaxis_title="Magnitude",
                        height=320, template="plotly_dark",
                    )
                    st.plotly_chart(fig_fft, use_container_width=True)
                else:
                    st.info("Ciphertext too short for FFT.")

            st.markdown("---")
            col_run, col_byte = st.columns(2)
            with col_run:
                st.markdown("### 🏃 Runs Length Histogram")
                rh = CryptoScientificLibrary.runs_length_histogram(ct)
                fig_runs = go.Figure()
                if len(rh["lengths_0"]) > 0:
                    fig_runs.add_trace(go.Bar(
                        x=rh["lengths_0"], y=rh["counts_0"],
                        name="Runs of 0", marker_color="#90A4AE",
                    ))
                if len(rh["lengths_1"]) > 0:
                    fig_runs.add_trace(go.Bar(
                        x=rh["lengths_1"], y=rh["counts_1"],
                        name="Runs of 1", marker_color="#FFAB40",
                    ))
                fig_runs.update_layout(
                    barmode="group", xaxis_title="Run length", yaxis_title="Count",
                    height=320, template="plotly_dark",
                )
                st.plotly_chart(fig_runs, use_container_width=True)
            with col_byte:
                st.markdown("### 📊 Byte Value Distribution")
                bx, by = CryptoScientificLibrary.byte_histogram(ct)
                fig_byte = go.Figure()
                fig_byte.add_trace(go.Bar(
                    x=bx, y=by, marker_color="#7C4DFF", name="Count",
                ))
                expected = len(ct) / 256.0 if ct else 0
                fig_byte.add_hline(y=expected, line_dash="dash", line_color="#69F0AE",
                                   annotation_text="Uniform expected")
                fig_byte.update_layout(
                    xaxis_title="Byte value (0-255)", yaxis_title="Count",
                    height=320, template="plotly_dark",
                )
                st.plotly_chart(fig_byte, use_container_width=True)

            st.markdown("---")
            st.markdown("### 📐 Extended Features")
            e1, e2, e3, e4 = st.columns(4)
            e1.metric("Chi-Square", f"{m.get('chi2', 0):.1f}")
            e2.metric("Autocorrelation (lag-1)", f"{m.get('autocorr', 0):.4f}")
            e3.metric("Compression ratio", f"{m.get('compress', 1):.3f}")
            e4.metric("SAC avalanche %", f"{m.get('sac', 0):.1f}")
        else:
            st.info("Encrypt a message first (Tab 1) to see NIST analysis and scientific plots.")

    # ======== TAB 5: ML PIPELINE (19 features) ========
    with t5:
        st.subheader("🤖 ML Pipeline — 19 Features, 10 Cipher Classes")
        st.caption(
            "Features: Shannon entropy, SAC avalanche, byte uniformity, monobit, block freq, runs, "
            "FFT, diffusion, cumulative sums, serial test (×2), approx entropy, chi-square, "
            "autocorrelation, compression ratio. Classifier: Random Forest (100 trees) + MLP (64,32) "
            "+ Isolation Forest anomaly detection."
        )

        model = st.session_state.rf_model
        if model and model.is_trained:
            if st.session_state.metrics_cache:
                m = st.session_state.metrics_cache
                feat_vec = np.array([[
                    m["h"], m["sac"], m["uni"],
                    m["mono"], m["mono_p"],
                    m.get("block_p", 0.5) * 10, m.get("block_p", 0.5),
                    m["runs"], m["runs_p"],
                    m.get("fft_d", 0), m["fft_p"],
                    m["diff"],
                    m.get("cum_p", 0.5),
                    m.get("ser_p1", 0.5), m.get("ser_p2", 0.5),
                    m.get("ap_p", 0.5),
                    m.get("chi2", 0),
                    m.get("autocorr", 0),
                    m.get("compress", 1.0),
                ]])

                col_ml1, col_ml2 = st.columns(2)

                with col_ml1:
                    pred, conf = model.predict(feat_vec)
                    probas = model.predict_all_probas(feat_vec)
                    st.markdown("### 🏷️ Cipher Identification (10-class)")
                    st.metric("Predicted Cipher", model.get_class_label(pred),
                              delta=f"confidence {conf:.1%}")
                    top3 = np.argsort(probas)[-3:][::-1]
                    for rank, idx in enumerate(top3):
                        st.markdown(f"**#{rank + 1}** {model.get_class_label(idx)}: `{probas[idx]:.1%}`")

                    short_labels = [model.get_class_label(i).split("(")[0].strip() for i in range(len(probas))]
                    fig_proba = px.bar(
                        x=short_labels, y=probas,
                        labels={"x": "Cipher Mode", "y": "Probability"},
                        title="Class Probability Distribution",
                        color=probas, color_continuous_scale="Viridis",
                    )
                    fig_proba.update_layout(xaxis_tickangle=45, height=320, template="plotly_dark")
                    st.plotly_chart(fig_proba, use_container_width=True)

                    is_anom, anom_score = model.detect_anomaly(feat_vec)
                    st.markdown("### 🧠 Why this prediction? (feature contribution)")
                    try:
                        expl = explanation_from_features(
                            feat_vec,
                            getattr(model, "_permutation_importance", None) or getattr(model, "_feature_importances", None),
                            top_n=8,
                        )
                        if expl:
                            fig_ex = px.bar(
                                x=[e["score"] for e in expl],
                                y=[e["feature"] for e in expl],
                                orientation="h",
                                title="Top contributing features (importance × |value|)",
                                color=[e["score"] for e in expl],
                                color_continuous_scale="Viridis",
                            )
                            fig_ex.update_layout(height=320, template="plotly_dark")
                            st.plotly_chart(fig_ex, use_container_width=True)
                    except Exception:
                        st.caption("Explanation unavailable.")

                    st.markdown("### 🚨 Anomaly Detection (Isolation Forest)")
                    st.metric(
                        "Anomaly Score", f"{anom_score:.3f}",
                        delta="ANOMALY ⚠️" if is_anom else "Normal ✅",
                        delta_color="inverse" if is_anom else "normal",
                    )

                with col_ml2:
                    st.markdown("### 📊 Feature Importance (Permutation)")
                    fi_df = model.get_feature_importance_df()
                    fig_fi = px.bar(
                        fi_df.head(12), x="importance", y="feature",
                        orientation="h", title="Top Features (permutation)",
                        color="importance", color_continuous_scale="Tealgrn",
                    )
                    fig_fi.update_layout(height=400, template="plotly_dark")
                    st.plotly_chart(fig_fi, use_container_width=True)

                    st.markdown("### 📈 Model Performance")
                    c1, c2, c3 = st.columns(3)
                    with c1:
                        if model.test_accuracy is not None:
                            st.metric("RF Test Accuracy", f"{model.test_accuracy:.3f}")
                    with c2:
                        if model.cv_score is not None:
                            st.metric("CV Score", f"{model.cv_score:.3f}")
                    with c3:
                        st.metric("Features", len(FEATURE_NAMES))

                st.markdown("---")
                st.markdown("### 📉 Anomaly Score Context")
                try:
                    X_syn, _ = model._generate_benchmark_data(n_per_class=15)
                    syn_scores = model.anomaly_detector.score_samples(X_syn)
                    fig_anom = go.Figure()
                    fig_anom.add_trace(go.Histogram(
                        x=syn_scores, nbinsx=30, name="Benchmark scores",
                        marker_color="#5C6BC0", opacity=0.75,
                    ))
                    fig_anom.add_vline(
                        x=anom_score, line_dash="dash", line_color="#FF5252",
                        annotation_text="Current sample",
                    )
                    fig_anom.update_layout(
                        xaxis_title="Isolation Forest score (higher = more normal)",
                        yaxis_title="Count", height=300, template="plotly_dark",
                    )
                    st.plotly_chart(fig_anom, use_container_width=True)
                except Exception:
                    st.caption("Anomaly distribution unavailable.")

                st.markdown("---")
                col_dr1, col_dr2 = st.columns(2)
                with col_dr1:
                    st.markdown("### 🔍 PCA 2D Projection")
                    if st.session_state.history and len(st.session_state.history) >= 2:
                        df_h = pd.DataFrame(st.session_state.history)
                        feat_cols_hist = ["Entropy", "SAC", "Uniformity", "Monobit", "Runs", "Diffusion"]
                        pca_result = CipherMLClassifier.compute_pca(df_h, feat_cols_hist)
                        if pca_result is not None:
                            hover = "CipherMode" if "CipherMode" in pca_result.columns else None
                            fig_pca = px.scatter(
                                pca_result, x="PC1", y="PC2", color="SecurityIndex",
                                hover_data=[hover] if hover else None,
                                title="PCA 2D (history)",
                                color_continuous_scale="Viridis",
                            )
                            fig_pca.update_layout(height=360, template="plotly_dark")
                            st.plotly_chart(fig_pca, use_container_width=True)
                        else:
                            st.info("Not enough data for PCA.")
                    else:
                        st.info("Need ≥2 history entries.")

                with col_dr2:
                    st.markdown("### 🔮 t-SNE 2D Projection")
                    if st.session_state.history and len(st.session_state.history) >= 3:
                        df_h = pd.DataFrame(st.session_state.history)
                        feat_cols_hist = ["Entropy", "SAC", "Uniformity", "Monobit", "Runs", "Diffusion"]
                        tsne_result = CipherMLClassifier.compute_tsne(df_h, feat_cols_hist)
                        if tsne_result is not None:
                            hover = "CipherMode" if "CipherMode" in tsne_result.columns else None
                            fig_tsne = px.scatter(
                                tsne_result, x="tSNE1", y="tSNE2", color="SecurityIndex",
                                hover_data=[hover] if hover else None,
                                title="t-SNE 2D (history)",
                                color_continuous_scale="Plasma",
                            )
                            fig_tsne.update_layout(height=360, template="plotly_dark")
                            st.plotly_chart(fig_tsne, use_container_width=True)
                        else:
                            st.info("Not enough data (need ≥3).")
                    else:
                        st.info("Need ≥3 history entries.")

                st.markdown("---")
                col_cm, col_lc = st.columns(2)
                with col_cm:
                    st.markdown("### 🧮 Confusion Matrix (Benchmark)")
                    cm_df = model.get_confusion_matrix()
                    if cm_df is not None:
                        short_cm = [c.split("(")[0].strip()[:18] for c in cm_df.columns]
                        fig_cm = px.imshow(
                            cm_df.values,
                            x=short_cm, y=short_cm,
                            text_auto=True, aspect="auto",
                            title="RF Confusion Matrix (10 classes)",
                            color_continuous_scale="Blues",
                        )
                        fig_cm.update_layout(height=480, xaxis_tickangle=45, template="plotly_dark")
                        st.plotly_chart(fig_cm, use_container_width=True)
                    else:
                        st.info("Confusion matrix not available.")

                with col_lc:
                    st.markdown("### 📉 Learning Curve (Benchmark)")
                    lc_data = model._learning_curve
                    if lc_data is None:
                        if st.button("⚡ Compute Learning Curve"):
                            with st.spinner("Computing learning curve (15 fits over 5 train sizes)..."):
                                model.compute_learning_curve()
                            st.rerun()
                    else:
                        fig_lc = go.Figure()
                        fig_lc.add_trace(go.Scatter(
                            x=lc_data["train_sizes"], y=lc_data["train_mean"],
                            mode="lines+markers", name="Train",
                            line=dict(color="#40C4FF"),
                        ))
                        fig_lc.add_trace(go.Scatter(
                            x=lc_data["train_sizes"], y=lc_data["test_mean"],
                            mode="lines+markers", name="Test",
                            line=dict(color="#69F0AE"),
                        ))
                        fig_lc.update_layout(
                            title="Learning Curve",
                            xaxis_title="Training samples", yaxis_title="Accuracy",
                            height=400, template="plotly_dark",
                        )
                        st.plotly_chart(fig_lc, use_container_width=True)
                        if st.button("🔄 Recompute"):
                            model._learning_curve = None
                            st.rerun()

                st.markdown("---")
                st.markdown("### 🔄 Active Learning — Retrain with Real Data")
                if st.button("Retrain Model with History Data"):
                    n_hist = len(st.session_state.history) if st.session_state.history else 0
                    if n_hist >= 5:
                        with st.spinner(f"Retraining on {n_hist} history samples..."):
                            result = model.retrain_with_history(st.session_state.history)
                            if result:
                                model.save(MODEL_FILE)
                                st.success(f"Retrained! Accuracy: {result['test_accuracy']:.3f}")
                            else:
                                st.warning("Not enough valid training samples.")
                    else:
                        st.warning(f"Need ≥5 history samples (have {n_hist}).")

                st.markdown("---")
                st.markdown("### 📅 Feature Importance Over Time")
                drift_df = model.get_drift_df()
                if not drift_df.empty:
                    top_feats = model.get_top_features(5)
                    top_names = [f[0] for f in top_feats]
                    drift_top = drift_df[drift_df["feature"].isin(top_names)]
                    fig_drift = px.line(
                        drift_top, x="timestamp", y="importance",
                        color="feature", title="Top-5 Feature Importance Drift",
                        markers=True,
                    )
                    fig_drift.update_layout(height=350, template="plotly_dark")
                    st.plotly_chart(fig_drift, use_container_width=True)
                else:
                    st.info("No drift data yet (only 1 training run so far).")

            else:
                st.info("Encrypt a message first to see ML predictions.")
        else:
            st.error("ML model not available. Restart the application.")

    # ======== TAB 6: HISTORY & DATASET ========
    with t6:
        st.subheader("📈 Historical Dataset")
        if st.session_state.history:
            df_hist = pd.DataFrame(st.session_state.history)
            st.dataframe(df_hist, use_container_width=True)
            col_dl, col_clear = st.columns([1, 1])
            with col_dl:
                csv_data = df_hist.to_csv(index=False).encode('utf-8')
                st.download_button("📥 Download Dataset CSV", csv_data,
                                   file_name="crypto_lab_dataset.csv", mime="text/csv")
            with col_clear:
                if st.button("🗑️ Clear History"):
                    st.session_state.history = []
                    save_history_to_csv([])
                    st.rerun()
        else:
            st.info("No encryption history yet. Encrypt a message in Tab 1.")



    # ======== TAB 7: ENTERPRISE (P0-P3) ========
    with t7:
        st.subheader("Enterprise lab — compliance, benchmark, export, PQC")
        mode = st.session_state.get("cipher_mode", "AES-256-GCM")
        metrics = st.session_state.get("metrics_cache") or {}
        has_key = check_key_active()
        key_method = st.session_state.get("last_key_method", "")

        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("### Compliance checklist")
            items = compliance_checklist(
                mode, metrics=metrics if metrics else None,
                has_key=has_key, key_method=key_method,
            )
            score = compliance_score(items)
            st.metric("Compliance score", f"{score:.0%}")
            for it in items:
                icon = "✅" if it["pass"] else "❌"
                st.markdown(f"{icon} **{it['code']}** {it['title']} — `{it['detail']}`")

        with col_b:
            st.markdown("### Evidence export (P0)")
            sec_idx = None
            if metrics:
                try:
                    sec_idx = CryptoScientificLibrary.compute_security_index(metrics, weights)
                except Exception:
                    sec_idx = None
            notes = st.text_input("Case notes (optional)", key="case_notes")
            if st.button("Build evidence pack (ZIP)"):
                pack = build_evidence_pack(
                    mode, metrics, items,
                    ciphertext=st.session_state.get("last_enc"),
                    license_code=st.session_state.get("license_code", ""),
                    security_index=sec_idx,
                    benchmark_rows=st.session_state.get("benchmark_rows"),
                    case_notes=notes,
                )
                st.session_state.last_export_ts = time.time()
                st.download_button(
                    "Download evidence pack",
                    data=pack,
                    file_name="mcl_evidence_pack.zip",
                    mime="application/zip",
                    key="dl_pack",
                )
            pdf = try_build_pdf_report(mode, metrics, items, security_index=sec_idx)
            if pdf:
                st.download_button("Download PDF report", data=pdf, file_name="mcl_report.pdf", mime="application/pdf", key="dl_pdf")
            else:
                txt = build_text_report(mode, metrics, items, st.session_state.get("license_code", ""), sec_idx)
                st.download_button("Download text report", data=txt.encode(), file_name="mcl_report.txt", mime="text/plain", key="dl_txt")
                st.caption("Install reportlab for PDF: pip install reportlab")

            st.markdown("### Case file (collaborative)")
            if st.button("Export case file (JSON)"):
                enc = st.session_state.get("last_enc")
                cf = export_case_file(
                    mode,
                    st.session_state.get("u_text", ""),
                    metrics,
                    license_code=st.session_state.get("license_code", ""),
                    notes=notes,
                    ciphertext_hex=enc.hex() if isinstance(enc, (bytes, bytearray)) else "",
                )
                st.download_button("Download case file", data=cf, file_name="mcl_case.json", mime="application/json", key="dl_case")
            up = st.file_uploader("Import case file", type=["json"], key="case_up")
            if up is not None:
                try:
                    obj = import_case_file(up.read())
                    st.json(obj)
                    st.success(f"Case loaded — fingerprint {obj.get('fingerprint')}")
                except Exception as e:
                    st.error(str(e))

        st.markdown("---")
        st.markdown("### Multi-cipher benchmark (P2)")
        bench_pt = st.text_input("Benchmark plaintext", value="Master Crypto Lab enterprise benchmark payload.", key="bench_pt")
        if st.button("Run benchmark"):
            with st.spinner("Benchmarking cipher suite..."):
                rows = run_cipher_benchmark(bench_pt)
                st.session_state.benchmark_rows = rows
        rows = st.session_state.get("benchmark_rows")
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
            ok_rows = [r for r in rows if r.get("entropy") is not None]
            if ok_rows:
                fig_b = px.bar(
                    x=[r["mode"].split("(")[0].strip()[:18] for r in ok_rows],
                    y=[r["entropy"] for r in ok_rows],
                    labels={"x": "Mode", "y": "Entropy"},
                    title="Ciphertext Shannon entropy by mode",
                    color=[r["entropy"] for r in ok_rows],
                    color_continuous_scale="Tealgrn",
                )
                fig_b.update_layout(template="plotly_dark", height=340, xaxis_tickangle=35)
                st.plotly_chart(fig_b, use_container_width=True)

        st.markdown("---")
        st.markdown("### ML model card & local API (P2/P3)")
        model = st.session_state.get("rf_model")
        if model:
            card = ml_model_card(model)
            st.json(card)
        st.caption("Local API (optional): `pip install fastapi uvicorn` then `uvicorn crypto_lab.api_server:app --port 8765`")

        st.markdown("---")
        st.markdown("### Post-quantum lab (educational P3)")
        st.warning("Toy hash-KEM below is **not** secure — for narrative/UI only. Prefer NIST ML-KEM in production stacks.")
        st.dataframe(PQC_ALGORITHMS, use_container_width=True)
        st.markdown("**Migration checklist**")
        for row in migration_checklist():
            st.markdown(f"- `{row['priority']}` {row['item']}")
        if st.button("Run toy KEM demo"):
            pk, sk = toy_hash_kem_keypair()
            ct, ss1 = toy_hash_kem_encaps(pk)
            ss2 = toy_hash_kem_decaps(sk, ct)
            st.code(f"pk={pk.hex()[:32]}…\nct={ct.hex()[:32]}…\nss_match={ss1==ss2}\nss={ss1.hex()[:32]}…")


if __name__ == "__main__":
    main()
