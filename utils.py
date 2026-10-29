import os
import time
import base64
import pandas as pd
import streamlit as st
from typing import List, Dict, Optional

from .config import STATE_KEYS, DEFAULT_STATE, HISTORY_FILE, FERNET_KEY_PATTERN
from .nist_suite import CryptoScientificLibrary


def init_session_state():
    for key in STATE_KEYS:
        if key not in st.session_state:
            st.session_state[key] = DEFAULT_STATE.get(key, None)

    # Load history from CSV if available
    if st.session_state.history is None:
        st.session_state.history = load_history_from_csv()


def load_history_from_csv() -> List[Dict]:
    if os.path.exists(HISTORY_FILE):
        try:
            df = pd.read_csv(HISTORY_FILE)
            return df.to_dict(orient="records")
        except Exception:
            return []
    return []


def save_history_to_csv(history: List[Dict]):
    if not history:
        return
    try:
        df = pd.DataFrame(history)
        df.to_csv(HISTORY_FILE, index=False)
    except Exception:
        pass


def append_to_history(entry: Dict):
    st.session_state.history.append(entry)
    save_history_to_csv(st.session_state.history)


def validate_fernet_key_format(key_str: str) -> Optional[str]:
    import re
    if not key_str or not key_str.strip():
        return "Key cannot be empty."
    if not re.match(FERNET_KEY_PATTERN, key_str.strip()):
        return (
            "Invalid key format. A valid Fernet key is a Base64-URL-safe string "
            "containing two parts separated by a dot (e.g., 'xxxx.xxxx')."
        )
    return None


def validate_ciphertext_format(ct_str: str) -> Optional[str]:
    if not ct_str or not ct_str.strip():
        return "Ciphertext cannot be empty."
    try:
        base64.b64decode(ct_str.strip())
        return None
    except Exception:
        return "Invalid ciphertext format. Ciphertext must be valid Base64."


def check_key_active() -> bool:
    return st.session_state.key is not None


def require_key() -> bool:
    if not check_key_active():
        st.error("Initialize a Master Key in the sidebar first.")
        return False
    return True


def get_splash_html(splash_path: str = "splash.png") -> Optional[str]:
    try:
        with open(splash_path, "rb") as f:
            data = f.read()
        encoded = base64.b64encode(data).decode()

        return f"""
        <style>
        #splash-container {{
            position: fixed;
            top: 0; left: 0;
            width: 100vw; height: 100vh;
            background-color: black;
            display: flex; justify-content: center; align-items: center;
            z-index: 999999; opacity: 0;
            animation: fadeIn 1.2s forwards, fadeOut 1.2s 3.6s forwards;
            pointer-events: none;
        }}
        #splash-container img {{ width: 100%; height: 100%; object-fit: cover; }}
        @keyframes fadeIn {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
        @keyframes fadeOut {{ from {{ opacity: 1; }} to {{ opacity: 0; }} }}
        </style>
        <div id="splash-container"><img src="data:image/png;base64,{encoded}"></div>
        <script>
        setTimeout(function(){{
            var el = document.getElementById("splash-container");
            if (el) {{ el.parentNode.removeChild(el); }}
        }}, 3600);
        </script>
        """
    except FileNotFoundError:
        return None


def splash_screen():
    if st.session_state.get("splash_shown", False):
        return
    html = get_splash_html()
    if html:
        st.markdown(html, unsafe_allow_html=True)
    else:
        # Pure CSS cyber boot sequence (no image required)
        st.markdown("""
<style>
#mcl-boot {
  position: fixed; inset: 0; z-index: 999999;
  background: #05070b;
  display: flex; flex-direction: column;
  align-items: center; justify-content: center;
  animation: mclBootOut 0.6s ease 2.4s forwards;
  pointer-events: none;
  font-family: 'JetBrains Mono', monospace;
}
#mcl-boot .ring {
  width: 120px; height: 120px; border-radius: 50%;
  border: 2px solid transparent;
  border-top-color: #00e5ff;
  border-right-color: rgba(0,229,255,0.3);
  animation: spin 0.9s linear infinite;
  box-shadow: 0 0 40px rgba(0,229,255,0.35);
  margin-bottom: 1.5rem;
}
#mcl-boot .logo {
  font-family: Orbitron, sans-serif;
  font-weight: 900; letter-spacing: 0.28em;
  font-size: 1.4rem; color: #00e5ff;
  text-shadow: 0 0 30px rgba(0,229,255,0.7);
  margin-bottom: 0.5rem;
}
#mcl-boot .line {
  color: #8b9bb4; font-size: 0.7rem; letter-spacing: 0.15em;
  opacity: 0; animation: fadeLine 0.4s ease forwards;
}
#mcl-boot .line:nth-child(3) { animation-delay: 0.3s; }
#mcl-boot .line:nth-child(4) { animation-delay: 0.6s; }
#mcl-boot .line:nth-child(5) { animation-delay: 0.9s; }
@keyframes spin { to { transform: rotate(360deg); } }
@keyframes fadeLine { to { opacity: 1; } }
@keyframes mclBootOut {
  to { opacity: 0; visibility: hidden; }
}
</style>
<div id="mcl-boot">
  <div class="ring"></div>
  <div class="logo">MASTER CRYPTO LAB</div>
  <div class="line">// INITIALIZING CRYPTOGRAPHIC CORE</div>
  <div class="line">// LOADING NIST SP 800-22 SUITE</div>
  <div class="line">// ML CLASSIFIER ONLINE</div>
</div>
""", unsafe_allow_html=True)
    st.session_state.splash_shown = True


def make_weights_sliders() -> Dict[str, float]:
    st.subheader("METRIC WEIGHTS")
    w_entropy = st.slider("Entropy Weight", 0.0, 1.0, 0.25, 0.05)
    w_sac = st.slider("SAC Weight", 0.0, 1.0, 0.25, 0.05)
    w_uni = st.slider("Uniformity Weight", 0.0, 1.0, 0.15, 0.05)
    w_mono = st.slider("Monobit Weight", 0.0, 1.0, 0.10, 0.05)
    w_runs = st.slider("Runs Weight", 0.0, 1.0, 0.10, 0.05)
    w_diff = st.slider("Diffusion Weight", 0.0, 1.0, 0.15, 0.05)

    total = w_entropy + w_sac + w_uni + w_mono + w_runs + w_diff
    if total <= 0:
        st.warning("Total weight is zero. Using equal weights.")
        return {"h": 0.25, "sac": 0.25, "uni": 0.15, "mono": 0.10, "runs": 0.10, "diff": 0.15}

    return {"h": w_entropy, "sac": w_sac, "uni": w_uni, "mono": w_mono, "runs": w_runs, "diff": w_diff}
