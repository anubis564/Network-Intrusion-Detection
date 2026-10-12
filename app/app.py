"""NIDS - Network Intrusion Detection System (Streamlit app).

Run locally:  streamlit run app/app.py
"""
import faulthandler
import sys
from pathlib import Path

import streamlit as st

# If a native library (polars, XGBoost, scikit-learn) ever crashes the process, print the Python stack of every
# thread to the server log instead of dying silently with "Connection error" in the browser.
if not faulthandler.is_enabled():
    faulthandler.enable(all_threads=True)

APP_DIR = Path(__file__).resolve().parent
for p in (APP_DIR, APP_DIR.parent):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from core import assistant, ui  # noqa: E402
from core.engine import load_engine  # noqa: E402

st.set_page_config(page_title="NIDS | Network Intrusion Detection", page_icon=str(APP_DIR / "assets" / "icon.svg"),
                   layout="wide")
st.logo(str(APP_DIR / "assets" / "logo.svg"), size="large", icon_image=str(APP_DIR / "assets" / "icon.svg"))
ui.inject_css()

pages = {
    "Monitor": [
        st.Page("views/dashboard.py", title="Dashboard", icon=":material/dashboard:", default=True),
        st.Page("views/live.py", title="Live Monitor", icon=":material/monitor_heart:", url_path="live"),
    ],
    "Investigate": [
        st.Page("views/investigate.py", title="Alert Investigation", icon=":material/troubleshoot:", url_path="investigate"),
        st.Page("views/assistant.py", title="AI Assistant", icon=":material/smart_toy:", url_path="assistant"),
        st.Page("views/batch.py", title="Batch Scan", icon=":material/upload_file:", url_path="batch"),
    ],
    "Knowledge": [
        st.Page("views/library.py", title="Attack Library", icon=":material/menu_book:", url_path="library"),
        st.Page("views/insights.py", title="Model & Data", icon=":material/insights:", url_path="insights"),
    ],
}
nav = st.navigation(pages)

engine = load_engine()
with st.sidebar:
    ok = engine.mode == "model"
    llm = assistant.llm_available()
    st.markdown(
        f'<div style="font-size:.82rem;line-height:1.8;margin-top:.4rem">'
        f'<span class="dot" style="background:{"#22c55e" if ok else "#f59e0b"}"></span>'
        f'{"Detection models online" if ok else "Replay mode (models not loaded)"}<br>'
        f'<span class="dot" style="background:{"#22c55e" if llm else "#64748b"}"></span>'
        f'{"AI assistant: Gemini" if llm else "AI assistant: offline mode"}</div>',
        unsafe_allow_html=True,
    )
    st.caption("Dataset: improved CICIDS2017 (Engelen et al., 2021). Blocked / Logged actions are simulated.")

nav.run()
