import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP_DIR = ROOT / "app"
MODELS_DIR = Path(os.environ.get("NIDS_MODELS_DIR", ROOT / "models"))
DEMO_DATA = APP_DIR / "data" / "demo_flows.parquet"
KNOWLEDGE_DIR = APP_DIR / "knowledge"

DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"

COLORS = {
    "bg": "#0b1120", "card": "#111a2e", "border": "#1e2a44", "text": "#e2e8f0", "muted": "#8b9bb4",
    "blue": "#3b82f6", "red": "#ef4444", "orange": "#f59e0b", "green": "#22c55e", "purple": "#a855f7",
}
SEVERITY_COLORS = {"Critical": "#ef4444", "High": "#f97316", "Medium": "#f59e0b", "Low": "#22c55e"}

IDENTIFIER_COLUMNS = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Timestamp"]


def secret(name: str, default=None):
    """Read a setting from Streamlit secrets, then from the environment."""
    try:
        import streamlit as st
        if name in st.secrets:
            return st.secrets[name]
    except Exception:
        pass
    return os.environ.get(name, default)
