import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP_DIR = ROOT / "app"
MODELS_DIR = Path(os.environ.get("NIDS_MODELS_DIR", ROOT / "models"))
TRAFFIC_DATA = APP_DIR / "data" / "test_flows.parquet"  # held-out test flows, see scripts/build_test_replay.py
KNOWLEDGE_DIR = APP_DIR / "knowledge"


COLORS = {
    "bg": "#0b1120", "card": "#111a2e", "border": "#1e2a44", "text": "#e2e8f0", "muted": "#8b9bb4",
    "blue": "#3b82f6", "red": "#ef4444", "orange": "#f59e0b", "green": "#22c55e", "purple": "#a855f7",
}
SEVERITY_COLORS = {"Critical": "#ef4444", "High": "#f97316", "Medium": "#f59e0b", "Low": "#22c55e"}

IDENTIFIER_COLUMNS = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Timestamp"]


SECRETS_FILE = ROOT / ".streamlit" / "secrets.toml"


def _repo_secrets() -> dict:
    # Streamlit only reads .streamlit/secrets.toml from the folder the app was started in, so the repo's own
    # file is read directly as well: the key is then found however `streamlit run` was launched
    try:
        import tomllib
        with open(SECRETS_FILE, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return {}


def secret(name: str, default=None):
    """Read a setting from Streamlit secrets, the environment, then the repo's .streamlit/secrets.toml."""
    try:
        import streamlit as st
        if name in st.secrets:
            return st.secrets[name]
    except Exception:
        pass
    value = os.environ.get(name) or _repo_secrets().get(name)
    return value if value else default
