"""Shared page state: scored test traffic and the currently selected alert."""
import pandas as pd
import polars as pl
import streamlit as st

from core import engine as eng


def results():
    engine = eng.load_engine()
    res = eng.score_traffic(engine, eng.engine_key(engine))
    return engine, res


def mode_banner(engine):
    if engine.mode != "model":
        st.warning(
            "**Replay mode:** the trained models could not be loaded, so the app replays the dataset's ground-truth "
            f"labels. Explanations and live scoring need the models.  \nReason: `{engine.error}`",
            icon=":material/warning:",
        )


def select_alert(idx: int):
    st.session_state["alert_idx"] = int(idx)


def selected_alert_idx(res: pd.DataFrame) -> int:
    idx = st.session_state.get("alert_idx")
    if idx is None or idx >= len(res):
        attacks = res.index[res["is_attack"]]
        idx = int(attacks[-1]) if len(attacks) else 0
        st.session_state["alert_idx"] = idx
    return idx


def raw_row(idx: int) -> pl.DataFrame:
    return eng.load_traffic().slice(idx, 1)


def alert_record(engine, res: pd.DataFrame, idx: int) -> dict:
    """Everything known about one flow: identifiers, prediction, top types and feature contributions."""
    cache = st.session_state.setdefault("_alert_cache", {})
    key = (eng.engine_key(engine), idx)
    if key in cache:
        return cache[key]
    rec = res.iloc[idx].to_dict()
    rec["idx"] = idx
    row = raw_row(idx)
    rec["top_types"] = eng.specialist_top(engine, row) if rec["is_attack"] else []
    expl, method = eng.explain(engine, row)
    rec["explanation_method"] = method
    if expl is not None:
        items = expl.head(12).to_dict("records")
        for it in items:
            it["benign_median"] = eng.benign_median(it["feature"])
            it["benign_pct"] = eng.percentile_in_benign(it["feature"], it["value"])
        rec["explanation"] = items
    else:
        rec["explanation"] = []
    cache[key] = rec
    return rec


def alert_label(res: pd.DataFrame, idx: int) -> str:
    r = res.iloc[idx]
    ts = pd.to_datetime(r["Timestamp"]).strftime("%a %H:%M:%S") if "Timestamp" in r else ""
    return f"#{idx} | {ts} | {r['pred_label']} | {r.get('Src IP', '?')} -> {r.get('Dst IP', '?')}:{r.get('Dst Port', '?')}"
