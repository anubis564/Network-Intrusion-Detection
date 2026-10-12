import html

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from core import engine as eng
from core import knowledge as kb
from core import state, ui
from core.config import COLORS, SEVERITY_COLORS

engine, res = state.results()
demo = eng.load_demo()
ui.page_header("Live Monitor", "Replays the captured traffic in time order through the models, as if it were arriving now")
state.mode_banner(engine)

live = st.session_state.setdefault("live", {"pos": 0, "running": False, "seen": [], "history": []})

c1, c2, c3, c4, c5 = st.columns([1, 1, 1, 2, 2], vertical_alignment="bottom")
if c1.button("Pause" if live["running"] else "Start", icon=":material/pause:" if live["running"] else ":material/play_arrow:",
             type="primary", width="stretch"):
    live["running"] = not live["running"]
    st.rerun()
if c2.button("Reset", icon=":material/restart_alt:", width="stretch"):
    st.session_state["live"] = {"pos": 0, "running": False, "seen": [], "history": []}
    st.rerun()
if c3.button("Jump to attack", icon=":material/fast_forward:", width="stretch",
             help="Skip ahead to the next part of the capture that contains an attack"):
    nxt = res.index[(res.index > live["pos"] + 50) & res["true_attack"]]
    if len(nxt):
        live["pos"] = max(int(nxt[0]) - 20, 0)
speed = c4.select_slider("Flows per second", [5, 10, 25, 50, 100, 250], value=50)
c5.progress(live["pos"] / len(res), text=f"Capture position: {live['pos']:,} / {len(res):,} flows")


@st.fragment(run_every=1.0 if live["running"] else None)
def stream():
    s = st.session_state["live"]
    if s["running"] and s["pos"] < len(res):
        batch_raw = demo.slice(s["pos"], speed)
        scored = eng.score(engine, batch_raw)  # really runs the models on the new flows
        meta = res.iloc[s["pos"]: s["pos"] + len(scored)][["Timestamp", "Src IP", "Dst IP", "Dst Port"]].reset_index(drop=True)
        batch = pd.concat([meta, scored], axis=1)
        batch["idx"] = range(s["pos"], s["pos"] + len(batch))
        s["pos"] += len(batch)
        s["history"].append({"t": batch["Timestamp"].iloc[-1], "flows": len(batch), "alerts": int(batch["is_attack"].sum())})
        s["history"] = s["history"][-120:]
        new_alerts = batch[batch["is_attack"]]
        s["seen"] = (new_alerts.to_dict("records") + s["seen"])[:200]
        crit = new_alerts[new_alerts["severity"] == "Critical"]
        if len(crit):
            st.toast(f"Critical: {crit.iloc[0]['pred_label']} from {crit.iloc[0]['Src IP']}", icon="🚨")
    elif s["pos"] >= len(res):
        s["running"] = False

    seen = pd.DataFrame(s["seen"])
    total_alerts = len(seen)
    hist = pd.DataFrame(s["history"])
    ui.kpi_row([
        ui.kpi_card("Flows processed", ui.fmt_int(s["pos"]), COLORS["blue"], hist["flows"].values if len(hist) else None),
        ui.kpi_card("Alerts raised", ui.fmt_int(total_alerts), COLORS["red"], hist["alerts"].values if len(hist) else None),
        ui.kpi_card("Critical", ui.fmt_int((seen["severity"] == "Critical").sum() if total_alerts else 0), COLORS["orange"]),
        ui.kpi_card("Capture clock", pd.to_datetime(res.iloc[min(s["pos"], len(res) - 1)]["Timestamp"]).strftime("%a %H:%M"),
                    COLORS["purple"]),
    ])
    st.write("")
    left, right = st.columns([3, 2])
    with left, st.container(border=True):
        st.markdown("**Flows and alerts per tick**")
        fig = go.Figure()
        if len(hist):
            fig.add_trace(go.Scatter(y=hist["flows"] - hist["alerts"], name="Normal", stackgroup="a",
                                     line=dict(color=COLORS["blue"])))
            fig.add_trace(go.Scatter(y=hist["alerts"], name="Alerts", stackgroup="a", line=dict(color=COLORS["red"])))
        fig.update_xaxes(title="tick (1 s)")
        st.plotly_chart(ui.plotly_layout(fig, 330), width="stretch", key="live-chart")
    with right, st.container(border=True, height=402):
        st.markdown("**Alert feed**")
        if not total_alerts:
            st.caption("No alerts yet. Press Start, or Jump to attack.")
        for a in s["seen"][:12]:
            c = SEVERITY_COLORS.get(a["severity"], "#64748b")
            st.markdown(
                f'<div class="feed-item" style="border-color:{c}"><b>{html.escape(a["pred_label"])}</b> '
                f'{ui.severity_badge(a["severity"])}<br><span style="color:#8b9bb4">'
                f'{pd.to_datetime(a["Timestamp"]):%H:%M:%S} · {a["Src IP"]} → {a["Dst IP"]}:{a["Dst Port"]} · '
                f'p={a["attack_prob"]:.2f}</span></div>', unsafe_allow_html=True)


stream()

if live["seen"]:
    with st.container(border=True):
        last = live["seen"][0]
        st.markdown(f"Latest alert: **{last['pred_label']}** from {last['Src IP']} ({kb.family_of(last['pred_label'])})")
        if st.button("Investigate latest alert", icon=":material/troubleshoot:"):
            state.select_alert(last["idx"])
            st.switch_page("views/investigate.py")
