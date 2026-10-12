import html

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from core import engine as eng
from core import knowledge as kb
from core import state, ui
from core.config import COLORS, SEVERITY_COLORS

TICK_SECONDS = 1.0
MAX_SCORED_PER_TICK = 6000   # caps the work per tick during floods (DDoS / DoS Hulk peaks)
QUIET_GAP = np.timedelta64(10, "m")

engine, res = state.results()
traffic = eng.load_traffic()
times = pd.to_datetime(res["Timestamp"]).to_numpy()
ui.page_header("Live Monitor",
               "Held-out test flows replayed on their real capture timeline and scored by the models as they arrive")
state.mode_banner(engine)


def fresh_state():
    return {"clock": times[0], "running": False, "seen": [], "history": [], "processed": 0, "skipped": 0,
            "alerts": 0, "critical": 0}


live = st.session_state.setdefault("live3", fresh_state())

c1, c2, c3, c4, c5 = st.columns([1, 1, 1.3, 2, 2], vertical_alignment="bottom")
if c1.button("Pause" if live["running"] else "Start", icon=":material/pause:" if live["running"] else ":material/play_arrow:",
             type="primary", width="stretch"):
    live["running"] = not live["running"]
    st.rerun()
if c2.button("Reset", icon=":material/restart_alt:", width="stretch"):
    st.session_state["live3"] = fresh_state()
    st.rerun()
if c3.button("Jump to next attack", icon=":material/fast_forward:", width="stretch",
             help="Move the capture clock to one minute before the next attack flow"):
    later = np.flatnonzero((times > live["clock"]) & res["true_attack"].to_numpy())
    if len(later):
        live["clock"] = times[later[0]] - np.timedelta64(60, "s")
speed = c4.select_slider("Replay speed (capture seconds per real second)", [1, 10, 30, 60, 300, 900], value=60,
                         format_func=lambda v: f"{v}x")
day_names = pd.to_datetime(times).day_name().unique().tolist()
jump_day = c5.selectbox("Go to day", ["-"] + day_names)
if jump_day != "-" and st.session_state.get("_last_day_jump") != jump_day:
    first = np.flatnonzero(pd.to_datetime(times).day_name() == jump_day)[0]
    live["clock"] = times[first]
st.session_state["_last_day_jump"] = jump_day


@st.fragment(run_every=TICK_SECONDS if live["running"] else None)
def stream():
    s = st.session_state["live3"]
    if s["running"]:
        start = np.searchsorted(times, s["clock"], side="left")
        if start >= len(times):
            s["running"] = False
        else:
            if times[start] - s["clock"] > QUIET_GAP:          # night or quiet period: skip ahead
                s["clock"] = times[start]
            end_clock = s["clock"] + np.timedelta64(int(speed * TICK_SECONDS), "s")
            end = np.searchsorted(times, end_clock, side="left")
            step = max(1, -(-(end - start) // MAX_SCORED_PER_TICK))  # flood: score every step-th flow this tick
            idx = np.arange(start, end, step)
            s["skipped"] += (end - start) - len(idx)
            if len(idx):
                window = traffic.slice(int(start), int(end - start)).gather_every(step)
                scored = eng.score(engine, window)              # the models really run on the new flows
                meta = res.iloc[idx][["Timestamp", "Src IP", "Dst IP", "Dst Port", "true_label"]].reset_index(drop=True)
                batch = pd.concat([meta, scored], axis=1)
                batch["idx"] = idx
                s["processed"] += len(batch)
                new_alerts = batch[batch["is_attack"]]
                s["alerts"] += len(new_alerts)
                s["critical"] += int((new_alerts["severity"] == "Critical").sum())
                s["seen"] = (new_alerts.to_dict("records")[::-1] + s["seen"])[:200]
                crit = new_alerts[new_alerts["severity"] == "Critical"]
                if len(crit):
                    st.toast(f"Critical: {crit.iloc[0]['pred_label']} from {crit.iloc[0]['Src IP']}", icon="🚨")
                fams = new_alerts["family"].value_counts().to_dict()
            else:
                fams = {}
            s["history"].append({"t": pd.Timestamp(end_clock), "flows": int(end - start),
                                 "alerts": int(len(new_alerts)) if len(idx) else 0, **fams})
            s["history"] = s["history"][-180:]
            s["clock"] = end_clock

    hist = pd.DataFrame(s["history"]).fillna(0)
    seen = pd.DataFrame(s["seen"])
    rate = hist["flows"].iloc[-1] / max(speed * TICK_SECONDS, 1) if len(hist) else 0
    ui.kpi_row([
        ui.kpi_card("Capture clock", pd.Timestamp(s["clock"]).strftime("%a %H:%M:%S"), COLORS["purple"],
                    delta=f"{speed}x", delta_note="replay speed"),
        ui.kpi_card("Flows processed", ui.fmt_int(s["processed"]), COLORS["blue"], hist["flows"].values if len(hist) else None,
                    delta=f"{rate:,.1f}/s", delta_note="capture rate"),
        ui.kpi_card("Alerts raised", ui.fmt_int(s["alerts"]), COLORS["red"], hist["alerts"].values if len(hist) else None),
        ui.kpi_card("Critical", ui.fmt_int(s["critical"]), COLORS["orange"]),
    ])
    st.write("")
    left, right = st.columns([3, 2])
    with left, st.container(border=True):
        st.markdown("**Traffic on the capture timeline**")
        fig = go.Figure()
        if len(hist):
            fig.add_trace(go.Scatter(x=hist["t"], y=hist["flows"] - hist["alerts"], name="Normal", stackgroup="a",
                                     line=dict(color=COLORS["blue"])))
            for fam in [c for c in hist.columns if c not in ("t", "flows", "alerts")]:
                fig.add_trace(go.Scatter(x=hist["t"], y=hist[fam], name=fam, stackgroup="a",
                                         line=dict(color=kb.family_color(fam))))
        fig.update_yaxes(title=f"Flows per {speed} s of capture")
        st.plotly_chart(ui.plotly_layout(fig, 330), width="stretch", key="live-chart")
        if s["skipped"]:
            st.caption(f"During floods only {MAX_SCORED_PER_TICK:,} flows per tick are scored; "
                       f"{s['skipped']:,} flows were counted but not scored so far.")
    with right, st.container(border=True, height=402):
        st.markdown("**Alert feed**")
        if not len(seen):
            st.caption("No alerts yet. Press Start, or Jump to next attack.")
        for a in s["seen"][:12]:
            c = SEVERITY_COLORS.get(a["severity"], "#64748b")
            check = "" if a["pred_label"] == a["true_label"] else f' · label: {html.escape(a["true_label"])}'
            st.markdown(
                f'<div class="feed-item" style="border-color:{c}"><b>{html.escape(a["pred_label"])}</b> '
                f'{ui.severity_badge(a["severity"])}<br><span style="color:#8b9bb4">'
                f'{pd.to_datetime(a["Timestamp"]):%H:%M:%S} · {a["Src IP"]} → {a["Dst IP"]}:{a["Dst Port"]} · '
                f'p={a["attack_prob"]:.2f}{check}</span></div>', unsafe_allow_html=True)


stream()

if live["seen"]:
    with st.container(border=True):
        last = live["seen"][0]
        st.markdown(f"Latest alert: **{last['pred_label']}** from {last['Src IP']} ({kb.family_of(last['pred_label'])})")
        if st.button("Investigate latest alert", icon=":material/troubleshoot:"):
            state.select_alert(last["idx"])
            st.switch_page("views/investigate.py")
