import html
from datetime import datetime

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from core import assistant, rag, state, ui
from core import knowledge as kb
from core.config import COLORS

engine, res = state.results()

top_l, top_r = st.columns([3, 2], vertical_alignment="bottom")
with top_l:
    ui.page_header("Network Intrusion Detection System",
                   "Held-out test flows from the improved CICIDS2017 capture (3-7 July 2017): traffic the detection model never saw in training")
days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
res["day"] = pd.to_datetime(res["Timestamp"]).dt.day_name()
with top_r:
    c1, c2 = st.columns([3, 2], vertical_alignment="bottom")
    day = c1.selectbox("Day", ["All days (3-7 Jul 2017)"] + days, label_visibility="collapsed")
    chosen = days if day.startswith("All") else [day]
state.mode_banner(engine)

view = res[res["day"].isin(chosen)].copy()
view["bucket"] = pd.to_datetime(view["Timestamp"]).dt.floor("30min" if len(chosen) > 1 else "10min")
alerts = view[view["is_attack"]]

# --------------------------------------------------------------------- export report
def report_html() -> str:
    by_type = alerts["pred_label"].value_counts()
    rows = "".join(f"<tr><td>{html.escape(k)}</td><td>{v:,}</td><td>{kb.severity_of(k)}</td></tr>" for k, v in by_type.items())
    return (f"<html><head><meta charset='utf-8'><title>NIDS report</title></head><body style='font-family:sans-serif'>"
            f"<h1>NIDS detection report</h1><p>Generated {datetime.now():%Y-%m-%d %H:%M}. Days: {', '.join(chosen)}.</p>"
            f"<p>Flows analysed: {len(view):,}<br>Alerts: {len(alerts):,}<br>"
            f"Critical alerts: {(alerts['severity'] == 'Critical').sum():,}<br>"
            f"Distinct attacking sources: {alerts['Src IP'].nunique():,}</p>"
            f"<h2>Alerts by type</h2><table border=1 cellpadding=5><tr><th>Type</th><th>Alerts</th><th>Severity</th></tr>"
            f"{rows}</table></body></html>")


c2.download_button("Export report", report_html(), file_name="nids_report.html", mime="text/html",
                   icon=":material/download:", width="stretch", type="primary")

# ---------------------------------------------------------------------------- KPIs
per_bucket = view.groupby("bucket").agg(flows=("is_attack", "size"), alerts=("is_attack", "sum"),
                                         critical=("severity", lambda s: (s == "Critical").sum()))
correct = (view["is_attack"] == view["true_attack"]).mean() if len(view) else 0
sources = alerts.groupby("bucket")["Src IP"].nunique().reindex(per_bucket.index, fill_value=0)
ui.kpi_row([
    ui.kpi_card("Flows analysed", ui.fmt_int(len(view)), COLORS["blue"], per_bucket["flows"].values,
                f"{len(view) / max(len(res), 1):.0%}", "of the test traffic"),
    ui.kpi_card("Total alerts", ui.fmt_int(len(alerts)), COLORS["red"], per_bucket["alerts"].values,
                f"{len(alerts) / max(len(view), 1):.1%}", "of analysed flows"),
    ui.kpi_card("Critical alerts", ui.fmt_int((alerts["severity"] == "Critical").sum()), COLORS["orange"],
                per_bucket["critical"].values,
                f"{(alerts['action'] == 'Blocked').sum():,} blocked", "simulated"),
    ui.kpi_card("Attacking sources", ui.fmt_int(alerts["Src IP"].nunique()), COLORS["purple"], sources.values,
                f"{alerts['Dst Port'].nunique()} ports", "targeted"),
    ui.kpi_card("Detection agreement", f"{correct:.2%}", COLORS["green"], None,
                f"{(view['is_attack'] & ~view['true_attack']).sum()} FP / {(~view['is_attack'] & view['true_attack']).sum()} FN",
                "vs dataset labels"),
])
st.write("")

# ------------------------------------------------------------- traffic + attack types
left, right = st.columns([3, 2])
with left, st.container(border=True):
    st.markdown("**Traffic overview**")
    status = view.groupby(["bucket", "status"]).size().unstack(fill_value=0)
    fig = go.Figure()
    for name, color in [("Normal", COLORS["blue"]), ("Suspicious", COLORS["orange"]), ("Malicious", COLORS["red"])]:
        if name in status:
            y = status[name].where(status[name] > 0)  # no point instead of a drop to zero on the log axis
            fig.add_trace(go.Scatter(x=status.index, y=y, name=f"{name} traffic", mode="lines+markers",
                                     connectgaps=False, line=dict(color=color, width=2), marker=dict(size=5)))
    if len(chosen) > 1:
        fig.update_xaxes(rangebreaks=[dict(bounds=[22.5, 13.5], pattern="hour")])
    fig.update_yaxes(title=f"Flows / {'30' if len(chosen) > 1 else '10'} min", type="log")
    st.plotly_chart(ui.plotly_layout(fig, 330), width="stretch")

with right, st.container(border=True):
    st.markdown("**Top attack types**")
    counts = alerts["pred_label"].value_counts()
    top = counts.head(6)
    if len(counts) > 6:
        top["Others"] = counts.iloc[6:].sum()
    colors = [kb.family_color(kb.family_of(l)) if l != "Others" else "#64748b" for l in top.index]
    pie = go.Figure(go.Pie(labels=top.index, values=top.values, hole=0.62, marker=dict(colors=colors,
                           line=dict(color=COLORS["card"], width=2)), sort=False, textinfo="none",
                           hovertemplate="%{label}: %{value:,} (%{percent})<extra></extra>"))
    pie.add_annotation(text=f"<b>{len(alerts):,}</b><br>alerts", showarrow=False, font=dict(size=18))
    pie.update_layout(legend=dict(orientation="v", x=1.02, y=0.5))
    st.plotly_chart(ui.plotly_layout(pie, 330, legend=True).update_layout(
        legend=dict(orientation="v", x=1.0, y=0.5, yanchor="middle")), width="stretch")

# ------------------------------------------------------------- recent alerts + status
left, right = st.columns([3, 2])
with left, st.container(border=True):
    h1, h2 = st.columns([3, 2], vertical_alignment="center")
    h1.markdown("**Recent alerts**")
    recent = alerts.sort_values("Timestamp", ascending=False).head(8)
    rows = []
    for idx, r in recent.iterrows():
        act_cls = "act-blocked" if r["action"] == "Blocked" else "act-logged"
        rows.append(
            f"<tr><td>{pd.to_datetime(r['Timestamp']):%b %d, %H:%M:%S}</td><td>{html.escape(r['pred_label'])}</td>"
            f"<td>{html.escape(str(r['Src IP']))}</td><td>{html.escape(str(r['Dst IP']))}:{r['Dst Port']}</td>"
            f"<td>{ui.severity_badge(r['severity'])}</td><td class='{act_cls}'>{r['action']}</td></tr>")
    st.markdown("<table class='alerts'><tr><th>Time</th><th>Type</th><th>Source IP</th><th>Destination</th>"
                "<th>Severity</th><th>Action</th></tr>" + "".join(rows) + "</table>", unsafe_allow_html=True)
    st.write("")
    if len(recent):
        pick = st.selectbox("Investigate an alert", recent.index, format_func=lambda i: state.alert_label(res, i))
        if st.button("Open investigation", icon=":material/troubleshoot:", type="primary"):
            state.select_alert(pick)
            st.switch_page("views/investigate.py")

with right, st.container(border=True):
    st.markdown("**System status**")
    lat = res.attrs.get("latency_ms_per_flow", 0)
    chunks, _, _ = rag.build_index()
    bars = [
        ui.status_bar("Detection engine", "Online" if engine.mode == "model" else "Replay mode",
                      1.0 if engine.mode == "model" else 0.35, COLORS["green"] if engine.mode == "model" else COLORS["orange"]),
        ui.status_bar("Binary model", engine.binary_name, 1.0 if engine.binary else 0, COLORS["blue"]),
        ui.status_bar("Attack-type model", f"{engine.specialist_name} - {len(engine.specialist_classes)} classes",
                      1.0 if engine.specialist else 0, COLORS["purple"]),
        ui.status_bar("Inference latency", f"{lat:.3f} ms / flow", min(lat / 1.0, 1.0), COLORS["orange"]),
        ui.status_bar("Knowledge base (RAG)", f"{len(chunks)} passages indexed", 1.0, COLORS["blue"]),
        ui.status_bar("AI assistant", f"Gemini ({assistant.gemini_model()})" if assistant.llm_available() else "Offline mode",
                      1.0 if assistant.llm_available() else 0.4, COLORS["green"] if assistant.llm_available() else "#64748b"),
    ]
    st.markdown("".join(bars), unsafe_allow_html=True)
