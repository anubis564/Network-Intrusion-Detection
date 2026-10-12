from datetime import datetime

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import polars as pl
import streamlit as st

from core import engine as eng
from core import knowledge as kb
from core import state, ui
from core.config import COLORS, SEVERITY_COLORS

engine, res = state.results()
ui.page_header("Alert Investigation", "Why the model raised this alert, what the attack is, and how to respond")
state.mode_banner(engine)

# ---------------------------------------------------------------------------- pick a flow
idx = state.selected_alert_idx(res)
c1, c2, c3 = st.columns([4, 2, 1], vertical_alignment="bottom")
alert_ids = list(res.index[res["is_attack"]][::-1])
if idx not in alert_ids:
    alert_ids = [idx] + alert_ids
choice = c1.selectbox("Alert", alert_ids, index=alert_ids.index(idx), format_func=lambda i: state.alert_label(res, i))
labels = sorted(res["true_label"].unique())
pick_type = c2.selectbox("Or a random flow of type", ["-"] + labels)
if c3.button("Random", icon=":material/casino:", width="stretch") and pick_type != "-":
    choice = int(np.random.choice(res.index[res["true_label"] == pick_type]))
if choice != idx:
    state.select_alert(choice)
    st.rerun()

rec = state.alert_record(engine, res, idx)
info = kb.info(rec["pred_label"])
attack = bool(rec["is_attack"])
sev = rec["severity"] if attack else "None"
color = SEVERITY_COLORS.get(sev, COLORS["green"]) if attack else COLORS["green"]

# ---------------------------------------------------------------------------- verdict
left, right = st.columns([3, 2])
with left:
    verdict = f"{info['name']}" if attack else "Benign traffic"
    truth = rec.get("true_label", "")
    match = "matches" if (truth == rec["pred_label"]) or (not attack and truth == "BENIGN") else "differs from"
    st.markdown(
        f'<div class="verdict" style="border-color:{color}66;background:{color}12">'
        f'<div style="color:{color};font-weight:700;letter-spacing:.06em;font-size:.8rem">'
        f'{"THREAT DETECTED" if attack else "NO THREAT"}</div>'
        f'<div class="big">{verdict}</div>'
        f'<div style="margin:6px 0 10px;color:#cbd5e1">{info["summary"]}</div>'
        f'{ui.severity_badge(sev) if attack else ""} &nbsp; <span class="chip">Family: {info["family"]}</span>'
        f'<span class="chip">Attack probability {rec["attack_prob"]:.2%}</span>'
        f'<span class="chip">Action: {rec["action"]}</span><br>'
        f'{ui.chips([f"{t} {n}" for t, n in info["mitre"]])}'
        f'<div style="margin-top:10px;color:#8b9bb4;font-size:.8rem">Dataset label: <b>{truth}</b> ({match} the prediction)</div>'
        f'</div>', unsafe_allow_html=True)
with right, st.container(border=True):
    proto = {6: "TCP", 17: "UDP"}.get(int(rec.get("Protocol", 0)), str(rec.get("Protocol")))
    st.markdown("**Flow details**")
    details = pd.DataFrame({
        "Field": ["Time", "Source", "Destination", "Protocol", "Duration", "Packets (fwd / bwd)", "Bytes (fwd / bwd)"],
        "Value": [f"{pd.to_datetime(rec['Timestamp']):%A %d %b %Y, %H:%M:%S}",
                  f"{rec['Src IP']}:{rec['Src Port']}", f"{rec['Dst IP']}:{rec['Dst Port']}", proto,
                  f"{rec['Flow Duration'] / 1e6:.3f} s",
                  f"{int(rec['Total Fwd Packet'])} / {int(rec['Total Bwd packets'])}",
                  f"{rec['Total Length of Fwd Packet']:,.0f} / {rec['Total Length of Bwd Packet']:,.0f}"],
    })
    st.dataframe(details, hide_index=True, width="stretch")

# ---------------------------------------------------------------------------- explanation
left, right = st.columns([3, 2])
with left, st.container(border=True):
    st.markdown("**Why the model decided this**")
    expl = pd.DataFrame(rec["explanation"])
    if expl.empty:
        st.info(rec["explanation_method"])
    else:
        top = expl.head(10).iloc[::-1]
        bar_colors = [COLORS["red"] if c > 0 else COLORS["green"] for c in top["contribution"]]
        fig = go.Figure(go.Bar(
            x=top["contribution"], y=[f"{f} = {v:,.4g}" for f, v in zip(top["feature"], top["value"])],
            orientation="h", marker_color=bar_colors,
            hovertemplate="%{y}<br>contribution %{x:+.3f}<extra></extra>"))
        fig.add_vline(x=0, line_color="#475569")
        fig.update_xaxes(title="Contribution  (red = towards attack, green = towards benign)")
        st.plotly_chart(ui.plotly_layout(fig, 380, legend=False), width="stretch")
        st.caption(rec["explanation_method"])
        bullets = []
        for f in rec["explanation"][:3]:
            towards = "towards **attack**" if f["contribution"] > 0 else "towards **benign**"
            pct = f" - higher than {f['benign_pct']:.0f}% of normal flows" if f.get("benign_pct") is not None else ""
            bullets.append(f"- `{f['feature']}` = **{f['value']:,.4g}**{pct}; it pushed the decision {towards}.")
        st.markdown("\n".join(bullets))

with right, st.container(border=True):
    if attack and rec["top_types"]:
        st.markdown("**Attack type (specialist model)**")
        tt = pd.DataFrame(rec["top_types"], columns=["type", "p"]).iloc[::-1]
        fig = go.Figure(go.Bar(x=tt["p"], y=tt["type"], orientation="h", text=[f"{p:.1%}" for p in tt["p"]],
                               marker_color=[kb.family_color(kb.family_of(t)) for t in tt["type"]]))
        fig.update_xaxes(range=[0, 1], tickformat=".0%")
        st.plotly_chart(ui.plotly_layout(fig, 170, legend=False), width="stretch")
    st.markdown("**Compared with normal traffic**")
    keys = ["Flow Duration", "Total Fwd Packet", "Total Length of Fwd Packet", "Flow Bytes/s",
            "Flow IAT Mean", "Bwd Init Win Bytes"]
    raw = state.raw_row(idx)
    comp = []
    for k in keys:
        if k in raw.columns:
            v = float(raw[k][0])
            comp.append({"Feature": k, "This flow": v, "Normal median": eng.benign_median(k),
                         "Percentile in normal": eng.percentile_in_benign(k, v)})
    st.dataframe(pd.DataFrame(comp), hide_index=True, width="stretch",
                 column_config={"This flow": st.column_config.NumberColumn(format="%.4g"),
                                "Normal median": st.column_config.NumberColumn(format="%.4g"),
                                "Percentile in normal": st.column_config.ProgressColumn(format="%.0f%%", min_value=0, max_value=100)})

# ---------------------------------------------------------------------------- response
left, right = st.columns([3, 2])
with left, st.container(border=True):
    st.markdown("**Response playbook**")
    if attack:
        done = st.session_state.setdefault("playbook_done", {})
        for i, step in enumerate(info["response"]):
            done[(idx, i)] = st.checkbox(step, value=done.get((idx, i), False), key=f"pb-{idx}-{i}")
        progress = sum(done.get((idx, i), False) for i in range(len(info["response"]))) / max(len(info["response"]), 1)
        st.progress(progress, text=f"Containment progress: {progress:.0%}")
        st.markdown("**Suggested firewall rule** (review before applying):")
        st.code(f"# Linux (iptables)\niptables -A INPUT -s {rec['Src IP']} -p tcp --dport {rec['Dst Port']} -j DROP\n"
                f"# Windows (PowerShell)\nNew-NetFirewallRule -DisplayName \"NIDS block {rec['Src IP']}\" "
                f"-Direction Inbound -RemoteAddress {rec['Src IP']} -Protocol TCP -LocalPort {rec['Dst Port']} -Action Block",
                language="bash")
    else:
        st.success("No action needed for benign traffic.")
    fb = st.session_state.setdefault("feedback", {})
    a, b = st.columns(2)
    if a.button("Confirm alert", icon=":material/thumb_up:", width="stretch"):
        fb[idx] = "confirmed"
    if b.button("Mark as false positive" if attack else "Report missed attack", icon=":material/flag:", width="stretch"):
        fb[idx] = "false_positive" if attack else "false_negative"
    if idx in fb:
        st.caption(f"Analyst feedback recorded: **{fb[idx].replace('_', ' ')}** (kept for this session).")

with right, st.container(border=True):
    st.markdown("**Next steps**")
    if st.button("Ask the AI assistant about this alert", icon=":material/smart_toy:", type="primary", width="stretch"):
        st.session_state["assistant_prefill"] = "Why was this flow flagged, and how should I respond?" if attack \
            else "Why was this flow considered benign?"
        st.switch_page("views/assistant.py")
    report = [f"# Incident report - alert #{idx}", f"Generated: {datetime.now():%Y-%m-%d %H:%M}", "",
              f"**Verdict:** {'ATTACK - ' + info['name'] if attack else 'Benign'}",
              f"**Severity:** {sev}  |  **Attack probability:** {rec['attack_prob']:.2%}  |  **Simulated action:** {rec['action']}",
              f"**Flow:** {rec['Src IP']}:{rec['Src Port']} -> {rec['Dst IP']}:{rec['Dst Port']} at {rec['Timestamp']}",
              f"**MITRE ATT&CK:** {', '.join(f'{t} {n}' for t, n in info['mitre']) or '-'}", "",
              "## Description", info["summary"], "", info["how"], "", "## Why the model flagged it"]
    report += [f"- {f['feature']} = {f['value']:.4g} (contribution {f['contribution']:+.3f})" for f in rec["explanation"][:8]]
    report += ["", "## Response steps"] + [f"{i}. {s}" for i, s in enumerate(info["response"], 1)]
    if idx in fb:
        report += ["", f"Analyst feedback: {fb[idx]}"]
    st.download_button("Download incident report", "\n".join(report), file_name=f"incident_{idx}.md",
                       icon=":material/description:", width="stretch")
    st.markdown("**How it works**")
    st.write(info["how"] or "-")

# ---------------------------------------------------------------------------- what-if lab
if engine.mode == "model" and rec["explanation"]:
    with st.expander("What-if lab: change the strongest features and re-score the flow", icon=":material/science:"):
        raw = state.raw_row(idx)
        feats = [f["feature"] for f in rec["explanation"] if f["feature"] in raw.columns][:4]
        cols = st.columns(len(feats))
        edited = {}
        for col, f in zip(cols, feats):
            v = float(raw[f][0])
            edited[f] = col.number_input(f, value=v, min_value=0.0, format="%.4g", key=f"wi-{idx}-{f}")
        new_row = raw.with_columns([pl.lit(v).cast(raw[f].dtype).alias(f) for f, v in edited.items()])
        new = eng.score(engine, new_row).iloc[0]
        delta = new["attack_prob"] - rec["attack_prob"]
        m1, m2 = st.columns(2)
        m1.metric("Attack probability", f"{new['attack_prob']:.2%}", f"{delta:+.2%}", delta_color="inverse")
        m2.metric("Prediction", new["pred_label"], "changed" if new["pred_label"] != rec["pred_label"] else "unchanged",
                  delta_color="off")
