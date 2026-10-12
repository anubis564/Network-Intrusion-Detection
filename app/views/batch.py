import time

import plotly.graph_objects as go
import polars as pl
import streamlit as st

from core import engine as eng
from core import knowledge as kb
from core import state, ui
from core.config import COLORS

MAX_ROWS = 300_000

engine, res = state.results()
ui.page_header("Batch Scan", "Upload flow records in CICFlowMeter CSV format and score them all at once")
state.mode_banner(engine)

with st.container(border=True):
    up, sample = st.columns([3, 1], vertical_alignment="bottom")
    file = up.file_uploader("CSV file (same columns as the CICIDS2017 day files)", type=["csv"])
    demo = eng.load_traffic()
    sample_csv = demo.sample(300, seed=7).sort("Timestamp").with_columns(
        pl.col("Timestamp").dt.strftime("%d/%m/%Y %I:%M:%S %p")).write_csv()
    sample.download_button("Sample CSV (300 flows)", sample_csv, file_name="sample_flows.csv",
                           icon=":material/download:", width="stretch")

if file is None:
    st.info("Upload a CSV to start. The sample file shows the expected format.", icon=":material/upload_file:")
    st.stop()

try:
    df = eng.read_uploaded_csv(file)
except Exception as exc:
    st.error(f"Could not read the file: {exc}")
    st.stop()
if df.height > MAX_ROWS:
    st.warning(f"The file has {df.height:,} rows; only the first {MAX_ROWS:,} are scanned.")
    df = df.head(MAX_ROWS)

t0 = time.perf_counter()
try:
    out = eng.score(engine, df)
except ValueError as exc:
    st.error(str(exc))
    st.stop()
elapsed = time.perf_counter() - t0

keep = [c for c in ["Timestamp", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Label"] if c in df.columns]
table = df.select(keep).to_pandas().join(out)

alerts = table[table["is_attack"]]
ui.kpi_row([
    ui.kpi_card("Flows scanned", ui.fmt_int(len(table)), COLORS["blue"], delta=f"{elapsed:.2f} s", delta_note="total time"),
    ui.kpi_card("Alerts", ui.fmt_int(len(alerts)), COLORS["red"], delta=f"{len(alerts) / max(len(table), 1):.1%}",
                delta_note="of flows"),
    ui.kpi_card("Critical", ui.fmt_int((alerts["severity"] == "Critical").sum()), COLORS["orange"]),
    ui.kpi_card("Invalid rows", ui.fmt_int((~table["valid"]).sum()), COLORS["purple"], delta="skipped",
                delta_note="inf / NaN / negative"),
])
st.write("")

left, right = st.columns([2, 3])
with left, st.container(border=True):
    st.markdown("**Alerts by type**")
    counts = alerts["pred_label"].value_counts()
    if len(counts):
        fig = go.Figure(go.Pie(labels=counts.index, values=counts.values, hole=0.6, textinfo="none",
                               marker=dict(colors=[kb.family_color(kb.family_of(l)) for l in counts.index])))
        st.plotly_chart(ui.plotly_layout(fig, 300), width="stretch")
    else:
        st.success("No attacks detected in this file.")
with right, st.container(border=True):
    st.markdown("**Results**")
    only_alerts = st.toggle("Show alerts only", value=len(alerts) > 0)
    shown = alerts if only_alerts else table
    st.dataframe(shown[keep + ["pred_label", "attack_prob", "severity", "action", "status"]], hide_index=True,
                 width="stretch", height=300,
                 column_config={"attack_prob": st.column_config.ProgressColumn("Attack prob.", min_value=0, max_value=1,
                                                                             format="%.2f")})
    if "Label" in table.columns:
        truth = table["Label"].map(lambda l: "BENIGN" if str(l).endswith("Attempted") else kb.base_label(l))
        agree = ((truth != "BENIGN") == table["is_attack"]).mean()
        st.caption(f"The file has a Label column: attack/benign agreement with it is **{agree:.2%}**.")
    st.download_button("Download results CSV", table.to_csv(index=False), file_name="nids_scan_results.csv",
                       icon=":material/download:", type="primary")
