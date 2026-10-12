import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from core import rag, state, ui
from core.config import COLORS

engine, res = state.results()
ui.page_header("Model & Data", "How the detection models perform, what the data looks like, and how well the assistant retrieves")
state.mode_banner(engine)

tab_models, tab_data, tab_rag = st.tabs(["Models", "Dataset findings", "RAG evaluation"])

with tab_models:
    meta = engine.metadata
    m = meta.get("metrics", {})
    b, s = m.get("binary", {}), m.get("specialist", {})
    ui.kpi_row([
        ui.kpi_card("Binary F1 (attack)", f"{b['f1_attack']:.4f}" if "f1_attack" in b else "-", COLORS["green"]),
        ui.kpi_card("Binary recall (attack)", f"{b['recall_attack']:.4f}" if "recall_attack" in b else "-", COLORS["blue"]),
        ui.kpi_card("Binary precision (attack)", f"{b['precision_attack']:.4f}" if "precision_attack" in b else "-",
                    COLORS["purple"]),
        ui.kpi_card("Attack-type macro F1", f"{s['f1_macro']:.4f}" if "f1_macro" in s else "-", COLORS["orange"]),
    ])
    st.caption("Test-set metrics saved with the models (model_metadata.json).")
    if meta.get("notes"):
        st.info(meta["notes"], icon=":material/info:")

    left, right = st.columns([2, 3])
    with left, st.container(border=True):
        st.markdown("**Pipeline**")
        st.markdown(
            "1. Drop identifiers (IPs, ports, flow ID, timestamp)\n"
            "2. Drop rows with inf / NaN values and impossible negatives\n"
            "3. Relabel *Attempted* flows as BENIGN\n"
            "4. Remove duplicate flows\n"
            "5. Drop near-empty features (non-zero in at most 200 rows)\n"
            "6. Drop one of each pair of features with |r| > 0.95\n"
            "7. One-hot encode Protocol\n"
            f"8. **Binary model** ({engine.binary_name}): benign vs attack\n"
            f"9. **Specialist model** ({engine.specialist_name}): attack type, only for flagged flows")
        v = meta.get("versions", {})
        if v:
            st.caption("Trained with " + ", ".join(f"{k} {val}" for k, val in v.items()) + f" on {meta.get('saved_on', '?')}")
    with right, st.container(border=True):
        st.markdown("**Demo traffic: predicted type vs dataset label**")
        labels = sorted(set(res["true_label"]) | set(res["pred_label"]))
        cm = pd.crosstab(res["true_label"], res["pred_label"]).reindex(index=labels, columns=labels, fill_value=0)
        z = cm.div(cm.sum(axis=1).replace(0, 1), axis=0)
        fig = go.Figure(go.Heatmap(z=z.values, x=labels, y=labels, colorscale="Blues", text=cm.values,
                                   texttemplate="%{text}", hovertemplate="true %{y}<br>pred %{x}<br>%{text} flows<extra></extra>",
                                   showscale=False))
        fig.update_xaxes(title="Predicted", tickangle=40)
        fig.update_yaxes(title="Dataset label", autorange="reversed")
        st.plotly_chart(ui.plotly_layout(fig, 520, legend=False), width="stretch")
        st.caption("The demo flows were sampled from the full dataset, so some of them were also seen in training.")

with tab_data:
    findings = [
        ("100% vs 0%", "of Attempted flows vs real attack flows carry no payload, which justifies relabelling Attempted as benign"),
        ("1 day, 1 port", "every attack family runs on a single day against a single service (except PortScan: 1,001 ports)"),
        ("100% TCP", "of attack flows, while about 60% of benign flows are UDP"),
        ("99%", "of PortScan flows are duplicates once identifiers are removed (159,023 to about 1,670)"),
        ("+5 h", "the recorded timestamps are 5 hours ahead of the lab's local time"),
        ("Shortcut risk", "initial TCP window sizes are very predictive but partly describe the lab machines"),
    ]
    cols = st.columns(3)
    for i, (big, text) in enumerate(findings):
        with cols[i % 3], st.container(border=True):
            st.markdown(f"<div style='font-size:1.5rem;font-weight:800;color:{COLORS['blue']}'>{big}</div>"
                        f"<div style='color:#cbd5e1'>{text}</div>", unsafe_allow_html=True)
    with st.container(border=True):
        st.markdown("**Demo traffic composition**")
        comp = res["true_label"].value_counts().rename_axis("Label").reset_index(name="Flows")
        st.dataframe(comp, hide_index=True, width="stretch")

with tab_rag:
    st.markdown("The team's question bank (50 questions with expected answers) is run through the retriever. The question "
                "bank itself is excluded from the index, so the retriever has to find the answer in the other documents. "
                "A question counts as a hit when one of the top-K passages contains the expected answer's numbers and most of its key terms.")
    k = st.slider("TOP_K", 1, 8, 4, key="rag-k")
    rows = pd.DataFrame(rag.evaluate(top_k=k))
    if rows.empty:
        st.warning("Question bank not found.")
    else:
        hit = rows["hit"].mean()
        mrr = rows["rank"].dropna().map(lambda r: 1 / r).sum() / len(rows)
        chunks, _, _ = rag.build_index()
        ui.kpi_row([
            ui.kpi_card(f"Hit rate @ {k}", f"{hit:.0%}", COLORS["green"]),
            ui.kpi_card("Mean reciprocal rank", f"{mrr:.2f}", COLORS["blue"]),
            ui.kpi_card("Questions", str(len(rows)), COLORS["purple"]),
            ui.kpi_card("Indexed passages", str(len(chunks)), COLORS["orange"]),
        ])
        st.write("")
        st.dataframe(rows, hide_index=True, width="stretch", height=420,
                     column_config={"hit": st.column_config.CheckboxColumn("Hit"),
                                    "expected": st.column_config.TextColumn("Expected answer", width="large")})
