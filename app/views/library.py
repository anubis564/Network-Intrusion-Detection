import html

import streamlit as st

from core import knowledge as kb
from core import state, ui

engine, res = state.results()
ui.page_header("Attack Library", "Every attack in CICIDS2017: how it works, how it looks in network flows, and how to respond")

counts = res["true_label"].value_counts()
families = [f for f in kb.FAMILIES if f != "Benign"]
family = st.segmented_control("Family", ["All"] + families, default="All")

labels = [l for l, a in kb.ATTACKS.items() if l != "BENIGN" and (family in (None, "All") or a["family"] == family)]
labels.sort(key=lambda l: kb.SEVERITY_ORDER.index(kb.ATTACKS[l]["severity"]))

cols = st.columns(2)
for i, label in enumerate(labels):
    a = kb.ATTACKS[label]
    color = kb.family_color(a["family"])
    with cols[i % 2], st.container(border=True):
        st.markdown(
            f'<div style="display:flex;justify-content:space-between;align-items:center">'
            f'<span style="font-size:1.08rem;font-weight:700">{html.escape(a["name"])}</span>'
            f'{ui.severity_badge(a["severity"])}</div>'
            f'<div style="margin:4px 0 6px"><span class="chip" style="border-color:{color};color:{color}">{a["family"]}</span>'
            f'{ui.chips([f"{t} {n}" for t, n in a["mitre"]])}</div>'
            f'<div style="color:#cbd5e1">{html.escape(a["summary"])}</div>'
            f'<div style="color:#8b9bb4;font-size:.8rem;margin-top:6px">{counts.get(label, 0):,} flows in the demo data</div>',
            unsafe_allow_html=True)
        with st.expander("Details and response playbook"):
            st.markdown(f"**How it works.** {a['how']}")
            st.markdown("**How it shows up in the flows**\n" + "\n".join(f"- {x}" for x in a["indicators"]))
            st.markdown(f"**Impact.** {a['impact']}")
            st.markdown("**Response**\n" + "\n".join(f"{n}. {x}" for n, x in enumerate(a["response"], 1)))
            if a["prevention"]:
                st.markdown("**Prevention**\n" + "\n".join(f"- {x}" for x in a["prevention"]))
            examples = res.index[(res["true_label"] == label) & res["is_attack"]]
            if len(examples) and st.button("Investigate an example", key=f"ex-{label}", icon=":material/troubleshoot:"):
                state.select_alert(int(examples[0]))
                st.switch_page("views/investigate.py")
