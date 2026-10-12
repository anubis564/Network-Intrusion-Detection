import streamlit as st

from core import assistant as ai
from core import knowledge as kb
from core import rag, state, ui
from core.config import SECRETS_FILE

engine, res = state.results()
ui.page_header("AI Assistant", "Ask why an alert was raised, what an attack is, how to respond, or anything about the dataset")

chat_col, side = st.columns([5, 2])

# ----------------------------------------------------------------------------- side panel
with side:
    with st.container(border=True):
        st.markdown("**Alert in context**")
        use_alert = st.toggle("Include the selected alert", value=True)
        idx = state.selected_alert_idx(res)
        alert = state.alert_record(engine, res, idx) if use_alert else None
        if alert:
            info = kb.info(alert["pred_label"])
            st.markdown(f"**{info['name'] if alert['is_attack'] else 'Benign traffic'}**  \n"
                        f"{alert['Src IP']} -> {alert['Dst IP']}:{alert['Dst Port']}  \n"
                        f"Attack probability {alert['attack_prob']:.2%}"
                        + (f"  \n{ui.severity_badge(alert['severity'])}" if alert["is_attack"] else ""),
                        unsafe_allow_html=True)
            if st.button("Change alert", icon=":material/swap_horiz:", width="stretch"):
                st.switch_page("views/investigate.py")
    suggestions = [
        "Why was this flow flagged?",
        "How should I respond to this alert?",
        "What does the 'X - Attempted' label mean?",
        "How many effective DoS Hulk flows are in the dataset?",
        "ليه الموديل اعتبر الـ flow ده هجوم؟",
        "What changed in the fixed CICFlowMeter?",
    ]
    with st.container(border=True):
        picked = st.pills("Try asking", suggestions, key=f"sug-{len(st.session_state.get('chat', []))}")
        if picked:
            st.session_state["assistant_prefill"] = picked

    with st.container(border=True):
        if ai.llm_available():
            st.markdown(f":green[:material/check_circle:] Gemini connected (`{ai.gemini_model()}`)")
        else:
            st.markdown(":orange[:material/key_off:] **No Gemini API key found**, so answers come straight from the "
                        "knowledge base. Add this line to `.streamlit/secrets.toml` in the project folder "
                        f"(`{SECRETS_FILE}`) and restart the app:")
            st.code('GEMINI_API_KEY = "your-key"', language="toml")
        with st.popover("Settings", icon=":material/tune:", width="stretch"):
            top_k = st.slider("TOP_K passages", 1, 8, 4)
            show_sources = st.toggle("Show retrieved sources", value=True)
            if st.button("Test Gemini connection", icon=":material/network_check:", disabled=not ai.llm_available()):
                try:
                    reply = ai.generate_gemini("Reply with the single word OK.")
                    st.success(f"Gemini answered with {ai.gemini_model()}: {reply.strip()[:40]}")
                except Exception as exc:
                    st.error(f"Gemini failed: {exc}")
        if st.button("Clear conversation", icon=":material/delete_sweep:", width="stretch"):
            st.session_state["chat"] = []
            st.rerun()

# ----------------------------------------------------------------------------- chat
history = st.session_state.setdefault("chat", [])
with chat_col:
    box = st.container(height=600, border=True)
    with box:
        if not history:
            st.markdown(
                "<div style='text-align:center;color:#8b9bb4;padding:60px 10px'>"
                "<div style='font-size:2.4rem'>🛡️</div><b>NIDS security assistant</b><br>"
                "I can explain the selected alert, describe attacks, suggest response steps, "
                "and answer questions about the CICIDS2017 dataset. You can ask in Arabic or English.</div>",
                unsafe_allow_html=True)
        for m in history:
            with st.chat_message(m["role"], avatar=":material/person:" if m["role"] == "user" else ":material/shield:"):
                st.markdown(m["content"])
                if m.get("notice"):
                    st.warning(m["notice"], icon=":material/cloud_off:")
                if m.get("sources") and show_sources:
                    with st.expander(f"Sources ({len(m['sources'])})"):
                        for i, s in enumerate(m["sources"], 1):
                            st.markdown(f"**[S{i}] {s['source']} > {s['title']}** (similarity {s['score']:.2f})")
                            st.caption(s["text"][:500] + ("..." if len(s["text"]) > 500 else ""))

prompt = st.chat_input("Ask about the alert, an attack, or the dataset...")
prompt = prompt or st.session_state.pop("assistant_prefill", None)

if prompt:
    with box:
        with st.chat_message("user", avatar=":material/person:"):
            st.markdown(prompt)
        hits = rag.retrieve(ai.search_query(prompt, alert), top_k=top_k)
        sources = [{"source": c.source, "title": c.title, "text": c.text, "score": s} for c, s in hits]
        with st.chat_message("assistant", avatar=":material/shield:"):
            answer, notice = None, None
            if ai.llm_available():
                waiting = st.empty()
                waiting.markdown(":gray[_جاري التفكير…_]" if ai.is_arabic(prompt) else ":gray[_Thinking…_]")

                def chunks():
                    for i, text in enumerate(ai.stream_gemini(history[-8:], ai.build_prompt(prompt, alert, hits))):
                        if i == 0:
                            waiting.empty()  # the first words replace the "thinking" note
                        yield text

                try:
                    answer = st.write_stream(chunks())
                except Exception as exc:
                    notice = f"Gemini did not answer, so this reply comes from the knowledge base only. Reason: {exc}"
                waiting.empty()
            else:
                notice = f"No GEMINI_API_KEY found (looked in Streamlit secrets and {SECRETS_FILE})."
            if not answer:
                answer = ai.offline_answer(prompt, alert, hits)
                st.markdown(answer)
    history.append({"role": "user", "content": prompt})
    history.append({"role": "assistant", "content": answer, "sources": sources, "notice": notice})
    st.rerun()
