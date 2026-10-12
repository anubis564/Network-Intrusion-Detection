"""AI assistant: retrieval + Gemini, with an offline fallback that answers from the knowledge base."""
import functools
import re

from core import knowledge as kb
from core import rag
from core.config import DEFAULT_GEMINI_MODEL, secret

SYSTEM_PROMPT = """You are the security analyst assistant inside a Network Intrusion Detection System (NIDS) built on the improved CICIDS2017 dataset.
You help SOC analysts and students understand alerts raised by the machine-learning models, the attacks behind them, and how to respond.

How to answer:
- Ground every factual statement in the ALERT CONTEXT or the SOURCES given in the latest message. Cite sources inline as [S1], [S2] using their numbers. Never invent a source number.
- If neither the alert context nor the sources contain the answer, say clearly that it is not in the available sources, then give general guidance labelled as such.
- When explaining a prediction, refer to the concrete feature values and their contributions from the alert context, and explain in plain words why they point to an attack or to normal traffic. Mention uncertainty when the confidence is low.
- When asked how to respond, give practical, defensive, step-by-step actions (containment, investigation, recovery, prevention). Note that "Blocked"/"Logged" in the app are simulated actions.
- Stay defensive: do not give instructions for carrying out attacks.
- Reply in the same language as the user's question (Arabic questions get Arabic answers; keep technical terms such as feature names and attack names in English).
- Be concise and well structured: short paragraphs or bullet points, headings only for longer answers."""


# ------------------------------------------------------------------------------------- Gemini
def gemini_key() -> str | None:
    return secret("GEMINI_API_KEY") or secret("GOOGLE_API_KEY")


def gemini_model() -> str:
    return secret("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)


def llm_available() -> bool:
    return bool(gemini_key())


def _client():
    # keep one client alive per key: a client that is garbage-collected closes its connection mid-stream
    return _client_for(gemini_key())


@functools.lru_cache(maxsize=2)
def _client_for(api_key: str):
    from google import genai
    return genai.Client(api_key=api_key)


def _contents(history: list[dict], final_user_text: str) -> list[dict]:
    contents = []
    for m in history:
        role = "model" if m["role"] == "assistant" else "user"
        contents.append({"role": role, "parts": [{"text": m["content"]}]})
    contents.append({"role": "user", "parts": [{"text": final_user_text}]})
    return contents


def stream_gemini(history: list[dict], prompt: str):
    """Yield answer text chunks from Gemini."""
    from google.genai import types

    stream = _client().models.generate_content_stream(
        model=gemini_model(),
        contents=_contents(history, prompt),
        config=types.GenerateContentConfig(system_instruction=SYSTEM_PROMPT, temperature=0.3,
                                           max_output_tokens=4096),
    )
    for chunk in stream:
        if chunk.text:
            yield chunk.text


def search_query(question: str, alert: dict | None) -> str:
    """English query for the retriever. Arabic questions are translated by Gemini when it is available."""
    extra = ""
    if alert:
        extra = f" {alert['pred_label']} {kb.family_of(alert['pred_label'])}"
    if re.search(r"[؀-ۿ]", question) and llm_available():
        try:
            from google.genai import types

            resp = _client().models.generate_content(
                model=gemini_model(),
                contents=f"Rewrite this question as a short English search query about network security. "
                         f"Return only the query.\n\nQuestion: {question}",
                config=types.GenerateContentConfig(temperature=0, max_output_tokens=60),
            )
            if resp.text:
                return resp.text.strip() + extra
        except Exception:
            pass
    return question + extra


# ------------------------------------------------------------------------------------- prompts
def alert_context(alert: dict | None) -> str:
    if not alert:
        return "No alert is selected."
    a = kb.info(alert["pred_label"])
    lines = [
        f"Flow: {alert.get('Src IP', '?')}:{alert.get('Src Port', '?')} -> {alert.get('Dst IP', '?')}:{alert.get('Dst Port', '?')}"
        f" (protocol {alert.get('Protocol', '?')}), time {alert.get('Timestamp', '?')}",
        f"Verdict: {'ATTACK' if alert['is_attack'] else 'BENIGN'}; attack probability {alert['attack_prob']:.4f}",
        f"Predicted type: {alert['pred_label']} (family {a['family']}, severity {alert.get('severity', a['severity'])}, "
        f"type confidence {alert.get('pred_conf', 1):.3f}); simulated action: {alert.get('action', '-')}",
    ]
    if alert.get("true_label"):
        lines.append(f"Ground-truth label in the dataset: {alert['true_label']}")
    if alert.get("top_types"):
        lines.append("Specialist model top types: " + ", ".join(f"{n} {p:.3f}" for n, p in alert["top_types"]))
    if alert.get("explanation"):
        lines.append("Features that drove the prediction (value, contribution; positive pushes towards ATTACK):")
        for f in alert["explanation"][:8]:
            bm = f"; normal median {f['benign_median']:.4g}" if f.get("benign_median") is not None else ""
            lines.append(f"- {f['feature']} = {f['value']:.4g} (contribution {f['contribution']:+.3f}{bm})")
    if a["mitre"]:
        lines.append("MITRE ATT&CK: " + ", ".join(f"{t} {n}" for t, n in a["mitre"]))
    return "\n".join(lines)


def build_prompt(question: str, alert: dict | None, hits: list) -> str:
    sources = "\n\n".join(f"[S{i}] ({c.source} > {c.title})\n{c.text}" for i, (c, _) in enumerate(hits, 1))
    return (f"ALERT CONTEXT\n{alert_context(alert)}\n\n"
            f"SOURCES\n{sources or 'No relevant sources were retrieved.'}\n\n"
            f"QUESTION\n{question}")


# ------------------------------------------------------------------------------- offline answers
_WHY = re.compile(r"\bwhy\b|reason|explain (the|this) (prediction|alert)|flag|ليه|لماذا|سبب|اتعلم|اتصنف|ازاي الموديل|إزاي الموديل", re.I)
_RESPOND = re.compile(r"respond|response|mitigat|handle|fix|stop|block|prevent|what should|اتعامل|أتعامل|اعمل ايه|أعمل إيه|حل|امنع|أمنع|اوقف|أوقف|خطوات", re.I)
_WHAT = re.compile(r"what is|what's|explain|describe|tell me about|ايه هو|إيه هو|ما هو|ما هي|اشرح|يعني ايه|يعني إيه", re.I)


def offline_answer(question: str, alert: dict | None, hits: list) -> str:
    """Answer without a language model, from the alert context and the retrieved passages."""
    parts = []
    label = alert["pred_label"] if alert else None
    a = kb.info(label) if label else None

    if alert and _WHY.search(question):
        verdict = "an **attack**" if alert["is_attack"] else "**benign** traffic"
        parts.append(f"The binary model classified this flow as {verdict} with an attack probability of "
                     f"**{alert['attack_prob']:.2%}**.")
        if alert["is_attack"]:
            parts.append(f"The specialist model identified it as **{a['name']}** ({a['family']}, severity {alert['severity']}).")
        if alert.get("explanation"):
            parts.append("The features that pushed the decision the most:")
            for f in alert["explanation"][:5]:
                direction = "towards attack" if f["contribution"] > 0 else "towards benign"
                bm = f" (normal traffic median: {f['benign_median']:.4g})" if f.get("benign_median") is not None else ""
                parts.append(f"- `{f['feature']}` = {f['value']:.4g}{bm}: pushed {direction}")
        if a and a["indicators"]:
            parts.append("This matches what we know about this traffic type:\n" + "\n".join(f"- {i}" for i in a["indicators"]))
    elif alert and alert["is_attack"] and _RESPOND.search(question):
        parts.append(f"**Response playbook for {a['name']}** (severity {alert['severity']}):")
        parts += [f"{i}. {s}" for i, s in enumerate(a["response"], 1)]
        if a["prevention"]:
            parts.append("**Prevention:**\n" + "\n".join(f"- {p}" for p in a["prevention"]))
    elif alert and alert["is_attack"] and _WHAT.search(question) and not hits:
        parts.append(f"**{a['name']}**: {a['summary']}\n\n{a['how']}\n\n**Impact:** {a['impact']}")

    if hits and not parts:
        best = rag.best_sentences(question, hits, n=3)
        if best:
            parts.append("From the knowledge base:")
            for i, sentence in best:
                parts.append(f"- {sentence} [S{i}]")
    if not parts:
        parts.append("I could not find an answer to that in the knowledge base. Try asking about the selected alert "
                     "(why it was flagged, how to respond), an attack type, or the CICIDS2017 dataset.")
    parts.append("\n_Offline mode: answer built from the knowledge base. Add a Gemini API key for full conversational answers._")
    return "\n\n".join(parts)
