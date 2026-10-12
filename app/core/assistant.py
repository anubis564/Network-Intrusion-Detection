"""AI assistant: retrieval + Gemini, with an offline fallback that answers from the knowledge base."""
import functools
import re
import time

from core import knowledge as kb
from core import rag
from core.config import secret

SYSTEM_PROMPT = """You are the AI assistant inside a Network Intrusion Detection System (NIDS) built on the improved CICIDS2017 dataset.
Your main users are SOC analysts and students: you explain alerts raised by the machine-learning models, the attacks behind them, and how to respond. You can also answer any other question the user asks, on any topic, like a helpful general assistant.

How to answer:
- Language: always reply in the language of the user's latest message. Arabic in, Arabic out (match the user's dialect when it is Egyptian Arabic); English in, English out. Keep technical terms such as feature names, attack names and commands in English.
- When the ALERT CONTEXT or the SOURCES in the latest message are relevant, use them. Cite SOURCES inline as [S1], [S2] by their numbers; never invent a source number. Do not cite or mention the alert context as a source (no "[ALERT CONTEXT]"): just state the alert's values.
- When the question is not covered by the sources (general knowledge, other topics, small talk), simply answer it from your own knowledge. Do not apologise and do not mention the sources in that case.
- When explaining a prediction, refer to the concrete feature values and their contributions from the alert context, and explain in plain words why they point to an attack or to normal traffic. Mention uncertainty when the confidence is low.
- When asked how to respond to an attack, give practical, defensive, step-by-step actions (containment, investigation, recovery, prevention). Note that "Blocked"/"Logged" in the app are simulated actions.
- Stay defensive: do not give step-by-step instructions for carrying out attacks against systems.
- Be clear and well structured: short paragraphs or bullet points, headings only for longer answers."""

# Tried in order when GEMINI_MODEL is not set or fails. The models a key can use change over time
# (older ones are retired, popular ones return 503 under load), so the app never depends on a single name.
FALLBACK_MODELS = ["gemini-3.8-flash", "gemini-3.7-flash", "gemini-3.6-flash", "gemini-3.5-flash",
                   "gemini-3.5-flash-lite", "gemini-flash-latest"]
_RETRY_CODES = {404, 408, 429, 500, 502, 503, 504}
# How long a model is skipped after it fails: out of quota (429) for a while, overloaded (503) briefly,
# retired (404) for the rest of the session. Without this every question waited on the same failing model.
_COOLDOWN_SECONDS = {429: 600, 404: 86400}
_DEFAULT_COOLDOWN = 60
_cooldown: dict[str, float] = {}
_active = {"model": None}
REQUEST_TIMEOUT_MS = 15_000


# ------------------------------------------------------------------------------------- Gemini
def gemini_key() -> str | None:
    return secret("GEMINI_API_KEY") or secret("GOOGLE_API_KEY")


def llm_available() -> bool:
    return bool(gemini_key())


def _client():
    # keep one client alive per key: a client that is garbage-collected closes its connection mid-stream
    return _client_for(gemini_key())


@functools.lru_cache(maxsize=2)
def _client_for(api_key: str):
    from google import genai
    from google.genai import types

    # The SDK retries a busy model up to 5 times with growing waits (about 15 s in total) before giving up.
    # Fail fast instead and let the app move on to the next model.
    return genai.Client(api_key=api_key, http_options=types.HttpOptions(
        timeout=REQUEST_TIMEOUT_MS, retry_options=types.HttpRetryOptions(attempts=1)))


@functools.lru_cache(maxsize=2)
def _candidates_for(api_key: str, configured: str) -> tuple:
    """Configured model first, then the newest 'gemini-X.Y-flash' models this key can use, then fixed fallbacks."""
    names = [configured] if configured else []
    try:
        found = []
        for m in _client_for(api_key).models.list():
            name = m.name.removeprefix("models/")
            match = re.fullmatch(r"gemini-(\d+(?:\.\d+)?)-flash(-lite)?", name)
            if match and "generateContent" in (m.supported_actions or []):
                found.append((bool(match.group(2)), -float(match.group(1)), name))
        flash = [n for lite, _, n in sorted(found) if not lite][:4]
        lite = [n for is_lite, _, n in sorted(found) if is_lite][:2]  # faster, used when the full models are busy
        names += flash + lite
    except Exception:
        pass
    return tuple(dict.fromkeys(names + FALLBACK_MODELS))


def candidate_models() -> list[str]:
    now = time.time()
    all_models = list(_candidates_for(gemini_key(), secret("GEMINI_MODEL") or ""))
    models = [m for m in all_models if _cooldown.get(m, 0) <= now] or all_models
    if _active["model"] in models:  # the model that answered last time goes first
        models.remove(_active["model"])
        models.insert(0, _active["model"])
    return models


def gemini_model() -> str:
    return _active["model"] or candidate_models()[0]


def _config(system, max_tokens: int, temperature: float, thinking: bool):
    from google.genai import types

    # low thinking: newer Gemini models think before answering, and without a cap the thinking can use
    # the whole output budget and leave an empty answer
    return types.GenerateContentConfig(
        system_instruction=system, temperature=temperature, max_output_tokens=max_tokens,
        thinking_config=types.ThinkingConfig(thinking_level=types.ThinkingLevel.LOW) if thinking else None,
    )


def _reasons(tried) -> list[str]:
    out = []
    for model, err in tried:
        code = getattr(err, "code", None)
        status = getattr(err, "status", None)
        out.append(f"{model}: {code} {status}" if code else f"{model}: {err}")
    return out


def _mark_failed(model: str, exc) -> None:
    code = getattr(exc, "code", None)
    _cooldown[model] = time.time() + _COOLDOWN_SECONDS.get(code, _DEFAULT_COOLDOWN)


def _retryable(exc) -> tuple[bool, bool]:
    """(try the next model?, retry this model without the thinking setting?)"""
    code = getattr(exc, "code", None)
    return code in _RETRY_CODES, code == 400 and "think" in str(exc).lower()


def stream_gemini(history: list[dict], prompt: str):
    """Yield answer text chunks, moving to the next model when one is retired, overloaded or returns nothing."""
    from google.genai import errors

    last_error, tried = None, []
    for model in candidate_models():
        for thinking in (True, False):
            got_text = False
            try:
                stream = _client().models.generate_content_stream(
                    model=model, contents=_contents(history, prompt),
                    config=_config(SYSTEM_PROMPT, 8192, 0.4, thinking))
                for chunk in stream:
                    if chunk.text:
                        got_text = True
                        _active["model"] = model
                        yield chunk.text
                if got_text:
                    return
                last_error = RuntimeError(f"{model} returned an empty answer")
                tried.append((model, "empty answer"))
                break
            except errors.APIError as exc:
                if got_text:
                    raise
                next_model, without_thinking = _retryable(exc)
                last_error = exc
                tried.append((model, exc))
                if next_model:
                    _mark_failed(model, exc)
                if without_thinking and thinking:
                    continue
                if next_model:
                    break
                raise
            except Exception as exc:  # network errors and read timeouts are not APIError: try the next model too
                if got_text:
                    raise
                last_error = exc
                tried.append((model, exc))
                _mark_failed(model, exc)
                break
    raise RuntimeError("no Gemini model answered: " + "; ".join(_reasons(tried)))


def generate_gemini(prompt: str, max_tokens: int = 1024) -> str:
    """One short non-streamed answer, with the same model fallback."""
    from google.genai import errors

    last_error, tried = None, []
    for model in candidate_models():
        for thinking in (True, False):
            try:
                resp = _client().models.generate_content(model=model, contents=prompt,
                                                         config=_config(None, max_tokens, 0.0, thinking))
                if resp.text:
                    _active["model"] = model
                    return resp.text
                break
            except errors.APIError as exc:
                next_model, without_thinking = _retryable(exc)
                last_error = exc
                tried.append((model, exc))
                if next_model:
                    _mark_failed(model, exc)
                if without_thinking and thinking:
                    continue
                if next_model:
                    break
                raise
            except Exception as exc:
                last_error = exc
                tried.append((model, exc))
                _mark_failed(model, exc)
                break
    raise RuntimeError("no Gemini model answered: " + "; ".join(_reasons(tried)))


def _contents(history: list[dict], final_user_text: str) -> list[dict]:
    contents = []
    for m in history:
        role = "model" if m["role"] == "assistant" else "user"
        contents.append({"role": role, "parts": [{"text": m["content"]}]})
    contents.append({"role": "user", "parts": [{"text": final_user_text}]})
    return contents


def is_arabic(text: str) -> bool:
    return bool(re.search(r"[؀-ۿ]", text))


# Arabic words that matter for retrieval, mapped to the English terms used in the knowledge base.
# Translating locally saves a full Gemini round trip on every Arabic question.
_AR_TERMS = {
    "هجوم": "attack", "هجمات": "attacks", "اختراق": "intrusion infiltration", "ثغرة": "vulnerability exploit",
    "حجب": "denial of service DoS", "اغراق": "flood", "إغراق": "flood", "فحص": "scan PortScan",
    "منافذ": "ports PortScan", "بورت": "port", "كلمة السر": "password brute force", "كلمات السر": "password brute force",
    "تخمين": "brute force guessing", "بوت": "Bot botnet", "شبكة": "network", "سيرفر": "server", "خادم": "server",
    "داتا": "dataset data", "بيانات": "dataset data", "عدد": "how many count flows", "كام": "how many count",
    "موديل": "model", "نموذج": "model", "تدريب": "training", "دقة": "accuracy F1",
    "اتعامل": "respond response mitigation", "أتعامل": "respond response mitigation", "حماية": "prevention protection",
    "امنع": "prevent prevention", "أمنع": "prevent prevention", "خطوات": "response steps", "حل": "response mitigation",
    "ليه": "why prediction features", "لماذا": "why prediction features", "سبب": "reason why features",
    "يعني ايه": "what is definition", "يعني إيه": "what is definition", "ايه هو": "what is", "إيه هو": "what is",
    "محاولة": "attempted", "محاولات": "attempted", "تنظيف": "cleaning preprocessing", "خصائص": "features",
    "استرجاع": "retrieval RAG", "مصادر": "sources citations", "حقن": "injection SQL", "سكريبت": "script XSS",
}


def search_query(question: str, alert: dict | None) -> str:
    """English query for the retriever: Arabic keywords are mapped to English terms locally (no extra API call)."""
    extra = ""
    if alert:
        extra = f" {alert['pred_label']} {kb.family_of(alert['pred_label'])}"
    if is_arabic(question):
        terms = [en for ar, en in _AR_TERMS.items() if ar in question]
        latin = " ".join(re.findall(r"[A-Za-z][A-Za-z0-9\-/]*", question))  # English words kept as written
        return f"{latin} {' '.join(terms)}".strip() + extra
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
            f"QUESTION\n{question}\n\n"
            # the language rule is repeated next to the question: the faster lite models follow it more reliably
            # here than in the system instruction, especially when every source passage is in English
            + ("ANSWER LANGUAGE: Arabic (Egyptian dialect if the question is Egyptian). Keep technical terms in English."
               if is_arabic(question) else "ANSWER LANGUAGE: English."))


# ------------------------------------------------------------------------------- offline answers
_WHY = re.compile(r"\bwhy\b|reason|explain (the|this) (prediction|alert)|flag|ليه|لماذا|سبب|اتعلم|اتصنف|ازاي الموديل|إزاي الموديل", re.I)
_RESPOND = re.compile(r"respond|response|mitigat|handle|fix|stop|block|prevent|what should|اتعامل|أتعامل|اعمل ايه|أعمل إيه|حل|امنع|أمنع|اوقف|أوقف|خطوات", re.I)
_WHAT = re.compile(r"what is|what's|explain|describe|tell me about|ايه هو|إيه هو|ما هو|ما هي|اشرح|يعني ايه|يعني إيه", re.I)


def offline_answer(question: str, alert: dict | None, hits: list) -> str:
    """Answer without a language model, from the alert context and the retrieved passages."""
    parts = []
    ar = is_arabic(question)
    label = alert["pred_label"] if alert else None
    a = kb.info(label) if label else None

    if alert and _WHY.search(question):
        if ar:
            verdict = "**هجوم**" if alert["is_attack"] else "traffic **طبيعي**"
            parts.append(f"الـ binary model صنّف الـ flow ده على إنه {verdict}، واحتمال الهجوم **{alert['attack_prob']:.2%}**.")
            if alert["is_attack"]:
                parts.append(f"والـ specialist model حدد نوعه: **{a['name']}** ({a['family']}، severity {alert['severity']}).")
        else:
            verdict = "an **attack**" if alert["is_attack"] else "**benign** traffic"
            parts.append(f"The binary model classified this flow as {verdict} with an attack probability of "
                         f"**{alert['attack_prob']:.2%}**.")
            if alert["is_attack"]:
                parts.append(f"The specialist model identified it as **{a['name']}** ({a['family']}, severity {alert['severity']}).")
        if alert.get("explanation"):
            parts.append("أكتر الـ features اللي أثرت على القرار:" if ar else "The features that pushed the decision the most:")
            for f in alert["explanation"][:5]:
                bm_value = f.get("benign_median")
                if ar:
                    direction = "ناحية الهجوم" if f["contribution"] > 0 else "ناحية الطبيعي"
                    bm = f" (الـ median في الـ traffic الطبيعي: {bm_value:.4g})" if bm_value is not None else ""
                    parts.append(f"- `{f['feature']}` = {f['value']:.4g}{bm}: زقّت القرار {direction}")
                else:
                    direction = "towards attack" if f["contribution"] > 0 else "towards benign"
                    bm = f" (normal traffic median: {bm_value:.4g})" if bm_value is not None else ""
                    parts.append(f"- `{f['feature']}` = {f['value']:.4g}{bm}: pushed {direction}")
        if a and a["indicators"]:
            head = "وده متوافق مع اللي نعرفه عن النوع ده:" if ar else "This matches what we know about this traffic type:"
            parts.append(head + "\n" + "\n".join(f"- {i}" for i in a["indicators"]))
    elif alert and alert["is_attack"] and _RESPOND.search(question):
        parts.append(f"**خطوات التعامل مع {a['name']}** (severity {alert['severity']}):" if ar
                     else f"**Response playbook for {a['name']}** (severity {alert['severity']}):")
        parts += [f"{i}. {s}" for i, s in enumerate(a["response"], 1)]
        if a["prevention"]:
            parts.append("**Prevention:**\n" + "\n".join(f"- {p}" for p in a["prevention"]))
    elif alert and alert["is_attack"] and _WHAT.search(question) and not hits:
        parts.append(f"**{a['name']}**: {a['summary']}\n\n{a['how']}\n\n**Impact:** {a['impact']}")

    if hits and not parts:
        best = rag.best_sentences(question, hits, n=3)
        if best:
            parts.append("من الـ knowledge base:" if ar else "From the knowledge base:")
            for i, sentence in best:
                parts.append(f"- {sentence} [S{i}]")
    if not parts:
        parts.append("ملقيتش إجابة للسؤال ده في الـ knowledge base. جرّب تسأل عن الـ alert المختار (ليه اتعلم عليه، "
                     "وإزاي نتعامل معاه)، أو عن نوع هجوم، أو عن داتا CICIDS2017." if ar else
                     "I could not find an answer to that in the knowledge base. Try asking about the selected alert "
                     "(why it was flagged, how to respond), an attack type, or the CICIDS2017 dataset.")
    parts.append("\n_Offline mode: الإجابة دي من الـ knowledge base بس، لأن Gemini مش متاح دلوقتي._" if ar else
                 "\n_Offline mode: answer built from the knowledge base only, because Gemini is not available right now._")
    return "\n\n".join(parts)
