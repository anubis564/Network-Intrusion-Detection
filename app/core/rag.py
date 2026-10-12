"""Retrieval for the assistant: chunk the knowledge files, index them with TF-IDF, rank by cosine similarity.

Runs fully offline (no embedding API), so retrieval works even without a Gemini key.
"""
import re
from dataclasses import dataclass

import numpy as np
import streamlit as st
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS, TfidfVectorizer

from core import knowledge as kb
from core.config import KNOWLEDGE_DIR

CHUNK_CHARS = 900
OVERLAP_CHARS = 150
QA_SOURCE = "Question bank"


@dataclass
class Chunk:
    source: str
    title: str
    text: str


def _split_long(text: str) -> list[str]:
    if len(text) <= CHUNK_CHARS:
        return [text]
    parts, start = [], 0
    while start < len(text):
        end = min(start + CHUNK_CHARS, len(text))
        if end < len(text):  # cut at a sentence end when possible
            cut = text.rfind(". ", start + CHUNK_CHARS // 2, end)
            end = cut + 1 if cut != -1 else end
        parts.append(text[start:end].strip())
        if end >= len(text):
            break
        start = max(end - OVERLAP_CHARS, start + 1)
    return parts


def _markdown_chunks(path) -> list[Chunk]:
    raw = path.read_text(encoding="utf-8")
    doc_title = next((l[2:].strip() for l in raw.splitlines() if l.startswith("# ")), path.stem)
    sections = re.split(r"\n(?=#{2,3} )", raw)
    chunks = []
    for sec in sections:
        lines = sec.strip().splitlines()
        if not lines:
            continue
        title = lines[0].lstrip("# ").strip() if lines[0].startswith("#") else doc_title
        body = "\n".join(lines[1:] if lines[0].startswith("#") else lines).strip()
        if not body:
            continue
        for piece in _split_long(body):
            chunks.append(Chunk(source=doc_title, title=title, text=f"{title}\n{piece}"))
    return chunks


@st.cache_resource(show_spinner="Indexing the knowledge base...")
def build_index():
    chunks = []
    for path in sorted(KNOWLEDGE_DIR.glob("*.md")):
        chunks.extend(_markdown_chunks(path))
    for doc in kb.as_documents():
        for piece in _split_long(doc["text"]):
            chunks.append(Chunk(source="Attack library", title=doc["source"].split(" - ", 1)[-1], text=piece))
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, stop_words="english",
                                 token_pattern=r"(?u)\b[\w\-/']+\b")
    matrix = vectorizer.fit_transform([c.text for c in chunks])
    return chunks, vectorizer, matrix


def retrieve(query: str, top_k: int = 4, exclude_sources: tuple = ()) -> list[tuple[Chunk, float]]:
    chunks, vectorizer, matrix = build_index()
    q = vectorizer.transform([query])
    scores = (matrix @ q.T).toarray().ravel()  # rows are L2-normalised, so this is cosine similarity
    order = np.argsort(scores)[::-1]
    hits = []
    for i in order:
        if scores[i] <= 0 or len(hits) == top_k:
            break
        if chunks[i].source in exclude_sources:
            continue
        hits.append((chunks[i], float(scores[i])))
    return hits


def best_sentences(query: str, hits: list, n: int = 3) -> list[tuple[int, str]]:
    """The sentences (or table rows) from the retrieved passages that best match the query.

    Returns (source number, sentence) pairs; source numbers are 1-based positions in ``hits``.
    """
    _, vectorizer, _ = build_index()
    candidates = []
    for i, (c, _) in enumerate(hits, 1):
        body = c.text.split("\n", 1)[-1]
        header = None
        for line in body.splitlines():
            line = line.strip(" -")
            if not line or set(line) <= set("|-: "):
                continue
            if line.startswith("|"):  # table row: spell out "column: value" using the header row
                cells = [x.strip() for x in line.strip("|").split("|")]
                if header is None:
                    header = cells
                    continue
                candidates.append((i, ", ".join(f"{h}: {v}" for h, v in zip(header, cells))))
                continue
            header = None
            candidates += [(i, s.strip()) for s in re.split(r"(?<=[.!?])\s+", line)
                           if len(s.strip()) > 3 and not s.strip().endswith(":")]
    if not candidates:
        return []
    q = vectorizer.transform([query])
    scores = (vectorizer.transform([s for _, s in candidates]) @ q.T).toarray().ravel()
    order = [k for k in np.argsort(scores)[::-1] if scores[k] > 0][:n]
    return [candidates[k] for k in sorted(order)]


# ------------------------------------------------------------------------------------ evaluation
def question_bank() -> list[tuple[str, str]]:
    path = KNOWLEDGE_DIR / "qa_bank.md"
    if not path.exists():
        return []
    pairs = re.findall(r"### Q\d+\. (.+?)\n(.+?)(?=\n### |\Z)", path.read_text(encoding="utf-8"), flags=re.S)
    return [(q.strip(), a.strip()) for q, a in pairs]


_GENERIC = {"page", "states", "state", "lists", "listed", "answer", "mentioned", "shows", "table"}


def _stem(word: str) -> str:
    word = word.replace("our", "or") if word.endswith("our") else word  # behaviour -> behavior
    for suffix in ("ing", "ed", "es", "s"):
        if word.endswith(suffix) and len(word) - len(suffix) >= 4:
            return word[: -len(suffix)]
    return word


def _terms(text: str) -> set[str]:
    words = re.findall(r"[a-z0-9][a-z0-9\-/']*", text.lower().replace(",", "").replace("–", "-").replace("behaviour", "behavior"))
    return {w if w.isdigit() else _stem(w) for w in words
            if w.isdigit() or (w not in ENGLISH_STOP_WORDS and w not in _GENERIC and len(w) > 2)}


def supports(answer: str, passage: str) -> bool:
    """A passage supports an answer when it contains every number in it and most of its key terms."""
    a, p = _terms(answer), _terms(passage)
    numbers = {w for w in a if w.isdigit() and len(w) > 1}
    if numbers and not numbers <= p:
        return False
    return len(a & p) / max(len(a), 1) >= 0.5


def evaluate(top_k: int = 4) -> list[dict]:
    """Run the question bank through the retriever (the bank itself is excluded from the index)."""
    rows = []
    for q, a in question_bank():
        hits = retrieve(q, top_k=top_k, exclude_sources=(QA_SOURCE,))
        hit_rank = next((r for r, (c, _) in enumerate(hits, 1) if supports(a, c.text)), None)
        rows.append({"question": q, "expected": a, "hit": hit_rank is not None, "rank": hit_rank,
                     "top_source": f"{hits[0][0].source} > {hits[0][0].title}" if hits else "-",
                     "top_score": round(hits[0][1], 3) if hits else 0.0})
    return rows
