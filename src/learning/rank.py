"""Lexical ranking of canonical fields for an unrecognised line (PLAN 2.5). Pure.

A search box over our own schema: the line's words are compared with each field's plain-English
description and path, by TF-IDF cosine plus plain token overlap. The output pre-fills a form; a
human picks the field. Nothing here writes to a canonical model or influences a verdict.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from src.learning.author import learnable
from src.learning.cluster import Cluster
from src.mapping.canonical import Catalogue, FieldSpec

TIER = "lexical"
_WORD = re.compile(r"[a-z0-9]+")
_STOP = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has", "in", "is", "it", "its", "may",
    "no", "not", "of", "on", "only", "or", "such", "than", "that", "the", "their", "them", "this", "to",
    "with", "which", "whether", "what", "when", "how", "many", "much", "one", "other", "set",
})


def _stem(word: str) -> str:
    if len(word) > 4 and word.endswith("ies"):
        return word[:-3] + "y"
    if len(word) > 3 and word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word


def words(text: str) -> list[str]:
    """Lower-case stems. A hyphenated or underscored compound also yields its joined form, so
    `time-out` meets `timeout` and `proxy_arp` meets `proxy-arp`."""
    out: list[str] = []
    for chunk in text.lower().split():
        parts = _WORD.findall(chunk)
        if len(parts) > 1:
            out.append("".join(parts))
        out.extend(parts)
    return [_stem(w) for w in out if w not in _STOP and not w.isdigit()]


def _field_words(path: str, spec: FieldSpec) -> list[str]:
    # The path's own words count twice: `services.ssh.timeout` says what the field is more exactly
    # than any sentence about it.
    path_words = words(path.replace(".", " ").replace("[]", " "))
    return words(spec.description) + path_words * 2


def _value_kind(spec: FieldSpec) -> str:
    t = (spec.value_schema or {}).get("type", "string")
    types = [t] if isinstance(t, str) else list(t)
    return next((x for x in types if x != "null"), "string")


def _compatible(spec: FieldSpec, value_slots: list[str]) -> bool:
    """Can a line with these unbound slots fill this field? Integers need an integer to capture;
    booleans and strings can take a fixed value the administrator states."""
    kind = _value_kind(spec)
    if kind == "integer":
        return "INT" in value_slots
    return True


def rank(cluster: Cluster, catalogue: Catalogue, limit: int = 5) -> list[dict[str, Any]]:
    """Candidates shaped like `Suggestion` in docs/openapi.yaml, best first. Zero scores are dropped."""
    sample = cluster.sample
    query: list[str] = []
    for template in (sample.scope, sample.line):
        if template is not None:
            query.extend(w for lit in template.literals for w in words(lit))
    origins = {s.origin for t in (sample.scope, sample.line) if t for s in t.slots if s.origin}
    for origin in origins:  # a slot recognised as an interface name says the line is about interfaces
        query.extend(words(origin.replace(".", " ").replace("[]", " ")))
    value_slots = [s.kind for s in sample.line.slots if s.origin is None or s.origin == "device.hostname"]
    if not query:
        return []

    fields = {p: s for p, s in catalogue.fields.items() if learnable(p, catalogue) is None}
    docs = {p: Counter(_field_words(p, s)) for p, s in fields.items()}
    df: Counter[str] = Counter()
    for counts in docs.values():
        df.update(counts.keys())
    n = len(docs)

    def idf(w: str) -> float:
        return math.log((1 + n) / (1 + df[w])) + 1.0

    q_counts = Counter(query)
    q_vec = {w: c * idf(w) for w, c in q_counts.items()}
    q_norm = math.sqrt(sum(v * v for v in q_vec.values()))
    out: list[dict[str, Any]] = []
    for path, counts in docs.items():
        d_vec = {w: c * idf(w) for w, c in counts.items()}
        d_norm = math.sqrt(sum(v * v for v in d_vec.values()))
        cosine = sum(q_vec[w] * d_vec.get(w, 0.0) for w in q_vec) / (q_norm * d_norm) if d_norm else 0.0
        overlap = len(set(q_counts) & set(counts)) / len(q_counts)
        score = 0.6 * cosine + 0.4 * overlap
        if not _compatible(fields[path], value_slots):
            score *= 0.5
        if score > 0:
            out.append({"canonical_field": path, "score": round(min(score, 1.0), 4), "tier": TIER,
                        "description": fields[path].description})
    out.sort(key=lambda c: (-c["score"], c["canonical_field"]))
    return out[:limit]
