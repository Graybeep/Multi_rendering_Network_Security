"""Redaction never changes structure. Catches the class of bug where a mask eats a delimiter (`key 0 {` → `key 0 ****`),
which fails the whole file rather than one field. Value-level cases live in test_redaction_cases.py.

Invariant, per line: the same line count, and the same sequence of `{ } ; [ ]` outside quoted strings. A quoted secret
may contain any character; masking it removes the string, not a delimiter around it.
"""

import itertools
import re
from pathlib import Path

import pytest

from src.ingest.redact import redact, redact_line
from tests.conftest import ROOT

_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*(?:"|$)')  # an unterminated quote runs to end of line, as the readers read it
_DELIM = re.compile(r"[^{};\[\]]")

FIXTURES = sorted(p for p in (ROOT / "fixtures" / "configs").rglob("*") if p.is_file() and p.name != "SOURCE.md")


def _delimiters(line: str) -> str:
    return _DELIM.sub("", _QUOTED.sub("", line))


def _assert_structure_kept(before: list[str], after: list[str]) -> None:
    assert len(after) == len(before)
    for no, (a, b) in enumerate(zip(before, after, strict=True), start=1):
        assert _delimiters(b) == _delimiters(a), f"line {no}: {a!r} -> {b!r}"


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_redaction_keeps_line_count_and_delimiters_of_every_fixture(path: Path) -> None:
    text = path.read_text(errors="replace")
    _assert_structure_kept([line.rstrip("\r") for line in text.split("\n")], redact(text))


# Every secret keyword the redactor knows, in every brace-form shape a keyword line can take.
_KEYWORDS = ["secret", "password", "encrypted-password", "pre-shared-key", "authentication-password",
             "privacy-password", "authentication-key", "key", "key 0", "key-string", "community", "ascii-text",
             "hexadecimal", "snmp community", "message-digest-key 1 md5"]
_SHAPES = ["{kw} {{", "{kw} X {{", "{kw} X;", '{kw} "X";', '{kw} "a {{ b";', '{kw} "X"; ## SECRET-DATA',
           "{kw} [ X Y ];", "{kw} X; }}", "inactive: {kw} {{"]


@pytest.mark.parametrize("kw, shape", list(itertools.product(_KEYWORDS, _SHAPES)))
def test_no_secret_construct_eats_a_delimiter(kw: str, shape: str) -> None:
    line = "    " + shape.format(kw=kw)
    _assert_structure_kept([line], [redact_line(line)])
