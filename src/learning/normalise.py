"""Template signatures for unrecognised lines (PLAN 2.3). Pure: no I/O, no vendor knowledge.

A line is split into tokens and every token that varies between devices is replaced by a typed
placeholder: addresses, integers, quoted strings, interface names and the names a device gave its
own objects. `exec-timeout 600` and `exec-timeout 900` then share one signature, so one human answer
covers every device that has the line.

Names are taken from the device's own canonical model (its hostname, the keys of its collections)
rather than guessed from spelling: `as2dept1` is a name on one device and nothing is known about it on
another, and a guess that turns `sha256` into a placeholder would merge settings that mean different
things.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from src.mapping.canonical import Catalogue, Model, parse_path

_TOKEN = re.compile(r'"[^"]*"|\S+')
_KINDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("STR", re.compile(r'^"[^"]*"$')),
    ("IPV4", re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")),
    ("PREFIX", re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")),
    ("MAC", re.compile(r"^(?:[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}|[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})$")),
    ("IPV6", re.compile(r"^(?=.*[0-9A-Fa-f])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:/\d{1,3})?$")),
    ("INT", re.compile(r"^\d+$")),
    # A port name with a slot/port or unit separator: Gi0/1, ge-0/0/0, xe-0/0/0:1, Ethernet1/1.100, lo0.0.
    # Names without one (Loopback0, Vlan10) are recognised from the device's own interface list.
    ("IFACE", re.compile(r"^[A-Za-z][A-Za-z-]*\d+(?:(?:[/:]\d+)+(?:\.\d+)?|\.\d+)$")),
    # A dotted name ending in a word: lab.local, ntp.example.com. Not 1.2.3.4, not lo0.0.
    ("DOMAIN", re.compile(r"^(?=.*[A-Za-z])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z][A-Za-z0-9-]*\.?$")),
)

# What a placeholder matches inside a learned mapping's regex.
SLOT_REGEX = {
    "STR": r'"[^"]*"',
    "IPV4": r"\d{1,3}(?:\.\d{1,3}){3}",
    "PREFIX": r"\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}",
    "MAC": r"(?:[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}|[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})",
    "IPV6": r"[0-9A-Fa-f:]*:[0-9A-Fa-f:]*(?:/\d{1,3})?",
    "INT": r"\d+",
    "IFACE": r"\S+",
    "DOMAIN": r"\S+",
    "NAME": r"\S+(?:\s+\S+)*?",
}

# Values a synthetic fixture uses in place of the operator's: documentation ranges (RFC 5737, 3849,
# 7042), so a learned pack shared with another site carries none of this site's addresses or names.
EXAMPLE = {"STR": '"example"', "IPV4": "192.0.2.1", "PREFIX": "192.0.2.0/24", "MAC": "0000.5e00.5300",
            "IPV6": "2001:db8::1", "NAME": "example", "DOMAIN": "example.com"}


@dataclass(frozen=True)
class Slot:
    kind: str
    text: str
    origin: str | None  # canonical path the value was recognised from, e.g. "interfaces[]"


@dataclass(frozen=True)
class Template:
    parts: tuple[str | Slot, ...]  # literal tokens, and a Slot wherever a varying value was cut out

    @property
    def slots(self) -> tuple[Slot, ...]:
        return tuple(p for p in self.parts if isinstance(p, Slot))

    @property
    def literals(self) -> tuple[str, ...]:
        return tuple(p for p in self.parts if isinstance(p, str))

    @property
    def signature(self) -> str:
        return " ".join(f"<{p.kind}>" if isinstance(p, Slot) else p for p in self.parts)


Identifiers = dict[tuple[str, ...], tuple[str, str]]  # token sequence -> (kind, origin)


def identifiers(model: Model | None, catalogue: Catalogue) -> Identifiers:
    """Names this device gave its own objects: its hostname and the keys of its collection items."""
    out: Identifiers = {}
    if not model:
        return out
    host = model["device"]["hostname"]["value"]
    if isinstance(host, str) and host.strip():
        out[tuple(host.split())] = ("NAME", "device.hostname")
    for path, spec in catalogue.fields.items():
        if not (spec.collection and spec.key and path.count("[]") == 1):
            continue
        holder: Any = model
        for seg in parse_path(path):
            holder = holder[seg.name]
        kind = "IFACE" if path == "interfaces[]" else "NAME"
        for item in holder["items"]:
            value = item[spec.key]["value"]
            if isinstance(value, str) and value.strip():
                out[tuple(value.split())] = (kind, path)
    return out


def _classify(token: str) -> str | None:
    for kind, pattern in _KINDS:
        if pattern.match(token):
            return kind
    return None


def normalise(text: str, known: Identifiers | None = None) -> Template:
    """Cut every varying token out of `text`. Known names win over the generic token classes."""
    words = _TOKEN.findall(text)
    by_length = sorted((known or {}).items(), key=lambda kv: -len(kv[0]))
    parts: list[str | Slot] = []
    i = 0
    while i < len(words):
        for seq, (kind, origin) in by_length:
            if tuple(words[i:i + len(seq)]) == seq:
                parts.append(Slot(kind, " ".join(seq), origin))
                i += len(seq)
                break
        else:
            found = _classify(words[i])
            parts.append(words[i] if found is None else Slot(found, words[i], None))
            i += 1
    return Template(tuple(parts))


def example_line(raw: str, known: Identifiers | None = None) -> str:
    """`raw` with its indentation kept and every slot replaced by a documentation value.

    Integers and interface names are kept: they identify nothing, and a fixture reads better with the
    real port and number in it.
    """
    indent = raw[: len(raw) - len(raw.lstrip(" \t"))]
    parts = normalise(raw.strip(), known).parts
    return indent + " ".join(EXAMPLE.get(p.kind, p.text) if isinstance(p, Slot) else p for p in parts)
