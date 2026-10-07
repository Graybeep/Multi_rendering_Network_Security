"""Cluster unrecognised lines across a batch (PLAN 2.4). Pure: device results in, clusters out.

Lines with the same vendor pack, the same enclosing-block signature and the same line signature form
one cluster, so one question to the administrator covers every device that has the line. Clusters are
sorted by how many devices they cover, most first.

Block headers (`router bgp 65000`, `interface Gi0/1`) are not questions: what they open is described by
the lines inside them, and a learned mapping uses the header only as its scope.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from src.learning.normalise import Identifiers, Template, identifiers, normalise
from src.mapping.canonical import Catalogue

MAX_MEMBERS = 200  # occurrences kept per cluster to check a learned mapping against; all are counted


@dataclass(frozen=True)
class Member:
    device_id: str
    text: str  # statement text as the reader produced it (redacted)
    raw: str  # redacted source line, indentation kept
    parent_text: str | None
    parent_raw: str | None
    line: Template
    scope: Template | None
    known: Identifiers


@dataclass
class Cluster:
    cluster_id: str
    vendor: str  # vendor pack id
    signature: str
    scope: str | None
    members: list[Member] = field(default_factory=list)
    devices: set[str] = field(default_factory=set)
    occurrences: int = 0

    @property
    def sample(self) -> Member:
        return self.members[0]

    def view(self) -> dict[str, Any]:
        """Shaped like `Cluster` in docs/openapi.yaml."""
        return {"cluster_id": self.cluster_id, "vendor": self.vendor, "signature": self.signature,
                "sample_line": self.sample.raw.strip(), "device_count": len(self.devices),
                "occurrence_count": self.occurrences, "scope": self.scope}


def cluster_id(vendor: str, scope: str | None, signature: str) -> str:
    """Stable across scans: the same pattern under the same pack is the same question."""
    digest = hashlib.sha256(f"{vendor}\n{scope or ''}\n{signature}".encode()).hexdigest()
    return "c" + digest[:16]


def build_clusters(results: Iterable[dict[str, Any]], catalogue: Catalogue) -> list[Cluster]:
    """`results` are audit results (see src/audit.py). Devices without a vendor pack are skipped:
    a learned mapping belongs to a pack, and an undetected device has none to extend."""
    clusters: dict[str, Cluster] = {}
    for result in results:
        if result.get("status") != "done" or not result.get("vendor_pack"):
            continue
        vendor = str(result["vendor_pack"]).split("@", 1)[0]
        known = identifiers(result.get("canonical"), catalogue)
        for u in result.get("unmatched") or []:
            if not u.get("leaf", True):
                continue
            line = normalise(u["text"], known)
            if not line.parts:
                continue
            parent_text = u["scope"][-1] if u.get("scope") else None
            scope = normalise(parent_text, known) if parent_text else None
            scope_sig = scope.signature if scope else None
            cid = cluster_id(vendor, scope_sig, line.signature)
            c = clusters.get(cid)
            if c is None:
                c = clusters[cid] = Cluster(cid, vendor, line.signature, scope_sig)
            c.devices.add(str(result["device_id"]))
            c.occurrences += 1
            if len(c.members) < MAX_MEMBERS:
                c.members.append(Member(str(result["device_id"]), u["text"], u.get("raw") or u["text"],
                                        parent_text, u.get("parent_raw"), line, scope, known))
    return sorted(clusters.values(), key=lambda c: (-len(c.devices), -c.occurrences, c.signature))
