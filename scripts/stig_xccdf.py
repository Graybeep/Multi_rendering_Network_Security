"""Extract rules from a DISA STIG XCCDF file, so rule packs cite the source instead of retyping it.

    python -I scripts/stig_xccdf.py <xccdf.xml> [STIG-ID,STIG-ID,...] > out.md

With no IDs, prints one row per rule: group id (V-…), STIG id, severity, SRG id, CCIs, title. With IDs, prints
those rules in full: the same fields plus check and fix text, verbatim. DISA STIGs are US government work and
may be redistributed; CIS and ISO text may not, and this tool never reads it.

The XCCDF is untrusted input: parsed with defusedxml (CLAUDE.md invariant 1).
"""

from __future__ import annotations

import sys
from xml.etree.ElementTree import Element

from defusedxml.ElementTree import parse

NS = {"x": "http://checklists.nist.gov/xccdf/1.1"}


def _text(node: Element | None) -> str:
    return (node.text or "").strip() if node is not None else ""


def rules(path: str) -> tuple[str, list[dict[str, str]]]:
    root = parse(path).getroot()
    release = _text(root.find("x:plain-text[@id='release-info']", NS))
    header = f"{_text(root.find('x:title', NS))} — {release}"
    out = []
    for group in root.findall("x:Group", NS):
        rule = group.find("x:Rule", NS)
        if rule is None:
            continue
        out.append({
            "group": group.get("id", ""),
            "stig_id": _text(rule.find("x:version", NS)),
            "severity": rule.get("severity", ""),
            "srg": _text(group.find("x:title", NS)),
            "cci": ", ".join(_text(i) for i in rule.findall("x:ident", NS) if i.get("system", "").endswith("cci")),
            "title": _text(rule.find("x:title", NS)),
            "check": _text(rule.find("x:check/x:check-content", NS)),
            "fix": _text(rule.find("x:fixtext", NS)),
        })
    return header, out


def main() -> None:
    header, found = rules(sys.argv[1])
    wanted = sys.argv[2].split(",") if len(sys.argv) > 2 else None
    print(f"## {header}\n")
    if wanted is None:
        print("| group | STIG id | severity | SRG | CCI | title |\n|---|---|---|---|---|---|")
        for r in found:
            print(f"| {r['group']} | {r['stig_id']} | {r['severity']} | {r['srg']} | {r['cci']} | {r['title']} |")
        return
    for r in (r for r in found if r["stig_id"] in wanted):
        print(f"### {r['stig_id']} ({r['group']}) — {r['severity']}\n")
        print(f"- SRG: `{r['srg']}`\n- CCI: {r['cci']}\n- Title: {r['title']}\n")
        print(f"Check:\n\n```\n{r['check']}\n```\n\nFix:\n\n```\n{r['fix']}\n```\n")


if __name__ == "__main__":
    main()
