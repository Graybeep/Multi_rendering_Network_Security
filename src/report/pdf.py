"""Per-device PDF: identification, summary with coverage, findings by severity with cited lines, remediation.

Returns bytes; writing the file is the caller's job. Built-in PDF fonts only — nothing fetched.
"""

from __future__ import annotations

import io
import json
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

INK = colors.HexColor("#1f2328")
MUTED = colors.HexColor("#59636e")
RULE = colors.HexColor("#d1d9e0")
VERDICT_COLOURS = {
    "FAIL": colors.HexColor("#b42318"),
    "PASS": colors.HexColor("#1a7f37"),
    # Deliberately neutral: NOT_DETERMINED means "we did not read this", not a soft failure.
    "NOT_DETERMINED": colors.HexColor("#3b5bdb"),
}
VERDICT_LABELS = {"FAIL": "FAIL", "PASS": "PASS", "NOT_DETERMINED": "NOT DETERMINED"}
SEVERITIES = ("critical", "high", "medium", "low", "info")

_base = getSampleStyleSheet()
H1 = ParagraphStyle("h1", parent=_base["Heading1"], fontSize=16, textColor=INK, spaceAfter=2 * mm)
H2 = ParagraphStyle("h2", parent=_base["Heading2"], fontSize=12, textColor=INK, spaceBefore=5 * mm,
                    spaceAfter=2 * mm)
BODY = ParagraphStyle("body", parent=_base["BodyText"], fontSize=9, leading=12, textColor=INK)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=8, leading=10, textColor=MUTED)
CODE = ParagraphStyle("code", parent=BODY, fontName="Courier", fontSize=8, leading=10,
                      backColor=colors.HexColor("#f6f8fa"), borderPadding=4, leftIndent=4)


def _p(text: Any, style: ParagraphStyle = BODY) -> Paragraph:
    return Paragraph(escape("" if text is None else str(text)), style)


def _kv_table(rows: list[tuple[str, Any]]) -> Table:
    t = Table([[_p(k, SMALL), _p(v)] for k, v in rows], colWidths=[38 * mm, 132 * mm])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, RULE),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _evidence_table(evidence: list[dict[str, Any]]) -> Table | None:
    if not evidence:
        return None
    rows = [[_p("Line", SMALL), _p("Config (redacted)", SMALL), _p("Canonical field", SMALL), _p("State", SMALL)]]
    for e in evidence:
        if e["line_no"]:
            line, text = str(e["line_no"]), e["text"]
        elif e["state"] == "defaulted":
            line, text = "—", f"not configured; pack default = {json.dumps(e.get('value'))}"
        elif e["state"] == "mapped":
            value = e.get("value")
            line, text = "—", "read; none configured" if value == [] else f"read; value = {json.dumps(value)}"
        else:
            line, text = "—", "not read"
        rows.append([_p(line), Paragraph(escape(text or ""), CODE if e["line_no"] else BODY),
                     _p(e["canonical_field"], SMALL), _p(e["state"], SMALL)])
    t = Table(rows, colWidths=[12 * mm, 88 * mm, 50 * mm, 20 * mm], repeatRows=1)
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, MUTED),
        ("LINEBELOW", (0, 1), (-1, -1), 0.25, RULE),
    ]))
    return t


def _finding(f: dict[str, Any]) -> list[Any]:
    colour = VERDICT_COLOURS[f["verdict"]].hexval()[2:]
    control = f.get("control") or "uncited"
    head = (f'<font color="#{colour}"><b>{VERDICT_LABELS[f["verdict"]]}</b></font>  '
            f'<b>{escape(f["rule_id"])}</b> — {escape(f["title"])}')
    parts: list[Any] = [Paragraph(head, BODY),
                        _p(f'Severity {f["severity"]} · control {control} · {f["rule_pack_version"]}', SMALL)]
    if f["verdict"] == "NOT_DETERMINED":
        reason = f.get("error") or ("required fields not read from this configuration: "
                                    + ", ".join(f["missing_fields"]))
        parts.append(_p(f"Not determined — {reason}. This is not a failure.", SMALL))
    table = _evidence_table(f["evidence"][:40])
    if table is not None:
        parts += [Spacer(1, 1.5 * mm), table]
    if len(f["evidence"]) > 40:
        parts.append(_p(f"… {len(f['evidence']) - 40} more evidence rows in the JSON output.", SMALL))
    fix = f.get("remediation")
    if fix:
        flags = ["reload required" if fix["reload_required"] else "no reload required"]
        if fix.get("operator_input"):
            flags.append("replace before pasting: " + ", ".join(fix["operator_input"]))
        parts += [Spacer(1, 1.5 * mm), _p(f'Remediation ({fix["fix_id"]}; {"; ".join(flags)})', SMALL),
                  Preformatted("\n".join(fix["commands"]), CODE)]
        if fix.get("note"):
            parts.append(_p(f"Note: {fix['note']}", SMALL))
    elif f["verdict"] == "FAIL":
        parts.append(_p("No remediation template for this vendor and OS version.", SMALL))
    parts.append(Spacer(1, 4 * mm))
    return [KeepTogether(parts[:4]), *parts[4:]]


def render_pdf(result: dict[str, Any], generated_at: str) -> bytes:
    ident = result["identity"]
    packs = sorted({f["rule_pack_version"] for f in result["findings"]})
    buf = io.BytesIO()
    footer = f'{result["filename"]} · vendor pack {result["vendor_pack"] or "none detected"} · ' \
             f'rule packs {", ".join(packs) or "none"}'

    def on_page(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(20 * mm, 10 * mm, footer[:150])
        canvas.drawRightString(190 * mm, 10 * mm, f"page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
                            topMargin=18 * mm, bottomMargin=18 * mm,
                            title=f"Compliance report {ident['hostname'] or result['filename']}")
    story: list[Any] = [
        _p(f"Configuration compliance report — {ident['hostname'] or result['filename']}", H1),
        _p(f"Generated {generated_at}. Audited from exported configuration text; this reflects what the "
           "device was configured to do, not its runtime state.", SMALL),
        _p("Device", H2),
        _kv_table([
            ("Hostname", ident["hostname"] or "not detected"),
            ("Vendor / OS", f"{ident['vendor'] or '?'} / {ident['os_family'] or '?'}"),
            ("OS version", ident["os_version"] or "not detected"),
            ("Model", ident["model"] or "not in configuration"),
            ("Serial", ident["serial"] or "not in configuration"),
            ("Source file", result["filename"]),
            ("SHA-256", result["sha256"]),
            ("Vendor pack", result["vendor_pack"] or "none detected — every rule is NOT DETERMINED"),
            ("Rule packs", ", ".join(packs) or "none"),
        ]),
    ]

    v, c = result["verdicts"], result["coverage"]
    total = v["pass"] + v["fail"]
    rate = f"{100 * v['pass'] / total:.0f}% of determined rules pass" if total else "no rule could be determined"
    story += [
        _p("Summary", H2),
        _kv_table([
            ("Verdicts", f"{v['fail']} FAIL · {v['pass']} PASS · {v['not_determined']} NOT DETERMINED"),
            ("Compliance", rate),
            ("Coverage", (f"{100 * c['ratio']:.0f}% of canonical fields known "
                          f"({c['mapped']} read, {c['defaulted']} pack default, {c['unknown']} not read)")),
        ]),
        _p("NOT DETERMINED means a field the rule needs was not read from this file. It is never counted "
           "as a failure; teach the system the missing command and re-run.", SMALL),
    ]
    if result.get("warnings"):
        story += [_p("Warnings", H2)] + [_p(w, SMALL) for w in result["warnings"]]

    for sev in SEVERITIES:
        group = [f for f in result["findings"] if f["severity"] == sev]
        if group:
            story.append(_p(f"{sev.capitalize()} severity ({len(group)})", H2))
            for f in group:
                story += _finding(f)

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()
