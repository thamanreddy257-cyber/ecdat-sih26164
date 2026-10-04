"""CSV export and a simple PDF report (reportlab, no network)."""
from __future__ import annotations

import html
import io
from datetime import datetime, timezone

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from risk import TIERS, tier_counts

NAVY = colors.HexColor("#0b2545")
TIER_COLORS = {"Critical": "#d03b3b", "High": "#ec835a", "Medium": "#fab219", "Low": "#0ca30c"}

CSV_COLUMNS = ["tier", "asset", "algorithm", "param", "family", "file", "line", "confidence",
               "quantum_vulnerable", "classically_weak", "criticality", "X", "Y", "Z", "overshoot",
               "replacement", "effort", "rule_id", "snippet", "cert_not_after", "cert_days_left"]


def to_csv(df: pd.DataFrame) -> bytes:
    cols = [c for c in CSV_COLUMNS if c in df.columns]
    return df[cols].to_csv(index=False).encode("utf-8")


def _table(data, widths, header_bg=NAVY):
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), header_bg),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c8d1dc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f5f9")]),
    ]))
    return t


def to_pdf(df: pd.DataFrame, roadmap_df: pd.DataFrame, scenario: dict, target: str) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=12 * mm, rightMargin=12 * mm,
                            topMargin=12 * mm, bottomMargin=12 * mm, title="ECDAT report")
    ss = getSampleStyleSheet()
    h1, h2, body = ss["Title"], ss["Heading2"], ss["BodyText"]
    small = ss["BodyText"].clone("small", fontSize=7.5, leading=9)
    P = lambda t: Paragraph(html.escape(str(t)), small)   # escape <, & from code snippets

    counts = tier_counts(df)
    story = [
        Paragraph("ECDAT - Cryptographic Discovery &amp; Analysis Report", h1),
        Paragraph(f"Target: <b>{html.escape(target)}</b> &nbsp; | &nbsp; Generated: "
                  f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC &nbsp; | &nbsp; Phase 1 prototype", body),
        Paragraph(f"Mosca scenario: migration time Y = {scenario['Y']} y, years to CRQC Z = {scenario['Z']} y "
                  f"(Z is a scenario parameter, not a prediction). Shelf-life X is set per folder.", body),
        Spacer(1, 4 * mm),
        Paragraph("Summary", h2),
    ]
    summary = [["Total findings"] + TIERS, [str(len(df))] + [str(counts[t]) for t in TIERS]]
    st = _table(summary, [40 * mm] + [30 * mm] * 4)
    for i, t in enumerate(TIERS, start=1):
        st.setStyle(TableStyle([("BACKGROUND", (i, 0), (i, 0), colors.HexColor(TIER_COLORS[t]))]))
    story += [st, Spacer(1, 4 * mm), Paragraph("Prioritised migration roadmap", h2)]

    rm = [["#", "Tier", "Asset", "Count", "Replacement", "Trade-off", "Effort"]]
    for r in roadmap_df.itertuples():
        rm.append([r.priority, r.tier, P(r.asset), r.occurrences, P(r.replacement), P(r.tradeoff), r.effort])
    story += [_table(rm, [8 * mm, 18 * mm, 45 * mm, 13 * mm, 85 * mm, 90 * mm, 14 * mm]),
              Spacer(1, 4 * mm), Paragraph("Inventory", h2)]

    inv = [["Tier", "Asset", "Family", "File:line", "Conf.", "QV", "Snippet"]]
    for r in df.itertuples():
        inv.append([r.tier, P(r.asset), r.family, P(f"{r.file}:{r.line}"), r.confidence,
                    "yes" if r.quantum_vulnerable else "no", P(str(r.snippet)[:120])])
    story += [_table(inv, [18 * mm, 45 * mm, 22 * mm, 55 * mm, 14 * mm, 10 * mm, 109 * mm]),
              Spacer(1, 4 * mm),
              Paragraph("Scope: Phase 1 prototype - source code, configuration and certificate scanning. "
                        "Binary, container and KMS/HSM connectors are on the roadmap. Findings marked "
                        "'medium' confidence are keyword matches and should be reviewed by hand.", small)]
    doc.build(story)
    return buf.getvalue()
