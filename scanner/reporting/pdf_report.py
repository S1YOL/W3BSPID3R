from __future__ import annotations
"""
scanner/reporting/pdf_report.py
---------------------------------
PDF report generator for executive-friendly vulnerability reports.

Uses fpdf2 (a lightweight pure-Python PDF library) to produce
professional reports with:
  - Cover page with scan metadata
  - Executive summary with severity statistics
  - Detailed findings with payloads and remediation
  - Colour-coded severity indicators
  - Print-optimised layout

Requires: pip install fpdf2

Usage:
    from scanner.reporting.pdf_report import write_pdf_report
    path = write_pdf_report(summary, "scan_report.pdf")
"""

import logging
from pathlib import Path
from typing import Optional

from scanner.reporting.models import Finding, ScanSummary, Severity

logger = logging.getLogger(__name__)

# Severity → RGB colour mapping
_SEV_COLORS = {
    Severity.CRITICAL: (220, 38, 38),     # Red
    Severity.HIGH:     (234, 88, 12),      # Orange
    Severity.MEDIUM:   (202, 138, 4),      # Yellow/Amber
    Severity.LOW:      (37, 99, 235),      # Blue
}


def write_pdf_report(summary: ScanSummary, output_path: str) -> Path:
    """
    Generate a professional PDF vulnerability report.

    Args:
        summary     : Completed ScanSummary from the scanner.
        output_path : Destination .pdf file path.

    Returns:
        Path to the written PDF file.

    Raises:
        ImportError if fpdf2 is not installed.
    """
    try:
        from fpdf import FPDF
    except ImportError:
        raise ImportError(
            "PDF report generation requires fpdf2. "
            "Install with: pip install fpdf2"
        )

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    pdf = _W3BSP1D3RPDF()
    pdf.set_auto_page_break(auto=True, margin=20)

    # Cover page
    _add_cover_page(pdf, summary)

    # Executive summary
    _add_executive_summary(pdf, summary)

    # Findings
    _add_findings(pdf, summary)

    # Write output
    pdf.output(str(path))
    logger.info("PDF report written to %s", path)
    return path


class _W3BSP1D3RPDF:
    """Wrapper around FPDF with helper methods for the report."""

    def __init__(self):
        from fpdf import FPDF
        self._pdf = FPDF()
        self._pdf.set_margins(15, 15, 15)

    def __getattr__(self, name):
        return getattr(self._pdf, name)

    def output(self, path: str):
        self._pdf.output(path)


def _add_cover_page(pdf: _W3BSP1D3RPDF, summary: ScanSummary) -> None:
    """Add a cover page with scan metadata."""
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 28)
    pdf.ln(40)
    pdf.cell(0, 15, "W3BSP1D3R", new_x="LMARGIN", new_y="NEXT", align="C")

    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 10, "Web Vulnerability Scan Report", new_x="LMARGIN", new_y="NEXT", align="C")

    pdf.ln(20)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(0, 0, 0)

    meta = [
        ("Target", summary.target_url),
        ("Scan Type", summary.scan_type),
        ("Started", summary.started_at),
        ("Finished", summary.finished_at),
        ("Total Findings", str(summary.total_findings)),
    ]

    for label, value in meta:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(50, 8, f"{label}:", new_x="RIGHT")
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 8, value, new_x="LMARGIN", new_y="NEXT")

    # Disclaimer
    pdf.ln(30)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(150, 0, 0)
    pdf.multi_cell(
        0, 5,
        "CONFIDENTIAL - This report contains sensitive security information. "
        "Unauthorised distribution is prohibited. This tool is for authorised "
        "testing only. The author assumes no responsibility for misuse.",
    )
    pdf.set_text_color(0, 0, 0)


def _add_executive_summary(pdf: _W3BSP1D3RPDF, summary: ScanSummary) -> None:
    """Add executive summary with statistics."""
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # Stats table
    pdf.set_font("Helvetica", "", 10)
    stats = [
        ("Pages Crawled", str(summary.pages_crawled)),
        ("Forms Discovered", str(summary.forms_found)),
        ("Parameters Tested", str(summary.params_tested)),
        ("Total Findings", str(summary.total_findings)),
    ]

    for label, value in stats:
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(60, 7, label, border=1)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 7, value, border=1, new_x="LMARGIN", new_y="NEXT")

    pdf.ln(8)

    # Severity breakdown
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Severity Breakdown", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    breakdown = [
        ("CRITICAL", summary.critical_count, _SEV_COLORS[Severity.CRITICAL]),
        ("HIGH", summary.high_count, _SEV_COLORS[Severity.HIGH]),
        ("MEDIUM", summary.medium_count, _SEV_COLORS[Severity.MEDIUM]),
        ("LOW", summary.low_count, _SEV_COLORS[Severity.LOW]),
    ]

    total = max(summary.total_findings, 1)

    for label, count, color in breakdown:
        # Severity label
        pdf.set_fill_color(*color)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(25, 7, label, fill=True)

        # Count
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(15, 7, str(count))

        # Bar
        bar_width = int((count / total) * 120)
        if bar_width > 0:
            pdf.set_fill_color(*color)
            pdf.cell(bar_width, 7, "", fill=True)

        pdf.ln(8)

    pdf.set_text_color(0, 0, 0)


def _add_findings(pdf: _W3BSP1D3RPDF, summary: ScanSummary) -> None:
    """Add detailed finding cards."""
    findings = summary.sorted_findings()
    if not findings:
        pdf.ln(10)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 10, "No vulnerabilities detected.", new_x="LMARGIN", new_y="NEXT")
        return

    pdf.add_page()
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, f"Findings ({len(findings)})", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    for idx, finding in enumerate(findings, 1):
        _add_finding_card(pdf, idx, finding)


def _add_finding_card(pdf: _W3BSP1D3RPDF, idx: int, finding: Finding) -> None:
    """Add a single finding to the PDF."""
    color = _SEV_COLORS.get(finding.severity, (100, 100, 100))

    # Check if we need a new page (rough estimate)
    if pdf.get_y() > 230:
        pdf.add_page()

    # Finding header with severity badge
    pdf.set_fill_color(*color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(
        0, 8,
        f"  #{idx}  {finding.vuln_type}  [{finding.severity}]",
        fill=True,
        new_x="LMARGIN", new_y="NEXT",
    )

    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "", 9)

    # Metadata
    details = [
        ("URL", finding.url),
        ("Parameter", finding.parameter),
        ("Method", finding.method),
    ]
    for label, value in details:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(25, 5, f"{label}:")
        pdf.set_font("Helvetica", "", 9)
        # Truncate long URLs
        display_val = value[:100] + "..." if len(value) > 100 else value
        pdf.cell(0, 5, display_val, new_x="LMARGIN", new_y="NEXT")

    # Payload
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(0, 5, "Payload:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Courier", "", 8)
    payload_display = finding.payload[:120] + "..." if len(finding.payload) > 120 else finding.payload
    pdf.multi_cell(0, 4, payload_display)

    # Evidence
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(0, 5, "Evidence:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "I", 8)
    evidence_display = finding.evidence[:200] + "..." if len(finding.evidence) > 200 else finding.evidence
    pdf.multi_cell(0, 4, evidence_display)

    # Remediation
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(0, 5, "Fix:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(0, 100, 0)
    pdf.multi_cell(0, 4, finding.remediation[:300])
    pdf.set_text_color(0, 0, 0)

    pdf.ln(5)
