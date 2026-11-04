"""
CyberScribe Pure-Python PDF 1.4 Report Generator
------------------------------------------------
Zero-dependency, standards-compliant PDF 1.4 generator for CTI threat reports.
Produces valid, streamable PDF binaries without third-party C-libraries or subprocesses.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


def _sanitize_pdf_text(text: str) -> str:
    """Escapes string characters for PDF text operators."""
    if not text:
        return ""
    # Map common unicode quotes and dashes to ASCII
    text = (
        str(text)
        .replace("\u2018", "'")
        .replace("\u2019", "'")
        .replace("\u201c", '"')
        .replace("\u201d", '"')
        .replace("\u2013", "-")
        .replace("\u2014", "--")
        .replace("\u2022", "*")
    )
    # Strip non-ASCII
    clean = "".join(c if 32 <= ord(c) < 127 or c in "\t\n\r" else " " for c in text)
    # Escape PDF parentheses and backslashes
    return clean.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap_text(text: str, max_chars: int = 78) -> List[str]:
    """Wraps paragraphs to stay within page margin bounds."""
    if not text:
        return []
    lines = []
    for raw_para in str(text).replace("\r\n", "\n").split("\n"):
        words = raw_para.split()
        if not words:
            lines.append("")
            continue
        current = ""
        for w in words:
            if not current:
                current = w
            elif len(current) + 1 + len(w) <= max_chars:
                current += " " + w
            else:
                lines.append(current)
                current = w
        if current:
            lines.append(current)
    return lines


def generate_threat_pdf_bytes(report: Any, mitre_techniques: Optional[List[str]] = None) -> bytes:
    """
    Compiles a structured ThreatReport into a valid PDF 1.4 byte document.
    """
    cve = getattr(report, "cve_id", None) or "CVE-ADVISORY"
    title = getattr(report, "title", "Threat Intelligence Advisory")
    severity = (getattr(report, "severity", "medium") or "medium").upper()
    summary = getattr(report, "summary", "No summary available.")
    source_url = getattr(report, "source_url", "N/A")
    pub_date = getattr(report, "published_at", None)
    pub_str = pub_date.strftime("%Y-%m-%d %H:%M UTC") if pub_date else "N/A"

    # Severity color
    sev_color = {
        "CRITICAL": "0.8 0.1 0.1",
        "HIGH": "0.9 0.4 0.1",
        "MEDIUM": "0.8 0.6 0.1",
        "LOW": "0.2 0.6 0.2"
    }.get(severity, "0.4 0.4 0.4")

    page_width = 612
    page_height = 792
    margin = 50
    content_width = page_width - (2 * margin)

    pages_ops: List[str] = []
    current_ops: List[str] = []
    y = page_height - margin

    def check_space(needed: int):
        nonlocal y, current_ops, pages_ops
        if y - needed < margin + 30:
            pages_ops.append("\n".join(current_ops))
            current_ops = []
            y = page_height - margin

    # --- Header Banner ---
    current_ops.append(f"q 0.08 0.12 0.18 rg 0 {page_height - 65} {page_width} 65 re f Q")
    current_ops.append(f"BT /F2 16 Tf 0.95 0.96 0.98 rg {margin} {page_height - 38} Td (CYBERSCRIBE THREAT ADVISORY) Tj ET")
    current_ops.append(f"BT /F1 9 Tf 0.6 0.7 0.8 rg {margin} {page_height - 52} Td (Autonomous Multi-Agent Threat Intelligence Platform) Tj ET")
    y = page_height - 85

    # --- CVE & Severity Block ---
    check_space(50)
    current_ops.append(f"q 0.94 0.95 0.97 rg {margin} {y - 40} {content_width} 40 re f Q")
    current_ops.append(f"BT /F2 14 Tf 0.1 0.15 0.2 rg {margin + 12} {y - 22} Td ({_sanitize_pdf_text(cve)}) Tj ET")
    current_ops.append(f"BT /F2 11 Tf {sev_color} rg {margin + 360} {y - 22} Td (SEVERITY: {_sanitize_pdf_text(severity)}) Tj ET")
    y -= 55

    # --- Metadata Details ---
    check_space(45)
    current_ops.append(f"BT /F2 9 Tf 0.3 0.35 0.4 rg {margin} {y} Td (Published Date:) Tj ET")
    current_ops.append(f"BT /F1 9 Tf 0.1 0.1 0.1 rg {margin + 90} {y} Td ({_sanitize_pdf_text(pub_str)}) Tj ET")
    y -= 14
    current_ops.append(f"BT /F2 9 Tf 0.3 0.35 0.4 rg {margin} {y} Td (Source URL:) Tj ET")
    current_ops.append(f"BT /F1 8.5 Tf 0.1 0.25 0.5 rg {margin + 90} {y} Td ({_sanitize_pdf_text(source_url[:75])}) Tj ET")
    y -= 22

    # --- Title Section ---
    check_space(40)
    current_ops.append(f"BT /F2 11 Tf 0.15 0.2 0.3 rg {margin} {y} Td (Advisory Title) Tj ET")
    y -= 14
    for line in _wrap_text(title, 72):
        check_space(14)
        current_ops.append(f"BT /F1 9.5 Tf 0.1 0.1 0.1 rg {margin + 8} {y} Td ({_sanitize_pdf_text(line)}) Tj ET")
        y -= 13
    y -= 10

    # --- MITRE ATT&CK Mapping ---
    if mitre_techniques:
        check_space(35)
        current_ops.append(f"BT /F2 11 Tf 0.15 0.2 0.3 rg {margin} {y} Td (MITRE ATT&CK Techniques) Tj ET")
        y -= 14
        tech_str = ", ".join(mitre_techniques)
        for line in _wrap_text(tech_str, 75):
            check_space(14)
            current_ops.append(f"BT /F1 9 Tf 0.2 0.3 0.4 rg {margin + 8} {y} Td ({_sanitize_pdf_text(line)}) Tj ET")
            y -= 13
        y -= 10

    # --- Executive Summary & Technical Narrative ---
    check_space(40)
    current_ops.append(f"BT /F2 11 Tf 0.15 0.2 0.3 rg {margin} {y} Td (Executive Summary & Technical Analysis) Tj ET")
    y -= 14
    for line in _wrap_text(summary, 78):
        check_space(14)
        current_ops.append(f"BT /F1 9 Tf 0.15 0.15 0.15 rg {margin + 8} {y} Td ({_sanitize_pdf_text(line)}) Tj ET")
        y -= 13
    y -= 15

    # --- Footer ---
    current_ops.append(f"BT /F1 7.5 Tf 0.5 0.5 0.55 rg {margin} {margin} Td (Generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | CyberScribe CTI Fabric) Tj ET")
    pages_ops.append("\n".join(current_ops))

    # --- Assemble PDF 1.4 Binary ---
    total_pages = len(pages_ops)
    objects: List[Dict[str, Any]] = []
    page_obj_ids = []
    content_obj_ids = []
    next_id = 3

    for i in range(total_pages):
        page_obj_ids.append(next_id)
        next_id += 1
        content_obj_ids.append(next_id)
        next_id += 1

    res_id = next_id
    next_id += 1
    font1_id = next_id
    next_id += 1
    font2_id = next_id
    next_id += 1

    objects.append({"id": 1, "body": "<< /Type /Catalog /Pages 2 0 R >>"})
    kids_str = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
    objects.append({"id": 2, "body": f"<< /Type /Pages /Kids [{kids_str}] /Count {total_pages} >>"})

    for i in range(total_pages):
        pid = page_obj_ids[i]
        cid = content_obj_ids[i]
        objects.append({
            "id": pid,
            "body": f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {page_width} {page_height}] /Contents {cid} 0 R /Resources {res_id} 0 R >>"
        })
        stream_bytes = pages_ops[i].encode("latin1", errors="replace")
        objects.append({
            "id": cid,
            "body": f"<< /Length {len(stream_bytes)} >>\nstream\n{pages_ops[i]}\nendstream"
        })

    objects.append({
        "id": res_id,
        "body": f"<< /Font << /F1 {font1_id} 0 R /F2 {font2_id} 0 R >> >>"
    })
    objects.append({
        "id": font1_id,
        "body": "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
    })
    objects.append({
        "id": font2_id,
        "body": "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"
    })

    # Compile byte buffer and xref table
    out = bytearray()
    out.extend(b"%PDF-1.4\n")
    xref_offsets = {}

    for obj in sorted(objects, key=lambda x: x["id"]):
        xref_offsets[obj["id"]] = len(out)
        out.extend(f"{obj['id']} 0 obj\n{obj['body']}\nendobj\n".encode("latin1", errors="replace"))

    startxref = len(out)
    total_objs = len(objects) + 1
    out.extend(f"xref\n0 {total_objs}\n0000000000 65535 f \n".encode("latin1"))
    for i in range(1, total_objs):
        offset = xref_offsets.get(i, 0)
        out.extend(f"{offset:010d} 00000 n \n".encode("latin1"))

    out.extend(f"trailer\n<< /Size {total_objs} /Root 1 0 R >>\nstartxref\n{startxref}\n%%EOF\n".encode("latin1"))
    return bytes(out)
