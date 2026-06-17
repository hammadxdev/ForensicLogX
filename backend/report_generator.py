"""
ForensicLogX — Forensic PDF Report Generator
Uses ReportLab to produce professional forensic incident reports
with cover page, executive summary, evidence integrity validation,
MITRE ATT&CK mapping, chain of custody, and NIST-aligned recommendations.
"""

import os
import logging
from datetime import datetime
from backend.detection_rules import DETECTION_RULES

logger = logging.getLogger("ForensicLogX.report_generator")
# Ensure standard formatting and logging destination
if not logger.handlers and not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle, HRFlowable, PageBreak, KeepTogether)
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


# ─── Color Palette ───────────────────────────────────────────────────────────
PRIMARY_COLOR = colors.HexColor("#0f172a") # Slate 900 (Corporate Primary)
SECONDARY_COLOR = colors.HexColor("#1e293b") # Slate 800
TEXT_COLOR    = colors.HexColor("#334155") # Slate 700
LIGHT_BG      = colors.HexColor("#f8fafc") # Slate 50
BORDER_COLOR  = colors.HexColor("#e2e8f0") # Slate 200

# Severity Badge Colors
CRITICAL_COLOR = colors.HexColor("#ef4444") # Red
HIGH_COLOR     = colors.HexColor("#f97316") # Orange
MEDIUM_COLOR   = colors.HexColor("#8b5cf6") # Purple
LOW_COLOR      = colors.HexColor("#10b981") # Green


# ─── Numbered Canvas for Dynamic Page Numbering ──────────────────────────────
class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and render total page count
    along with running headers and footers.
    """
    def __init__(self, *args, **kwargs):
        canvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_decorations(self, page_count):
        # Suppress header and footer on the Cover Page (Page 1)
        if self._pageNumber == 1:
            return

        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#64748b")) # Slate 500

        # Running Header
        self.drawString(56, 800, "FORENSIC INCIDENT REPORT — CONFIDENTIAL")
        self.setFont("Helvetica", 8)
        self.drawRightString(539, 800, datetime.now().strftime("%Y-%m-%d"))
        self.setStrokeColor(BORDER_COLOR)
        self.setLineWidth(0.5)
        self.line(56, 792, 539, 792)

        # Running Footer
        self.line(56, 48, 539, 48)
        self.drawString(56, 36, "ForensicLogX — Enterprise Security Command Console")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(539, 36, page_text)
        self.restoreState()


# ─── MITRE ATT&CK Mapping Reference ──────────────────────────────────────────
MITRE_MAPPINGS = {
    "Brute Force": ("Brute Force", "T1110", "Credential Access"),
    "SQL Injection": ("Exploit Public-Facing Application", "T1190", "Initial Access"),
    "Directory Traversal": ("File and Directory Discovery", "T1083", "Discovery"),
    "LFI / Path Traversal": ("File and Directory Discovery", "T1083", "Discovery"),
    "RFI": ("Exploit Public-Facing Application", "T1190", "Initial Access"),
    "RCE": ("Command and Scripting Interpreter", "T1059", "Execution"),
    "HTTP Flood / DDoS": ("Network Denial of Service", "T1498", "Impact"),
    "Vulnerability Scanner": ("Active Scanning", "T1595", "Reconnaissance"),
    "XSS": ("Exploit Public-Facing Application", "T1190", "Initial Access"),
    "CSRF": ("User Execution", "T1204", "Execution"),
    "API": ("Exploit Public-Facing Application", "T1190", "Initial Access"),
    "CSP Bypass": ("User Execution", "T1204", "Execution"),
    "Weak Session IDs": ("Modify Authentication Process", "T1556", "Credential Access / Defense Evasion"),
    "Auth Bypass": ("Modify Authentication Process", "T1556", "Credential Access / Defense Evasion"),
    "Error Storm": ("Network Denial of Service", "T1498", "Impact"),
}


def escape_metadata(text: str) -> str:
    """
    Perform standard HTML/XML escaping for metadata fields (analyst, organization, filename)
    to prevent ReportLab XML markup crashes, while allowing normal rendering (e.g. '&' shows as '&').
    """
    if not text:
        return ""
    if not isinstance(text, str):
        text = str(text)
    # Escape ampersand, less-than, greater-than, quotes
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")


def defang_payload(text: str) -> str:
    """
    Sanitize and defang threat payloads/details to prevent ReportLab markup crashes
    and evade Chrome Safe Browsing false positive blocks on downloaded PDFs.
    """
    if not text:
        return ""
    if not isinstance(text, str):
        text = str(text)
    
    # 1. Escape basic XML characters using safe text brackets to avoid ReportLab parsing crashes
    # and break tag parsing signatures.
    text = text.replace("&", "[amp]").replace("<", "[lt]").replace(">", "[gt]")
    
    # 2. Defang common security-sensitive keywords and patterns (XSS, SQLi, LFI, CMDi)
    import re
    replacements = {
        # Script / JS signatures
        r"(?i)script": "scr_ipt",
        r"(?i)onload": "on_load",
        r"(?i)onerror": "on_error",
        r"(?i)onclick": "on_click",
        r"(?i)onmouseover": "on_mouseover",
        r"(?i)javascript:": "java_script:",
        r"(?i)alert\s*\(": "al_ert(",
        
        # SQL Injection signatures
        r"(?i)union\s+select": "uni_on sel_ect",
        r"(?i)union\s+all\s+select": "uni_on all sel_ect",
        r"(?i)select\s+": "sel_ect ",
        r"(?i)union\s+": "uni_on ",
        r"(?i)insert\s+": "ins_ert ",
        r"(?i)delete\s+": "del_ete ",
        r"(?i)drop\s+": "dr_op ",
        r"(?i)update\s+": "upd_ate ",
        r"(?i)information_schema": "info_rmation_schema",
        r"(?i)and\s+sleep\s*\(": "and sl_eep(",
        
        # Code execution signatures
        r"(?i)eval\s*\(": "ev_al(",
        r"(?i)system\s*\(": "sys_tem(",
        r"(?i)exec\s*\(": "ex_ec(",
        r"(?i)passthru\s*\(": "pass_thru(",
        r"(?i)shell_exec\s*\(": "shell_ex_ec(",
        r"(?i)base64_decode": "base64_dec_ode",
        r"(?i)\<\?php": "[php_start]",
        r"(?i)\?\>": "[php_end]",
        
        # File System / Traversal paths
        r"\.\./": "..[slash]",
        r"\.\.\\": "..[backslash]",
        r"(?i)etc/passwd": "etc/[passwd]",
        r"(?i)boot\.ini": "boot[.]ini",
        r"(?i)win\.ini": "win[.]ini",
        
        # Linux/Windows command tools
        r"(?i)cmd\.exe": "cmd[.]exe",
        r"(?i)/bin/sh": "/bin/[sh]",
        r"(?i)/bin/bash": "/bin/[bash]",
        r"(?i)iptables": "ip_tables",
        r"(?i)ufw": "u_f_w",
        
        # Geolocation / IPs / Hostnames matching
        r"(?i)etc/hosts": "etc/[hosts]"
    }
    
    for pattern, repl in replacements.items():
        text = re.sub(pattern, repl, text)
        
    return text


def defang_text(text: str) -> str:
    """Wrapper for backward compatibility in unit tests."""
    return defang_payload(text)


def generate_pdf_report(
    output_path: str,
    analyst: str,
    organization: str,
    summary: dict,
    threats: list[dict],
    custody_entries: list[dict],
    file_hash: str,
    filename: str,
) -> str:
    """
    Generate a forensic PDF report in compliance with enterprise and industry standards.
    """
    # Escape metadata fields to allow normal character rendering (e.g. '&' is rendered as '&')
    analyst = escape_metadata(analyst)
    organization = escape_metadata(organization)
    file_hash = escape_metadata(file_hash)
    filename = escape_metadata(filename)
    
    # Defang threat payloads and custody descriptions
    defanged_threats = []
    for t in threats:
        dt = dict(t)
        dt["type"] = defang_payload(t.get("type", "Other"))
        dt["ip"] = defang_payload(t.get("ip", "-"))
        dt["detail"] = defang_payload(t.get("detail", ""))
        defanged_threats.append(dt)
    threats = defanged_threats
    
    defanged_custody = []
    for e in custody_entries:
        de = dict(e)
        de["action"] = defang_payload(e.get("action", ""))
        de["detail"] = defang_payload(e.get("detail", ""))
        de["actor"] = defang_payload(e.get("actor", ""))
        defanged_custody.append(de)
    custody_entries = defanged_custody

    if not REPORTLAB_AVAILABLE:
        return _generate_text_report(output_path, analyst, organization,
                                     summary, threats, custody_entries, file_hash, filename)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Standard A4 Document with balanced 2cm margins (except top/bottom 2.5cm to leave header/footer room)
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2.5*cm,
        bottomMargin=2.5*cm
    )
    styles = getSampleStyleSheet()
    story  = []

    # ─── Custom Font Styles ───────────────────────────────────────────────────
    title_style = ParagraphStyle(
        "CoverTitle", parent=styles["Normal"],
        fontSize=24, textColor=colors.white, fontName="Helvetica-Bold",
        alignment=TA_CENTER, leading=28, spaceAfter=8
    )
    subtitle_style = ParagraphStyle(
        "CoverSubtitle", parent=styles["Normal"],
        fontSize=10, textColor=colors.HexColor("#94a3b8"), fontName="Helvetica",
        alignment=TA_CENTER, leading=14
    )
    cover_meta_label = ParagraphStyle(
        "CoverMetaLabel", parent=styles["Normal"],
        fontSize=9.5, textColor=colors.HexColor("#475569"), fontName="Helvetica-Bold", leading=13
    )
    cover_meta_val = ParagraphStyle(
        "CoverMetaVal", parent=styles["Normal"],
        fontSize=9.5, textColor=PRIMARY_COLOR, leading=13
    )
    heading_style = ParagraphStyle(
        "SectionHeading", parent=styles["Normal"],
        fontSize=13, textColor=PRIMARY_COLOR, fontName="Helvetica-Bold",
        leading=16, spaceBefore=18, spaceAfter=8, keepWithNext=True
    )
    body_style = ParagraphStyle(
        "BodyText", parent=styles["Normal"],
        fontSize=9.5, textColor=TEXT_COLOR, leading=14.5, spaceAfter=6
    )
    mono_style = ParagraphStyle(
        "MonoText", parent=styles["Normal"],
        fontSize=8, textColor=PRIMARY_COLOR, fontName="Courier-Bold", leading=10, spaceAfter=2
    )
    table_header_style = ParagraphStyle(
        "TableHeader", parent=styles["Normal"],
        fontSize=8.5, textColor=colors.white, fontName="Helvetica-Bold", leading=11
    )
    cell_style = ParagraphStyle(
        "TableCell", parent=styles["Normal"],
        fontSize=8, textColor=PRIMARY_COLOR, leading=10
    )
    cell_bold_style = ParagraphStyle(
        "TableCellBold", parent=styles["Normal"],
        fontSize=8, textColor=PRIMARY_COLOR, fontName="Helvetica-Bold", leading=10
    )

    # Status Badges
    badge_critical = ParagraphStyle(
        'BadgeCritical', fontName='Helvetica-Bold', fontSize=7.5, textColor=colors.white,
        backColor=CRITICAL_COLOR, alignment=TA_CENTER, borderPadding=3, borderRadius=3, leading=9
    )
    badge_high = ParagraphStyle(
        'BadgeHigh', fontName='Helvetica-Bold', fontSize=7.5, textColor=colors.white,
        backColor=HIGH_COLOR, alignment=TA_CENTER, borderPadding=3, borderRadius=3, leading=9
    )
    badge_medium = ParagraphStyle(
        'BadgeMedium', fontName='Helvetica-Bold', fontSize=7.5, textColor=colors.white,
        backColor=colors.HexColor("#7c3aed"),
        alignment=TA_CENTER, borderPadding=3, borderRadius=3, leading=9
    )
    badge_low = ParagraphStyle(
        'BadgeLow', fontName='Helvetica-Bold', fontSize=7.5, textColor=colors.white,
        backColor=LOW_COLOR, alignment=TA_CENTER, borderPadding=3, borderRadius=3, leading=9
    )

    # ─── COVER PAGE (Page 1) ──────────────────────────────────────────────────
    story.append(Spacer(1, 1.5*cm))
    
    # Banner Box
    cover_title_data = [
        [Paragraph("FORENSIC LOG ANALYSIS REPORT", title_style)],
        [Paragraph("HIGH-FIDELITY EVIDENCE INVESTIGATION & THREAT INTELLIGENCE", subtitle_style)]
    ]
    # 17cm fits exactly within A4 printable width (21.0 - 2.0*2 = 17.0cm)
    cover_title_table = Table(cover_title_data, colWidths=[17*cm])
    cover_title_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), PRIMARY_COLOR),
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 32),
        ("BOTTOMPADDING", (0,0), (-1,-1), 32),
        ("LEFTPADDING", (0,0), (-1,-1), 20),
        ("RIGHTPADDING", (0,0), (-1,-1), 20),
    ]))
    story.append(cover_title_table)
    story.append(Spacer(1, 2.5*cm))

    # Case Metadata Card
    meta_data = [
        [Paragraph("<b>CASE METADATA & EVIDENCE RECORD</b>", ParagraphStyle("MetaHeader", parent=styles["Normal"], fontSize=10.5, fontName="Helvetica-Bold", textColor=SECONDARY_COLOR)), ""],
        [Paragraph("<b>Incident Case ID:</b>", cover_meta_label), Paragraph(f"FLX-{datetime.now().strftime('%Y%m%d-%H%M%S')}", cover_meta_val)],
        [Paragraph("<b>Date of Report:</b>", cover_meta_label), Paragraph(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), cover_meta_val)],
        [Paragraph("<b>Lead Analyst:</b>", cover_meta_label), Paragraph(analyst, cover_meta_val)],
        [Paragraph("<b>Target Organization:</b>", cover_meta_label), Paragraph(organization, cover_meta_val)],
        [Paragraph("<b>Evidence File Source:</b>", cover_meta_label), Paragraph(filename, cover_meta_val)],
        [Paragraph("<b>Evidence Hash (SHA-256):</b>", cover_meta_label), Paragraph(file_hash, mono_style)],
    ]
    meta_table = Table(meta_data, colWidths=[6.0*cm, 11.0*cm])
    meta_table.setStyle(TableStyle([
        ("SPAN", (0,0), (1,0)),
        ("BACKGROUND", (0,0), (-1,-1), LIGHT_BG),
        ("PADDING", (0,0), (-1,-1), 8),
        ("LINEBELOW", (0,0), (1,0), 1, BORDER_COLOR),
        ("BOX", (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
    ]))
    story.append(meta_table)
    story.append(PageBreak())

    # ─── SECTION 1: EXECUTIVE SUMMARY (Page 2) ───────────────────────────────
    story.append(Paragraph("1. Executive Summary & Overview", heading_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=10))

    # Calculations for summary
    critical_count = sum(1 for t in threats if t.get("severity") == "critical")
    high_count     = sum(1 for t in threats if t.get("severity") == "high")
    medium_count   = sum(1 for t in threats if t.get("severity") == "medium")

    if critical_count > 0:
        risk_level = "CRITICAL RISK"
        risk_color = "#ef4444"
    elif high_count > 0:
        risk_level = "HIGH RISK"
        risk_color = "#f97316"
    elif medium_count > 0:
        risk_level = "MODERATE RISK"
        risk_color = "#8b5cf6"
    else:
        risk_level = "LOW RISK"
        risk_color = "#10b981"

    story.append(Paragraph(
        f"Automated security auditing of the evidence source <b>{filename}</b> has been completed. "
        f"The forensic ingest engine processed a total of <b>{summary.get('total_requests', 0):,}</b> log entries, "
        f"originating from <b>{summary.get('unique_ips', 0)}</b> distinct network endpoints. "
        f"A total of <b>{len(threats)}</b> malicious signatures or behavioral anomalies were flagged. "
        f"Based on the severity of the threat telemetry, the overall security posture is classified as "
        f"<font color='{risk_color}'><b>{risk_level}</b></font>. Immediate containment and security controls tuning "
        f"are recommended. The following sections provide detailed technical logs, MITRE ATT&CK technique mappings, "
        f"and structured remediation roadmaps aligned with NIST SP 800-61 incident response phases.",
        body_style
    ))
    story.append(Spacer(1, 0.5*cm))

    # Metric Cards Grid
    metrics_data = [
        [
            Paragraph("TOTAL REQUESTS AUDITED<br/><br/><font size=16><b>{:,}</b></font>".format(summary.get('total_requests', 0)), ParagraphStyle("C1", parent=styles["Normal"], alignment=TA_CENTER, leading=14)),
            Paragraph("SECURITY THREATS FOUND<br/><br/><font size=16><b>{:,}</b></font>".format(len(threats)), ParagraphStyle("C2", parent=styles["Normal"], alignment=TA_CENTER, leading=14))
        ],
        [
            Paragraph("UNIQUE ATTACKING IPS<br/><br/><font size=16><b>{:,}</b></font>".format(summary.get('unique_ips', 0)), ParagraphStyle("C3", parent=styles["Normal"], alignment=TA_CENTER, leading=14)),
            Paragraph("POSTURE RISK INDEX<br/><br/><font size=12 color='{}'><b>{}</b></font>".format(risk_color, risk_level), ParagraphStyle("C4", parent=styles["Normal"], alignment=TA_CENTER, leading=14))
        ]
    ]
    metrics_table = Table(metrics_data, colWidths=[8.5*cm, 8.5*cm])
    metrics_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), LIGHT_BG),
        ("BOX", (0,0), (0,0), 0.5, colors.HexColor("#cbd5e1")),
        ("BOX", (1,0), (1,0), 0.5, colors.HexColor("#cbd5e1")),
        ("BOX", (0,1), (0,1), 0.5, colors.HexColor("#cbd5e1")),
        ("BOX", (1,1), (1,1), 0.5, colors.HexColor("#cbd5e1")),
        ("PADDING", (0,0), (-1,-1), 12),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(metrics_table)
    story.append(Spacer(1, 0.8*cm))

    # ─── SECTION 2: EVIDENCE INTEGRITY & CUSTODY ─────────────────────────────
    story.append(Paragraph("2. Evidence Integrity & Chain of Custody", heading_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=10))
    story.append(Paragraph(
        "A rigorous chain of custody and cryptographic hash record has been maintained to "
        "ensure the admissibility, authenticity, and non-repudiation of the digital evidence under analysis.",
        body_style
    ))
    story.append(Spacer(1, 0.3*cm))

    coc_data = [
        [
            Paragraph("<b>#</b>", table_header_style),
            Paragraph("<b>Timestamp</b>", table_header_style),
            Paragraph("<b>Action Taken</b>", table_header_style),
            Paragraph("<b>Action Details / Audit Log</b>", table_header_style),
            Paragraph("<b>Authorized Actor</b>", table_header_style),
        ]
    ]
    for i, e in enumerate(custody_entries, 1):
        coc_data.append([
            Paragraph(str(i), cell_style),
            Paragraph(e.get("timestamp","")[:19].replace("T", " "), cell_style),
            Paragraph(e.get("action",""), cell_bold_style),
            Paragraph(e.get("detail","")[:100], cell_style),
            Paragraph(e.get("actor",""), cell_style),
        ])
    coc_table = Table(coc_data, colWidths=[0.7*cm, 3.8*cm, 3.5*cm, 6.0*cm, 3.0*cm])
    coc_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), SECONDARY_COLOR),
        ("GRID",       (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, LIGHT_BG]),
        ("PADDING", (0,0), (-1,-1), 6),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
    ]))
    story.append(coc_table)
    story.append(PageBreak())

    # ─── SECTION 3: THREAT DETECTION & ANALYSIS (IoCs) ───────────────────────
    story.append(Paragraph("3. Indication of Compromise (IoC) & Threat Analysis", heading_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=10))
    story.append(Paragraph(
        "The following table details the specific threat signatures, Web Application Firewall (WAF) "
        "alerts, and heuristic detections triggered during log inspection. Detections are ordered by "
        "severity (critical/high prioritized).",
        body_style
    ))
    story.append(Spacer(1, 0.3*cm))

    if threats:
        limit = 20
        # Sort so critical & high are on top
        sorted_threats = sorted(threats, key=lambda x: {"critical":0, "high":1, "medium":2, "low":3, "info":4}.get(x.get("severity","medium").lower(), 2))
        displayed_threats = sorted_threats[:limit]

        th_data = [
            [
                Paragraph("<b>#</b>", table_header_style),
                Paragraph("<b>Threat Category</b>", table_header_style),
                Paragraph("<b>Severity</b>", table_header_style),
                Paragraph("<b>Source IP</b>", table_header_style),
                Paragraph("<b>Count</b>", table_header_style),
                Paragraph("<b>Evidence Details Summary</b>", table_header_style),
            ]
        ]
        for i, t in enumerate(displayed_threats, 1):
            sev = t.get("severity", "").lower()
            if sev == "critical":
                badge_style = badge_critical
            elif sev == "high":
                badge_style = badge_high
            elif sev == "medium":
                badge_style = badge_medium
            else:
                badge_style = badge_low

            th_data.append([
                Paragraph(str(i), cell_style),
                Paragraph(t.get("type", "Other"), cell_bold_style),
                Paragraph(t.get("severity", "medium").upper(), badge_style),
                Paragraph(t.get("ip", "-"), cell_style),
                Paragraph(str(t.get("count", 1)), cell_style),
                Paragraph(t.get("detail", "")[:120], cell_style),
            ])
        th_table = Table(th_data, colWidths=[0.7*cm, 3.8*cm, 2.3*cm, 3.0*cm, 1.2*cm, 6.0*cm])
        th_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), SECONDARY_COLOR),
            ("GRID",       (0,0), (-1,-1), 0.5, BORDER_COLOR),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#fffbfe")]),
            ("PADDING", (0,0), (-1,-1), 5),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ]))
        story.append(th_table)

        if len(threats) > limit:
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph(
                f"<i>* Note: Displaying the top {limit} of {len(threats)} total threats. "
                "The complete threat log index is available inside the SOC console.</i>",
                ParagraphStyle("Footnote", parent=styles["Normal"], fontSize=8, textColor=colors.HexColor("#64748b"))
            ))
    else:
        story.append(Paragraph("No security threats detected in the log evidence.", body_style))

    story.append(Spacer(1, 0.8*cm))

    # ─── SECTION 4: MITRE ATT&CK FRAMEWORK MAPPING ───────────────────────────
    story.append(Paragraph("4. MITRE ATT&CK Framework Mapping", heading_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=10))
    story.append(Paragraph(
        "To align with security standards and industry best practices, detected threat categories "
        "are mapped below to standard MITRE ATT&CK Techniques, IDs, and Tactics.",
        body_style
    ))
    story.append(Spacer(1, 0.3*cm))

    mitre_data = [
        [
            Paragraph("<b>Threat Category</b>", table_header_style),
            Paragraph("<b>MITRE Technique</b>", table_header_style),
            Paragraph("<b>Technique ID</b>", table_header_style),
            Paragraph("<b>Associated Tactic</b>", table_header_style),
        ]
    ]
    seen_categories = set()
    for t in threats:
        cat = t.get("type", "Other")
        if cat in seen_categories:
            continue
        
        rule_id = t.get("rule_id")
        rule = DETECTION_RULES.get(rule_id) if rule_id else None
        
        if rule:
            mitre_info = rule.get("mitre", {})
            tactic = mitre_info.get("tactic", "Initial Access")
            tech_id = mitre_info.get("technique_id", "T1190")
            tech_name = mitre_info.get("technique", "Exploit Public-Facing Application")
        else:
            # Fallback mapping
            mapping = None
            for k, v in MITRE_MAPPINGS.items():
                if k.lower() in cat.lower():
                    mapping = v
                    break
            if not mapping:
                mapping = ("Exploit Public-Facing Application", "T1190", "Initial Access")
            tech_name, tech_id, tactic = mapping
        
        seen_categories.add(cat)
        mitre_data.append([
            Paragraph(cat, cell_bold_style),
            Paragraph(tech_name, cell_style),
            Paragraph(tech_id, mono_style),
            Paragraph(tactic, cell_style),
        ])
    
    mitre_table = Table(mitre_data, colWidths=[4.2*cm, 4.3*cm, 2.5*cm, 6.0*cm])
    mitre_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), SECONDARY_COLOR),
        ("GRID",       (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, LIGHT_BG]),
        ("PADDING", (0,0), (-1,-1), 6),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(mitre_table)
    story.append(PageBreak())

    # ─── SECTION 5: NIST INCIDENT RESPONSE RECOMMENDATIONS ────────────────────
    story.append(Paragraph("5. NIST-Aligned Actionable Roadmap", heading_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=10))
    story.append(Paragraph(
        "Remediation actions are structured below in accordance with the <b>NIST SP 800-61 r2</b> "
        "Computer Security Incident Handling Guide, prioritizing immediate containment followed by eradication and hardening.",
        body_style
    ))
    story.append(Spacer(1, 0.3*cm))

    threat_ips = list(set(t["ip"] for t in threats if t.get("ip") not in ("Multiple", "-")))
    if not threat_ips:
        threat_ips = ["N/A"]

    recommendations_data = [
        [
            Paragraph("<b>Response Phase</b>", table_header_style),
            Paragraph("<b>Target Action Items & Implementation Details</b>", table_header_style),
        ],
        [
            Paragraph("<font color='#ef4444'><b>PHASE 1<br/>Containment</b></font><br/><i>(0-24 Hours)</i>", cell_bold_style),
            Paragraph(
                "• <b>Block Malicious IPs:</b> Update firewall rules (iptables/UFW) to drop incoming packets from identified attack sources: {}<br/>"
                "• <b>Terminate Active Sessions:</b> Invalidate current active sessions or tokens associated with the suspicious IP ranges.<br/>"
                "• <b>Isolate Vulnerable Endpoints:</b> Limit access to targeted URL paths (/wp-login.php, /admin, config files) to trusted internal IPs.",
                cell_style
            )
        ],
        [
            Paragraph("<font color='#f97316'><b>PHASE 2<br/>Eradication</b></font><br/><i>(24-72 Hours)</i>", cell_bold_style),
            Paragraph(
                "• <b>Patch Vulnerable Web Apps:</b> Update CMS core files, plugins, and server scripts to eliminate code-level flaws (SQL Injection, Path Traversal).<br/>"
                "• <b>Deploy Rate-Limiting:</b> Configure nginx/Apache limit_req modules or fail2ban rules to rate-limit authentication routes.<br/>"
                "• <b>File Integrity Scans:</b> Run deep file-integrity checks (SHA-256) across public HTML paths to detect unauthorized code modifications.",
                cell_style
            )
        ],
        [
            Paragraph("<font color='#10b981'><b>PHASE 3<br/>Strategic Hardening</b></font><br/><i>(Post Incident)</i>", cell_bold_style),
            Paragraph(
                "• <b>Deploy Web Application Firewall (WAF):</b> Fully enable ModSecurity and tune the OWASP Core Rule Set to active blocking mode.<br/>"
                "• <b>Centralized Logging:</b> Move log auditing to a SIEM system (e.g. Wazuh, ELK Stack) to enable real-time detection and alerting.<br/>"
                "• <b>Regular Audits:</b> Establish a weekly automated forensic review schedule using ForensicLogX with cryptographic verification.",
                cell_style
            )
        ]
    ]
    recs_table = Table(recommendations_data, colWidths=[4.0*cm, 13.0*cm])
    recs_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), SECONDARY_COLOR),
        ("GRID",       (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, LIGHT_BG]),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("PADDING", (0,0), (-1,-1), 9),
    ]))
    story.append(recs_table)

    # Build the document using NumberedCanvas
    logger.info("Building PDF report: %s", output_path)
    try:
        doc.build(story, canvasmaker=NumberedCanvas)
    except Exception as build_err:
        logger.error("ReportLab doc.build failed: %s", build_err)
        raise build_err

    # PDF size validation
    if os.path.exists(output_path):
        pdf_size = os.path.getsize(output_path)
        logger.info("Report generation finished. PDF saved to %s", output_path)
        logger.info("Generated PDF size: %d bytes", pdf_size)
        print(f"[Report] PDF saved: {output_path} ({pdf_size} bytes)")
    else:
        logger.error("PDF generation failed: file %s does not exist on disk", output_path)
        raise FileNotFoundError(f"PDF file was not created: {output_path}")

    return output_path


def _generate_text_report(output_path, analyst, organization, summary,
                           threats, custody_entries, file_hash, filename) -> str:
    """Fallback plain-text report if ReportLab is not installed."""
    txt_path = output_path.replace(".pdf", ".txt")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=" * 70,
        "  FORENSIC INCIDENT REPORT — ForensicLogX",
        f"  Analyst: {analyst} | Organization: {organization}",
        f"  Generated: {now}",
        "=" * 70, "",
        f"Evidence File : {filename}",
        f"SHA-256 Hash  : {file_hash}", "",
        "EXECUTIVE SUMMARY",
        "-" * 40,
        f"Total Requests : {summary.get('total_requests', 0):,}",
        f"Unique IPs     : {summary.get('unique_ips', 0)}",
        f"Error Rate     : {summary.get('error_rate_pct', 0)}%",
        f"Threats Found  : {len(threats)}", "",
        "THREATS",
        "-" * 40,
    ]
    for i, t in enumerate(threats, 1):
        lines.append(f"{i}. [{t['severity'].upper()}] {t['type']} — {t['ip']} — {t['detail']}")
    lines += ["", "CHAIN OF CUSTODY", "-" * 40]
    for e in custody_entries:
        lines.append(f"  {e.get('timestamp','')[:19]}  {e.get('action','')}  ({e.get('actor','')})")
    with open(txt_path, "w") as f:
        f.write("\n".join(lines))
    print(f"[Report] Text report saved (ReportLab not installed): {txt_path}")
    return txt_path
