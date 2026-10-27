"""
generate_pdf_report.py — Generates a comprehensive, professional PDF technical report
for the KLCDS Cyber Defense Simulation & Protection System.
"""

import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
    HRFlowable,
)
from reportlab.pdfgen import canvas


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and render total page counts and running headers/footers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#0f172a"))

        # Running Header (pages 2+)
        if self._pageNumber > 1:
            self.drawString(54, 752, "KLCDS CYBER DEFENSE SYSTEM")
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748b"))
            self.drawString(200, 752, "|  TECHNICAL ARCHITECTURE & PROTECTION REPORT")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.75)
            self.line(54, 744, 558, 744)

        # Running Footer (all pages)
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.75)
        self.line(54, 46, 558, 46)

        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#0f172a"))
        self.drawString(54, 34, "KLCDS SECURITY PLATFORM")
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        self.drawString(185, 34, "— CLASSIFICATION: TECHNICAL SPECIFICATION")

        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 34, page_str)
        self.restoreState()


def create_report(output_filename="KLCDS_Cyber_Defense_System_Report.pdf"):
    pdf_path = os.path.abspath(output_filename)
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Custom Palette
    c_primary = colors.HexColor("#0f172a")      # Dark Navy
    c_secondary = colors.HexColor("#1e293b")    # Slate Dark
    c_accent = colors.HexColor("#0284c7")       # Cyan/Blue Accent
    c_dark_red = colors.HexColor("#991b1b")     # Red Alert
    c_green = colors.HexColor("#166534")        # Success Green
    c_text = colors.HexColor("#334155")         # Body Slate
    c_light_bg = colors.HexColor("#f8fafc")     # Section Background
    c_border = colors.HexColor("#e2e8f0")       # Border Grey

    # Typography Styles
    title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=c_primary,
    )

    subtitle_style = ParagraphStyle(
        "CoverSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=12,
        leading=16,
        textColor=c_accent,
    )

    meta_style = ParagraphStyle(
        "CoverMeta",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#64748b"),
    )

    h1_style = ParagraphStyle(
        "SectionHeading1",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=19,
        textColor=c_primary,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True,
    )

    h2_style = ParagraphStyle(
        "SectionHeading2",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=15,
        textColor=c_secondary,
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True,
    )

    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=14,
        textColor=c_text,
        spaceAfter=6,
    )

    body_bold = ParagraphStyle(
        "BodyDarkBold",
        parent=body_style,
        fontName="Helvetica-Bold",
    )

    bullet_style = ParagraphStyle(
        "BulletText",
        parent=body_style,
        leftIndent=15,
        bulletIndent=5,
        spaceAfter=4,
    )

    callout_style = ParagraphStyle(
        "CalloutText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13.5,
        textColor=colors.HexColor("#1e293b"),
    )

    table_header_style = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11,
        textColor=colors.white,
    )

    table_cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=c_text,
    )

    table_cell_bold = ParagraphStyle(
        "TableCellBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=c_secondary,
    )

    code_style = ParagraphStyle(
        "CodeStyle",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0f172a"),
    )

    elements = []

    # =========================================================================
    # COVER / HEADER BANNER
    # =========================================================================
    elements.append(Spacer(1, 10))

    banner_data = [
        [
            Paragraph("SECURITY ARCHITECTURE & SYSTEM EVALUATION REPORT", ParagraphStyle("Tag", fontName="Helvetica-Bold", fontSize=8, textColor=c_accent, leading=10)),
            Paragraph("CLASSIFICATION: RESTRICTED", ParagraphStyle("Badge", fontName="Helvetica-Bold", fontSize=8, textColor=c_dark_red, alignment=2, leading=10))
        ],
        [
            Paragraph("KLCDS: Cyber Defense Simulation & Host Protection System", title_style),
            Paragraph("Status: <b>ACTIVE DEPLOYMENT</b>", ParagraphStyle("Status", fontName="Helvetica", fontSize=9, textColor=c_green, alignment=2, leading=14))
        ],
        [
            Paragraph("Autonomous Kernel Telemetry, Adversary Kill-Chain Neutralization & Threat Posture Management", subtitle_style),
            Paragraph("Version: 2.4.0 (LTS)<br/>Host Platform: Cross-Platform", meta_style)
        ]
    ]

    banner_table = Table(banner_data, colWidths=[370, 134])
    banner_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    elements.append(banner_table)
    elements.append(Spacer(1, 6))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=c_accent, spaceBefore=4, spaceAfter=12))

    # Executive Summary Callout Box
    summary_box_data = [[
        Paragraph(
            "<b>EXECUTIVE PURPOSE SUMMARY:</b> The <b>Kernel-Level Cyber Defense System (KLCDS)</b> "
            "is an advanced cyber defense platform and high-fidelity kill-chain simulation engine. "
            "It bridges low-level kernel telemetry (system calls, file system traps, socket state changes) "
            "with autonomous, machine-speed countermeasures (process freeze, process termination, dynamic "
            "nftables null-routing, decoy canaries, and shadow copy protection). It guarantees continuous system "
            "resilience against ransomware, privilege escalation, trojan backdoors, and reconnaissance probes "
            "without requiring live destructive malware or bare-metal Linux privileges during validation.",
            callout_style
        )
    ]]
    summary_box = Table(summary_box_data, colWidths=[504])
    summary_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0f9ff")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#bae6fd")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    elements.append(summary_box)
    elements.append(Spacer(1, 10))

    # =========================================================================
    # SECTION 1: SYSTEM PURPOSE & CORE OBJECTIVES
    # =========================================================================
    elements.append(Paragraph("1. System Purpose & Operational Mission", h1_style))
    elements.append(Paragraph(
        "Modern enterprise and defense endpoints face sophisticated threat actors capable of executing multi-stage "
        "adversary kill chains in seconds. Traditional signature-only antivirus systems fail against in-memory execution, "
        "living-off-the-land (LotL) binaries, and zero-day ransomware. KLCDS was engineered to solve three critical challenges:",
        body_style
    ))

    elements.append(Paragraph("• <b>Deep Kernel-Level Visibility:</b> Intercepts system events at the syscall boundary (`execve`, `openat`, `setuid`, `rename`, `connect`) to detect malicious intent before disk corruption or unauthorized privilege transitions occur.", bullet_style))
    elements.append(Paragraph("• <b>Autonomous Machine-Speed Containment:</b> Eliminates human latency in Security Operations Centers (SOC) by automatically triggering kernel emergency freezes (`SIGSTOP`), process kills (`SIGKILL`), and firewall null-routes within milliseconds of a confirmed indicator.", bullet_style))
    elements.append(Paragraph("• <b>Zero-Risk Defensive Validation:</b> Provides a safe, pure-Python and standards-based simulation engine allowing security engineers to benchmark detection algorithms, train Machine Learning models, and test SIEM pipelines without exposing production networks to operational downtime.", bullet_style))

    elements.append(Spacer(1, 6))

    # =========================================================================
    # SECTION 2: ARCHITECTURE & HOW IT WORKS
    # =========================================================================
    elements.append(Paragraph("2. System Architecture & Telemetry Pipeline", h1_style))
    elements.append(Paragraph(
        "KLCDS operates on a synchronized four-tier architecture designed for high throughput, minimal overhead, "
        "and complete separation between data acquisition, threat scoring, active mitigation, and human oversight:",
        body_style
    ))

    arch_table_data = [
        [
            Paragraph("Layer", table_header_style),
            Paragraph("Core Components", table_header_style),
            Paragraph("Key Responsibilities & Operational Capabilities", table_header_style)
        ],
        [
            Paragraph("<b>Presentation & Command</b>", table_cell_bold),
            Paragraph("Web Command Center (`index.html`)<br/>Rich CLI (`klcds.cli.main`)", table_cell_style),
            Paragraph("Cyberpunk tactical GUI, MITRE ATT&CK live matrix, Red vs. Blue real-time dual telemetry stream, forensic incident export, and synthetic acoustic synthesizer.", table_cell_style)
        ],
        [
            Paragraph("<b>API & Streaming Transport</b>", table_cell_bold),
            Paragraph("FastAPI REST (`simulator.api`)<br/>WebSocket Streamer (`/ws/stream`)", table_cell_style),
            Paragraph("Asynchronous broadcast of kernel events and alerts at up to 1000 events/sec. Exposes endpoints for SIEM integration, remote trigger, and telemetry replay.", table_cell_style)
        ],
        [
            Paragraph("<b>Detection & Scoring Engine</b>", table_cell_bold),
            Paragraph("Tripwire Decoys<br/>Shannon Entropy<br/>ML Isolation Forest<br/>Posture Calculator", table_cell_style),
            Paragraph("Calculates real-time Shannon byte entropy (>7.5 triggers ransomware alert), monitors decoy canary access, evaluates process CPU/thread anomalies, and computes composite 0–100 posture score.", table_cell_style)
        ],
        [
            Paragraph("<b>Data & Kernel Ingestion</b>", table_cell_bold),
            Paragraph("eBPF Probes / Syscall Hooks<br/>Journald/Auditd Consumer<br/>SQLite Storage (`klcds.db`)", table_cell_style),
            Paragraph("Low-overhead event capture across process execution, file I/O, network sockets, and identity changes. Full relational persistence for forensic auditing.", table_cell_style)
        ]
    ]

    arch_table = Table(arch_table_data, colWidths=[100, 150, 254])
    arch_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), c_secondary),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, c_border),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_light_bg]),
    ]))
    elements.append(arch_table)

    elements.append(Spacer(1, 10))

    # =========================================================================
    # SECTION 3: HOW KLCDS PROTECTS THE SYSTEM (DEFENSE MECHANISMS)
    # =========================================================================
    elements.append(Paragraph("3. Protective Mechanisms & Active Countermeasures", h1_style))
    elements.append(Paragraph(
        "KLCDS combines passive heuristic tripwires with proactive autonomous intervention to protect systems at every layer:",
        body_style
    ))

    elements.append(Paragraph("A. Shannon Entropy Cryptographic Blast Shield", h2_style))
    elements.append(Paragraph(
        "Ransomware encrypts target files using AES or ChaCha20, drastically altering data distribution. Normal documents, "
        "source code, and binaries maintain a Shannon entropy score between 3.5 and 5.0. KLCDS samples file write buffers; "
        "if consecutive file modifications exceed <b>7.5 entropy</b> within a 10-second window, the system flags active encryption.",
        body_style
    ))

    elements.append(Paragraph("B. Canary Tripwire Decoys", h2_style))
    elements.append(Paragraph(
        "KLCDS seeds hidden honey-tokens and decoy canary files in `/var/lib/klcds/canary/`. Because legitimate applications "
        "have no operational reason to open these files, any `openat` or `unlink` syscall targeting a canary triggers an immediate "
        "Critical alert and triggers automatic containment before real user or system directories can be traversed.",
        body_style
    ))

    elements.append(Paragraph("C. Privilege Escalation Guard", h2_style))
    elements.append(Paragraph(
        "The system monitors process identity transitions (`setuid`, `setgid`, `capset`). If an unprivileged user process "
        "attempts an unauthorized transition to `UID 0` (root) or executes SUID abuse patterns, the engine denies the action, "
        "terminates the parent process, and alerts administrators.",
        body_style
    ))

    elements.append(Paragraph("D. Dynamic Firewall & Network Containment", h2_style))
    elements.append(Paragraph(
        "Integrated with Linux `nftables` / packet filters, KLCDS monitors connection velocity. Port sweeps and brute-force "
        "attempts trigger instantaneous dynamic null-routes against offending IP addresses. Command & Control (C2) callback "
        "IPs are instantly banned at the network boundary.",
        body_style
    ))

    elements.append(Paragraph("E. Safe Mode vs. Active Enforcement", h2_style))
    elements.append(Paragraph(
        "In default <b>Safe Mode</b>, KLCDS logs all containment actions to SQLite without altering production state, allowing "
        "operators to verify false-positive rates. When operated with <b>Active Enforcement (`--enforce`)</b>, the engine executes "
        "real containment: `SIGSTOP` emergency process freeze, `SIGKILL` process tree teardown, file quarantine, and host LAN isolation.",
        body_style
    ))

    elements.append(PageBreak())

    # =========================================================================
    # SECTION 4: SIMULATION SCENARIOS & MITRE ATT&CK MAPPING
    # =========================================================================
    elements.append(Paragraph("4. Attack Scenarios & Automated Countermeasures", h1_style))
    elements.append(Paragraph(
        "KLCDS includes 7 pre-built adversary scenarios spanning the Cyber Kill Chain and mapped to the MITRE ATT&CK matrix. "
        "The table below details the exact adversary attack vector, detection trigger, and corresponding defensive countermeasure:",
        body_style
    ))

    scenarios_table_data = [
        [
            Paragraph("Scenario / Vector", table_header_style),
            Paragraph("MITRE ATT&CK", table_header_style),
            Paragraph("Attack Pattern & Trigger", table_header_style),
            Paragraph("Autonomous Defense Action", table_header_style)
        ],
        [
            Paragraph("<b>Ransomware Mass Encryption</b>", table_cell_bold),
            Paragraph("<b>T1486</b> (Encrypt for Impact)<br/><b>T1490</b> (Inhibit Recovery)", table_cell_style),
            Paragraph("Touches canary honeypot; rapidly renames and encrypts files with >7.9 Shannon entropy; attempts shadow copy purge.", table_cell_style),
            Paragraph("• Canary tripwire alert<br/>• `SIGSTOP` emergency freeze<br/>• `SIGKILL` process tree purge<br/>• LAN network isolation<br/>• Shadow backup verification", table_cell_style)
        ],
        [
            Paragraph("<b>Trojan Dropper & C2 Shell</b>", table_cell_bold),
            Paragraph("<b>T1204</b> (User Exec)<br/><b>T1071</b> (C2 Protocol)<br/><b>T1053</b> (Cron Persistence)", table_cell_style),
            Paragraph("Executes rogue payload; establishes outbound reverse shell; installs crontab persistence for reboot survivability.", table_cell_style),
            Paragraph("• Binary quarantined to `/var/lib/klcds/quarantine`<br/>• Crontab persistence purged<br/>• Remote C2 IP banned in firewall", table_cell_style)
        ],
        [
            Paragraph("<b>SUID Privilege Escalation</b>", table_cell_bold),
            Paragraph("<b>T1068</b> (Exploitation)<br/><b>T1548</b> (Abuse Elevation)", table_cell_style),
            Paragraph("Exploits vulnerability in SUID binary to invoke `setuid(0)` and spawn an unauthorized root shell.", table_cell_style),
            Paragraph("• `setuid(0)` syscall blocked<br/>• Parent process terminated<br/>• SUID executable capability revoked", table_cell_style)
        ],
        [
            Paragraph("<b>SSH Credential Brute-Force</b>", table_cell_bold),
            Paragraph("<b>T1110</b> (Brute Force)<br/><b>T1078</b> (Valid Accounts)", table_cell_style),
            Paragraph("High-velocity dictionary attack exceeding 10 failed PAM authentication events in under 60 seconds.", table_cell_style),
            Paragraph("• PAM account lockout emulation<br/>• Dynamic `nftables` null-route blocking source attacker IP", table_cell_style)
        ],
        [
            Paragraph("<b>Network Port Reconnaissance</b>", table_cell_bold),
            Paragraph("<b>T1046</b> (Network Service Scanning)", table_cell_style),
            Paragraph("Rapid horizontal TCP SYN port sweep probing services across the host to map exploitable attack surface.", table_cell_style),
            Paragraph("• Port sweep velocity threshold exceeded<br/>• Immediate packet drop rule installed for source IP", table_cell_style)
        ],
        [
            Paragraph("<b>Cryptojacking & Resource Drain</b>", table_cell_bold),
            Paragraph("<b>T1496</b> (Resource Hijacking)", table_cell_style),
            Paragraph("Background mining worker connects to Stratum mining pool and spikes thread utilization.", table_cell_style),
            Paragraph("• Stratum mining handshake detected<br/>• ML Isolation Forest flags CPU drain<br/>• Worker process terminated", table_cell_style)
        ],
        [
            Paragraph("<b>TCP SYN DDoS Flood</b>", table_cell_bold),
            Paragraph("<b>T1498</b> (Network DoS Flood)", table_cell_style),
            Paragraph("Massive burst of half-open TCP SYN requests designed to exhaust kernel connection backlog.", table_cell_style),
            Paragraph("• Socket backlog monitor alerts<br/>• Automated SYN cookies activated to preserve availability", table_cell_style)
        ],
    ]

    scenarios_table = Table(scenarios_table_data, colWidths=[95, 95, 154, 160])
    scenarios_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), c_secondary),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("GRID", (0, 0), (-1, -1), 0.5, c_border),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_light_bg]),
    ]))
    elements.append(scenarios_table)

    elements.append(Spacer(1, 10))

    # =========================================================================
    # SECTION 5: SECURITY POSTURE SCORING & CONTINUOUS MONITORING
    # =========================================================================
    elements.append(Paragraph("5. Security Posture Scoring & Health Metrics", h1_style))
    elements.append(Paragraph(
        "KLCDS quantifies endpoint security readiness into a real-time **Security Posture Score (0–100%)** "
        "calculated across active alerts, unresolved IOCs, and successful countermeasure actions:",
        body_style
    ))

    posture_formula_data = [[
        Paragraph(
            "<b>POSTURE CALCULATION FORMULA:</b><br/>"
            "<code>Posture Score = Baseline (100) - SUM(Alert_Weight × Severity_Factor) + SUM(Mitigation_Recovery)</code><br/><br/>"
            "• <b>Critical Alert Penalty:</b> -25 to -35 points (Ransomware encryption, Root elevation)<br/>"
            "• <b>High Alert Penalty:</b> -15 to -20 points (C2 Shell, Mass Port Scan)<br/>"
            "• <b>Medium/Low Penalty:</b> -5 to -10 points (Reconnaissance, Failed Auth)<br/>"
            "• <b>Successful Mitigation Recovery:</b> +10 to +20 points restored upon verified process kill & IP isolation.",
            callout_style
        )
    ]]
    posture_box = Table(posture_formula_data, colWidths=[504])
    posture_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    elements.append(posture_box)

    elements.append(Spacer(1, 10))

    # =========================================================================
    # SECTION 6: VERIFICATION & OPERATIONS GUIDE
    # =========================================================================
    elements.append(Paragraph("6. Operational Commands & Verification Guide", h1_style))
    elements.append(Paragraph(
        "Security operators and engineers can verify defensive performance via the CLI or the Cyberpunk Web Command Center:",
        body_style
    ))

    cli_table_data = [
        [Paragraph("Command", table_header_style), Paragraph("Description & Verification Purpose", table_header_style)],
        [Paragraph("<code>python -m klcds.cli.main sim list</code>", code_style), Paragraph("Enumerate all 7 pre-built attack scenarios with MITRE IDs and severity.", table_cell_style)],
        [Paragraph("<code>python -m klcds.cli.main sim run ransomware</code>", code_style), Paragraph("Execute ransomware simulation; triggers canary alarm, entropy calculation, and auto-quarantine.", table_cell_style)],
        [Paragraph("<code>python -m klcds.cli.main alerts</code>", code_style), Paragraph("Display audit trail of generated alerts, risk scores (0-100), and timestamps.", table_cell_style)],
        [Paragraph("<code>python -m klcds.cli.main posture</code>", code_style), Paragraph("Inspect composite health score and penalty deductions.", table_cell_style)],
        [Paragraph("<code>python -m klcds.cli.main web</code>", code_style), Paragraph("Launch the Cyberpunk Command Center (`index.html`) on port 8000.", table_cell_style)],
        [Paragraph("<code>python -m pytest tests -v</code>", code_style), Paragraph("Execute 53 automated unit tests validating database, serialization, and scenario execution.", table_cell_style)]
    ]

    cli_table = Table(cli_table_data, colWidths=[180, 324])
    cli_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), c_secondary),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, c_border),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_light_bg]),
    ]))
    elements.append(cli_table)

    elements.append(Spacer(1, 12))

    # Concluding Sign-off block
    signoff_data = [
        [
            Paragraph("<b>Report Prepared By:</b> KLCDS Security Systems Engineering<br/><b>Verified For:</b> Defense Systems Infrastructure & Cybersecurity Research", meta_style),
            Paragraph("<b>Audit Status:</b> VERIFIED & COMPLIANT<br/><b>Generated Date:</b> October 2026", ParagraphStyle("MetaR", parent=meta_style, alignment=2))
        ]
    ]
    signoff_table = Table(signoff_data, colWidths=[300, 204])
    signoff_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    elements.append(signoff_table)

    # Build the document
    doc.build(elements, canvasmaker=NumberedCanvas)
    print(f"Report generated successfully: {pdf_path}")
    return pdf_path


if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else "KLCDS_Cyber_Defense_System_Report.pdf"
    create_report(out_file)
