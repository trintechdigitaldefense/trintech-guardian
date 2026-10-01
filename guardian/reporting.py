"""
Client-facing report generator for TrinTech-Guardian.
Produces HTML and (when reportlab is available) PDF executive summaries.
"""

import json
import os
from datetime import datetime, timezone
from typing import List, Optional


def _load_incidents(log_dir: str, limit: int = 200) -> List[dict]:
    reports = []
    if not os.path.isdir(log_dir):
        return reports
    files = sorted(
        [os.path.join(log_dir, f) for f in os.listdir(log_dir) if f.endswith(".json")],
        key=os.path.getmtime,
        reverse=True,
    )[:limit]
    for fp in files:
        try:
            with open(fp) as f:
                reports.append(json.load(f))
        except Exception:
            continue
    return reports


def generate_html_report(
    log_dir: str = "incident_reports",
    output_path: str = "guardian_client_report.html",
    client_name: str = "Client",
    engagement_id: str = "",
    dry_run: bool = True,
    extra_status: Optional[dict] = None,
) -> str:
    incidents = _load_incidents(log_dir)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    mode = "DRY-RUN (simulation only)" if dry_run else "LIVE CONTAINMENT"

    severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "NORMAL": 0}
    attackers = set()
    for inc in incidents:
        sev = (inc.get("severity_level") or "NORMAL").upper()
        if sev in severities:
            severities[sev] += 1
        ip = inc.get("attacker_ip")
        if ip and not str(ip).startswith("local-"):
            attackers.add(ip)

    rows = []
    for inc in incidents[:50]:
        rows.append(
            f"<tr><td>{inc.get('timestamp_utc', inc.get('timestamp', '—'))}</td>"
            f"<td>{inc.get('attacker_ip', '—')}</td>"
            f"<td>{inc.get('severity_level', '—')}</td>"
            f"<td>{inc.get('threat_score', '—')}</td>"
            f"<td>{inc.get('action_taken', '—')}</td></tr>"
        )
    table_body = "\n".join(rows) if rows else "<tr><td colspan='5'>No incidents recorded in this period.</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>TrinTech-Guardian Report — {client_name}</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:40px;color:#1a1a1a;line-height:1.5}}
h1{{color:#b91c1c;margin-bottom:4px}}h2{{color:#333;border-bottom:2px solid #b91c1c;padding-bottom:6px;margin-top:32px}}
.meta{{color:#555;font-size:0.95em}}.badge{{display:inline-block;padding:2px 10px;border-radius:4px;font-size:0.85em;font-weight:600}}
.dry{{background:#fef3c7;color:#92400e}}.live{{background:#fee2e2;color:#991b1b}}
.stat-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:20px 0}}
.stat{{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:16px;text-align:center}}
.stat .n{{font-size:1.8em;font-weight:700;color:#b91c1c}}.stat .l{{font-size:0.85em;color:#64748b;text-transform:uppercase}}
table{{width:100%;border-collapse:collapse;margin-top:12px;font-size:0.9em}}
th,td{{border:1px solid #e2e8f0;padding:8px 10px;text-align:left}}th{{background:#f1f5f9}}
.footer{{margin-top:40px;font-size:0.85em;color:#64748b;border-top:1px solid #e2e8f0;padding-top:16px}}
.warn{{background:#fff7ed;border-left:4px solid #ea580c;padding:12px 16px;margin:16px 0}}
</style></head><body>
<h1>TrinTech-Guardian Defense Report</h1>
<p class="meta"><strong>Client:</strong> {client_name}<br>
{"<strong>Engagement:</strong> " + engagement_id + "<br>" if engagement_id else ""}
<strong>Generated:</strong> {now}<br>
<strong>Mode:</strong> <span class="badge {'dry' if dry_run else 'live'}">{mode}</span><br>
<strong>Engine:</strong> TrinTech-Guardian v1.3.0 · TrinTech Digital Defense</p>
<div class="warn"><strong>Authorized use only.</strong> Produced under signed Rules of Engagement. NDA protected.</div>
<h2>Executive Summary</h2>
<div class="stat-grid">
<div class="stat"><div class="n">{len(incidents)}</div><div class="l">Incidents</div></div>
<div class="stat"><div class="n">{len(attackers)}</div><div class="l">Unique Sources</div></div>
<div class="stat"><div class="n">{severities['CRITICAL']+severities['HIGH']}</div><div class="l">High / Critical</div></div>
<div class="stat"><div class="n">{severities['MEDIUM']}</div><div class="l">Medium</div></div>
</div>
<p>Guardian recorded <strong>{len(incidents)}</strong> incident(s).
<strong>{len(attackers)}</strong> unique external source(s) crossed the alert threshold.
{"All containment actions were simulated (dry-run)." if dry_run else "Live isolation rules were applied where authorized."}</p>
<h2>Incident Timeline (most recent)</h2>
<table><thead><tr><th>Timestamp (UTC)</th><th>Source</th><th>Severity</th><th>Score</th><th>Action</th></tr></thead>
<tbody>{table_body}</tbody></table>
<h2>Recommendations</h2>
<ol>
<li>Review HIGH/CRITICAL sources against expected partners and scanners.</li>
<li>Align firewall baselines with the signed engagement scope.</li>
<li>Only enable live containment after explicit ROE approval.</li>
<li>Rotate credentials on any host that may have been exposed.</li>
<li>Consider continuous managed monitoring for production networks.</li>
</ol>
<div class="footer"><strong>TrinTech Digital Defense</strong> · Trinidad & Tobago<br>
trintechdigitaldefense@gmail.com · WhatsApp +1-868-362-0679<br>
https://trintechdigitaldefense.github.io<br>Confidential — NDA protected engagement material.</div>
</body></html>"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path


def generate_pdf_report(
    log_dir: str = "incident_reports",
    output_path: str = "guardian_client_report.pdf",
    client_name: str = "Client",
    engagement_id: str = "",
    dry_run: bool = True,
) -> Optional[str]:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    except ImportError:
        print("[REPORT] reportlab not installed — skipping PDF (HTML still available)")
        return None

    incidents = _load_incidents(log_dir)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    mode = "DRY-RUN" if dry_run else "LIVE"

    doc = SimpleDocTemplate(output_path, pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Tiny", fontSize=8, textColor=colors.grey))
    story = []
    story.append(Paragraph("TrinTech-Guardian Defense Report", styles["Title"]))
    story.append(Paragraph(f"<b>Client:</b> {client_name}", styles["Normal"]))
    if engagement_id:
        story.append(Paragraph(f"<b>Engagement:</b> {engagement_id}", styles["Normal"]))
    story.append(Paragraph(f"<b>Generated:</b> {now} &nbsp;|&nbsp; <b>Mode:</b> {mode}", styles["Normal"]))
    story.append(Paragraph("TrinTech Digital Defense · Trinidad & Tobago", styles["Tiny"]))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#b91c1c")))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    attackers = {i.get("attacker_ip") for i in incidents if i.get("attacker_ip") and not str(i.get("attacker_ip")).startswith("local-")}
    story.append(Paragraph(
        f"Incidents recorded: <b>{len(incidents)}</b>. Unique external sources: <b>{len(attackers)}</b>. "
        f"{'Containment was simulated only (dry-run).' if dry_run else 'Live isolation was active under ROE.'}",
        styles["Normal"],
    ))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Incident Timeline", styles["Heading2"]))
    data = [["Timestamp (UTC)", "Source", "Severity", "Score", "Action"]]
    for inc in incidents[:40]:
        data.append([
            str(inc.get("timestamp_utc", inc.get("timestamp", "—")))[:22],
            str(inc.get("attacker_ip", "—"))[:18],
            str(inc.get("severity_level", "—")),
            str(inc.get("threat_score", "—")),
            str(inc.get("action_taken", "—"))[:28],
        ])
    if len(data) == 1:
        data.append(["—", "No incidents", "—", "—", "—"])
    t = Table(data, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t)
    story.append(Spacer(1, 14))
    story.append(Paragraph("Recommendations", styles["Heading2"]))
    for rec in [
        "Review HIGH/CRITICAL sources against expected partners and scanners.",
        "Align firewall baselines with the signed engagement scope.",
        "Only enable live containment after explicit ROE approval.",
        "Rotate credentials on any host that may have been exposed.",
        "Consider continuous managed monitoring for production networks.",
    ]:
        story.append(Paragraph(f"• {rec}", styles["Normal"]))
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
    story.append(Paragraph(
        "Confidential — NDA protected. TrinTech Digital Defense · trintechdigitaldefense@gmail.com · +1-868-362-0679",
        styles["Tiny"],
    ))
    doc.build(story)
    return output_path
