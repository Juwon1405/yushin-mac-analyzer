from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from xml.sax.saxutils import escape


IOC_RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
IOC_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
IOC_RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
IOC_RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
IOC_RE_URL = re.compile(r"\bhttps?://[^\s\"'<>]+", flags=re.IGNORECASE)
IOC_RE_ONION = re.compile(r"\b[a-z2-7]{16,56}\.onion\b", flags=re.IGNORECASE)


def build_dfir_pdf(
    *,
    case_data: dict[str, Any],
    case_dir: Path,
    analysis_source: str = "",
) -> dict[str, Any]:
    reportlab = _load_reportlab()
    pagesizes = reportlab["pagesizes"]
    colors = reportlab["colors"]
    styles_mod = reportlab["styles"]
    units = reportlab["units"]
    platypus = reportlab["platypus"]

    now = datetime.now(timezone.utc)
    reports_dir = case_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    filename = f"DFIR_Report_{case_data.get('case_id', 'CASE')}_{now.strftime('%Y%m%d_%H%M%S')}.pdf"
    out_path = reports_dir / filename

    artifacts = case_data.get("artifacts", []) or []
    summary = case_data.get("summary", {}) or {}
    timeline_rows = _timeline_rows(case_data)
    iocs = extract_iocs(artifacts)
    compromise, compromise_reason = determine_compromise(summary, artifacts, iocs)
    drawio_files = find_drawio_files(case_dir)
    ai_text, ai_engine = pick_ai_analysis(case_data, analysis_source=analysis_source)

    doc = platypus["SimpleDocTemplate"](
        str(out_path),
        pagesize=pagesizes["A4"],
        leftMargin=14 * units["mm"],
        rightMargin=14 * units["mm"],
        topMargin=12 * units["mm"],
        bottomMargin=12 * units["mm"],
        title="DFIR Report",
        author="macOS DFIR Toolkit",
    )
    styles = styles_mod["getSampleStyleSheet"]()
    title_style = styles_mod["ParagraphStyle"](
        "title",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=22,
        textColor=colors.HexColor("#0b2a4d"),
        spaceAfter=10,
    )
    h2 = styles_mod["ParagraphStyle"](
        "h2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        textColor=colors.HexColor("#0b2a4d"),
        spaceBefore=8,
        spaceAfter=6,
    )
    body = styles_mod["ParagraphStyle"](
        "body",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=12.2,
    )
    mono = styles_mod["ParagraphStyle"](
        "mono",
        parent=styles["BodyText"],
        fontName="Courier",
        fontSize=8.2,
        leading=10.8,
    )

    h1 = styles_mod["ParagraphStyle"](
        "h1",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=15,
        textColor=colors.HexColor("#0b2a4d"),
        spaceBefore=10,
        spaceAfter=6,
    )
    sub = styles_mod["ParagraphStyle"](
        "sub",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=8.8,
        textColor=colors.HexColor("#53657a"),
        leading=11,
    )

    sev = summary.get("severity", {}) or {}
    critical = int(sev.get("critical", 0) or 0)
    high = int(sev.get("high", 0) or 0)
    medium = int(sev.get("medium", 0) or 0)
    low = int(sev.get("low", 0) or 0)
    info = int(sev.get("info", 0) or 0)

    story: list[Any] = []
    story.append(platypus["Paragraph"]("DFIR Report", title_style))
    story.append(platypus["Paragraph"]("macOS DFIR Toolkit — Incident Investigation", body))
    story.append(platypus["Paragraph"](_p(f"Report UTC: {now.isoformat()}"), sub))
    story.append(platypus["Spacer"](1, 6))

    story.append(platypus["Paragraph"]("Case Overview", h1))
    meta_rows = [
        ["Case ID", str(case_data.get("case_id") or "-"), "Verdict", "COMPROMISED" if compromise else "NOT CONFIRMED"],
        ["Source Name", str(case_data.get("source_name") or "-"), "Source Type", str(case_data.get("source_type") or "-")],
        ["Artifact Count", str(summary.get("artifact_count") or 0), "Timeline Rows", str(len(timeline_rows))],
        ["IOC Count", str(len(iocs)), "Draw.io Count", str(len(drawio_files))],
    ]
    story.append(_table(platypus, [["Field", "Value", "Field", "Value"], *meta_rows], col_widths=[95, 180, 95, 190], header=True))

    story.append(platypus["Paragraph"]("Executive Summary", h1))
    story.append(
        platypus["Paragraph"](
            _p(
                build_executive_summary(
                    compromise=compromise,
                    compromise_reason=compromise_reason,
                    critical=critical,
                    high=high,
                    medium=medium,
                    low=low,
                    info=info,
                    ioc_count=len(iocs),
                    timeline_count=len(timeline_rows),
                )
            ),
            body,
        )
    )

    story.append(platypus["Paragraph"]("Findings (Priority)", h1))
    finding_rows = [["Severity", "Artifact ID", "Category", "Subcategory", "Title", "Key Detail"]]
    for row in top_priority_findings(artifacts, limit=80):
        finding_rows.append(
            [
                str(row.get("severity") or "-").upper(),
                str(row.get("id") or "-"),
                str(row.get("category") or "-"),
                str(row.get("subcategory") or "-"),
                _short(str(row.get("title") or "-"), 80),
                _short(str(row.get("details") or "-"), 130),
            ]
        )
    story.append(_table(platypus, finding_rows, col_widths=[56, 68, 88, 90, 108, 146], header=True))

    story.append(platypus["Paragraph"]("IOC List", h1))
    if iocs:
        ioc_rows = [["Type", "Value", "Severity", "Artifact ID"]]
        for row in iocs[:800]:
            ioc_rows.append([row["type"], row["value"], row["severity"], row["artifact_id"]])
        story.append(_table(platypus, ioc_rows, col_widths=[68, 332, 58, 70], header=True))
    else:
        story.append(platypus["Paragraph"]("No explicit IOC extracted from parsed artifacts.", body))

    story.append(platypus["Paragraph"]("Timeline (Key Events)", h1))
    if timeline_rows:
        time_rows = [["Time (UTC)", "Category", "Title", "Details"]]
        for row in timeline_rows[:900]:
            time_rows.append(
                [
                    str(row.get("timestamp") or "-"),
                    str(row.get("category") or "-"),
                    _short(str(row.get("title") or "-"), 88),
                    _short(str(row.get("details") or "-"), 170),
                ]
            )
        story.append(_table(platypus, time_rows, col_widths=[132, 90, 132, 190], header=True))
    else:
        story.append(platypus["Paragraph"]("No timestamped timeline rows available.", body))

    story.append(platypus["Paragraph"]("Event Burst Analysis", h1))
    burst_rows = [["Hour (UTC)", "Event Count"]]
    for hour, count in top_timeline_bursts(timeline_rows, limit=24):
        burst_rows.append([hour, str(count)])
    story.append(_table(platypus, burst_rows, col_widths=[220, 120], header=True))

    story.append(platypus["Paragraph"]("Actions Completed", h1))
    completed = derive_completed_actions(artifacts)
    if completed:
        done_rows = [["#", "Action", "Status"]]
        for idx, action in enumerate(completed[:30], start=1):
            done_rows.append([str(idx), action, "Done"])
        story.append(_table(platypus, done_rows, col_widths=[28, 420, 70], header=True))
    else:
        story.append(platypus["Paragraph"]("No explicit containment/response action artifacts were detected.", body))

    story.append(platypus["Paragraph"]("Recommendations (Outstanding)", h1))
    rec_rows = [["Priority", "#", "Recommendation"]]
    for idx, (priority, rec) in enumerate(derive_recommendations(compromise, artifacts, iocs), start=1):
        rec_rows.append([priority, str(idx), rec])
    story.append(_table(platypus, rec_rows, col_widths=[72, 28, 418], header=True))

    story.append(platypus["Paragraph"]("Artifacts (Catalog)", h1))
    artifact_rows = [["#", "Artifact", "Source", "Description"]]
    for idx, row in enumerate(top_priority_findings(artifacts, limit=220), start=1):
        artifact_rows.append(
            [
                str(idx),
                _short(f"{row.get('id')} | {row.get('title')}", 90),
                _short(str(row.get("source_file") or "-"), 105),
                _short(str(row.get("details") or "-"), 150),
            ]
        )
    story.append(_table(platypus, artifact_rows, col_widths=[24, 140, 170, 184], header=True))

    story.append(platypus["Paragraph"]("AI Analysis Narrative", h1))
    story.append(
        platypus["Paragraph"](
            _p(
                f"Engine: {ai_engine or 'N/A'}\n\n"
                f"{(ai_text or 'No AI analysis output saved yet.')[:9000]}"
            ),
            body,
        )
    )

    story.append(platypus["Paragraph"]("Draw.io Artifacts", h1))
    if drawio_files:
        for p in drawio_files[:250]:
            story.append(platypus["Paragraph"](_p(str(p)), mono))
    else:
        story.append(platypus["Paragraph"]("No .drawio files found in extracted evidence.", body))

    story.append(platypus["Paragraph"]("Appendix: Raw Evidence Excerpts", h1))
    appendix = top_priority_findings(artifacts, limit=70)
    if appendix:
        for row in appendix:
            story.append(
                platypus["Paragraph"](
                    _p(
                        f"[{row.get('id')}] {row.get('category')} / {row.get('subcategory')} / {row.get('severity')}\n"
                        f"Source: {row.get('source_file')}\n"
                        f"Raw: {_short(str(row.get('raw_excerpt') or row.get('details') or '-'), 450)}"
                    ),
                    mono,
                )
            )
            story.append(platypus["Spacer"](1, 3))
    else:
        story.append(platypus["Paragraph"]("No appendix excerpts available.", body))

    doc.build(story)

    return {
        "file_path": str(out_path),
        "file_name": filename,
        "generated_at": now.isoformat(),
        "compromise": compromise,
        "compromise_reason": compromise_reason,
        "ioc_count": len(iocs),
        "timeline_count": len(timeline_rows),
        "drawio_count": len(drawio_files),
        "analysis_engine": ai_engine,
    }


def pick_ai_analysis(case_data: dict[str, Any], analysis_source: str = "") -> tuple[str, str]:
    analysis = case_data.get("analysis", {}) or {}
    source = (analysis_source or "").strip().lower()
    if source in {"openai", "local"}:
        block = analysis.get(source, {}) or {}
        txt = str(block.get("analysis") or "").strip()
        if txt:
            return txt, source

    openai_txt = str((analysis.get("openai", {}) or {}).get("analysis") or "").strip()
    if openai_txt:
        return openai_txt, "openai"
    local_txt = str((analysis.get("local", {}) or {}).get("analysis") or "").strip()
    if local_txt:
        return local_txt, "local"
    return "", ""


def determine_compromise(
    summary: dict[str, Any],
    artifacts: list[dict[str, Any]],
    iocs: list[dict[str, str]],
) -> tuple[bool, str]:
    sev = summary.get("severity", {}) if isinstance(summary, dict) else {}
    critical = int(sev.get("critical", 0) or 0)
    high = int(sev.get("high", 0) or 0)
    ioc_count = len(iocs)
    suspicious_terms = 0
    for row in artifacts[:5000]:
        blob = f"{row.get('title','')} {row.get('details','')} {row.get('raw_excerpt','')}".lower()
        if any(t in blob for t in (".onion", "mimikatz", "tamper", "unauthorized", "persistence", "screen sharing")):
            suspicious_terms += 1
    compromised = critical > 0 or (high >= 8 and ioc_count >= 3) or (ioc_count >= 10 and suspicious_terms >= 3)
    if compromised:
        return True, f"critical={critical}, high={high}, ioc_count={ioc_count}, suspicious_terms={suspicious_terms}"
    return False, f"critical={critical}, high={high}, ioc_count={ioc_count}, suspicious_terms={suspicious_terms}"


def build_executive_summary(
    *,
    compromise: bool,
    compromise_reason: str,
    critical: int,
    high: int,
    medium: int,
    low: int,
    info: int,
    ioc_count: int,
    timeline_count: int,
) -> str:
    verdict = "Compromise confirmed." if compromise else "Compromise not confirmed from currently parsed data."
    return (
        f"{verdict}\n"
        f"Severity distribution: critical={critical}, high={high}, medium={medium}, low={low}, info={info}.\n"
        f"Extracted IOCs: {ioc_count}. Timeline events: {timeline_count}.\n"
        f"Determination basis: {compromise_reason}.\n"
        "This report emphasizes evidence-backed findings and incident-response actions suitable for analyst and leadership review."
    )


def top_priority_findings(artifacts: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ranked = sorted(
        artifacts,
        key=lambda x: (
            severity_rank.get(str(x.get("severity") or "low").lower(), 9),
            str(x.get("timestamp") or ""),
            str(x.get("id") or ""),
        ),
    )
    return ranked[:limit]


def top_timeline_bursts(timeline_rows: list[dict[str, Any]], limit: int = 24) -> list[tuple[str, int]]:
    buckets: dict[str, int] = {}
    for row in timeline_rows:
        ts = str(row.get("timestamp") or "")
        if len(ts) < 13:
            continue
        hour = ts[:13] + ":00"
        buckets[hour] = buckets.get(hour, 0) + 1
    return sorted(buckets.items(), key=lambda kv: kv[1], reverse=True)[:limit]


def derive_completed_actions(artifacts: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    checks = [
        ("Security Agents", "Security agent telemetry captured."),
        ("Network", "Network connection inventory captured for triage."),
        ("Persistence", "Persistence/autostart entries enumerated."),
        ("Command History", "Shell command history collected."),
        ("Browser", "Browser history databases parsed."),
    ]
    categories = {str(a.get("category") or "") for a in artifacts}
    for category, text in checks:
        if category in categories:
            out.append(text)
    if any(str(a.get("subcategory") or "").lower().startswith("install") for a in artifacts):
        out.append("Software install timeline parsed from InstallHistory.")
    if any(".drawio" in str(a.get("source_file") or "").lower() for a in artifacts):
        out.append("Draw.io artifacts indexed for reporting.")
    return out


def derive_recommendations(
    compromise: bool,
    artifacts: list[dict[str, Any]],
    iocs: list[dict[str, str]],
) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    categories = {str(a.get("category") or "") for a in artifacts}
    if compromise:
        rows.append(("CRITICAL", "Rotate exposed credentials and revoke active sessions on affected hosts."))
        rows.append(("CRITICAL", "Contain affected endpoints, isolate high-risk hosts, and preserve volatile evidence."))
    if len(iocs) > 0:
        rows.append(("HIGH", "Block and hunt listed IoCs across EDR, DNS, proxy, and firewall telemetry."))
    if "Persistence" in categories:
        rows.append(("HIGH", "Validate and remove unauthorized LaunchAgents/LaunchDaemons/login items."))
    if "Network" in categories:
        rows.append(("HIGH", "Review suspicious outbound sessions and enforce egress allowlisting."))
    if "Security Agents" in categories:
        rows.append(("MEDIUM", "Verify JAMF/Falcon/Tanium service health and tamper-protection posture."))
    rows.append(("MEDIUM", "Establish detection rules for suspicious shell commands and remote-access tooling."))
    rows.append(("MEDIUM", "Extend centralized log retention and add high-fidelity alerting for persistence changes."))
    rows.append(("LOW", "Document incident timeline and lessons learned in post-incident review."))
    return rows[:20]


def extract_iocs(artifacts: list[dict[str, Any]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in artifacts[:20000]:
        text = " ".join(
            [
                str(row.get("title") or ""),
                str(row.get("details") or ""),
                str(row.get("raw_excerpt") or ""),
            ]
        )
        artifact_id = str(row.get("id") or "-")
        severity = str(row.get("severity") or "low")

        for url in IOC_RE_URL.findall(text):
            if not _is_suspicious_url(url):
                continue
            _append_ioc(rows, seen, "url", url, severity, artifact_id)
            host = urlparse(url).hostname or ""
            if host.endswith(".onion"):
                _append_ioc(rows, seen, "domain", host, severity, artifact_id)
        for onion in IOC_RE_ONION.findall(text):
            _append_ioc(rows, seen, "domain", onion, severity, artifact_id)
        for ip in IOC_RE_IPV4.findall(text):
            if not _is_public_ipv4(ip):
                continue
            _append_ioc(rows, seen, "ipv4", ip, severity, artifact_id)
        for h in IOC_RE_SHA256.findall(text):
            _append_ioc(rows, seen, "sha256", h.lower(), severity, artifact_id)
        for h in IOC_RE_SHA1.findall(text):
            _append_ioc(rows, seen, "sha1", h.lower(), severity, artifact_id)
        for h in IOC_RE_MD5.findall(text):
            _append_ioc(rows, seen, "md5", h.lower(), severity, artifact_id)
    return rows


def _append_ioc(
    out: list[dict[str, str]],
    seen: set[tuple[str, str]],
    ioc_type: str,
    value: str,
    severity: str,
    artifact_id: str,
) -> None:
    val = value.strip()
    if not val:
        return
    key = (ioc_type, val.lower())
    if key in seen:
        return
    seen.add(key)
    out.append(
        {
            "type": ioc_type,
            "value": val,
            "severity": severity,
            "artifact_id": artifact_id,
        }
    )


def _is_public_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except Exception:
        return False
    if ip.version != 4:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)


def _is_suspicious_url(url: str) -> bool:
    low = url.lower()
    if ".onion" in low:
        return True
    suspicious_terms = ("mimikatz", "malware", "phish", "stealer", "ransom", "c2", "dropper")
    return any(t in low for t in suspicious_terms)


def find_drawio_files(case_dir: Path) -> list[str]:
    extracted = case_dir / "extracted"
    if not extracted.exists():
        return []
    rows = []
    for p in extracted.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() == ".drawio" or p.name.lower().endswith(".drawio.svg"):
            rows.append(str(p))
    rows.sort()
    return rows


def _timeline_rows(case_data: dict[str, Any]) -> list[dict[str, Any]]:
    timeline = case_data.get("timeline", []) or []
    if timeline:
        rows = timeline
    else:
        rows = [x for x in (case_data.get("artifacts", []) or []) if x.get("timestamp")]
    rows = sorted(rows, key=lambda x: (str(x.get("timestamp") or ""), str(x.get("id") or "")))
    return rows


def _p(text: str) -> str:
    return escape(text).replace("\n", "<br/>")


def _short(text: str, size: int) -> str:
    t = text.replace("\n", " ").strip()
    if len(t) <= size:
        return t
    return t[: size - 1] + "…"


def _table(platypus: dict[str, Any], rows: list[list[str]], col_widths: list[int], header: bool) -> Any:
    Table = platypus["Table"]
    TableStyle = platypus["TableStyle"]
    colors = _load_reportlab()["colors"]

    data = [[str(cell).replace("\n", " | ") for cell in r] for r in rows]
    table = Table(data, colWidths=col_widths, repeatRows=1 if header else 0)
    style_cmds = [
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#5f7691")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONT", (0, 0), (-1, -1), "Helvetica", 8.2),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        style_cmds.extend(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f2b4a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8.5),
            ]
        )
    table.setStyle(TableStyle(style_cmds))
    return table


def _load_reportlab() -> dict[str, Any]:
    try:
        from reportlab.lib import colors
        from reportlab.lib import pagesizes
        from reportlab.lib import styles
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except Exception as exc:
        raise RuntimeError("reportlab is required for PDF report generation. Install with: pip install reportlab") from exc
    return {
        "colors": colors,
        "pagesizes": {"A4": pagesizes.A4},
        "styles": {"getSampleStyleSheet": styles.getSampleStyleSheet, "ParagraphStyle": styles.ParagraphStyle},
        "units": {"mm": mm},
        "platypus": {
            "SimpleDocTemplate": SimpleDocTemplate,
            "Paragraph": Paragraph,
            "Spacer": Spacer,
            "Table": Table,
            "TableStyle": TableStyle,
        },
    }
