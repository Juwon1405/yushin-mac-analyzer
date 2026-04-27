from __future__ import annotations

import json
import os
import plistlib
import re
import shutil
import sqlite3
import subprocess
import zipfile
from collections import Counter
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import requests


IOC_TERMS_CRITICAL = (
    ".onion",
    "mimikatz",
    "command and control",
    "ransomware",
    "credential dump",
)
IOC_TERMS_HIGH = (
    "tor",
    "ipmi",
    "idrac",
    "pikvm",
    "remote console",
    "virtual media",
    "screen sharing",
)

KVM_INDICATOR_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bip[-_ ]?kvm\b", re.IGNORECASE), "ip-kvm"),
    (re.compile(r"\bpikvm\b", re.IGNORECASE), "pikvm"),
    (re.compile(r"\bipmi\b", re.IGNORECASE), "ipmi"),
    (re.compile(r"\bidrac\b", re.IGNORECASE), "idrac"),
    (re.compile(r"\bilo\b", re.IGNORECASE), "ilo"),
    (re.compile(r"\bbmc\b", re.IGNORECASE), "bmc"),
    (re.compile(r"\bvirtual media\b", re.IGNORECASE), "virtual_media"),
    (re.compile(r"\bremote console\b", re.IGNORECASE), "remote_console"),
    (re.compile(r"\b(kvm over ip|kvmoip)\b", re.IGNORECASE), "kvm_over_ip"),
    (re.compile(r"\b(ard|apple remote desktop)\b", re.IGNORECASE), "apple_remote_desktop"),
    (re.compile(r"\bscreen sharing\b", re.IGNORECASE), "screen_sharing"),
    (re.compile(r"\bvnc\b", re.IGNORECASE), "vnc"),
)


_PARSER_AI_CTX: ContextVar["ParserAIAssistant | None"] = ContextVar("parser_ai_ctx", default=None)


class ParserAIAssistant:
    def __init__(
        self,
        *,
        model: str,
        endpoint: str,
        timeout_sec: int,
        max_calls: int,
    ) -> None:
        self.model = model
        self.endpoint = endpoint
        self.timeout_sec = timeout_sec
        self.max_calls = max_calls
        self.calls = 0

    @classmethod
    def from_env(cls) -> ParserAIAssistant | None:
        enabled_raw = str(os.getenv("PARSER_AI_FALLBACK", "1")).strip().lower()
        if enabled_raw in {"0", "false", "off", "no"}:
            return None
        model = str(os.getenv("PARSER_AI_MODEL", "qwen2.5:14b-q4_K_M")).strip() or "qwen2.5:14b-q4_K_M"
        endpoint = str(os.getenv("PARSER_AI_ENDPOINT", "http://127.0.0.1:11434/api/generate")).strip()
        timeout_sec = max(5, int(os.getenv("PARSER_AI_TIMEOUT", "45")))
        max_calls = max(0, int(os.getenv("PARSER_AI_MAX_CALLS", "24")))
        if not endpoint or max_calls <= 0:
            return None
        return cls(model=model, endpoint=endpoint, timeout_sec=timeout_sec, max_calls=max_calls)

    def parse_event_line(self, line: str, *, category: str, subcategory: str) -> dict[str, str] | None:
        if self.calls >= self.max_calls:
            return None
        if not line.strip():
            return None

        self.calls += 1
        prompt = (
            "You are a macOS DFIR parser assistant.\n"
            "Parse one difficult forensic log line.\n"
            "Return strict JSON only with keys: timestamp,title,details,reason.\n"
            "Rules:\n"
            "- timestamp must be ISO8601 UTC (e.g. 2026-02-18T03:27:00+00:00) or empty string if unknown.\n"
            "- title should be short, neutral, parser-focused.\n"
            "- details should be concise structured text for analyst table.\n"
            "- reason should explain why this parse was inferred.\n"
            "- no markdown.\n"
            f"Category: {category}\n"
            f"Subcategory: {subcategory}\n"
            f"Line: {line}\n"
        )
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.0, "num_ctx": 4096},
        }
        try:
            resp = requests.post(self.endpoint, json=payload, timeout=self.timeout_sec)
        except requests.RequestException:
            return None
        if resp.status_code >= 300:
            return None

        try:
            data = resp.json()
        except Exception:
            return None

        raw = str(data.get("response") or "").strip()
        parsed = _safe_json_object(raw)
        if not parsed:
            return None

        timestamp = str(parsed.get("timestamp") or "").strip()
        title = str(parsed.get("title") or "").strip()
        details = str(parsed.get("details") or "").strip()
        reason = str(parsed.get("reason") or "").strip()
        if not any((timestamp, title, details)):
            return None
        return {
            "timestamp": timestamp,
            "title": title,
            "details": details,
            "reason": reason,
        }


@dataclass
class Artifact:
    id: str
    category: str
    subcategory: str
    timestamp: str | None
    title: str
    details: str
    source_file: str
    severity: str
    severity_reason: str
    raw_excerpt: str
    parsed: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "subcategory": self.subcategory,
            "timestamp": self.timestamp,
            "title": self.title,
            "details": self.details,
            "source_file": self.source_file,
            "severity": self.severity,
            "severity_reason": self.severity_reason,
            "raw_excerpt": self.raw_excerpt,
            "parsed": self.parsed or {},
        }


class ArtifactBuilder:
    def __init__(self) -> None:
        self.counter = 0

    def make(
        self,
        *,
        category: str,
        subcategory: str,
        title: str,
        details: str,
        source_file: str,
        timestamp: str | None = None,
        raw_excerpt: str = "",
        severity: str | None = None,
        severity_reason: str | None = None,
        parsed: dict[str, Any] | None = None,
    ) -> Artifact:
        self.counter += 1
        auto_severity, auto_reason = classify_severity(
            category=category,
            subcategory=subcategory,
            title=title,
            details=details,
            source_file=source_file,
        )
        return Artifact(
            id=f"A-{self.counter:07d}",
            category=category,
            subcategory=subcategory,
            timestamp=timestamp,
            title=title,
            details=details,
            source_file=source_file,
            severity=severity or auto_severity,
            severity_reason=severity_reason or auto_reason,
            raw_excerpt=raw_excerpt.strip()[:5000],
            parsed=parsed or {},
        )


def parse_input(case_id: str, source_path: Path, case_dir: Path) -> dict[str, Any]:
    parser_ai = ParserAIAssistant.from_env()
    token = _PARSER_AI_CTX.set(parser_ai)
    source_name = source_path.name
    source_ext = source_path.suffix.lower()

    try:
        if source_ext == ".zip":
            extracted_dir = case_dir / "extracted"
            if extracted_dir.exists():
                shutil.rmtree(extracted_dir, ignore_errors=True)
            extracted_dir.mkdir(parents=True, exist_ok=True)
            _extract_zip(source_path, extracted_dir)
            artifacts = parse_macos_collector_bundle(extracted_dir)
            source_type = "macos_collector_zip"
        elif source_ext in {".dd", ".raw", ".img", ".e01", ".001", ".aff", ".dmg"}:
            artifacts = parse_disk_image(source_path)
            source_type = "disk_image"
        else:
            artifacts = parse_single_file(source_path)
            source_type = "single_file"

        artifact_dicts = [a.to_dict() for a in artifacts]
        artifact_dicts = cap_artifacts_for_ui(artifact_dicts)
        summary = build_summary(artifact_dicts)
        timeline = build_timeline(artifact_dicts)
        parser_ai_calls = parser_ai.calls if parser_ai else 0
        summary["parser_ai_calls"] = parser_ai_calls

        return {
            "case_id": case_id,
            "source_name": source_name,
            "source_path": str(source_path),
            "source_type": source_type,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "artifacts": artifact_dicts,
            "timeline": timeline,
        }
    finally:
        _PARSER_AI_CTX.reset(token)


def parse_single_file(path: Path) -> list[Artifact]:
    builder = ArtifactBuilder()
    ext = path.suffix.lower()

    if ext in {".db", ".sqlite", ".sqlite3"}:
        return parse_browser_db(path, builder, source_prefix=str(path))

    if ext in {".log", ".txt", ".json", ".ndjson"}:
        return parse_text_log(
            path,
            builder,
            category="Logs",
            subcategory="Raw File",
            max_lines=4000,
        )

    return [
        builder.make(
            category="Evidence",
            subcategory="Unsupported",
            title="Unsupported single file",
            details=f"File extension '{ext or 'none'}' is not handled directly. Use collector ZIP or disk image.",
            source_file=str(path),
            severity="low",
            severity_reason="Parser does not support this extension as a standalone source.",
        )
    ]


def parse_disk_image(path: Path) -> list[Artifact]:
    builder = ArtifactBuilder()
    artifacts: list[Artifact] = []
    size = path.stat().st_size if path.exists() else 0

    artifacts.append(
        builder.make(
            category="Disk Image",
            subcategory="Metadata",
            title="Disk image loaded",
            details=f"Name: {path.name}\nSizeBytes: {size}",
            source_file=str(path),
            severity="low",
            severity_reason="Input evidence loaded. No artifact interpretation yet.",
        )
    )

    mmls = _run_cmd(["/usr/bin/env", "mmls", "-B", str(path)])
    if mmls.returncode == 0 and mmls.stdout.strip():
        for line in mmls.stdout.splitlines()[:400]:
            line = line.strip()
            if not line:
                continue
            if line.lower().startswith("slot"):
                continue
            artifacts.append(
                builder.make(
                    category="Disk Image",
                    subcategory="Partition",
                    title="Partition entry",
                    details=line,
                    source_file=str(path),
                    raw_excerpt=line,
                    severity="medium",
                    severity_reason="Partition metadata extracted from image (mmls).",
                )
            )
    else:
        details = "mmls unavailable or failed. Install SleuthKit to parse partition table from disk image."
        artifacts.append(
            builder.make(
                category="Disk Image",
                subcategory="Partition",
                title="Partition parsing unavailable",
                details=details,
                source_file=str(path),
                severity="low",
                severity_reason="Tooling limitation, not an incident indicator.",
            )
        )

    return artifacts


def parse_macos_collector_bundle(extracted_dir: Path) -> list[Artifact]:
    builder = ArtifactBuilder()
    artifacts: list[Artifact] = []
    root = detect_bundle_root(extracted_dir)
    file_count = sum(1 for p in root.rglob("*") if p.is_file())

    artifacts.append(
        builder.make(
            category="Evidence",
            subcategory="Bundle",
            title="macOS collector archive extracted",
            details=f"Root: {root}\nFiles: {file_count}",
            source_file=str(root),
            severity="low",
            severity_reason="Evidence package successfully unpacked.",
        )
    )

    artifacts.extend(parse_collection_metadata(root, builder))
    artifacts.extend(parse_system_profile(root, builder))
    artifacts.extend(parse_security_agents(root, builder))
    artifacts.extend(parse_install_timeline(root, builder))
    artifacts.extend(parse_persistence(root, builder))
    artifacts.extend(parse_accounts(root, builder))
    artifacts.extend(parse_command_history(root, builder))
    artifacts.extend(parse_network(root, builder))
    artifacts.extend(parse_remote_kvm(root, builder))
    artifacts.extend(parse_browsers(root, builder))
    artifacts.extend(parse_logs(root, builder))
    return artifacts


def detect_bundle_root(extracted_dir: Path) -> Path:
    meta = next(iter(extracted_dir.rglob("metadata/collection_meta.txt")), None)
    if meta:
        return meta.parent.parent
    children = [p for p in extracted_dir.iterdir() if p.is_dir()]
    if len(children) == 1:
        return children[0]
    return extracted_dir


def parse_collection_metadata(root: Path, builder: ArtifactBuilder) -> list[Artifact]:
    artifacts: list[Artifact] = []
    meta = root / "metadata" / "collection_meta.txt"
    if not meta.exists():
        return artifacts
    text = _safe_read_text(meta).strip()
    artifacts.append(
        builder.make(
            category="System",
            subcategory="Collector",
            title="Collection metadata",
            details=text or "No metadata content",
            source_file=str(meta),
            raw_excerpt=text,
            severity="low",
            severity_reason="Collector context record.",
        )
    )
    return artifacts


def parse_system_profile(root: Path, builder: ArtifactBuilder) -> list[Artifact]:
    artifacts: list[Artifact] = []
    system_dir = root / "system"
    if not system_dir.exists():
        return artifacts

    interesting_files = (
        "sw_vers.txt",
        "uname.txt",
        "uptime.txt",
        "boot_time.txt",
        "whoami.txt",
    )
    for name in interesting_files:
        p = system_dir / name
        if not p.exists():
            continue
        text = _safe_read_text(p).strip()
        if not text:
            continue
        artifacts.append(
            builder.make(
                category="System",
                subcategory="Host",
                title=f"System profile: {name.replace('.txt', '')}",
                details=text[:3000],
                source_file=str(p),
                raw_excerpt=text[:1000],
                severity="low",
                severity_reason="Baseline host/system metadata.",
            )
        )
    return artifacts


def parse_security_agents(root: Path, builder: ArtifactBuilder) -> list[Artifact]:
    artifacts: list[Artifact] = []
    sec_dir = root / "security_agents"
    if not sec_dir.exists():
        return artifacts

    text_parts: list[str] = []
    for p in sec_dir.glob("*.txt"):
        text_parts.append(_safe_read_text(p))
    for p in sec_dir.glob("*.plist"):
        text_parts.append(p.name)
    joined = "\n".join(text_parts).lower()

    checks = [
        ("jamf", "JAMF"),
        ("falcon", "CrowdStrike Falcon"),
        ("crowdstrike", "CrowdStrike"),
        ("tanium", "Tanium"),
    ]
    dedupe: set[str] = set()
    for key, display in checks:
        if display in dedupe:
            continue
        dedupe.add(display)
        present = key in joined
        artifacts.append(
            builder.make(
                category="Security Agents",
                subcategory="Coverage",
                title=f"{display} visibility",
                details=("Detected in process/file/service outputs" if present else "Not detected in collected outputs"),
                source_file=str(sec_dir),
                severity=("medium" if present else "high"),
                severity_reason=(
                    f"{display} artifacts were found in collected data."
                    if present
                    else f"{display} artifacts were not found. Verify EDR/MDM health and tamper status."
                ),
                parsed={
                    "event_type": "agent_coverage_check",
                    "agent_name": display,
                    "status": ("detected" if present else "not_detected"),
                    "check_type": "coverage",
                    "version": "",
                    "process_name": "",
                    "path": str(sec_dir),
                },
            )
        )

    for p in sorted(sec_dir.glob("*.plist"))[:200]:
        agent_name = detect_agent_name_from_text(p.name)
        artifacts.append(
            builder.make(
                category="Security Agents",
                subcategory="Launch Plist",
                title=f"Captured agent plist: {p.name}",
                details="Launch agent/daemon plist captured for validation.",
                source_file=str(p),
                severity="medium",
                severity_reason="Persistence/service config file from security tooling.",
                parsed={
                    "event_type": "security_agent_launch_plist",
                    "agent_name": agent_name,
                    "status": "detected",
                    "check_type": "launch_plist",
                    "version": "",
                    "process_name": "",
                    "path": str(p),
                },
            )
        )

    lines_by_agent = extract_security_agent_lines(sec_dir)
    for agent_name, lines in lines_by_agent.items():
        if not lines:
            continue
        version = extract_version_from_lines(lines)
        process_name = extract_process_name_from_lines(lines)
        details = (
            f"EventType: security_agent_telemetry\n"
            f"AgentName: {agent_name}\n"
            f"Status: detected\n"
            f"Version: {version or '-'}\n"
            f"ProcessName: {process_name or '-'}\n"
            "EvidenceLines:\n" + "\n".join(lines[:15])
        )
        artifacts.append(
            builder.make(
                category="Security Agents",
                subcategory="Telemetry",
                title=f"{agent_name} telemetry",
                details=details,
                source_file=str(sec_dir),
                raw_excerpt="\n".join(lines[:10]),
                severity="medium",
                severity_reason=f"{agent_name} related evidence lines captured from collector outputs.",
                parsed={
                    "event_type": "security_agent_telemetry",
                    "agent_name": agent_name,
                    "status": "detected",
                    "check_type": "telemetry",
                    "version": version,
                    "process_name": process_name,
                    "path": str(sec_dir),
                },
            )
        )

    return artifacts


def parse_install_timeline(root: Path, builder: ArtifactBuilder) -> list[Artifact]:
    artifacts: list[Artifact] = []

    plist_path = root / "timeline" / "InstallHistory.plist"
    if plist_path.exists():
        try:
            with plist_path.open("rb") as f:
                plist_data = plistlib.load(f)
            if isinstance(plist_data, list):
                for entry in plist_data[:3000]:
                    if not isinstance(entry, dict):
                        continue
                    date = _to_iso(entry.get("date"))
                    name = str(entry.get("displayName") or entry.get("processName") or "Unknown package")
                    version = str(entry.get("displayVersion") or entry.get("version") or "")
                    process_name = str(entry.get("processName") or "")
                    package_ids_raw = entry.get("packageIdentifiers")
                    package_ids = package_ids_raw if isinstance(package_ids_raw, list) else ([str(package_ids_raw)] if package_ids_raw else [])
                    package_ids = [str(x) for x in package_ids if str(x).strip()]
                    pkg_text = ", ".join(package_ids)
                    details = (
                        "EventType: package_install_event\n"
                        f"ProgramName: {name}\n"
                        f"Version: {version or '-'}\n"
                        f"ProcessName: {process_name or '-'}\n"
                        f"PackageIDs: {pkg_text or '-'}"
                    )
                    artifacts.append(
                        builder.make(
                            category="Installed Programs",
                            subcategory="InstallHistory",
                            title="Package install event",
                            details=details,
                            source_file=str(plist_path),
                            timestamp=date,
                            raw_excerpt=json.dumps(entry, default=str)[:1600],
                            severity="medium",
                            severity_reason="Software install event parsed from InstallHistory.plist.",
                            parsed={
                                "event_type": "package_install_event",
                                "program_name": name,
                                "version": version,
                                "process_name": process_name,
                                "package_ids": pkg_text,
                                "package_count": len(package_ids),
                            },
                        )
                    )
        except Exception as exc:
            artifacts.append(
                builder.make(
                    category="Installed Programs",
                    subcategory="InstallHistory",
                    title="InstallHistory parse error",
                    details=str(exc),
                    source_file=str(plist_path),
                    severity="low",
                    severity_reason="Parser failed to decode InstallHistory; verify collector output integrity.",
                )
            )

    apps_txt = root / "timeline" / "installed_apps.txt"
    if apps_txt.exists():
        artifacts.extend(parse_installed_apps_text(apps_txt, builder))

    pkg_txt = root / "timeline" / "pkgutil_pkgs.txt"
    if pkg_txt.exists():
        for line in _safe_read_text(pkg_txt).splitlines()[:2500]:
            ln = line.strip()
            if not ln:
                continue
            program_name = ln.split(".")[-1] if "." in ln else ln
            artifacts.append(
                builder.make(
                    category="Installed Programs",
                    subcategory="Pkgutil",
                    title="Installed package id",
                    details=(
                        "EventType: pkgutil_package_id\n"
                        f"ProgramName: {program_name}\n"
                        "Version: -\n"
                        "ProcessName: -\n"
                        f"PackageIDs: {ln}"
                    ),
                    source_file=str(pkg_txt),
                    raw_excerpt=ln,
                    severity="low",
                    severity_reason="Package identifier from pkgutil list.",
                    parsed={
                        "event_type": "pkgutil_package_id",
                        "program_name": program_name,
                        "version": "",
                        "process_name": "",
                        "package_ids": ln,
                        "package_count": 1,
                    },
                )
            )

    return artifacts


def parse_installed_apps_text(path: Path, builder: ArtifactBuilder) -> list[Artifact]:
    artifacts: list[Artifact] = []
    lines = _safe_read_text(path).splitlines()
    current_name = ""
    current_fields: dict[str, str] = {}

    def flush() -> None:
        nonlocal current_name, current_fields
        if not current_name:
            current_fields = {}
            return
        version = (
            current_fields.get("Version")
            or current_fields.get("Get Info String")
            or ""
        )
        location = current_fields.get("Location") or current_fields.get("Path") or ""
        fields = [f"{k}: {v}" for k, v in current_fields.items()]
        details = (
            "EventType: installed_application_inventory\n"
            f"ProgramName: {current_name}\n"
            f"Version: {version or '-'}\n"
            "ProcessName: -\n"
            "PackageIDs: -\n"
        )
        if location:
            details += f"Location: {location}\n"
        details += "\n" + "\n".join(fields[:10])
        artifacts.append(
            builder.make(
                category="Installed Programs",
                subcategory="Applications",
                title="Installed application inventory",
                details=details.strip(),
                source_file=str(path),
                raw_excerpt=details[:1200],
                severity="medium",
                severity_reason="Installed application inventory entry.",
                parsed={
                    "event_type": "installed_application_inventory",
                    "program_name": current_name,
                    "version": version,
                    "process_name": "",
                    "package_ids": "",
                    "package_count": 0,
                    "location": location,
                },
            )
        )
        current_name = ""
        current_fields = {}

    for raw in lines[:8000]:
        line = raw.rstrip()
        if not line:
            continue
        # system_profiler mini output typically has app blocks with indentation.
        m_app = re.match(r"^\s{4}([^:]+):\s*$", line)
        if m_app:
            flush()
            current_name = m_app.group(1).strip()
            continue
        if current_name:
            m_field = re.match(r"^\s{8}([^:]+):\s*(.*)$", line)
            if m_field:
                current_fields[m_field.group(1).strip()] = m_field.group(2).strip()

    flush()
    return artifacts


def parse_persistence(root: Path, builder: ArtifactBuilder) -> list[Artifact]:
    artifacts: list[Artifact] = []
    persist_dir = root / "persistence"
    if not persist_dir.exists():
        return artifacts

    mapping = {
        "user_launchagents.txt": "User LaunchAgents",
        "system_launchagents.txt": "System LaunchAgents",
        "system_launchdaemons.txt": "System LaunchDaemons",
        "launchctl_list.txt": "launchctl list",
        "user_crontab.txt": "user crontab",
        "login_items.txt": "login items",
    }

    for file_name, label in mapping.items():
        p = persist_dir / file_name
        if not p.exists():
            continue
        for line in _safe_read_text(p).splitlines()[:3000]:
            ln = line.strip()
            if not ln or ln.startswith("#"):
                continue
            details, parsed = parse_persistence_record(ln, label)
            artifacts.append(
                builder.make(
                    category="Persistence",
                    subcategory=label,
                    title="Persistence record",
                    details=details,
                    source_file=str(p),
                    raw_excerpt=ln,
                    severity="medium",
                    severity_reason=f"Autorun/persistence source: {label}.",
                    parsed=parsed,
                )
            )

    return artifacts


def parse_accounts(root: Path, builder: ArtifactBuilder) -> list[Artifact]:
    artifacts: list[Artifact] = []
    acct_dir = root / "accounts"
    if not acct_dir.exists():
        return artifacts

    users_path = acct_dir / "local_users.txt"
    if users_path.exists():
        for line in _safe_read_text(users_path).splitlines()[:3000]:
            user = line.strip()
            if not user:
                continue
            artifacts.append(
                builder.make(
                    category="Accounts",
                    subcategory="Local users",
                    title="Local account record",
                    details=f"User: {user}",
                    source_file=str(users_path),
                    raw_excerpt=user,
                    severity="low",
                    severity_reason="Local user enumeration entry.",
                    parsed={
                        "event_type": "local_user_account",
                        "username": user,
                    },
                )
            )

    logins_path = acct_dir / "last_logins.txt"
    if logins_path.exists():
        for line in _safe_read_text(logins_path).splitlines()[:2500]:
            ln = line.strip()
            if not ln:
                continue
            details, ts, parsed = parse_last_logins_line(ln)
            artifacts.append(
                builder.make(
                    category="Accounts",
                    subcategory="Last logins",
                    title="Login session record",
                    details=details,
                    source_file=str(logins_path),
                    timestamp=ts,
                    raw_excerpt=ln,
                    severity="low",
                    severity_reason="Login/logout session record from 'last'.",
                    parsed=parsed,
                )
            )

    return artifacts


def parse_command_history(root: Path, builder: ArtifactBuilder) -> list[Artifact]:
    artifacts: list[Artifact] = []
    acct_dir = root / "accounts"
    if not acct_dir.exists():
        return artifacts

    zsh_path = acct_dir / "zsh_history.txt"
    if zsh_path.exists():
        for line in _safe_read_text(zsh_path).splitlines()[:4500]:
            ln = line.strip()
            if not ln:
                continue
            ts, command, raw = parse_zsh_history_line(ln)
            sev, reason = classify_command_severity(command)
            command_base = command.split()[0] if command.split() else ""
            artifacts.append(
                builder.make(
                    category="Command History",
                    subcategory="zsh",
                    title="Shell command",
                    details=command,
                    source_file=str(zsh_path),
                    timestamp=ts,
                    raw_excerpt=raw,
                    severity=sev,
                    severity_reason=reason,
                    parsed={
                        "event_type": "shell_command",
                        "shell": "zsh",
                        "command": command,
                        "command_base": command_base,
                    },
                )
            )

    bash_path = acct_dir / "bash_history.txt"
    if bash_path.exists():
        for ts, command, raw in parse_bash_history_lines(_safe_read_text(bash_path).splitlines()[:4500]):
            if not command:
                continue
            sev, reason = classify_command_severity(command)
            command_base = command.split()[0] if command.split() else ""
            artifacts.append(
                builder.make(
                    category="Command History",
                    subcategory="bash",
                    title="Shell command",
                    details=command,
                    source_file=str(bash_path),
                    timestamp=ts,
                    raw_excerpt=raw,
                    severity=sev,
                    severity_reason=reason,
                    parsed={
                        "event_type": "shell_command",
                        "shell": "bash",
                        "command": command,
                        "command_base": command_base,
                    },
                )
            )

    return artifacts


def parse_network(root: Path, builder: ArtifactBuilder) -> list[Artifact]:
    artifacts: list[Artifact] = []
    net_dir = root / "network"
    if not net_dir.exists():
        return artifacts

    netstat = net_dir / "netstat_anv.txt"
    if netstat.exists():
        process_counter: Counter[str] = Counter()
        state_counter: Counter[str] = Counter()
        kept = 0
        for line in _safe_read_text(netstat).splitlines()[:10000]:
            ln = line.strip()
            if not ln or "Proto" in ln:
                continue
            if not re.search(r"\b(TCP|UDP|ESTABLISHED|LISTEN|SYN_SENT)\b", ln, flags=re.IGNORECASE):
                continue
            parsed = parse_netstat_line(ln)
            state = parsed["state"]
            local_addr = parsed["local_addr"]
            remote_addr = parsed["remote_addr"]
            process_name = parsed["process_name"]
            if process_name:
                process_counter[process_name] += 1
            if state:
                state_counter[state] += 1
            artifacts.append(
                builder.make(
                    category="Network",
                    subcategory="Netstat",
                    title="Socket table entry",
                    details=(
                        f"Local: {local_addr or '-'}\n"
                        f"Remote: {remote_addr or '-'}\n"
                        f"State: {state or '-'}\n"
                        f"Process: {process_name or '-'}"
                    ),
                    source_file=str(netstat),
                    raw_excerpt=ln,
                    severity="medium",
                    severity_reason="Network connection or listening socket observed.",
                    parsed={
                        "event_type": "socket_table_entry",
                        "protocol": parsed["protocol"],
                        "state": state,
                        "local_addr": local_addr,
                        "remote_addr": remote_addr,
                        "process_name": process_name,
                        "pid": parsed["pid"],
                    },
                )
            )
            kept += 1
            if kept >= 2200:
                break

        if process_counter:
            top_process = "\n".join([f"{k}: {v}" for k, v in process_counter.most_common(20)])
            top_states = "\n".join([f"{k}: {v}" for k, v in state_counter.most_common(10)])
            artifacts.append(
                builder.make(
                    category="Network",
                    subcategory="Summary",
                    title="Socket concentration summary",
                    details=f"Top processes\n{top_process}\n\nStates\n{top_states}",
                    source_file=str(netstat),
                    severity="low",
                    severity_reason="Aggregated network socket distribution for analyst triage.",
                )
            )

    lsof = net_dir / "lsof_network.txt"
    if lsof.exists():
        kept = 0
        for line in _safe_read_text(lsof).splitlines()[:6000]:
            ln = line.strip()
            if not ln:
                continue
            if "TCP" not in ln and "UDP" not in ln:
                continue
            details, parsed = parse_lsof_network_line(ln)
            artifacts.append(
                builder.make(
                    category="Network",
                    subcategory="Lsof",
                    title="Process-to-socket mapping",
                    details=details,
                    source_file=str(lsof),
                    raw_excerpt=ln,
                    severity="medium",
                    severity_reason="Process network footprint captured by lsof.",
                    parsed=parsed,
                )
            )
            kept += 1
            if kept >= 1800:
                break

    return artifacts


def parse_remote_kvm(root: Path, builder: ArtifactBuilder) -> list[Artifact]:
    artifacts: list[Artifact] = []
    kvm_dir = root / "remote_kvm"
    if not kvm_dir.exists():
        return artifacts

    checked_files = [
        "kvm_keyword_hits.txt",
        "network_devices.txt",
        "ethernet_devices.txt",
        "thunderbolt_devices.txt",
        "usb_devices.txt",
        "pmset.txt",
    ]
    indicator_count = 0
    seen: set[tuple[str, str, str]] = set()
    for fname in checked_files:
        p = kvm_dir / fname
        if not p.exists():
            continue
        for raw in _safe_read_text(p).splitlines()[:12000]:
            line = raw.strip()
            if not line:
                continue
            keyword = detect_kvm_keyword(line)
            if not keyword:
                continue
            key = (fname, keyword, line.lower())
            if key in seen:
                continue
            seen.add(key)
            indicator_count += 1
            artifacts.append(
                builder.make(
                    category="Remote/KVM",
                    subcategory="Remote Management Indicator",
                    title="Explicit remote-management indicator",
                    details=(
                        f"EventType: remote_management_indicator\n"
                        f"Keyword: {keyword}\n"
                        f"Source: {fname}\n"
                        f"Line: {line}"
                    ),
                    source_file=str(p),
                    raw_excerpt=line,
                    severity="high",
                    severity_reason="Explicit IP-KVM/IPMI/remote-console indicator matched.",
                    parsed={
                        "event_type": "remote_management_indicator",
                        "keyword": keyword,
                        "source_name": fname,
                        "line": line,
                    },
                )
            )
            if indicator_count >= 400:
                break
        if indicator_count >= 400:
            break

    if indicator_count == 0:
        artifacts.append(
            builder.make(
                category="Remote/KVM",
                subcategory="Remote Management Indicator",
                title="No explicit remote-management indicator",
                details=(
                    "Scanned remote_kvm artifacts but found no explicit IP-KVM/IPMI/remote-console keywords. "
                    "General monitor/device inventory is intentionally excluded to avoid false positives."
                ),
                source_file=str(kvm_dir),
                severity="low",
                severity_reason="No explicit KVM/remote-management keyword observed.",
                parsed={
                    "event_type": "remote_management_indicator_summary",
                    "status": "not_detected",
                    "checked_files": ",".join(checked_files),
                },
            )
        )
    return artifacts


def parse_browsers(root: Path, builder: ArtifactBuilder) -> list[Artifact]:
    artifacts: list[Artifact] = []
    browser_dir = root / "browser"
    if not browser_dir.exists():
        return artifacts

    db_files = [p for p in browser_dir.glob("*.db") if p.is_file() and not p.name.startswith("._")]
    if not db_files:
        artifacts.append(
            builder.make(
                category="Browser",
                subcategory="History",
                title="No browser DB found",
                details="Collector bundle does not include browser history DB files.",
                source_file=str(browser_dir),
                severity="low",
                severity_reason="No browser database captured in bundle.",
            )
        )
        return artifacts

    for db_file in sorted(db_files)[:12]:
        artifacts.extend(parse_browser_db(db_file, builder, source_prefix=f"browser/{db_file.name}"))
    return artifacts


def parse_browser_db(db_file: Path, builder: ArtifactBuilder, source_prefix: str) -> list[Artifact]:
    artifacts: list[Artifact] = []
    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}

        if {"urls", "visits"}.issubset(tables):
            rows = conn.execute(
                """
                SELECT u.url, COALESCE(u.title,'') AS title, COALESCE(u.visit_count,0) AS visit_count, COALESCE(u.last_visit_time,0) AS last_visit_time
                FROM urls u
                ORDER BY u.last_visit_time DESC
                LIMIT 1200
                """
            ).fetchall()
            for row in rows:
                url = str(row["url"] or "")
                ts = _chromium_ts_to_iso(int(row["last_visit_time"]))
                page_title = str(row["title"] or "")
                parsed_url = parse_url_fields(url=url, page_title=page_title, browser_family="Chromium")
                details = (
                    f"URL: {url}\n"
                    f"PageTitle: {page_title}\n"
                    f"Domain: {parsed_url['domain']}\n"
                    f"Path: {parsed_url['path']}\n"
                    f"QueryKeys: {parsed_url['query_keys']}\n"
                    f"VisitCount: {row['visit_count']}"
                )
                severity, reason = classify_url_severity(url)
                artifacts.append(
                    builder.make(
                        category="Browser",
                        subcategory="Chromium History",
                        title="Browser visit",
                        details=details,
                        source_file=source_prefix,
                        timestamp=ts,
                        raw_excerpt=url,
                        severity=severity,
                        severity_reason=reason,
                        parsed={**parsed_url, "visit_count": int(row["visit_count"] or 0)},
                    )
                )

        elif {"moz_places", "moz_historyvisits"}.issubset(tables):
            rows = conn.execute(
                """
                SELECT p.url, COALESCE(p.title,'') AS title, COALESCE(p.visit_count,0) AS visit_count, COALESCE(v.visit_date,0) AS visit_date
                FROM moz_places p
                LEFT JOIN moz_historyvisits v ON p.id = v.place_id
                ORDER BY v.visit_date DESC
                LIMIT 1200
                """
            ).fetchall()
            for row in rows:
                url = str(row["url"] or "")
                ts = _firefox_ts_to_iso(int(row["visit_date"]))
                page_title = str(row["title"] or "")
                parsed_url = parse_url_fields(url=url, page_title=page_title, browser_family="Firefox")
                details = (
                    f"URL: {url}\n"
                    f"PageTitle: {page_title}\n"
                    f"Domain: {parsed_url['domain']}\n"
                    f"Path: {parsed_url['path']}\n"
                    f"QueryKeys: {parsed_url['query_keys']}\n"
                    f"VisitCount: {row['visit_count']}"
                )
                severity, reason = classify_url_severity(url)
                artifacts.append(
                    builder.make(
                        category="Browser",
                        subcategory="Firefox History",
                        title="Browser visit",
                        details=details,
                        source_file=source_prefix,
                        timestamp=ts,
                        raw_excerpt=url,
                        severity=severity,
                        severity_reason=reason,
                        parsed={**parsed_url, "visit_count": int(row["visit_count"] or 0)},
                    )
                )

        elif {"history_items", "history_visits"}.issubset(tables):
            rows = conn.execute(
                """
                SELECT i.url, COALESCE(i.title,'') AS title, COALESCE(v.visit_time,0) AS visit_time
                FROM history_items i
                JOIN history_visits v ON i.id = v.history_item
                ORDER BY v.visit_time DESC
                LIMIT 1200
                """
            ).fetchall()
            for row in rows:
                url = str(row["url"] or "")
                ts = _safari_ts_to_iso(float(row["visit_time"]))
                page_title = str(row["title"] or "")
                parsed_url = parse_url_fields(url=url, page_title=page_title, browser_family="Safari")
                details = (
                    f"URL: {url}\n"
                    f"PageTitle: {page_title}\n"
                    f"Domain: {parsed_url['domain']}\n"
                    f"Path: {parsed_url['path']}\n"
                    f"QueryKeys: {parsed_url['query_keys']}"
                )
                severity, reason = classify_url_severity(url)
                artifacts.append(
                    builder.make(
                        category="Browser",
                        subcategory="Safari History",
                        title="Browser visit",
                        details=details,
                        source_file=source_prefix,
                        timestamp=ts,
                        raw_excerpt=url,
                        severity=severity,
                        severity_reason=reason,
                        parsed=parsed_url,
                    )
                )
        else:
            row = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()
            count = int(row[0]) if row else 0
            artifacts.append(
                builder.make(
                    category="Browser",
                    subcategory="SQLite",
                    title="SQLite parsed (unknown browser schema)",
                    details=f"File: {db_file.name}\nTableCount: {count}",
                    source_file=source_prefix,
                    severity="low",
                    severity_reason="SQLite opened but known browser schema not matched.",
                )
            )
    except Exception as exc:
        artifacts.append(
            builder.make(
                category="Browser",
                subcategory="SQLite Error",
                title="Browser DB parse failed",
                details=f"File: {db_file.name}\nError: {exc}",
                source_file=source_prefix,
                severity="medium",
                severity_reason="Browser DB exists but parse failed; verify lock/corruption/permissions.",
            )
        )
    finally:
        if conn:
            conn.close()
    return artifacts


def parse_logs(root: Path, builder: ArtifactBuilder) -> list[Artifact]:
    artifacts: list[Artifact] = []
    log_dir = root / "logs"
    if not log_dir.exists():
        return artifacts

    mapping = [
        ("auth_remote_last6h.log", 1600),
        ("unified_last6h.log", 1200),
        ("security_controls_last24h.log", 1200),
        ("system.log", 800),
        ("install.log", 800),
        ("jamf.log", 800),
    ]
    for fname, limit in mapping:
        p = log_dir / fname
        if not p.exists():
            continue
        artifacts.extend(parse_text_log(p, builder, category="Logs", subcategory=fname, max_lines=limit))
    return artifacts


def parse_text_log(
    path: Path,
    builder: ArtifactBuilder,
    category: str,
    subcategory: str,
    max_lines: int,
) -> list[Artifact]:
    artifacts: list[Artifact] = []
    kept = 0
    ai_assisted = 0
    scanned = 0
    total = 0
    sample_every = 120
    scan_limit = max(max_lines * 35, 25000)
    stop_by_scan_limit = False

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            total += 1
            if total > scan_limit:
                stop_by_scan_limit = True
                break

            ln = raw.strip()
            if not ln:
                continue
            scanned += 1

            sev, reason = classify_log_line(ln)
            keep = sev != "low" or (scanned % sample_every == 0)
            if not keep:
                continue

            ts, process_name, message = parse_unified_log_line(ln)
            title = "Log event"
            details = f"Process: {process_name or '-'}\nMessage: {message}"
            ai_parse = try_ai_parse_line(ln, category=category, subcategory=subcategory, timestamp=ts, process_name=process_name)
            ai_used = False
            if ai_parse:
                ai_used = True
                ai_assisted += 1
                if not ts:
                    ts = ai_parse.get("timestamp") or ts
                title = ai_parse.get("title") or title
                details = ai_parse.get("details") or details
                note = ai_parse.get("reason") or ""
                if note:
                    details = f"{details}\nAI Parse Note: {note}"
            artifacts.append(
                builder.make(
                    category=category,
                    subcategory=subcategory,
                    title=title,
                    details=details,
                    source_file=str(path),
                    timestamp=ts or _extract_timestamp(ln),
                    raw_excerpt=ln,
                    severity=sev,
                    severity_reason=reason,
                    parsed={
                        "event_type": "log_line",
                        "process_name": process_name,
                        "message": message,
                        "ai_assisted": ai_used,
                        "log_source": path.name,
                    },
                )
            )
            kept += 1
            if kept >= max_lines:
                break

    artifacts.append(
        builder.make(
            category=category,
            subcategory=subcategory,
            title="Log coverage summary",
            details=(
                f"File: {path.name}\n"
                f"TotalScannedLines: {total}\n"
                f"SelectedEvents: {kept}\n"
                f"AIAssistedEvents: {ai_assisted}\n"
                f"SamplingPolicy: non-low + every {sample_every}th line"
            ),
            source_file=str(path),
            severity="low",
            severity_reason="Summarized log selection metadata for performance-aware analysis.",
        )
    )

    if stop_by_scan_limit:
        artifacts.append(
            builder.make(
                category=category,
                subcategory=subcategory,
                title="Log scan limit reached",
                details=f"Scan stopped at {scan_limit} lines to keep parsing latency stable.",
                source_file=str(path),
                severity="low",
                severity_reason="Performance guardrail for large logs.",
            )
        )

    return artifacts


def build_summary(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    by_severity = Counter(a.get("severity", "low") for a in artifacts)
    by_category = Counter(a.get("category", "Unknown") for a in artifacts)
    by_subcategory = Counter(a.get("subcategory", "Unknown") for a in artifacts)
    return {
        "artifact_count": len(artifacts),
        "severity": dict(by_severity),
        "category": dict(by_category),
        "subcategory": dict(by_subcategory),
    }


def cap_artifacts_for_ui(artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    per_category_limits = {
        "Logs": 2600,
        "Browser": 4200,
        "Network": 2600,
        "Command History": 2200,
        "Persistence": 2200,
        "Accounts": 1500,
        "Installed Programs": 1800,
        "Security Agents": 1000,
        "Remote/KVM": 800,
    }
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in artifacts:
        cat = str(row.get("category") or "Other")
        grouped.setdefault(cat, []).append(row)

    capped: list[dict[str, Any]] = []
    for category, rows in grouped.items():
        limit = per_category_limits.get(category, 1200)
        ordered = sorted(
            rows,
            key=lambda x: (
                severity_rank.get(str(x.get("severity") or "low").lower(), 9),
                str(x.get("timestamp") or ""),
            ),
        )
        capped.extend(ordered[:limit])

    capped.sort(key=lambda x: (str(x.get("timestamp") or ""), str(x.get("id") or "")))
    return capped


def build_timeline(artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = [a for a in artifacts if a.get("timestamp")]
    rows.sort(key=lambda x: (x.get("timestamp") or "", x.get("id") or ""))
    return rows[:15000]


def classify_severity(
    category: str,
    subcategory: str,
    title: str,
    details: str,
    source_file: str,
) -> tuple[str, str]:
    text = f"{category}\n{subcategory}\n{title}\n{details}\n{source_file}".lower()

    if "not detected in collected outputs" in text and any(agent in text for agent in ("falcon", "tanium", "jamf")):
        return "high", "Expected security agent signal missing from collected output."

    if category == "Persistence":
        return "medium", "Persistence/autostart related artifact."

    if category == "Remote/KVM" and "indicator" in title.lower():
        return "high", "Remote management / IP-KVM indicator found."

    if category == "Network":
        return "medium", "Network communication/process socket artifact."

    if category == "Installed Programs":
        return "medium", "Software installation inventory/event."

    if category == "Browser":
        sev, reason = classify_url_severity(details)
        return sev, reason

    for token in IOC_TERMS_CRITICAL:
        if token in text:
            return "critical", f"Explicit IOC term detected: '{token}'."
    for token in IOC_TERMS_HIGH:
        if token in text:
            return "high", f"Potentially risky term detected: '{token}'."

    return "low", "Parsed artifact. No elevated parser rule matched."


def classify_url_severity(text: str) -> tuple[str, str]:
    value = text.lower()
    if ".onion" in value:
        return "critical", "URL contains .onion domain (Tor hidden service)."
    if any(k in value for k in ("malware", "ransom", "phish", "stealer")):
        return "high", "URL contains known malware/phishing-like keyword."
    if any(k in value for k in ("tor", "proxy", "anonym", "vpn")):
        return "medium", "URL suggests anonymization/evasion-related context."
    return "low", "Browser history entry parsed."


def classify_log_line(line: str) -> tuple[str, str]:
    low = line.lower()
    if any(k in low for k in ("ransom", "mimikatz", ".onion", "command and control", "exfil")):
        return "critical", "Log line contains explicit critical IOC term."
    if any(k in low for k in ("failed password", "authentication failure", "unauthorized", "tamper", "screen sharing")):
        return "high", "Log line indicates auth failure or unauthorized access signal."
    if any(k in low for k in ("launchdaemon", "launchagent", "persistence", "error", "warning")):
        return "medium", "Log line includes persistence or warning/error signal."
    return "low", "General log entry."


def classify_command_severity(command: str) -> tuple[str, str]:
    cmd = command.lower()
    critical_tokens = ("rm -rf /", "launchctl bootout", "csrutil disable", "spctl --master-disable")
    high_tokens = (
        "sudo",
        "curl ",
        "wget ",
        "osascript",
        "launchctl",
        "defaults write",
        "chmod +x",
        "chflags",
        "xattr -d",
        "kextload",
    )
    if any(token in cmd for token in critical_tokens):
        return "critical", "Potentially destructive privileged shell command."
    if any(token in cmd for token in high_tokens):
        return "high", "Privileged or persistence-relevant shell command."
    return "medium", "Shell command history entry."


def parse_zsh_history_line(line: str) -> tuple[str | None, str, str]:
    # Extended history format: ": <epoch>:<duration>;<command>"
    m = re.match(r"^:\s*(\d+):\d+;(.*)$", line)
    if not m:
        return None, line, line
    epoch = int(m.group(1))
    command = m.group(2).strip()
    ts = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    return ts, command, line


def parse_bash_history_lines(lines: list[str]) -> list[tuple[str | None, str, str]]:
    out: list[tuple[str | None, str, str]] = []
    current_ts: str | None = None
    for raw in lines:
        ln = raw.strip()
        if not ln:
            continue
        if re.match(r"^#\d{9,12}$", ln):
            epoch = int(ln[1:])
            current_ts = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
            continue
        out.append((current_ts, ln, raw))
        current_ts = None
    return out


def parse_last_logins_line(line: str) -> tuple[str, str | None, dict[str, Any]]:
    ts = _extract_timestamp(line)
    # Korean month format from `last`: "2월 18 03:27"
    m = re.search(r"(\d{1,2})월\s*(\d{1,2})\s+(\d{2}):(\d{2})", line)
    if m and not ts:
        month = int(m.group(1))
        day = int(m.group(2))
        hour = int(m.group(3))
        minute = int(m.group(4))
        now = datetime.now(timezone.utc)
        year = now.year
        try:
            ts = datetime(year, month, day, hour, minute, tzinfo=timezone.utc).isoformat()
        except Exception:
            ts = None

    clean = line.strip()
    fields = re.split(r"\s{2,}", clean)
    parsed: dict[str, Any] = {"event_type": "login_session_record"}
    user = ""
    tty = ""
    session = ""
    m_line = re.match(r"^(\S+)\s+(\S+)\s+(.+)$", clean)
    if m_line:
        user, tty, session = m_line.group(1), m_line.group(2), m_line.group(3)
    elif len(fields) >= 3:
        user = fields[0]
        tty = fields[1]
        session = " ".join(fields[2:])

    if user and tty and session:
        details = f"User: {user}\nTTY: {tty}\nSession: {session}"
        parsed.update(
            {
                "username": user,
                "tty": tty,
                "session": session,
            }
        )
    else:
        details = clean
        parsed.update({"username": "", "tty": "", "session": ""})
    return details, ts, parsed


def parse_netstat_line(line: str) -> dict[str, str]:
    parts = re.split(r"\s+", line.strip())
    if len(parts) < 6:
        return {
            "protocol": "",
            "state": "",
            "local_addr": "",
            "remote_addr": "",
            "process_name": "",
            "pid": "",
        }
    state = ""
    local_addr = ""
    remote_addr = ""
    process_name = ""
    pid = ""
    protocol = parts[0].upper() if parts else ""

    # Typical macOS netstat_anv layout:
    # Proto Recv-Q Send-Q Local Foreign State rx tx ... process:pid ...
    if len(parts) >= 6:
        local_addr = parts[3]
        remote_addr = parts[4]
    if len(parts) >= 6:
        state = parts[5].strip("()")
    proc_matches = re.findall(
        r"([A-Za-z][A-Za-z0-9._()\\/-]*(?: [A-Za-z0-9._()\\/-]+){0,4}):(\d+)",
        line,
    )
    if proc_matches:
        process_name, pid = proc_matches[-1][0].strip(), proc_matches[-1][1].strip()
        process_name = re.sub(r"\s*\([^)]*$", "", process_name).strip()
    return {
        "protocol": protocol,
        "state": state,
        "local_addr": local_addr,
        "remote_addr": remote_addr,
        "process_name": process_name,
        "pid": pid,
    }


def parse_lsof_network_line(line: str) -> tuple[str, dict[str, Any]]:
    m = re.match(r"^(\S+)\s+(\d+)\s+(\S+)\s+.*?\b(TCP|UDP)\s+(.*)$", line.strip(), flags=re.IGNORECASE)
    if m:
        process = m.group(1).strip()
        pid = m.group(2).strip()
        user = m.group(3).strip()
        proto = m.group(4).upper()
        name = m.group(5).strip()
    else:
        process = ""
        pid = ""
        user = ""
        proto = "TCP" if "TCP" in line else ("UDP" if "UDP" in line else "")
        name = line.strip()
    return (
        f"Process: {process} (pid={pid}, user={user})\nProtocol: {proto}\nEndpoint: {name}",
        {
            "event_type": "process_socket_mapping",
            "protocol": proto,
            "process_name": process,
            "pid": pid,
            "user": user,
            "endpoint": name,
        },
    )


def parse_unified_log_line(line: str) -> tuple[str | None, str, str]:
    ts = _extract_timestamp(line)
    m = re.match(
        r"^\S+\s+\S+\s+\S+\s+([A-Za-z0-9_.\\-]+)\[(\d+)\]:\s*(.*)$",
        line,
    )
    if m:
        process_name = m.group(1)
        message = m.group(3).strip()
        return ts, process_name, message
    return ts, "", line


def parse_persistence_record(raw: str, label: str) -> tuple[str, dict[str, Any]]:
    text = raw.strip()
    parsed: dict[str, Any] = {
        "event_type": "persistence_record",
        "source_type": label,
        "path": "",
        "item_name": "",
        "pid": "",
        "status": "",
        "launch_label": "",
        "value": text,
    }
    if "/" in text and text.endswith(".plist"):
        name = Path(text).name
        parsed.update({"path": text, "item_name": name, "value": ""})
        return f"Type: {label}\nName: {name}\nPath: {text}", parsed
    if label == "launchctl list":
        cols = re.split(r"\s+", text)
        if len(cols) >= 3:
            launch_label = " ".join(cols[2:])
            parsed.update({"pid": cols[0], "status": cols[1], "launch_label": launch_label, "value": ""})
            return f"PID: {cols[0]}\nStatus: {cols[1]}\nLabel: {launch_label}", parsed
    if label == "login items":
        parsed.update({"item_name": text, "value": ""})
        return f"Login Item: {text}", parsed
    return f"Type: {label}\nValue: {text}", parsed


def detect_kvm_keyword(line: str) -> str:
    text = line.strip()
    if not text:
        return ""
    for pattern, keyword in KVM_INDICATOR_PATTERNS:
        if pattern.search(text):
            return keyword
    return ""


def try_ai_parse_line(
    line: str,
    *,
    category: str,
    subcategory: str,
    timestamp: str | None,
    process_name: str,
) -> dict[str, str] | None:
    ai = _PARSER_AI_CTX.get()
    if not ai:
        return None
    if timestamp:
        return None
    if process_name and len(process_name) > 1:
        return None
    if len(line) < 30:
        return None
    return ai.parse_event_line(line, category=category, subcategory=subcategory)


def _safe_json_object(value: str) -> dict[str, Any] | None:
    text = value.strip()
    if not text:
        return None
    try:
        decoded = json.loads(text)
        if isinstance(decoded, dict):
            return decoded
    except Exception:
        pass
    m = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not m:
        return None
    try:
        decoded = json.loads(m.group(0))
    except Exception:
        return None
    return decoded if isinstance(decoded, dict) else None


def _safe_read_text(path: Path) -> str:
    data = path.read_bytes()
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(enc)
        except Exception:
            continue
    return ""


def _extract_zip(source: Path, out_dir: Path) -> None:
    try:
        with zipfile.ZipFile(source, "r") as zf:
            encrypted = [i.filename for i in zf.infolist() if i.flag_bits & 0x1]
            if encrypted:
                raise RuntimeError(
                    "Encrypted ZIP detected. Please provide a non-encrypted collector ZIP or decrypt it before upload."
                )
            zf.extractall(out_dir)
    except RuntimeError as exc:
        if "encrypted" in str(exc).lower():
            raise RuntimeError(
                "Encrypted ZIP detected. Python parser cannot extract password-protected ZIP in web upload path."
            ) from exc
        raise
    except NotImplementedError as exc:
        raise RuntimeError("Unsupported ZIP encryption/compression method.") from exc


def _to_iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return None


def _chromium_ts_to_iso(raw: int) -> str | None:
    if raw <= 0:
        return None
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    dt = epoch + timedelta(microseconds=raw)
    return dt.isoformat()


def _firefox_ts_to_iso(raw: int) -> str | None:
    if raw <= 0:
        return None
    dt = datetime.fromtimestamp(raw / 1_000_000, tz=timezone.utc)
    return dt.isoformat()


def _safari_ts_to_iso(raw: float) -> str | None:
    if raw <= 0:
        return None
    epoch = datetime(2001, 1, 1, tzinfo=timezone.utc)
    dt = epoch + timedelta(seconds=raw)
    return dt.isoformat()


def _extract_timestamp(line: str) -> str | None:
    patterns = (
        r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)",
        r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
        r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2})",
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
        r"([월화수목금토일]\s+\d{1,2}월\s+\d{1,2}\s+\d{2}:\d{2})",
    )
    for pattern in patterns:
        m = re.search(pattern, line)
        if not m:
            continue
        raw = m.group(1)
        try:
            if re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}$", raw):
                dt = datetime.strptime(raw, "%b %d %H:%M:%S").replace(year=datetime.now().year, tzinfo=timezone.utc)
                return dt.isoformat()
            if re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}$", raw):
                dt = datetime.strptime(raw, "%b %d %H:%M").replace(year=datetime.now().year, tzinfo=timezone.utc)
                return dt.isoformat()
            if re.match(r"^[월화수목금토일]\s+\d{1,2}월\s+\d{1,2}\s+\d{2}:\d{2}$", raw):
                m2 = re.match(r"^[월화수목금토일]\s+(\d{1,2})월\s+(\d{1,2})\s+(\d{2}):(\d{2})$", raw)
                if m2:
                    month = int(m2.group(1))
                    day = int(m2.group(2))
                    hour = int(m2.group(3))
                    minute = int(m2.group(4))
                    dt = datetime(datetime.now().year, month, day, hour, minute, tzinfo=timezone.utc)
                    return dt.isoformat()
            if "T" in raw or raw.endswith("Z") or "+" in raw[10:] or "-" in raw[10:]:
                return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
            return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).isoformat()
        except Exception:
            continue
    return None


def _run_cmd(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True)


def parse_url_fields(url: str, page_title: str, browser_family: str) -> dict[str, Any]:
    parsed = {
        "browser_family": browser_family,
        "url": url or "",
        "page_title": page_title or "",
        "domain": "",
        "path": "",
        "query": "",
        "query_keys": "",
        "query_param_count": 0,
    }
    raw = (url or "").strip()
    if not raw:
        return parsed
    try:
        u = urlsplit(raw)
    except Exception:
        return parsed
    domain = (u.hostname or "").lower()
    query = u.query or ""
    keys = []
    if query:
        try:
            keys = sorted({k for k, _ in parse_qsl(query, keep_blank_values=True) if k})
        except Exception:
            keys = []
    parsed["domain"] = domain
    parsed["path"] = u.path or "/"
    parsed["query"] = query
    parsed["query_keys"] = ", ".join(keys[:20]) if keys else ""
    parsed["query_param_count"] = len(keys)
    return parsed


def detect_agent_name_from_text(value: str) -> str:
    text = (value or "").lower()
    if "jamf" in text:
        return "JAMF"
    if "falcon" in text or "crowdstrike" in text:
        return "CrowdStrike Falcon"
    if "tanium" in text:
        return "Tanium"
    return "Unknown"


def extract_security_agent_lines(sec_dir: Path) -> dict[str, list[str]]:
    mapping = {
        "JAMF": ("jamf",),
        "CrowdStrike Falcon": ("falcon", "crowdstrike"),
        "Tanium": ("tanium",),
    }
    buckets: dict[str, list[str]] = {k: [] for k in mapping}
    for p in sec_dir.glob("*.txt"):
        text = _safe_read_text(p)
        for raw in text.splitlines():
            ln = raw.strip()
            if not ln:
                continue
            low = ln.lower()
            for agent, keywords in mapping.items():
                if any(k in low for k in keywords):
                    buckets[agent].append(ln)
    return buckets


def extract_version_from_lines(lines: list[str]) -> str:
    for ln in lines[:200]:
        m = re.search(r"\b(?:version|ver)\s*[:=]?\s*([0-9]+(?:\.[0-9A-Za-z_-]+){0,4})\b", ln, flags=re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def extract_process_name_from_lines(lines: list[str]) -> str:
    for ln in lines[:200]:
        m = re.search(r"\b([A-Za-z0-9._-]+)\s*\(\d+\)", ln)
        if m:
            return m.group(1)
    for ln in lines[:200]:
        low = ln.lower()
        if "falcond" in low:
            return "falcond"
        if "taniumclient" in low:
            return "TaniumClient"
        if "jamf" in low:
            return "jamf"
    return ""
