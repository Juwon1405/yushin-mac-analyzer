from __future__ import annotations

import csv
import json
import os
import re
import secrets
import shutil
from io import StringIO
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

from .dfir_parser import parse_input
from .llm import run_local_ollama, run_openai
from .reporting import build_dfir_pdf


BASE_DIR = Path(__file__).resolve().parents[2]
CASES_DIR = BASE_DIR / "cases"
UPLOADS_DIR = BASE_DIR / "uploads"
CASES_DIR.mkdir(parents=True, exist_ok=True)
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
CASE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

VIEW_CATEGORY_MAP = {
    "browser": "Browser",
    "installed": "Installed Programs",
    "persistence": "Persistence",
    "security": "Security Agents",
    "remote": "Remote/KVM",
    "network": "Network",
    "logs": "Logs",
    "accounts": "Accounts",
    "commands": "Command History",
}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "webapp" / "templates"),
        static_folder=str(BASE_DIR / "webapp" / "static"),
    )
    app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024 * 1024  # 8GB
    app.config["OPENAI_API_KEY"] = str(os.getenv("OPENAI_API_KEY", "")).strip()
    app.config["OPENAI_CHAT_MODEL"] = str(os.getenv("OPENAI_CHAT_MODEL", "gpt-4.1-mini")).strip() or "gpt-4.1-mini"
    app.config["OPENAI_EMBED_MODEL"] = str(os.getenv("OPENAI_EMBED_MODEL", "text-embedding-3-small")).strip() or "text-embedding-3-small"

    @app.get("/")
    def index() -> str:
        return render_template("index.html")

    @app.get("/api/health")
    def health() -> Any:
        return jsonify(
            {
                "ok": True,
                "service": "macOS DFIR Toolkit",
                "openai": {
                    "configured": bool(app.config.get("OPENAI_API_KEY")),
                    "chat_model": app.config.get("OPENAI_CHAT_MODEL"),
                    "embed_model": app.config.get("OPENAI_EMBED_MODEL"),
                },
            }
        )

    @app.get("/api/cases")
    def list_cases() -> Any:
        rows = []
        for case_json in CASES_DIR.glob("*/case.json"):
            try:
                data = json.loads(case_json.read_text(encoding="utf-8"))
                rows.append(
                    {
                        "case_id": data.get("case_id"),
                        "source_name": data.get("source_name"),
                        "source_type": data.get("source_type"),
                        "created_at": data.get("created_at"),
                        "summary": data.get("summary", {}),
                    }
                )
            except Exception:
                continue
        rows.sort(key=lambda x: str(x.get("created_at") or ""), reverse=True)
        return jsonify({"cases": rows})

    @app.post("/api/cases/clear")
    def clear_cases() -> Any:
        removed_cases = remove_children(CASES_DIR)
        removed_uploads = remove_children(UPLOADS_DIR)
        return jsonify(
            {
                "ok": True,
                "removed_cases": removed_cases,
                "removed_uploads": removed_uploads,
            }
        )

    @app.get("/api/cases/<case_id>")
    def get_case(case_id: str) -> Any:
        data = load_case(case_id)
        if not data:
            return jsonify({"ok": False, "error": "Case not found"}), 404
        include_artifacts = parse_bool(request.args.get("include_artifacts"), default=False)
        return jsonify({"ok": True, "case": build_case_payload(data, include_artifacts=include_artifacts)})

    @app.get("/api/cases/<case_id>/dashboard")
    def get_dashboard(case_id: str) -> Any:
        case_data = load_case(case_id)
        if not case_data:
            return jsonify({"ok": False, "error": "Case not found"}), 404
        return jsonify({"ok": True, "dashboard": build_dashboard_payload(case_data)})

    @app.post("/api/cases/upload")
    def upload_case() -> Any:
        f = request.files.get("evidence")
        if not f or not f.filename:
            return jsonify({"ok": False, "error": "No evidence file uploaded"}), 400

        case_id = build_case_id()
        case_dir = CASES_DIR / case_id
        case_dir.mkdir(parents=True, exist_ok=True)

        safe_name = secure_filename(f.filename)
        if not safe_name:
            safe_name = f"evidence_{case_id}.bin"

        source_path = UPLOADS_DIR / f"{case_id}_{safe_name}"
        f.save(str(source_path))

        try:
            case_data = parse_input(case_id=case_id, source_path=source_path, case_dir=case_dir)
            case_data.setdefault("analysis", {})
            save_case(case_id, case_data)
            return jsonify({"ok": True, "case_id": case_id, "summary": case_data.get("summary", {})})
        except Exception as exc:
            try:
                if source_path.exists():
                    source_path.unlink()
            except Exception:
                pass
            shutil.rmtree(case_dir, ignore_errors=True)
            return jsonify({"ok": False, "error": f"Parse failed: {exc}"}), 500

    @app.get("/api/cases/<case_id>/rows")
    def get_rows(case_id: str) -> Any:
        case_data = load_case(case_id)
        if not case_data:
            return jsonify({"ok": False, "error": "Case not found"}), 404

        query = parse_query_args(request.args)
        rows_all = query_rows(case_data=case_data, query=query)
        total = len(rows_all)
        page = query["page"]
        page_size = query["page_size"]
        total_pages = max(1, (total + page_size - 1) // page_size)
        if page > total_pages:
            page = total_pages
        start = (page - 1) * page_size
        end = start + page_size
        page_rows = rows_all[start:end]

        return jsonify(
            {
                "ok": True,
                "view": query["view"],
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages,
                "rows": page_rows,
            }
        )

    @app.get("/api/cases/<case_id>/rows/csv")
    def export_rows_csv(case_id: str) -> Any:
        case_data = load_case(case_id)
        if not case_data:
            return jsonify({"ok": False, "error": "Case not found"}), 404

        query = parse_query_args(request.args)
        scope = str(request.args.get("scope") or "filtered").strip().lower()
        if scope == "all":
            query["view"] = "evidence"
            query["selected_only"] = False
        rows = query_rows(case_data=case_data, query=query)

        out = StringIO()
        writer = csv.writer(out)
        header = [
            "id",
            "severity",
            "severity_reason",
            "category",
            "subcategory",
            "timestamp",
            "title",
            "details",
            "raw_excerpt",
            "source_file",
            "domain",
            "page_title",
            "path",
            "query_keys",
            "url",
            "event_type",
            "program_name",
            "version",
            "process_name",
            "package_ids",
            "package_count",
            "location",
            "agent_name",
            "status",
            "check_type",
            "source_type",
            "item_name",
            "launch_label",
            "protocol",
            "state",
            "local_addr",
            "remote_addr",
            "pid",
            "user",
            "username",
            "tty",
            "session",
            "shell",
            "command_base",
            "keyword",
            "source_name",
            "line",
            "message",
        ]
        writer.writerow(header)
        for row in rows:
            parsed = row.get("parsed") if isinstance(row.get("parsed"), dict) else {}
            writer.writerow(
                [
                    str(row.get("id", "")),
                    str(row.get("severity", "")),
                    str(row.get("severity_reason", "")),
                    str(row.get("category", "")),
                    str(row.get("subcategory", "")),
                    str(row.get("timestamp", "")),
                    str(row.get("title", "")),
                    str(row.get("details", "")),
                    str(row.get("raw_excerpt", "")),
                    str(row.get("source_file", "")),
                    str((parsed or {}).get("domain", "")),
                    str((parsed or {}).get("page_title", "")),
                    str((parsed or {}).get("path", "")),
                    str((parsed or {}).get("query_keys", "")),
                    str((parsed or {}).get("url", "")),
                    str((parsed or {}).get("event_type", "")),
                    str((parsed or {}).get("program_name", "")),
                    str((parsed or {}).get("version", "")),
                    str((parsed or {}).get("process_name", "")),
                    str((parsed or {}).get("package_ids", "")),
                    str((parsed or {}).get("package_count", "")),
                    str((parsed or {}).get("location", "")),
                    str((parsed or {}).get("agent_name", "")),
                    str((parsed or {}).get("status", "")),
                    str((parsed or {}).get("check_type", "")),
                    str((parsed or {}).get("source_type", "")),
                    str((parsed or {}).get("item_name", "")),
                    str((parsed or {}).get("launch_label", "")),
                    str((parsed or {}).get("protocol", "")),
                    str((parsed or {}).get("state", "")),
                    str((parsed or {}).get("local_addr", "")),
                    str((parsed or {}).get("remote_addr", "")),
                    str((parsed or {}).get("pid", "")),
                    str((parsed or {}).get("user", "")),
                    str((parsed or {}).get("username", "")),
                    str((parsed or {}).get("tty", "")),
                    str((parsed or {}).get("session", "")),
                    str((parsed or {}).get("shell", "")),
                    str((parsed or {}).get("command_base", "")),
                    str((parsed or {}).get("keyword", "")),
                    str((parsed or {}).get("source_name", "")),
                    str((parsed or {}).get("line", "")),
                    str((parsed or {}).get("message", "")),
                ]
            )

        payload = "\ufeff" + out.getvalue()
        file_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_case = sanitize_case_for_filename(case_data.get("case_id"))
        safe_view = sanitize_case_for_filename(query.get("view"))
        file_name = f"{safe_case}_{safe_view}_{scope}_{file_ts}.csv"
        return Response(
            payload,
            content_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
        )

    @app.post("/api/cases/<case_id>/analysis/local")
    def analyze_local(case_id: str) -> Any:
        case_data = load_case(case_id)
        if not case_data:
            return jsonify({"ok": False, "error": "Case not found"}), 404

        req = request.get_json(silent=True) or {}
        model = str(req.get("model") or "qwen2.5:14b-q4_K_M")

        result = run_local_ollama(case_data=case_data, model=model)
        case_data.setdefault("analysis", {})["local"] = {
            **result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        save_case(case_id, case_data)
        return jsonify(result), (200 if result.get("ok") else 502)

    @app.post("/api/cases/<case_id>/analysis/openai")
    def analyze_openai(case_id: str) -> Any:
        case_data = load_case(case_id)
        if not case_data:
            return jsonify({"ok": False, "error": "Case not found"}), 404

        api_key = str(app.config.get("OPENAI_API_KEY") or "").strip()
        chat_model = str(app.config.get("OPENAI_CHAT_MODEL") or "gpt-4.1-mini")
        embed_model = str(app.config.get("OPENAI_EMBED_MODEL") or "text-embedding-3-small")
        if not api_key:
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": "OPENAI_API_KEY is not configured in server environment",
                    }
                ),
                400,
            )

        result = run_openai(
            case_data=case_data,
            api_key=api_key,
            chat_model=chat_model,
            embed_model=embed_model,
        )
        case_data.setdefault("analysis", {})["openai"] = {
            **result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        save_case(case_id, case_data)
        return jsonify(result), (200 if result.get("ok") else 502)

    @app.post("/api/cases/<case_id>/report/pdf")
    def generate_report_pdf(case_id: str) -> Any:
        case_data = load_case(case_id)
        if not case_data:
            return jsonify({"ok": False, "error": "Case not found"}), 404

        req = request.get_json(silent=True) or {}
        analysis_source = str(req.get("analysis_source") or "").strip().lower()
        case_dir = CASES_DIR / case_id
        try:
            report_meta = build_dfir_pdf(case_data=case_data, case_dir=case_dir, analysis_source=analysis_source)
        except Exception as exc:
            return jsonify({"ok": False, "error": f"PDF report generation failed: {exc}"}), 500

        report_meta["download_url"] = f"/api/cases/{case_id}/report/pdf"
        case_data.setdefault("analysis", {})["report_pdf"] = report_meta
        save_case(case_id, case_data)
        return jsonify({"ok": True, **report_meta})

    @app.get("/api/cases/<case_id>/report/pdf")
    def download_report_pdf(case_id: str) -> Any:
        case_data = load_case(case_id)
        if not case_data:
            return jsonify({"ok": False, "error": "Case not found"}), 404

        report_meta = ((case_data.get("analysis") or {}).get("report_pdf") or {})
        file_path = str(report_meta.get("file_path") or "").strip()
        if not file_path:
            return jsonify({"ok": False, "error": "No generated PDF report for this case"}), 404

        path = Path(file_path)
        if not path.exists():
            return jsonify({"ok": False, "error": "Saved report file not found"}), 404
        try:
            resolved = path.resolve()
            case_root = (CASES_DIR / case_id).resolve()
            if case_root not in resolved.parents:
                return jsonify({"ok": False, "error": "Invalid report path"}), 400
        except Exception:
            return jsonify({"ok": False, "error": "Invalid report path"}), 400

        return send_file(str(path), mimetype="application/pdf", as_attachment=True, download_name=path.name)

    return app


def build_case_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"CASE-{ts}-{secrets.token_hex(3).upper()}"


def case_json_path(case_id: str) -> Path:
    case_dir = safe_case_dir(case_id)
    if not case_dir:
        raise ValueError("Invalid case_id")
    return case_dir / "case.json"


def load_case(case_id: str) -> dict[str, Any] | None:
    try:
        path = case_json_path(case_id)
    except ValueError:
        return None
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def save_case(case_id: str, data: dict[str, Any]) -> None:
    case_dir = safe_case_dir(case_id)
    if not case_dir:
        raise ValueError("Invalid case_id")
    case_dir.mkdir(parents=True, exist_ok=True)
    path = case_json_path(case_id)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def remove_children(path: Path) -> int:
    removed = 0
    for child in path.iterdir():
        if child.name == ".gitkeep":
            continue
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
            removed += 1
        else:
            try:
                child.unlink()
                removed += 1
            except Exception:
                continue
    return removed


def safe_case_dir(case_id: str) -> Path | None:
    cid = str(case_id or "").strip()
    if not CASE_ID_RE.match(cid):
        return None
    path = (CASES_DIR / cid).resolve()
    try:
        path.relative_to(CASES_DIR.resolve())
    except Exception:
        return None
    return path


def parse_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def parse_int(value: Any, default: int, min_v: int, max_v: int) -> int:
    try:
        n = int(value)
    except Exception:
        return default
    if n < min_v:
        return min_v
    if n > max_v:
        return max_v
    return n


def build_case_payload(data: dict[str, Any], include_artifacts: bool = False) -> dict[str, Any]:
    payload = {
        "case_id": data.get("case_id"),
        "source_name": data.get("source_name"),
        "source_path": data.get("source_path"),
        "source_type": data.get("source_type"),
        "created_at": data.get("created_at"),
        "summary": data.get("summary", {}),
        "analysis": data.get("analysis", {}),
        "timeline_count": len(data.get("timeline", []) or []),
    }
    if include_artifacts:
        payload["artifacts"] = data.get("artifacts", [])
        payload["timeline"] = data.get("timeline", [])
    return payload


def parse_query_args(args: Any) -> dict[str, Any]:
    severities = [s.strip().lower() for s in str(args.get("severities") or "").split(",") if s.strip()]
    selected_ids = [s.strip() for s in str(args.get("selected_ids") or "").split(",") if s.strip()]
    sort_field = str(args.get("sort_field") or "timestamp").strip().lower()
    sort_dir = str(args.get("sort_dir") or "desc").strip().lower()
    if sort_field not in {
        "severity",
        "category",
        "subcategory",
        "timestamp",
        "title",
        "details",
        "domain",
        "page_title",
        "query_keys",
        "path",
        "event_type",
        "program_name",
        "version",
        "process_name",
        "package_ids",
        "location",
        "agent_name",
        "status",
        "check_type",
        "source_type",
        "item_name",
        "launch_label",
        "protocol",
        "state",
        "local_addr",
        "remote_addr",
        "pid",
        "user",
        "username",
        "tty",
        "session",
        "shell",
        "command_base",
        "keyword",
        "source_name",
        "line",
        "message",
    }:
        sort_field = "timestamp"
    if sort_dir not in {"asc", "desc"}:
        sort_dir = "desc"
    return {
        "view": str(args.get("view") or "evidence").strip().lower(),
        "search": str(args.get("search") or "").strip(),
        "severities": severities,
        "selected_only": parse_bool(args.get("selected_only"), default=False),
        "selected_ids": set(selected_ids),
        "sort_field": sort_field,
        "sort_dir": sort_dir,
        "page": parse_int(args.get("page"), default=1, min_v=1, max_v=100000),
        "page_size": parse_int(args.get("page_size"), default=200, min_v=20, max_v=2000),
    }


def query_rows(case_data: dict[str, Any], query: dict[str, Any]) -> list[dict[str, Any]]:
    rows = rows_for_view(case_data, query["view"])
    search = str(query.get("search") or "").strip().lower()
    severities = set(query.get("severities") or [])
    selected_only = bool(query.get("selected_only"))
    selected_ids = set(query.get("selected_ids") or set())

    out: list[dict[str, Any]] = []
    for row in rows:
        rid = str(row.get("id") or "")
        sev = str(row.get("severity") or "low").lower()
        if severities and sev not in severities:
            continue
        if selected_only and rid not in selected_ids:
            continue
        if search:
            hay = "\n".join(
                [
                    str(row.get("id") or ""),
                    str(row.get("category") or ""),
                    str(row.get("subcategory") or ""),
                    str(row.get("title") or ""),
                    str(row.get("details") or ""),
                    str(row.get("raw_excerpt") or ""),
                    flatten_for_search(row.get("parsed") or {}),
                ]
            ).lower()
            if search not in hay:
                continue
        out.append(row)

    sort_field = query["sort_field"]
    sort_dir = query["sort_dir"]
    out.sort(key=lambda x: sort_key(x, sort_field), reverse=(sort_dir == "desc"))
    return out


def rows_for_view(case_data: dict[str, Any], view: str) -> list[dict[str, Any]]:
    v = str(view or "evidence").lower()
    if v == "timeline":
        return list(case_data.get("timeline", []) or [])
    artifacts = list(case_data.get("artifacts", []) or [])
    if v == "evidence":
        return artifacts
    category = VIEW_CATEGORY_MAP.get(v)
    if not category:
        return artifacts
    return [r for r in artifacts if str(r.get("category") or "") == category]


def sort_key(row: dict[str, Any], field: str) -> tuple[Any, ...]:
    if field == "severity":
        sev = str(row.get("severity") or "low").lower()
        return (SEVERITY_RANK.get(sev, 99), str(row.get("timestamp") or ""), str(row.get("id") or ""))
    if field == "timestamp":
        return (str(row.get("timestamp") or ""), str(row.get("id") or ""))
    if field in {
        "domain",
        "page_title",
        "query_keys",
        "path",
        "event_type",
        "program_name",
        "version",
        "process_name",
        "package_ids",
        "location",
        "agent_name",
        "status",
        "check_type",
        "source_type",
        "item_name",
        "launch_label",
        "protocol",
        "state",
        "local_addr",
        "remote_addr",
        "pid",
        "user",
        "username",
        "tty",
        "session",
        "shell",
        "command_base",
        "keyword",
        "source_name",
        "line",
        "message",
    }:
        parsed = row.get("parsed") if isinstance(row.get("parsed"), dict) else {}
        return (str((parsed or {}).get(field) or "").lower(), str(row.get("timestamp") or ""), str(row.get("id") or ""))
    return (str(row.get(field) or "").lower(), str(row.get("id") or ""))


def build_dashboard_payload(case_data: dict[str, Any]) -> dict[str, Any]:
    artifacts = list(case_data.get("artifacts", []) or [])
    timeline = list(case_data.get("timeline", []) or [])
    summary = case_data.get("summary", {}) or {}

    buckets: dict[str, int] = {}
    for row in timeline:
        ts = str(row.get("timestamp") or "")
        if len(ts) < 13:
            continue
        key = ts[:13] + ":00"
        buckets[key] = buckets.get(key, 0) + 1
    burst = [{"hour": k, "count": v} for k, v in sorted(buckets.items(), key=lambda kv: kv[1], reverse=True)[:24]]

    critical_high = [
        r
        for r in artifacts
        if str(r.get("severity") or "").lower() in {"critical", "high"}
    ]
    critical_high.sort(key=lambda x: (SEVERITY_RANK.get(str(x.get("severity") or "").lower(), 99), str(x.get("timestamp") or "")))

    top_categories = sorted((summary.get("category", {}) or {}).items(), key=lambda kv: kv[1], reverse=True)[:12]
    return {
        "summary": summary,
        "top_categories": [{"category": k, "count": v} for k, v in top_categories],
        "burst": burst,
        "critical_high": critical_high[:30],
    }


def sanitize_case_for_filename(value: Any) -> str:
    raw = str(value or "case").strip()
    clean = re.sub(r"[^A-Za-z0-9_.-]+", "_", raw)
    return clean[:120] or "case"


def flatten_for_search(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(flatten_for_search(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(flatten_for_search(v) for v in value)
    return str(value or "")
