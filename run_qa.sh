#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$ROOT_DIR/.venv"
SAMPLE_ZIP="${1:-}"

if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
pip install --upgrade pip >/dev/null
pip install -r "$ROOT_DIR/requirements.txt" >/dev/null

echo "[qa] Python compile check"
python3 -m compileall "$ROOT_DIR/webapp/app" >/dev/null

if command -v node >/dev/null 2>&1; then
  echo "[qa] JavaScript syntax check"
  node -c "$ROOT_DIR/webapp/static/js/app.js" >/dev/null
else
  echo "[qa][warn] node not found, skipping JS syntax check"
fi

echo "[qa] API smoke check"
python3 - << 'PY'
from webapp.app.server import create_app

app = create_app()
client = app.test_client()
print("health", client.get("/api/health").status_code)
print("cases", client.get("/api/cases").status_code)
print("clear", client.post("/api/cases/clear", json={}).status_code)
PY

if [[ -n "$SAMPLE_ZIP" ]]; then
  echo "[qa] End-to-end sample parse/report check: $SAMPLE_ZIP"
  python3 - << 'PY' "$SAMPLE_ZIP"
from io import BytesIO
from pathlib import Path
import sys
from webapp.app.server import create_app

sample = Path(sys.argv[1]).expanduser()
if not sample.exists():
    raise SystemExit(f"sample not found: {sample}")

app = create_app()
client = app.test_client()
with sample.open("rb") as f:
    up = client.post(
        "/api/cases/upload",
        data={"evidence": (BytesIO(f.read()), sample.name)},
        content_type="multipart/form-data",
    )
upj = up.get_json() or {}
assert up.status_code == 200 and upj.get("ok"), f"upload failed: {up.status_code} {upj}"
case_id = upj["case_id"]

rows = client.get(
    f"/api/cases/{case_id}/rows?view=evidence&page=1&page_size=25&sort_field=timestamp&sort_dir=desc&severities=critical,high,medium,low,info&selected_only=0"
)
rowsj = rows.get_json() or {}
assert rows.status_code == 200 and rowsj.get("ok"), f"rows failed: {rows.status_code} {rowsj}"

report = client.post(f"/api/cases/{case_id}/report/pdf", json={})
repj = report.get_json() or {}
assert report.status_code == 200 and repj.get("ok"), f"report failed: {report.status_code} {repj}"

pdf = client.get(f"/api/cases/{case_id}/report/pdf")
assert pdf.status_code == 200 and "pdf" in (pdf.content_type or "").lower(), f"pdf download failed: {pdf.status_code} {pdf.content_type}"
print("sample_e2e", "ok", case_id, repj.get("ioc_count"), repj.get("compromise"))
PY
fi

echo "[qa] done"
