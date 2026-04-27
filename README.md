# yushin-mac-analyzer

> **macOS DFIR Web Analyzer** — Flask web app that ingests collector ZIPs (or raw disk images), parses artifacts into a searchable evidence table, and generates DFIR PDF reports with optional local LLM (Ollama) or OpenAI-assisted analysis.

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/flask-3.x-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![macOS](https://img.shields.io/badge/macOS-12%2B-000000?logo=apple&logoColor=white)](https://support.apple.com/macos)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A self-hosted analyzer for macOS incident response. Designed to pair with a forensic collector (this repo includes a bundled one, and is fully compatible with [yushin-mac-triage](https://github.com/Juwon1405/yushin-mac-triage)). The analyzer ingests a collection ZIP, parses ~30+ artifact categories into normalized evidence rows, and lets you triage interactively in a browser before exporting a chain-of-custody-ready PDF report.

---

## ✨ What It Does

| Capability | Detail |
|------------|--------|
| **Ingest** | Collector ZIP, DD/RAW/E01/AFF/DMG disk images, or single DB/LOG/TXT/JSON files |
| **Parse** | Unified Log, browser history (Chrome/Edge/Firefox/Safari), launch agents, persistence, network state, security agents, command history, quarantine events, IOCs |
| **Search** | Server-side query across all evidence — keyword, severity, time range, category, sortable, paginated |
| **Analyze (local)** | Ollama-backed LLM analysis (default `qwen2.5:14b-q4_K_M`) — runs offline, no data leaves the host |
| **Analyze (cloud)** | Optional OpenAI-backed analysis (default `gpt-4.1-mini`) — set `OPENAI_API_KEY` to enable |
| **Report** | Auto-generated DFIR PDF with verdict (compromise YES/NO), IOC list, timeline, and embedded Draw.io diagrams found in evidence |
| **Export** | CSV in 4 modes (visible / filtered / selected / all) + per-event single-row CSV |

---

## 🚀 Quick Start

### 1. Run the Web Analyzer

```bash
# From repo root
OPENAI_API_KEY="sk-..." \
OPENAI_CHAT_MODEL="gpt-4.1-mini" \
OPENAI_EMBED_MODEL="text-embedding-3-small" \
./run_web.sh
```

> `OPENAI_API_KEY` is **optional**. If unset, the OpenAI analysis button is disabled but local Ollama analysis still works.

Open: **http://127.0.0.1:17888**

The script auto-creates a `.venv/`, installs `requirements.txt`, and launches Flask.

### 2. Collect Evidence (bundled collector)

```bash
./run_collector.sh
# or quick mode
COLLECTOR_QUICK=1 ./run_collector.sh
```

Output: `HOSTNAME_YYYYMMDD_HHMM.zip` in the current working directory. Drag-and-drop this ZIP into the web UI to start a case.

### 3. (Optional) Local LLM Setup

```bash
ollama pull qwen2.5:14b-q4_K_M
ollama serve
```

The analyzer auto-detects Ollama at `http://127.0.0.1:11434`.

---

## 🖥️ UI Features

- **Dashboard-first landing** — stats + concentration-by-hour visualization
- **Fast evidence tables** with server-side query:
  - keyword search across all parsed fields
  - severity filter (critical / high / medium / low / info)
  - checkbox selection + selected-only mode
  - sortable columns, pagination, page-size control
- **Category tabs** — including dedicated `Command History` tab
- **Row modal** with parsed details + raw event preservation
- **CSV export modes:**
  - `CSV Visible` — current screen / page
  - `CSV Filtered` — current tab + active filters
  - `CSV Selected` — only checked rows
  - `CSV All` — every evidence row in the case
  - Per-modal `Export This Event (CSV)` — single artifact
- **Clear All History** button — wipes `cases/` + `uploads/` from UI / API
- **Help tab** — explains Local vs OpenAI analysis trade-offs
- **DFIR PDF Report:**
  - Auto-generated after Local / OpenAI analysis
  - Manual "Generate" button always available
  - Includes compromise verdict, IOC list, timeline, discovered Draw.io files

---

## 🔌 API Endpoints (for QA / automation)

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/api/health` | Service health check |
| `GET`  | `/api/cases` | List all cases |
| `POST` | `/api/cases/upload` | Upload evidence ZIP / image / single file |
| `GET`  | `/api/cases/<case_id>?include_artifacts=0` | Lightweight case metadata |
| `GET`  | `/api/cases/<case_id>/dashboard` | Dashboard aggregates |
| `GET`  | `/api/cases/<case_id>/rows` | Server-side filtered/paged rows |
| `GET`  | `/api/cases/<case_id>/rows/csv` | Filtered CSV export |
| `POST` | `/api/cases/<case_id>/report/pdf` | Generate DFIR PDF |
| `GET`  | `/api/cases/<case_id>/report/pdf` | Download latest generated PDF |
| `POST` | `/api/cases/clear` | Wipe all cases & uploads |

---

## ⚙️ Configuration

All configuration is via environment variables (set them before `./run_web.sh`):

| Variable | Default | Purpose |
|----------|---------|---------|
| `OPENAI_API_KEY` | *(empty)* | If set, enables OpenAI-backed analysis button |
| `OPENAI_CHAT_MODEL` | `gpt-4.1-mini` | Chat completion model |
| `OPENAI_EMBED_MODEL` | `text-embedding-3-small` | Embeddings model |
| `LOCAL_ANALYSIS_TIMEOUT` | `240` | Ollama request timeout (seconds) |
| `LOCAL_ANALYSIS_MAX_TOKENS` | `900` | Max tokens per Ollama call |
| `LOCAL_ANALYSIS_MAX_ARTIFACTS` | `60` | Max artifacts fed to local LLM in one pass |
| `LOCAL_ANALYSIS_NUM_CTX` | `4096` | Ollama context window |
| `PARSER_AI_FALLBACK` | `0` | Set `1` to allow parser to call Ollama for hard-to-parse log lines |
| `PARSER_AI_MODEL` | `qwen2.5:14b-q4_K_M` | Parser fallback model |
| `PARSER_AI_MAX_CALLS` | `24` | Max LLM-assisted parses per case |
| `PARSER_AI_TIMEOUT` | `45` | Parser fallback timeout (seconds) |
| `PARSER_AI_ENDPOINT` | `http://127.0.0.1:11434/api/generate` | Ollama generate endpoint |

---

## 🧪 QA Script

```bash
./run_qa.sh
```

Runs:
1. Python compile check across `webapp/app/`
2. JavaScript syntax check (`node -c`) if Node is installed
3. API smoke check — `/api/health`, `/api/cases`, `/api/cases/clear`

End-to-end with a sample collector ZIP:

```bash
./run_qa.sh /path/to/collector_output.zip
```

This will upload the ZIP, run the rows query, generate a PDF report, and download it — exercising the full pipeline.

---

## 📁 Repo Layout

```
.
├── collector/
│   └── macOS Collectors.sh           # Bundled triage collector
├── webapp/
│   ├── app/
│   │   ├── main.py                   # CLI entrypoint (--host, --port, --open)
│   │   ├── server.py                 # Flask app, routing, case lifecycle
│   │   ├── dfir_parser.py            # Multi-artifact parser (~30+ types)
│   │   ├── reporting.py              # PDF report generator (ReportLab)
│   │   └── llm.py                    # Ollama + OpenAI client wrappers
│   ├── static/
│   │   ├── css/styles.css
│   │   └── js/app.js                 # Frontend (vanilla JS)
│   └── templates/
│       └── index.html
├── cases/                            # Per-case extracted artifacts (created at runtime)
├── uploads/                          # Raw uploaded evidence (created at runtime)
├── run_web.sh                        # Start web analyzer
├── run_collector.sh                  # Run bundled collector
├── run_qa.sh                         # Run QA / smoke / e2e checks
├── start_macos_forensics.command     # Double-click launcher (macOS)
└── requirements.txt
```

---

## 📋 Notes & Limitations

- **Parsing is prioritized over auto-conclusion.** The analyzer surfaces evidence rather than auto-classifying. LLM analysis (when enabled) provides a second opinion, not a final verdict.
- Logs and browser history are **capped/sampled for UI responsiveness** — for full corpus analysis, use the API CSV export.
- **Encrypted ZIPs are not supported** — decrypt before upload.
- The bundled `collector/macOS Collectors.sh` is a baseline. For a more comprehensive collector with selective module execution and supply-chain IOC sweeps, use [yushin-mac-triage](https://github.com/Juwon1405/yushin-mac-triage).

---

## 🤝 Companion Tool

➡️ **[yushin-mac-triage](https://github.com/Juwon1405/yushin-mac-triage)** — Single-file modular collector with 10 modules including `supply_chain` IOC detection. Output ZIPs are fully compatible with this analyzer.

---

## 📄 License

MIT — see [LICENSE](LICENSE).

## ✍️ Author

**YuShin (優心 / Bang Juwon)** — DFIR practitioner, Tokyo.

> *"Parse first. Conclude later. Evidence speaks."*

If this tool helped you, a ⭐ on the repo means a lot. Issues / PRs welcome.
