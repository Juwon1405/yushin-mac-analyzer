# yushin-mac-forensics-platform

> **macOS DFIR Forensics Platform** — a self-hosted Flask web platform for macOS incident response. Ingests collector ZIPs and disk images, parses 30+ artifact categories into searchable evidence rows, and generates chain-of-custody-ready PDF reports — with optional local Ollama or OpenAI-assisted analysis.

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/flask-3.x-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![macOS](https://img.shields.io/badge/macOS-12%2B-000000?logo=apple&logoColor=white)](https://support.apple.com/macos)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## 🎯 What This Platform Analyzes

| Input Type | Source | Use Case |
|------------|--------|----------|
| **Collector ZIP** | Output of [yushin-mac-artifact-collector](https://github.com/Juwon1405/yushin-mac-artifact-collector) or the bundled `collector/macOS Collectors.sh` | Live-host triage, post-incident artifact review |
| **Disk images** | `.dd`, `.raw`, `.E01`, `.AFF`, `.dmg` | Dead-disk forensics, MacBook drive imaging |
| **Single artifacts** | `.db`, `.log`, `.txt`, `.json` | Targeted analysis of a single SQLite DB, log file, or JSON dump |

**Parsed artifact categories** (auto-detected and normalized into one searchable evidence table):

- macOS Unified Log (filtered by auth, remote access, TCC, privacy, security agents)
- Browser history — **Chrome, Edge, Firefox, Safari** (all profiles)
- Persistence — LaunchAgents, LaunchDaemons, crontab, login items, `~/.config/` scripts
- Network state — interfaces, active connections, DNS, remote-access logs
- Security agents — CrowdStrike Falcon, Tanium, JAMF presence + logs
- Quarantine events (LSQuarantineEventsV2)
- Command history — `zsh_history`, `bash_history`
- Login history (`last`)
- Installed applications, pkgutil packages, install timeline
- IP-KVM / IPMI / iDRAC indicators (USB, Thunderbolt, Ethernet enumeration)
- Supply-chain IOCs (litellm PyPI, malicious `.pth` files, Node.js install hooks)
- Embedded Draw.io diagrams found in evidence

---

## ✨ Platform Capabilities

| Capability | Detail |
|------------|--------|
| **Web UI** | Dashboard-first landing, server-side filtered evidence table, severity tags, category tabs, row modals |
| **Search** | Server-side keyword + severity + sortable columns + checkbox-selected-only mode + pagination |
| **Local LLM analysis** | Ollama-backed (default `qwen2.5:14b-q4_K_M`) — fully offline, no data leaves the host |
| **Cloud LLM analysis** | Optional OpenAI-backed (default `gpt-4.1-mini`) — set `OPENAI_API_KEY` to enable |
| **PDF reporting** | Auto-generated DFIR report with compromise verdict (YES/NO), IOC list, timeline, and embedded Draw.io diagrams |
| **CSV export** | Visible / Filtered / Selected / All — plus per-event single-row export |
| **REST API** | Every UI action is exposed as JSON — automate or integrate into your SOC pipeline |
| **Bundled collector** | `collector/macOS Collectors.sh` — baseline collector, runnable standalone |

---

## 🚀 Quick Start

### 1. Run the Platform

```bash
# From repo root — auto-creates .venv, installs deps, launches Flask
OPENAI_API_KEY="sk-..." \
OPENAI_CHAT_MODEL="gpt-4.1-mini" \
OPENAI_EMBED_MODEL="text-embedding-3-small" \
./run_web.sh
```

> `OPENAI_API_KEY` is **optional**. Without it, the OpenAI analysis button is disabled but local Ollama analysis still works.

Open: **http://127.0.0.1:17888**

### 2. Collect Evidence (bundled collector)

```bash
./run_collector.sh
# or quick mode (reduced log volume)
COLLECTOR_QUICK=1 ./run_collector.sh
```

Output: `HOSTNAME_YYYYMMDD_HHMM.zip` in the current working directory. Drag-and-drop into the web UI to start a case.

> 💡 For a more comprehensive collector with selective module execution and supply-chain IOC sweeps, use [yushin-mac-artifact-collector](https://github.com/Juwon1405/yushin-mac-artifact-collector). Its output ZIPs are fully compatible with this platform.

### 3. (Optional) Local LLM Setup

```bash
ollama pull qwen2.5:14b-q4_K_M
ollama serve
```

The platform auto-detects Ollama at `http://127.0.0.1:11434`.

---

## 🖥️ UI Walkthrough

- **Dashboard-first landing** — case stats, severity distribution, concentration-by-hour heatmap
- **Evidence table** with server-side query:
  - Keyword search across every parsed field
  - Severity filter (critical / high / medium / low / info)
  - Checkbox selection + "selected-only" mode
  - Sortable columns, pagination, page-size control
- **Category tabs** — including a dedicated `Command History` tab
- **Row modal** — parsed details + the original raw event preserved
- **CSV export modes:**
  - `CSV Visible` — current screen / page
  - `CSV Filtered` — current tab + active filters
  - `CSV Selected` — only checked rows
  - `CSV All` — every evidence row in the case
  - Per-modal `Export This Event (CSV)` — single artifact
- **Clear All History** — wipes `cases/` + `uploads/` from UI / API
- **DFIR PDF Report:**
  - Auto-generated after Local / OpenAI analysis runs
  - Manual "Generate" button always available
  - Compromise verdict, IOC list, timeline, Draw.io diagram extraction

---

## 🔌 REST API

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/api/health` | Service health check |
| `GET`  | `/api/cases` | List all cases |
| `POST` | `/api/cases/upload` | Upload evidence ZIP / disk image / single file |
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
│   └── macOS Collectors.sh           # Bundled baseline collector
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
├── run_web.sh                        # Start the platform
├── run_collector.sh                  # Run bundled collector
├── run_qa.sh                         # Run QA / smoke / e2e checks
├── start_macos_forensics.command     # Double-click launcher (macOS)
└── requirements.txt
```

---

## 📋 Notes & Limitations

- **Parsing is prioritized over auto-conclusion.** The platform surfaces evidence rather than auto-classifying. LLM analysis (when enabled) provides a second opinion, not a final verdict.
- Logs and browser history are **capped/sampled for UI responsiveness** — for full corpus analysis, use the API CSV export.
- **Encrypted ZIPs are not supported** — decrypt before upload.
- The bundled `collector/macOS Collectors.sh` is a baseline. For broader coverage and selective module execution, use [yushin-mac-artifact-collector](https://github.com/Juwon1405/yushin-mac-artifact-collector).

---

## 🤝 Companion Tool

➡️ **[yushin-mac-artifact-collector](https://github.com/Juwon1405/yushin-mac-artifact-collector)** — Single-file modular collector with 10 modules including `supply_chain` IOC detection. Output ZIPs drop straight into this platform.

---

## 📄 License

MIT — see [LICENSE](LICENSE).

## ✍️ Author

**YuShin (優心 / Bang Juwon)** — DFIR practitioner, Tokyo.

> *"Parse first. Conclude later. Evidence speaks."*

If this platform helped you, a ⭐ on the repo means a lot. Issues / PRs welcome.
