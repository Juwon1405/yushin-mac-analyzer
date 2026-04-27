const state = {
  cases: [],
  currentCaseId: null,
  caseData: null,
  dashboard: null,
  view: "dashboard",
  health: null,
  search: "",
  selectedOnly: false,
  selectedIds: new Set(),
  severityFilter: new Set(["critical", "high", "medium", "low", "info"]),
  sort: { field: "timestamp", dir: "desc" },
  page: 1,
  pageSize: 200,
  tableRows: [],
  tableTotal: 0,
  tableTotalPages: 1,
  tableLoading: false,
  tableError: "",
  tableSnapshot: { title: "Evidence", pageRows: [] },
  tableReqSeq: 0,
  modalRow: null,
};

const severityRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const views = {
  dashboard: "Dashboard",
  evidence: "Evidence",
  timeline: "Timeline",
  browser: "Browser Artifacts",
  installed: "Installed Programs",
  persistence: "Persistence",
  security: "Security Agents",
  remote: "Remote/KVM",
  network: "Network",
  logs: "Logs",
  accounts: "Accounts",
  commands: "Command History",
  help: "Help",
};

const viewToCategory = {
  browser: "Browser",
  installed: "Installed Programs",
  persistence: "Persistence",
  security: "Security Agents",
  remote: "Remote/KVM",
  network: "Network",
  logs: "Logs",
  accounts: "Accounts",
  commands: "Command History",
};

const elements = {
  uploadForm: document.getElementById("upload-form"),
  evidenceFile: document.getElementById("evidence-file"),
  nav: document.getElementById("left-nav"),
  contentHeader: document.getElementById("content-header"),
  contentBody: document.getElementById("content-body"),
  caseSelect: document.getElementById("case-select"),
  caseMeta: document.getElementById("case-meta"),
  btnClearHistory: document.getElementById("btn-clear-history"),
  localModel: document.getElementById("local-model"),
  btnLocal: document.getElementById("btn-local-llm"),
  localAnalysis: document.getElementById("local-analysis"),
  openaiConfig: document.getElementById("openai-config"),
  btnOpenai: document.getElementById("btn-openai"),
  openaiAnalysis: document.getElementById("openai-analysis"),
  btnReportPdf: document.getElementById("btn-report-pdf"),
  reportDownload: document.getElementById("report-download"),
  reportStatus: document.getElementById("report-status"),
  modal: document.getElementById("artifact-modal"),
  modalTitle: document.getElementById("modal-title"),
  modalContent: document.getElementById("modal-content"),
  modalClose: document.getElementById("modal-close"),
  modalExport: document.getElementById("modal-export"),
};

init();

async function init() {
  bindEvents();
  await fetchHealth();
  await refreshCases();
  render();
}

function bindEvents() {
  elements.uploadForm.addEventListener("submit", onUpload);
  elements.nav.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      setActiveView(btn.dataset.view || "dashboard");
    });
  });

  elements.caseSelect.addEventListener("change", (e) => {
    const caseId = e.target.value;
    if (caseId) loadCase(caseId);
  });

  elements.btnClearHistory.addEventListener("click", clearAllHistory);
  elements.btnLocal.addEventListener("click", runLocalAnalysis);
  elements.btnOpenai.addEventListener("click", runOpenAIAnalysis);
  elements.btnReportPdf.addEventListener("click", async () => {
    await generateReportPdf({ auto: false, analysisSource: "" });
  });

  elements.modalClose.addEventListener("click", closeModal);
  elements.modalExport.addEventListener("click", exportModalRowCsv);
  elements.modal.addEventListener("click", (e) => {
    if (e.target === elements.modal) closeModal();
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();
  });
}

async function fetchHealth() {
  try {
    const res = await fetch("/api/health");
    state.health = await res.json();
  } catch {
    state.health = null;
  }
}

async function refreshCases() {
  try {
    const res = await fetch("/api/cases");
    const data = await res.json();
    state.cases = data.cases || [];
    const exists = state.currentCaseId && state.cases.some((x) => x.case_id === state.currentCaseId);
    if (!exists) {
      state.currentCaseId = null;
      state.caseData = null;
      state.selectedIds = new Set();
      state.search = "";
      state.selectedOnly = false;
      state.page = 1;
      state.dashboard = null;
      state.tableRows = [];
      state.tableTotal = 0;
      state.tableTotalPages = 1;
      state.tableLoading = false;
      state.tableError = "";
      elements.localAnalysis.textContent = "Not executed yet.";
      elements.openaiAnalysis.textContent = "Not executed yet.";
      renderReportMeta(null);
    }

    if (!state.currentCaseId && state.cases.length) {
      await loadCase(state.cases[0].case_id);
    }
  } catch (err) {
    elements.caseMeta.textContent = `Failed to load case list: ${String(err)}`;
  }
}

async function onUpload(event) {
  event.preventDefault();
  if (!elements.evidenceFile.files.length) {
    alert("Select an evidence file first.");
    return;
  }

  const file = elements.evidenceFile.files[0];
  const formData = new FormData();
  formData.append("evidence", file);

  setBusy(true, "Parsing evidence...");
  try {
    const res = await fetch("/api/cases/upload", { method: "POST", body: formData });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      throw new Error(data.error || `Upload failed (HTTP ${res.status})`);
    }
    await refreshCases();
    await loadCase(data.case_id);
    setActiveView("dashboard");
    elements.evidenceFile.value = "";
  } catch (err) {
    alert(`Parse failed: ${String(err)}`);
  } finally {
    setBusy(false);
  }
}

async function loadCase(caseId) {
  if (!caseId) return;
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}?include_artifacts=0`);
    const data = await res.json();
    if (!res.ok || !data.ok) {
      throw new Error(data.error || `Case load failed (HTTP ${res.status})`);
    }

    state.currentCaseId = caseId;
    state.caseData = data.case;
    state.dashboard = null;
    state.selectedIds = new Set();
    state.page = 1;
    state.tableRows = [];
    state.tableTotal = 0;
    state.tableTotalPages = 1;
    state.tableError = "";
    hydrateExistingAnalysis();
    await refreshDashboard();
    if (!["dashboard", "help"].includes(state.view)) {
      await requestTableRefresh();
    }
    render();
  } catch (err) {
    elements.caseMeta.textContent = `Case load failed: ${String(err)}`;
  }
}

async function refreshDashboard() {
  if (!state.currentCaseId) return;
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(state.currentCaseId)}/dashboard`);
    const data = await res.json();
    if (!res.ok || !data.ok) {
      throw new Error(data.error || `Dashboard fetch failed (HTTP ${res.status})`);
    }
    state.dashboard = data.dashboard || null;
  } catch {
    state.dashboard = null;
  }
}

function hydrateExistingAnalysis() {
  const analysis = state.caseData?.analysis || {};
  elements.localAnalysis.textContent = analysis.local?.analysis || "Not executed yet.";
  elements.openaiAnalysis.textContent = analysis.openai?.analysis || "Not executed yet.";
  renderReportMeta(analysis.report_pdf || null);
}

function setActiveView(view) {
  state.view = view;
  state.page = 1;
  elements.nav.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.classList.toggle("active", (btn.dataset.view || "") === view);
  });
  if (["dashboard", "help"].includes(view)) {
    renderContent();
    return;
  }
  requestTableRefresh();
}

function render() {
  renderCaseOptions();
  renderCaseMeta();
  renderOpenAIConfig();
  renderNavCounts();
  renderContent();
}

function renderCaseOptions() {
  const rows = state.cases || [];
  if (!rows.length) {
    elements.caseSelect.innerHTML = `<option value="">(none)</option>`;
    return;
  }

  elements.caseSelect.innerHTML = rows
    .map((row) => {
      const value = escapeHtml(row.case_id || "");
      const label = `${row.case_id || "-"} · ${row.source_name || "-"}`;
      return `<option value="${value}">${escapeHtml(label)}</option>`;
    })
    .join("");

  if (state.currentCaseId) {
    elements.caseSelect.value = state.currentCaseId;
  }
}

function renderCaseMeta() {
  if (!state.caseData) {
    elements.caseMeta.textContent = "Waiting for evidence upload";
    return;
  }
  const c = state.caseData;
  const s = c.summary || {};
  elements.caseMeta.textContent = [
    `Case ID: ${c.case_id}`,
    `Source: ${c.source_name}`,
    `Type: ${c.source_type}`,
    `Artifacts: ${num(s.artifact_count || 0)}`,
    `Created: ${fmtTime(c.created_at)}`,
    `Timeline rows: ${num(c.timeline_count || 0)}`,
    `Parser AI fallback calls: ${num(s.parser_ai_calls || 0)}`,
  ].join("\n");
}

function renderOpenAIConfig() {
  const openai = state.health?.openai || null;
  if (!openai) {
    elements.openaiConfig.textContent = "Failed to read OpenAI server config.";
    elements.btnOpenai.disabled = true;
    return;
  }

  elements.openaiConfig.textContent = [
    `Configured: ${openai.configured ? "YES" : "NO"}`,
    `Chat model: ${openai.chat_model || "-"}`,
    `Embed model: ${openai.embed_model || "-"}`,
  ].join("\n");
  elements.btnOpenai.disabled = !openai.configured;
}

function renderNavCounts() {
  const summary = state.caseData?.summary || {};
  const byCategory = summary.category || {};
  const artifactCount = Number(summary.artifact_count || 0);
  const timelineCount = Number(state.caseData?.timeline_count || 0);

  elements.nav.querySelectorAll(".nav-btn").forEach((btn) => {
    const view = btn.dataset.view || "";
    const base = views[view] || view;
    let count = 0;
    if (view === "evidence") count = artifactCount;
    else if (view === "timeline") count = timelineCount;
    else if (viewToCategory[view]) count = byCategory[viewToCategory[view]] || 0;
    btn.textContent = count ? `${base} (${num(count)})` : base;
  });
}

function renderContent() {
  if (!state.caseData) {
    elements.contentHeader.innerHTML = `<h2>Dashboard</h2>`;
    elements.contentBody.classList.add("empty");
    elements.contentBody.innerHTML = "<p>Upload evidence to start analysis.</p>";
    state.tableSnapshot = { title: "Evidence", pageRows: [] };
    return;
  }

  if (state.view === "dashboard") {
    renderDashboard();
    return;
  }

  if (state.view === "help") {
    renderHelp();
    return;
  }

  renderTableView();
}

function renderDashboard() {
  const summary = state.dashboard?.summary || state.caseData?.summary || {};
  const severity = summary.severity || {};
  const burst = state.dashboard?.burst || [];
  const timelineCount = Number(state.caseData?.timeline_count || 0);
  const topCategories = (state.dashboard?.top_categories || [])
    .slice(0, 10)
    .map((row) => `${row.category}: ${num(row.count)}`)
    .join("\n");
  const criticalHigh = (state.dashboard?.critical_high || []).slice(0, 15);

  elements.contentHeader.innerHTML = `
    <div class="header-left">
      <h2>Dashboard</h2>
      <span class="counter">Overview for full collection window</span>
    </div>
  `;

  elements.contentBody.classList.remove("empty");
  elements.contentBody.innerHTML = `
    <div class="dashboard-grid">
      <div class="metric"><div class="value">${num(summary.artifact_count || 0)}</div><div class="label">Artifacts</div></div>
      <div class="metric"><div class="value">${num(timelineCount)}</div><div class="label">Timeline events</div></div>
      <div class="metric"><div class="value">${num(severity.critical || 0)}</div><div class="label">Critical</div></div>
      <div class="metric"><div class="value">${num(severity.high || 0)}</div><div class="label">High</div></div>
    </div>

    <div class="metric" style="margin-top:10px;">
      <div class="label" style="margin-bottom:6px;">Top Categories</div>
      <pre class="analysis-box" style="max-height:180px;">${escapeHtml(topCategories || "No category data")}</pre>
    </div>

    <div class="metric" style="margin-top:10px;">
      <div class="label" style="margin-bottom:8px;">Event concentration by hour</div>
      ${renderBurstBars(burst)}
    </div>

    <div class="metric" style="margin-top:10px;">
      <div class="label" style="margin-bottom:8px;">Critical/High quick list</div>
      ${criticalHigh.length ? buildCompactTable(criticalHigh) : "<p class='sub'>No critical/high events.</p>"}
    </div>
  `;

  bindTableEvents();
}

function renderHelp() {
  elements.contentHeader.innerHTML = `
    <div class="header-left">
      <h2>Help</h2>
      <span class="counter">How local/OpenAI analysis works</span>
    </div>
  `;

  elements.contentBody.classList.remove("empty");
  elements.contentBody.innerHTML = `
    <div class="modal-list">
      <div class="modal-item"><div class="k">Evidence ingestion</div><div class="v">Upload collector ZIP or disk image. Parser normalizes artifacts into categories and timeline entries.</div></div>
      <div class="modal-item"><div class="k">Local Analysis</div><div class="v">Runs Ollama model (default: qwen2.5:14b-q4_K_M) against parsed artifacts. It does not replace raw parsing; it adds analyst-oriented summaries and hypotheses.</div></div>
      <div class="modal-item"><div class="k">OpenAI Analysis</div><div class="v">Uses server-configured OpenAI credentials. Chat model is controlled by OPENAI_CHAT_MODEL; embedding model is displayed for reference and future expansion.</div></div>
      <div class="modal-item"><div class="k">Table controls</div><div class="v">Use keyword search, severity filters, row selection, selected-only mode, column sorting, and pagination for triage speed.</div></div>
      <div class="modal-item"><div class="k">Modal detail</div><div class="v">Click any row to inspect parsed fields and raw event excerpt.</div></div>
    </div>
  `;
}

function renderTableView() {
  const title = views[state.view] || "Evidence";
  const total = state.tableTotal || 0;
  const totalPages = state.tableTotalPages || 1;
  const start = (state.page - 1) * state.pageSize;
  const end = start + (state.tableRows || []).length;
  state.tableSnapshot = { title, pageRows: (state.tableRows || []).slice() };

  elements.contentHeader.innerHTML = buildTableHeaderHtml(title, total, start, end, totalPages);
  bindHeaderControls(totalPages);

  elements.contentBody.classList.remove("empty");
  if (state.tableLoading) {
    elements.contentBody.classList.add("empty");
    elements.contentBody.innerHTML = "<p>Loading rows...</p>";
    return;
  }
  if (state.tableError) {
    elements.contentBody.classList.add("empty");
    elements.contentBody.innerHTML = `<p>${escapeHtml(state.tableError)}</p>`;
    return;
  }
  if (!(state.tableRows || []).length) {
    elements.contentBody.classList.add("empty");
    elements.contentBody.innerHTML = "<p>No rows match current filters.</p>";
    return;
  }

  const isTimeline = state.view === "timeline";
  elements.contentBody.innerHTML = buildMainTable(state.tableRows, isTimeline);
  bindTableEvents();
}

function buildTableHeaderHtml(title, total, start, end, totalPages) {
  const selectedCount = state.selectedIds.size;
  const selectedDisabled = selectedCount ? "" : "disabled";
  return `
    <div class="header-left">
      <h2>${escapeHtml(title)}</h2>
      <span class="counter">Rows ${num(total)} | Showing ${num(Math.min(total, start + 1))}-${num(Math.min(total, end))} | Selected ${num(selectedCount)}</span>
    </div>
    <div class="header-right controls-wrap">
      <input id="search-input" class="control-input" placeholder="Keyword search (title/details/raw)" value="${escapeAttr(state.search)}" />
      <label class="mini"><input id="selected-only" type="checkbox" ${state.selectedOnly ? "checked" : ""} /> Selected only</label>
      <label class="mini">Page size
        <select id="page-size" class="control-select">
          ${[50, 100, 200, 500].map((n) => `<option value="${n}" ${state.pageSize === n ? "selected" : ""}>${n}</option>`).join("")}
        </select>
      </label>
      <label class="mini">Page
        <button class="btn btn-inline" id="page-prev" ${state.page <= 1 ? "disabled" : ""}>◀</button>
        <span>${state.page}/${totalPages}</span>
        <button class="btn btn-inline" id="page-next" ${state.page >= totalPages ? "disabled" : ""}>▶</button>
      </label>
      <div class="csv-actions">
        <button class="btn btn-inline" id="csv-visible">CSV Visible</button>
        <button class="btn btn-inline" id="csv-filtered">CSV Filtered</button>
        <button class="btn btn-inline" id="csv-selected" ${selectedDisabled}>CSV Selected</button>
        <button class="btn btn-inline" id="csv-all">CSV All</button>
      </div>
      <div class="sev-filter">
        ${["critical", "high", "medium", "low", "info"].map((s) => `<label class="mini"><input class="sev-check" data-sev="${s}" type="checkbox" ${state.severityFilter.has(s) ? "checked" : ""} /> ${s.toUpperCase()}</label>`).join("")}
      </div>
    </div>
  `;
}

function bindHeaderControls(totalPages) {
  const search = document.getElementById("search-input");
  const selectedOnly = document.getElementById("selected-only");
  const pageSize = document.getElementById("page-size");
  const pagePrev = document.getElementById("page-prev");
  const pageNext = document.getElementById("page-next");

  if (search) {
    search.addEventListener("input", (e) => {
      state.search = e.target.value || "";
      state.page = 1;
      requestTableRefresh();
    });
  }

  if (selectedOnly) {
    selectedOnly.addEventListener("change", (e) => {
      state.selectedOnly = e.target.checked;
      state.page = 1;
      requestTableRefresh();
    });
  }

  if (pageSize) {
    pageSize.addEventListener("change", (e) => {
      state.pageSize = Number(e.target.value || 200);
      state.page = 1;
      requestTableRefresh();
    });
  }

  if (pagePrev) {
    pagePrev.addEventListener("click", () => {
      if (state.page > 1) {
        state.page -= 1;
        requestTableRefresh();
      }
    });
  }

  if (pageNext) {
    pageNext.addEventListener("click", () => {
      if (state.page < totalPages) {
        state.page += 1;
        requestTableRefresh();
      }
    });
  }

  document.querySelectorAll(".sev-check").forEach((el) => {
    el.addEventListener("change", (e) => {
      const sev = e.target.dataset.sev;
      if (!sev) return;
      if (e.target.checked) state.severityFilter.add(sev);
      else state.severityFilter.delete(sev);
      state.page = 1;
      requestTableRefresh();
    });
  });

  const csvVisible = document.getElementById("csv-visible");
  const csvFiltered = document.getElementById("csv-filtered");
  const csvSelected = document.getElementById("csv-selected");
  const csvAll = document.getElementById("csv-all");

  if (csvVisible) {
    csvVisible.addEventListener("click", () => exportCsvRows(state.tableSnapshot.pageRows, "visible"));
  }
  if (csvFiltered) {
    csvFiltered.addEventListener("click", () => downloadCsvByScope("filtered"));
  }
  if (csvSelected) {
    csvSelected.addEventListener("click", () => {
      downloadCsvByScope("selected");
    });
  }
  if (csvAll) {
    csvAll.addEventListener("click", () => downloadCsvByScope("all"));
  }
}

function buildMainTable(rows, isTimeline) {
  if (state.view === "browser") {
    return buildBrowserTable(rows);
  }
  if (state.view === "evidence") {
    return buildEvidenceTable(rows);
  }
  if (state.view === "installed") {
    return buildInstalledTable(rows);
  }
  if (state.view === "security") {
    return buildSecurityTable(rows);
  }
  if (state.view === "persistence") {
    return buildPersistenceTable(rows);
  }
  if (state.view === "network") {
    return buildNetworkTable(rows);
  }
  if (state.view === "accounts") {
    return buildAccountsTable(rows);
  }
  if (state.view === "commands") {
    return buildCommandsTable(rows);
  }
  if (state.view === "remote") {
    return buildRemoteTable(rows);
  }
  const head = isTimeline
    ? `
      <tr>
        <th style="width:34px;"><input type="checkbox" id="check-all" /></th>
        ${sortableTh("severity", "Severity", "width:92px;")}
        ${sortableTh("category", "Category", "width:150px;")}
        ${sortableTh("timestamp", "Time", "width:200px;")}
        ${sortableTh("title", "Title", "width:220px;")}
        <th>Details</th>
      </tr>`
    : `
      <tr>
        <th style="width:34px;"><input type="checkbox" id="check-all" /></th>
        ${sortableTh("severity", "Severity", "width:92px;")}
        ${sortableTh("category", "Category", "width:130px;")}
        ${sortableTh("subcategory", "Subcategory", "width:180px;")}
        ${sortableTh("timestamp", "Time", "width:190px;")}
        ${sortableTh("title", "Title", "width:200px;")}
        <th>Details</th>
      </tr>`;

  const body = rows
    .map((row) => {
      const id = escapeAttr(row.id || "");
      const checked = state.selectedIds.has(String(row.id)) ? "checked" : "";
      const sev = severityBadge(row.severity, row.severity_reason);
      const category = escapeHtml(row.category || "-");
      const sub = escapeHtml(row.subcategory || "-");
      const time = escapeHtml(fmtTime(row.timestamp));
      const title = escapeHtml(shorten(row.title || "-", 84));
      const details = escapeHtml(shorten(flatten(row.details || ""), 220));

      return isTimeline
        ? `<tr class="clickable" data-artifact-id="${id}">
            <td><input class="row-check" type="checkbox" data-artifact-id="${id}" ${checked} /></td>
            <td>${sev}</td>
            <td>${category}</td>
            <td>${time}</td>
            <td class="truncate">${title}</td>
            <td class="truncate">${details}</td>
          </tr>`
        : `<tr class="clickable" data-artifact-id="${id}">
            <td><input class="row-check" type="checkbox" data-artifact-id="${id}" ${checked} /></td>
            <td>${sev}</td>
            <td>${category}</td>
            <td>${sub}</td>
            <td>${time}</td>
            <td class="truncate">${title}</td>
            <td class="truncate">${details}</td>
          </tr>`;
    })
    .join("");

  return `<table class="table"><thead>${head}</thead><tbody>${body}</tbody></table>`;
}

function buildBrowserTable(rows) {
  const head = `
    <tr>
      <th style="width:34px;"><input type="checkbox" id="check-all" /></th>
      ${sortableTh("severity", "Severity", "width:92px;")}
      ${sortableTh("timestamp", "Time", "width:175px;")}
      ${sortableTh("page_title", "Page Title", "width:220px;")}
      ${sortableTh("domain", "Domain", "width:190px;")}
      <th style="width:170px;">Path</th>
      ${sortableTh("query_keys", "Query Keys", "width:170px;")}
      <th>URL</th>
    </tr>`;

  const body = rows
    .map((row) => {
      const id = escapeAttr(row.id || "");
      const checked = state.selectedIds.has(String(row.id)) ? "checked" : "";
      const sev = severityBadge(row.severity, row.severity_reason);
      const parsed = row.parsed || {};
      const pageTitle = escapeHtml(shorten(parsed.page_title || "-", 90));
      const domain = escapeHtml(parsed.domain || "-");
      const path = escapeHtml(shorten(parsed.path || "-", 70));
      const queryKeys = escapeHtml(shorten(parsed.query_keys || "-", 70));
      const url = escapeHtml(shorten(parsed.url || row.raw_excerpt || "-", 160));
      const time = escapeHtml(fmtTime(row.timestamp));
      return `<tr class="clickable" data-artifact-id="${id}">
        <td><input class="row-check" type="checkbox" data-artifact-id="${id}" ${checked} /></td>
        <td>${sev}</td>
        <td>${time}</td>
        <td class="truncate">${pageTitle}</td>
        <td class="truncate">${domain}</td>
        <td class="truncate">${path}</td>
        <td class="truncate">${queryKeys}</td>
        <td class="truncate">${url}</td>
      </tr>`;
    })
    .join("");
  return `<table class="table"><thead>${head}</thead><tbody>${body}</tbody></table>`;
}

function buildEvidenceTable(rows) {
  const head = `
    <tr>
      <th style="width:34px;"><input type="checkbox" id="check-all" /></th>
      ${sortableTh("severity", "Severity", "width:92px;")}
      ${sortableTh("category", "Category", "width:130px;")}
      ${sortableTh("subcategory", "Subcategory", "width:170px;")}
      ${sortableTh("timestamp", "Time", "width:180px;")}
      ${sortableTh("domain", "Domain", "width:180px;")}
      ${sortableTh("query_keys", "Query Keys", "width:170px;")}
      ${sortableTh("title", "Title", "width:220px;")}
      <th>Details</th>
    </tr>`;

  const body = rows
    .map((row) => {
      const id = escapeAttr(row.id || "");
      const checked = state.selectedIds.has(String(row.id)) ? "checked" : "";
      const sev = severityBadge(row.severity, row.severity_reason);
      const parsed = row.parsed || {};
      return `<tr class="clickable" data-artifact-id="${id}">
        <td><input class="row-check" type="checkbox" data-artifact-id="${id}" ${checked} /></td>
        <td>${sev}</td>
        <td>${escapeHtml(row.category || "-")}</td>
        <td>${escapeHtml(row.subcategory || "-")}</td>
        <td>${escapeHtml(fmtTime(row.timestamp))}</td>
        <td class="truncate">${escapeHtml(parsed.domain || "-")}</td>
        <td class="truncate">${escapeHtml(shorten(parsed.query_keys || "-", 70))}</td>
        <td class="truncate">${escapeHtml(shorten(row.title || "-", 90))}</td>
        <td class="truncate">${escapeHtml(shorten(flatten(row.details || ""), 220))}</td>
      </tr>`;
    })
    .join("");
  return `<table class="table"><thead>${head}</thead><tbody>${body}</tbody></table>`;
}

function buildInstalledTable(rows) {
  const head = `
    <tr>
      <th style="width:34px;"><input type="checkbox" id="check-all" /></th>
      ${sortableTh("severity", "Severity", "width:92px;")}
      ${sortableTh("timestamp", "Time", "width:180px;")}
      ${sortableTh("event_type", "Event Type", "width:180px;")}
      ${sortableTh("program_name", "Program Name", "width:240px;")}
      ${sortableTh("version", "Version", "width:120px;")}
      ${sortableTh("process_name", "Process", "width:170px;")}
      <th>Package IDs</th>
    </tr>`;

  const body = rows
    .map((row) => {
      const id = escapeAttr(row.id || "");
      const checked = state.selectedIds.has(String(row.id)) ? "checked" : "";
      const sev = severityBadge(row.severity, row.severity_reason);
      const parsed = row.parsed || {};
      return `<tr class="clickable" data-artifact-id="${id}">
        <td><input class="row-check" type="checkbox" data-artifact-id="${id}" ${checked} /></td>
        <td>${sev}</td>
        <td>${escapeHtml(fmtTime(row.timestamp))}</td>
        <td class="truncate">${escapeHtml(parsed.event_type || "-")}</td>
        <td class="truncate">${escapeHtml(shorten(parsed.program_name || "-", 80))}</td>
        <td class="truncate">${escapeHtml(parsed.version || "-")}</td>
        <td class="truncate">${escapeHtml(parsed.process_name || "-")}</td>
        <td class="truncate">${escapeHtml(shorten(parsed.package_ids || "-", 130))}</td>
      </tr>`;
    })
    .join("");
  return `<table class="table"><thead>${head}</thead><tbody>${body}</tbody></table>`;
}

function buildSecurityTable(rows) {
  const head = `
    <tr>
      <th style="width:34px;"><input type="checkbox" id="check-all" /></th>
      ${sortableTh("severity", "Severity", "width:92px;")}
      ${sortableTh("agent_name", "Agent", "width:210px;")}
      ${sortableTh("event_type", "Event Type", "width:190px;")}
      ${sortableTh("check_type", "Check Type", "width:140px;")}
      ${sortableTh("status", "Status", "width:140px;")}
      ${sortableTh("version", "Version", "width:130px;")}
      ${sortableTh("process_name", "Process", "width:170px;")}
      <th>Source</th>
    </tr>`;

  const body = rows
    .map((row) => {
      const id = escapeAttr(row.id || "");
      const checked = state.selectedIds.has(String(row.id)) ? "checked" : "";
      const sev = severityBadge(row.severity, row.severity_reason);
      const parsed = row.parsed || {};
      return `<tr class="clickable" data-artifact-id="${id}">
        <td><input class="row-check" type="checkbox" data-artifact-id="${id}" ${checked} /></td>
        <td>${sev}</td>
        <td class="truncate">${escapeHtml(parsed.agent_name || "-")}</td>
        <td class="truncate">${escapeHtml(parsed.event_type || "-")}</td>
        <td class="truncate">${escapeHtml(parsed.check_type || "-")}</td>
        <td class="truncate">${escapeHtml(parsed.status || "-")}</td>
        <td class="truncate">${escapeHtml(parsed.version || "-")}</td>
        <td class="truncate">${escapeHtml(parsed.process_name || "-")}</td>
        <td class="truncate">${escapeHtml(shorten(row.source_file || "-", 120))}</td>
      </tr>`;
    })
    .join("");
  return `<table class="table"><thead>${head}</thead><tbody>${body}</tbody></table>`;
}

function buildPersistenceTable(rows) {
  const head = `
    <tr>
      <th style="width:34px;"><input type="checkbox" id="check-all" /></th>
      ${sortableTh("severity", "Severity", "width:92px;")}
      ${sortableTh("subcategory", "Source Type", "width:170px;")}
      ${sortableTh("item_name", "Item", "width:220px;")}
      ${sortableTh("launch_label", "Launch Label", "width:220px;")}
      ${sortableTh("pid", "PID", "width:100px;")}
      ${sortableTh("status", "Status", "width:120px;")}
      ${sortableTh("path", "Path", "width:260px;")}
      <th>Value</th>
    </tr>`;

  const body = rows
    .map((row) => {
      const id = escapeAttr(row.id || "");
      const checked = state.selectedIds.has(String(row.id)) ? "checked" : "";
      const sev = severityBadge(row.severity, row.severity_reason);
      const parsed = row.parsed || {};
      return `<tr class="clickable" data-artifact-id="${id}">
        <td><input class="row-check" type="checkbox" data-artifact-id="${id}" ${checked} /></td>
        <td>${sev}</td>
        <td>${escapeHtml(row.subcategory || "-")}</td>
        <td class="truncate">${escapeHtml(parsed.item_name || "-")}</td>
        <td class="truncate">${escapeHtml(parsed.launch_label || "-")}</td>
        <td>${escapeHtml(parsed.pid || "-")}</td>
        <td>${escapeHtml(parsed.status || "-")}</td>
        <td class="truncate">${escapeHtml(shorten(parsed.path || "-", 120))}</td>
        <td class="truncate">${escapeHtml(shorten(parsed.value || "-", 140))}</td>
      </tr>`;
    })
    .join("");
  return `<table class="table"><thead>${head}</thead><tbody>${body}</tbody></table>`;
}

function buildNetworkTable(rows) {
  const head = `
    <tr>
      <th style="width:34px;"><input type="checkbox" id="check-all" /></th>
      ${sortableTh("severity", "Severity", "width:92px;")}
      ${sortableTh("timestamp", "Time", "width:180px;")}
      ${sortableTh("protocol", "Proto", "width:90px;")}
      ${sortableTh("state", "State", "width:120px;")}
      ${sortableTh("process_name", "Process", "width:180px;")}
      ${sortableTh("local_addr", "Local", "width:200px;")}
      ${sortableTh("remote_addr", "Remote", "width:220px;")}
      ${sortableTh("pid", "PID", "width:100px;")}
      <th>Endpoint</th>
    </tr>`;

  const body = rows
    .map((row) => {
      const id = escapeAttr(row.id || "");
      const checked = state.selectedIds.has(String(row.id)) ? "checked" : "";
      const sev = severityBadge(row.severity, row.severity_reason);
      const parsed = row.parsed || {};
      return `<tr class="clickable" data-artifact-id="${id}">
        <td><input class="row-check" type="checkbox" data-artifact-id="${id}" ${checked} /></td>
        <td>${sev}</td>
        <td>${escapeHtml(fmtTime(row.timestamp))}</td>
        <td>${escapeHtml(parsed.protocol || "-")}</td>
        <td>${escapeHtml(parsed.state || "-")}</td>
        <td class="truncate">${escapeHtml(parsed.process_name || "-")}</td>
        <td class="truncate">${escapeHtml(parsed.local_addr || "-")}</td>
        <td class="truncate">${escapeHtml(parsed.remote_addr || "-")}</td>
        <td>${escapeHtml(parsed.pid || "-")}</td>
        <td class="truncate">${escapeHtml(shorten(parsed.endpoint || "-", 120))}</td>
      </tr>`;
    })
    .join("");
  return `<table class="table"><thead>${head}</thead><tbody>${body}</tbody></table>`;
}

function buildAccountsTable(rows) {
  const head = `
    <tr>
      <th style="width:34px;"><input type="checkbox" id="check-all" /></th>
      ${sortableTh("severity", "Severity", "width:92px;")}
      ${sortableTh("timestamp", "Time", "width:180px;")}
      ${sortableTh("event_type", "Event Type", "width:170px;")}
      ${sortableTh("username", "User", "width:140px;")}
      ${sortableTh("tty", "TTY", "width:120px;")}
      ${sortableTh("session", "Session", "width:220px;")}
      <th>Details</th>
    </tr>`;

  const body = rows
    .map((row) => {
      const id = escapeAttr(row.id || "");
      const checked = state.selectedIds.has(String(row.id)) ? "checked" : "";
      const sev = severityBadge(row.severity, row.severity_reason);
      const parsed = row.parsed || {};
      return `<tr class="clickable" data-artifact-id="${id}">
        <td><input class="row-check" type="checkbox" data-artifact-id="${id}" ${checked} /></td>
        <td>${sev}</td>
        <td>${escapeHtml(fmtTime(row.timestamp))}</td>
        <td>${escapeHtml(parsed.event_type || "-")}</td>
        <td>${escapeHtml(parsed.username || "-")}</td>
        <td>${escapeHtml(parsed.tty || "-")}</td>
        <td class="truncate">${escapeHtml(shorten(parsed.session || "-", 90))}</td>
        <td class="truncate">${escapeHtml(shorten(flatten(row.details || ""), 160))}</td>
      </tr>`;
    })
    .join("");
  return `<table class="table"><thead>${head}</thead><tbody>${body}</tbody></table>`;
}

function buildCommandsTable(rows) {
  const head = `
    <tr>
      <th style="width:34px;"><input type="checkbox" id="check-all" /></th>
      ${sortableTh("severity", "Severity", "width:92px;")}
      ${sortableTh("timestamp", "Time", "width:180px;")}
      ${sortableTh("shell", "Shell", "width:110px;")}
      ${sortableTh("command_base", "Base Cmd", "width:170px;")}
      <th>Command</th>
    </tr>`;

  const body = rows
    .map((row) => {
      const id = escapeAttr(row.id || "");
      const checked = state.selectedIds.has(String(row.id)) ? "checked" : "";
      const sev = severityBadge(row.severity, row.severity_reason);
      const parsed = row.parsed || {};
      return `<tr class="clickable" data-artifact-id="${id}">
        <td><input class="row-check" type="checkbox" data-artifact-id="${id}" ${checked} /></td>
        <td>${sev}</td>
        <td>${escapeHtml(fmtTime(row.timestamp))}</td>
        <td>${escapeHtml(parsed.shell || "-")}</td>
        <td class="truncate">${escapeHtml(parsed.command_base || "-")}</td>
        <td class="truncate">${escapeHtml(shorten(parsed.command || row.details || "-", 200))}</td>
      </tr>`;
    })
    .join("");
  return `<table class="table"><thead>${head}</thead><tbody>${body}</tbody></table>`;
}

function buildRemoteTable(rows) {
  const head = `
    <tr>
      <th style="width:34px;"><input type="checkbox" id="check-all" /></th>
      ${sortableTh("severity", "Severity", "width:92px;")}
      ${sortableTh("event_type", "Event Type", "width:220px;")}
      ${sortableTh("keyword", "Keyword", "width:150px;")}
      ${sortableTh("source_name", "Source", "width:180px;")}
      <th>Line</th>
    </tr>`;

  const body = rows
    .map((row) => {
      const id = escapeAttr(row.id || "");
      const checked = state.selectedIds.has(String(row.id)) ? "checked" : "";
      const sev = severityBadge(row.severity, row.severity_reason);
      const parsed = row.parsed || {};
      return `<tr class="clickable" data-artifact-id="${id}">
        <td><input class="row-check" type="checkbox" data-artifact-id="${id}" ${checked} /></td>
        <td>${sev}</td>
        <td class="truncate">${escapeHtml(parsed.event_type || "-")}</td>
        <td>${escapeHtml(parsed.keyword || "-")}</td>
        <td class="truncate">${escapeHtml(parsed.source_name || "-")}</td>
        <td class="truncate">${escapeHtml(shorten(parsed.line || row.details || "-", 220))}</td>
      </tr>`;
    })
    .join("");
  return `<table class="table"><thead>${head}</thead><tbody>${body}</tbody></table>`;
}

function sortableTh(field, label, style = "") {
  const active = state.sort.field === field;
  const dir = active ? (state.sort.dir === "asc" ? "▲" : "▼") : "";
  return `<th style="${style}"><button class="th-sort" data-sort="${field}">${label} ${dir}</button></th>`;
}

function buildCompactTable(rows) {
  const body = rows
    .map((row) => {
      const sev = severityBadge(row.severity, row.severity_reason);
      const id = escapeAttr(row.id || "");
      return `<tr class="clickable" data-artifact-id="${id}"><td>${sev}</td><td>${escapeHtml(row.category || "-")}</td><td>${escapeHtml(shorten(row.title || "-", 90))}</td><td>${escapeHtml(shorten(flatten(row.details || ""), 160))}</td></tr>`;
    })
    .join("");
  return `<table class="table"><thead><tr><th style="width:92px;">Severity</th><th style="width:150px;">Category</th><th style="width:220px;">Title</th><th>Details</th></tr></thead><tbody>${body}</tbody></table>`;
}

function bindTableEvents() {
  document.querySelectorAll(".th-sort").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      const field = e.currentTarget.dataset.sort;
      if (!field) return;
      if (state.sort.field === field) {
        state.sort.dir = state.sort.dir === "asc" ? "desc" : "asc";
      } else {
        state.sort = { field, dir: field === "timestamp" ? "desc" : "asc" };
      }
      requestTableRefresh();
    });
  });

  const checkAll = document.getElementById("check-all");
  if (checkAll) {
    checkAll.addEventListener("change", (e) => {
      const checked = e.target.checked;
      document.querySelectorAll(".row-check").forEach((rowCheck) => {
        const id = rowCheck.dataset.artifactId;
        rowCheck.checked = checked;
        if (id) {
          if (checked) state.selectedIds.add(id);
          else state.selectedIds.delete(id);
        }
      });
      if (state.selectedOnly) {
        requestTableRefresh();
      } else {
        renderContent();
      }
    });
  }

  document.querySelectorAll(".row-check").forEach((chk) => {
    chk.addEventListener("click", (e) => e.stopPropagation());
    chk.addEventListener("change", (e) => {
      const id = e.target.dataset.artifactId;
      if (!id) return;
      if (e.target.checked) state.selectedIds.add(id);
      else state.selectedIds.delete(id);
    });
  });

  elements.contentBody.querySelectorAll("tr.clickable[data-artifact-id]").forEach((rowEl) => {
    rowEl.addEventListener("click", () => {
      const id = rowEl.dataset.artifactId;
      const row =
        (state.tableRows || []).find((x) => String(x.id) === String(id)) ||
        (state.dashboard?.critical_high || []).find((x) => String(x.id) === String(id));
      if (row) openModal(row);
    });
  });
}

function openModal(row) {
  state.modalRow = row;
  elements.modalTitle.textContent = `${row.id} · ${row.title}`;
  const parsed = row.parsed || {};
  const parsedFields = Object.keys(parsed).length
    ? Object.entries(parsed).map(([k, v]) => [k, typeof v === "object" ? JSON.stringify(v) : String(v)])
    : [];
  const fields = [
    ["Severity", `${row.severity} (${row.severity_reason || "no reason"})`],
    ["Category", row.category || "-"],
    ["Subcategory", row.subcategory || "-"],
    ["Timestamp", fmtTime(row.timestamp)],
    ["Details", row.details || "-"],
    ["Raw Event", row.raw_excerpt || "-"],
    ["Source Path", row.source_file || "-"],
    ...parsedFields,
  ];

  elements.modalContent.innerHTML = `<div class="modal-list">${fields
    .map(([k, v]) => `<div class="modal-item"><div class="k">${escapeHtml(k)}</div><div class="v">${escapeHtml(v)}</div></div>`)
    .join("")}</div>`;
  elements.modal.classList.remove("hidden");
}

function closeModal() {
  state.modalRow = null;
  elements.modal.classList.add("hidden");
}

function exportModalRowCsv() {
  if (!state.modalRow) return;
  exportCsvRows([state.modalRow], "single");
}

async function runLocalAnalysis() {
  if (!state.currentCaseId) {
    alert("Upload evidence first.");
    return;
  }

  const model = (elements.localModel.value || "qwen2.5:14b-q4_K_M").trim();
  elements.localAnalysis.textContent = "Running local analysis...";

  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(state.currentCaseId)}/analysis/local`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model }),
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      throw new Error(data.error || `Local analysis failed (HTTP ${res.status})`);
    }
    const lines = [];
    if (data.model_note) lines.push(`[Model] ${data.model_note}`);
    lines.push(data.analysis || "No analysis output.");
    elements.localAnalysis.textContent = lines.join("\n\n");
    await generateReportPdf({ auto: true, analysisSource: "local" });
  } catch (err) {
    elements.localAnalysis.textContent =
      `Error: ${String(err)}\n\n` +
      "Tip: verify Ollama is running and the configured local model exists.";
  }
}

async function runOpenAIAnalysis() {
  if (!state.currentCaseId) {
    alert("Upload evidence first.");
    return;
  }
  if (!state.health?.openai?.configured) {
    alert("OPENAI_API_KEY is not configured on server.");
    return;
  }

  elements.openaiAnalysis.textContent = "Running OpenAI analysis...";
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(state.currentCaseId)}/analysis/openai`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      throw new Error(data.error || `OpenAI analysis failed (HTTP ${res.status})`);
    }
    elements.openaiAnalysis.textContent = data.analysis || "No analysis output.";
    await generateReportPdf({ auto: true, analysisSource: "openai" });
  } catch (err) {
    const msg = String(err);
    elements.openaiAnalysis.textContent = `Error: ${msg}`;
    if (/billing is not active|billing_not_active|account is not active/i.test(msg)) {
      elements.btnOpenai.disabled = true;
      elements.openaiConfig.textContent = [
        "Configured: YES",
        `Chat model: ${state.health?.openai?.chat_model || "-"}`,
        `Embed model: ${state.health?.openai?.embed_model || "-"}`,
        "Status: billing_not_active (OpenAI button disabled)",
      ].join("\n");
    }
  }
}

async function generateReportPdf({ auto = false, analysisSource = "" } = {}) {
  if (!state.currentCaseId) {
    if (!auto) alert("Upload evidence first.");
    return;
  }
  if (!auto) {
    elements.reportStatus.textContent = "Generating DFIR PDF report...";
  }
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(state.currentCaseId)}/report/pdf`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ analysis_source: analysisSource || "" }),
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      throw new Error(data.error || `Report generation failed (HTTP ${res.status})`);
    }
    if (!state.caseData.analysis) state.caseData.analysis = {};
    state.caseData.analysis.report_pdf = data;
    renderReportMeta(data);
    if (!auto) {
      alert(`DFIR PDF report generated.\n${data.file_name}`);
    }
  } catch (err) {
    const message = `Error: ${String(err)}`;
    elements.reportStatus.textContent = message;
    if (!auto) alert(message);
  }
}

async function clearAllHistory() {
  const ok = window.confirm(
    "This will permanently delete all case history and uploaded evidence files.\n\nContinue?"
  );
  if (!ok) return;

  setBusy(true, "Clearing case/upload history...");
  try {
    const res = await fetch("/api/cases/clear", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      throw new Error(data.error || `Clear failed (HTTP ${res.status})`);
    }

    state.cases = [];
    state.currentCaseId = null;
    state.caseData = null;
    state.selectedIds = new Set();
    state.search = "";
    state.selectedOnly = false;
    state.page = 1;
    state.dashboard = null;
    state.tableRows = [];
    state.tableTotal = 0;
    state.tableTotalPages = 1;
    state.tableLoading = false;
    state.tableError = "";
    elements.localAnalysis.textContent = "Not executed yet.";
    elements.openaiAnalysis.textContent = "Not executed yet.";
    renderReportMeta(null);
    render();

    alert(
      `History cleared.\nRemoved case entries: ${num(data.removed_cases || 0)}\nRemoved upload files: ${num(
        data.removed_uploads || 0
      )}`
    );
  } catch (err) {
    alert(`Failed to clear history: ${String(err)}`);
  } finally {
    setBusy(false);
  }
}

async function requestTableRefresh() {
  if (!state.currentCaseId) return;
  if (["dashboard", "help"].includes(state.view)) return;

  const requestedCaseId = state.currentCaseId;
  const seq = ++state.tableReqSeq;
  state.tableLoading = true;
  state.tableError = "";
  renderTableView();

  try {
    const params = buildRowsQuery();
    const res = await fetch(`/api/cases/${encodeURIComponent(state.currentCaseId)}/rows?${params.toString()}`);
    const data = await res.json();
    if (seq !== state.tableReqSeq) return;
    if (!res.ok || !data.ok) {
      if (res.status === 404 || /case not found/i.test(String(data.error || ""))) {
        await recoverMissingCase(requestedCaseId);
        return;
      }
      throw new Error(data.error || `Row query failed (HTTP ${res.status})`);
    }
    state.tableRows = data.rows || [];
    state.tableTotal = Number(data.total || 0);
    state.tableTotalPages = Number(data.total_pages || 1);
    state.page = Number(data.page || 1);
    state.pageSize = Number(data.page_size || state.pageSize);
    state.tableLoading = false;
    state.tableError = "";
    renderTableView();
  } catch (err) {
    if (seq !== state.tableReqSeq) return;
    state.tableRows = [];
    state.tableTotal = 0;
    state.tableTotalPages = 1;
    state.tableLoading = false;
    state.tableError = `Failed to load rows: ${String(err)}`;
    renderTableView();
  }
}

async function recoverMissingCase(missingCaseId) {
  await refreshCases();
  if (!state.currentCaseId) {
    state.tableRows = [];
    state.tableTotal = 0;
    state.tableTotalPages = 1;
    state.tableLoading = false;
    state.tableError = `Case not found (${missingCaseId}). Upload evidence again.`;
    render();
    return;
  }
  state.tableLoading = false;
  state.tableError = "";
  if (!["dashboard", "help"].includes(state.view)) {
    await requestTableRefresh();
  } else {
    render();
  }
}

function buildRowsQuery(extra = {}) {
  const params = new URLSearchParams();
  params.set("view", String(extra.view || state.view || "evidence"));
  params.set("page", String(extra.page || state.page || 1));
  params.set("page_size", String(extra.pageSize || state.pageSize || 200));
  params.set("search", String(extra.search ?? state.search ?? ""));
  params.set("sort_field", String(extra.sortField || state.sort.field || "timestamp"));
  params.set("sort_dir", String(extra.sortDir || state.sort.dir || "desc"));
  const severities = extra.severities || Array.from(state.severityFilter || []);
  params.set("severities", severities.join(","));
  const selectedOnly = typeof extra.selectedOnly === "boolean" ? extra.selectedOnly : state.selectedOnly;
  params.set("selected_only", selectedOnly ? "1" : "0");
  const selectedIds = extra.selectedIds || Array.from(state.selectedIds || []);
  if (selectedIds.length) {
    params.set("selected_ids", selectedIds.join(","));
  }
  return params;
}

function downloadCsvByScope(scope) {
  if (!state.currentCaseId) {
    alert("Upload evidence first.");
    return;
  }
  if (scope === "selected" && !state.selectedIds.size) {
    alert("No selected rows.");
    return;
  }
  const override = {};
  if (scope === "all") {
    override.view = "evidence";
    override.selectedOnly = false;
  }
  const params = buildRowsQuery(override);
  params.set("scope", scope);
  const url = `/api/cases/${encodeURIComponent(state.currentCaseId)}/rows/csv?${params.toString()}`;
  window.open(url, "_blank", "noopener,noreferrer");
}

function sortRows(rows, field, dir) {
  const arr = rows.slice();
  arr.sort((a, b) => {
    let av;
    let bv;
    if (field === "severity") {
      av = severityRank[String(a.severity || "low").toLowerCase()] ?? 99;
      bv = severityRank[String(b.severity || "low").toLowerCase()] ?? 99;
    } else if (field === "timestamp") {
      av = a.timestamp ? Date.parse(a.timestamp) || 0 : 0;
      bv = b.timestamp ? Date.parse(b.timestamp) || 0 : 0;
    } else {
      av = String(a[field] || "").toLowerCase();
      bv = String(b[field] || "").toLowerCase();
    }

    if (av < bv) return dir === "asc" ? -1 : 1;
    if (av > bv) return dir === "asc" ? 1 : -1;
    return 0;
  });
  return arr;
}

function buildTimelineBurst(timeline) {
  const buckets = {};
  for (const row of timeline || []) {
    const ts = row.timestamp;
    if (!ts) continue;
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) continue;
    const key = `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:00`;
    buckets[key] = (buckets[key] || 0) + 1;
  }
  return Object.entries(buckets)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 12)
    .map(([hour, count]) => ({ hour, count }));
}

function renderBurstBars(rows) {
  if (!rows.length) return "<p class='sub'>No timestamped events.</p>";
  const max = Math.max(...rows.map((r) => r.count), 1);
  return rows
    .map((r) => {
      const width = Math.max(6, Math.round((r.count / max) * 100));
      return `<div class="burst-row"><span>${escapeHtml(r.hour)}</span><div class="burst-bar"><i style="width:${width}%"></i></div><b>${num(r.count)}</b></div>`;
    })
    .join("");
}

function severityBadge(level, reason) {
  const raw = String(level || "low").toLowerCase();
  const sev = ["critical", "high", "medium", "low", "info"].includes(raw) ? raw : "low";
  return `<span class="severity-badge s-${sev}">${sev.toUpperCase()}<span class="tip">${escapeHtml(reason || "No reason")}</span></span>`;
}

function setBusy(isBusy, title = "") {
  if (isBusy) {
    elements.contentHeader.innerHTML = `<h2>${escapeHtml(title)}</h2>`;
  }
}

function fmtTime(value) {
  if (!value) return "-";
  const d = new Date(value);
  if (!Number.isNaN(d.getTime())) {
    return d.toLocaleString();
  }
  return String(value);
}

function flatten(text) {
  return String(text || "").replace(/\s+/g, " ").trim();
}

function shorten(text, max) {
  const t = String(text || "");
  if (t.length <= max) return t;
  return `${t.slice(0, max - 1)}…`;
}

function num(n) {
  return Number(n || 0).toLocaleString();
}

function pad2(n) {
  return String(n).padStart(2, "0");
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeAttr(value) {
  return escapeHtml(value).replace(/`/g, "&#96;");
}

function renderReportMeta(meta) {
  if (!meta) {
    elements.reportStatus.textContent = "Not generated yet.";
    elements.reportDownload.style.display = "none";
    elements.reportDownload.href = "#";
    return;
  }
  elements.reportStatus.textContent = [
    `Generated: ${fmtTime(meta.generated_at)}`,
    `Compromise: ${meta.compromise ? "YES" : "NO"}`,
    `IOC Count: ${num(meta.ioc_count || 0)}`,
    `Timeline Rows: ${num(meta.timeline_count || 0)}`,
    `Draw.io Files: ${num(meta.drawio_count || 0)}`,
    `Engine: ${meta.analysis_engine || "-"}`,
    `Reason: ${meta.compromise_reason || "-"}`,
  ].join("\n");
  elements.reportDownload.href = `/api/cases/${encodeURIComponent(state.currentCaseId)}/report/pdf`;
  elements.reportDownload.style.display = "inline-block";
}

function exportCsvRows(rows, scope) {
  const list = Array.isArray(rows) ? rows : [];
  if (!list.length) {
    alert("No rows available for CSV export.");
    return;
  }

  const headers = [
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
    "event_type",
    "program_name",
    "version",
    "process_name",
    "agent_name",
    "status",
    "check_type",
    "domain",
    "page_title",
    "query_keys",
    "url",
    "path",
    "protocol",
    "state",
    "local_addr",
    "remote_addr",
    "shell",
    "command_base",
    "keyword",
    "source_name",
    "parsed_json",
  ];
  const lines = [headers.join(",")];
  for (const row of list) {
    const parsed = row.parsed || {};
    const values = headers.map((h) => {
      if (h === "parsed_json") return csvCell(JSON.stringify(parsed || {}));
      if (h in row) return csvCell(row[h]);
      return csvCell(parsed[h]);
    });
    lines.push(values.join(","));
  }

  const csvText = "\uFEFF" + lines.join("\n");
  const viewName = String(state.tableSnapshot?.title || state.view || "evidence")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "evidence";
  const scopeName = String(scope || "rows").toLowerCase();
  const caseName = String(state.currentCaseId || "no-case").replace(/[^A-Za-z0-9_-]+/g, "_");
  const filename = `${caseName}_${viewName}_${scopeName}_${timestampForFile()}.csv`;
  downloadTextFile(filename, csvText, "text/csv;charset=utf-8;");
}

function csvCell(value) {
  const raw = value == null ? "" : String(value);
  const normalized = raw.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  return `"${normalized.replace(/"/g, '""')}"`;
}

function downloadTextFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function timestampForFile() {
  const d = new Date();
  return [
    d.getFullYear(),
    pad2(d.getMonth() + 1),
    pad2(d.getDate()),
    "_",
    pad2(d.getHours()),
    pad2(d.getMinutes()),
    pad2(d.getSeconds()),
  ].join("");
}
