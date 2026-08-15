const state = {
  scan: null,
  markdown: "",
  html: "",
  pdfBase64: "",
  aiAnalysis: null,
  projects: [],
  projectId: "",
  history: [],
  comparison: null,
};

const severityOrder = ["critical", "high", "medium", "low", "info"];

const form = document.querySelector("#scan-form");
const message = document.querySelector("#message");
const statusText = document.querySelector("#status-text");
const targetPill = document.querySelector("#target-pill");
const summaryEmpty = document.querySelector("#summary-empty");
const summaryContent = document.querySelector("#summary-content");
const findingsList = document.querySelector("#findings-list");
const modulesTable = document.querySelector("#modules-table");
const jsonOutput = document.querySelector("#json-output");
const reportOutput = document.querySelector("#report-output");
const htmlPreview = document.querySelector("#html-preview");
const generateReportButton = document.querySelector("#generate-report");
const downloadJsonButton = document.querySelector("#download-json");
const downloadAiButton = document.querySelector("#download-ai");
const downloadMdButton = document.querySelector("#download-md");
const downloadHtmlButton = document.querySelector("#download-html");
const downloadPdfButton = document.querySelector("#download-pdf");
const runAiButton = document.querySelector("#run-ai");
const aiSummary = document.querySelector("#ai-summary");
const aiOutput = document.querySelector("#ai-output");
const projectSelect = document.querySelector("#project-select");
const projectNameInput = document.querySelector("#project-name");
const projectClientInput = document.querySelector("#project-client");
const projectAuditorInput = document.querySelector("#project-auditor");
const projectEngagementInput = document.querySelector("#project-engagement");
const createProjectButton = document.querySelector("#create-project");
const historyTable = document.querySelector("#history-table");
const historyCount = document.querySelector("#history-count");
const refreshHistoryButton = document.querySelector("#refresh-history");
const compareBaseline = document.querySelector("#compare-baseline");
const compareCurrent = document.querySelector("#compare-current");
const runCompareButton = document.querySelector("#run-compare");
const compareOutput = document.querySelector("#compare-output");

document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => activateTab(button.dataset.tab));
});

initialize();

async function initialize() {
  await loadProjects();
  await loadHistory();
}

projectSelect.addEventListener("change", async () => {
  state.projectId = projectSelect.value;
  applyProject(currentProject());
  await loadHistory();
});

createProjectButton.addEventListener("click", async () => {
  clearMessage();
  const name = projectNameInput.value.trim();
  if (!name) {
    showMessage("El nombre del proyecto es obligatorio.");
    return;
  }
  createProjectButton.disabled = true;
  try {
    const response = await postJson("/api/projects/create", {
      name,
      target: document.querySelector("#target").value.trim(),
      client: projectClientInput.value.trim(),
      auditor: projectAuditorInput.value.trim(),
      engagement: projectEngagementInput.value.trim(),
      scope_summary: document.querySelector("#report-scope").value.trim(),
    });
    await loadProjects(response.project.id);
    state.projectId = response.project.id;
    applyProject(response.project);
    await loadHistory();
  } catch (error) {
    showMessage(error.message);
  } finally {
    createProjectButton.disabled = false;
  }
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearMessage();
  setBusy(true);
  try {
    const response = await postJson("/api/scan", collectPayload());
    state.scan = response.result;
    state.markdown = "";
    state.html = "";
    state.pdfBase64 = "";
    state.aiAnalysis = response.result.ai_analysis || null;
    renderScan(state.scan);
    reportOutput.value = "";
    renderAiAnalysis(state.aiAnalysis);
    document.querySelector("#ai-analysis").value = state.aiAnalysis ? JSON.stringify(state.aiAnalysis, null, 2) : "";
    htmlPreview.removeAttribute("srcdoc");
    generateReportButton.disabled = false;
    runAiButton.disabled = false;
    downloadJsonButton.disabled = false;
    downloadAiButton.disabled = !state.aiAnalysis;
    downloadMdButton.disabled = true;
    downloadHtmlButton.disabled = true;
    downloadPdfButton.disabled = true;
    activateTab("summary");
  } catch (error) {
    showMessage(error.message);
  } finally {
    setBusy(false);
  }
});

generateReportButton.addEventListener("click", async () => {
  if (!state.scan) {
    return;
  }
  clearMessage();
  generateReportButton.disabled = true;
  try {
    const title = document.querySelector("#report-title").value.trim();
    const response = await postJson("/api/report", {
      project_id: currentProjectId(),
      scan: state.scan,
      ai_analysis: currentAiAnalysisForReport(),
      title,
      format: "all",
      metadata: collectReportMetadata(),
    });
    state.markdown = response.markdown || "";
    state.html = response.html || "";
    state.pdfBase64 = response.pdf_base64 || "";
    reportOutput.value = state.markdown;
    if (state.html) {
      htmlPreview.srcdoc = state.html;
    }
    downloadMdButton.disabled = false;
    downloadHtmlButton.disabled = !state.html;
    downloadPdfButton.disabled = !state.pdfBase64;
    activateTab("report");
  } catch (error) {
    showMessage(error.message);
  } finally {
    generateReportButton.disabled = false;
  }
});

refreshHistoryButton.addEventListener("click", async () => {
  await loadHistory();
});

historyTable.addEventListener("click", async (event) => {
  if (!(event.target instanceof Element)) {
    return;
  }
  const button = event.target.closest("[data-load-history]");
  if (!button) {
    return;
  }
  clearMessage();
  try {
    const response = await postJson("/api/history/load", {
      project_id: currentProjectId(),
      id: button.dataset.loadHistory,
    });
    state.scan = response.scan;
    state.markdown = "";
    state.html = "";
    state.pdfBase64 = "";
    state.aiAnalysis = response.scan.ai_analysis || null;
    renderScan(state.scan);
    reportOutput.value = "";
    renderAiAnalysis(state.aiAnalysis);
    document.querySelector("#ai-analysis").value = state.aiAnalysis ? JSON.stringify(state.aiAnalysis, null, 2) : "";
    htmlPreview.removeAttribute("srcdoc");
    generateReportButton.disabled = false;
    runAiButton.disabled = false;
    downloadJsonButton.disabled = false;
    downloadAiButton.disabled = !state.aiAnalysis;
    downloadMdButton.disabled = true;
    downloadHtmlButton.disabled = true;
    downloadPdfButton.disabled = true;
    activateTab("summary");
  } catch (error) {
    showMessage(error.message);
  }
});

runCompareButton.addEventListener("click", async () => {
  clearMessage();
  try {
    const response = await postJson("/api/compare", {
      project_id: currentProjectId(),
      baseline_id: compareBaseline.value,
      current_id: compareCurrent.value,
    });
    state.comparison = response.comparison;
    renderComparison(state.comparison);
  } catch (error) {
    showMessage(error.message);
  }
});

runAiButton.addEventListener("click", async () => {
  if (!state.scan) {
    return;
  }
  clearMessage();
  runAiButton.disabled = true;
  runAiButton.textContent = "Analizando...";
  try {
    const response = await postJson("/api/analyze", {
      project_id: currentProjectId(),
      scan: state.scan,
      dry_run: document.querySelector("#ai-dry-run").checked,
      save_to_history: document.querySelector("#ai-save-history").checked,
      ai: {
        provider: document.querySelector("#ai-provider").value.trim(),
        model: document.querySelector("#ai-model").value.trim(),
        language: document.querySelector("#ai-language").value.trim(),
        max_input_chars: document.querySelector("#ai-max-input").value,
      },
    });
    state.aiAnalysis = response.analysis;
    if (response.scan) {
      state.scan = response.scan;
      jsonOutput.textContent = JSON.stringify(state.scan, null, 2);
      loadHistory();
    }
    renderAiAnalysis(state.aiAnalysis);
    document.querySelector("#ai-analysis").value = JSON.stringify(state.aiAnalysis, null, 2);
    downloadAiButton.disabled = false;
    activateTab("ai");
  } catch (error) {
    showMessage(error.message);
  } finally {
    runAiButton.disabled = false;
    runAiButton.textContent = "Analizar con IA";
  }
});

downloadJsonButton.addEventListener("click", () => {
  if (state.scan) {
    downloadText("audit-result.json", JSON.stringify(state.scan, null, 2) + "\n", "application/json");
  }
});

downloadAiButton.addEventListener("click", () => {
  if (state.aiAnalysis) {
    downloadText("ai-analysis.json", JSON.stringify(state.aiAnalysis, null, 2) + "\n", "application/json");
  }
});

downloadMdButton.addEventListener("click", () => {
  if (state.markdown) {
    downloadText("audit-report.md", state.markdown, "text/markdown");
  }
});

downloadHtmlButton.addEventListener("click", () => {
  if (state.html) {
    downloadText("audit-report.html", state.html, "text/html");
  }
});

downloadPdfButton.addEventListener("click", () => {
  if (state.pdfBase64) {
    downloadBase64("audit-report.pdf", state.pdfBase64, "application/pdf");
  }
});

function collectPayload() {
  const modules = {};
  document.querySelectorAll("[data-module]").forEach((input) => {
    modules[input.dataset.module] = input.checked;
  });

  return {
    project_id: currentProjectId(),
    target: document.querySelector("#target").value.trim(),
    allowed_hosts: document.querySelector("#allowed-hosts").value.trim(),
    include_paths: document.querySelector("#include-paths").value.trim(),
    exclude_paths: document.querySelector("#exclude-paths").value.trim(),
    allow_subdomains: document.querySelector("#allow-subdomains").checked,
    resolve_dns: document.querySelector("#resolve-dns").checked,
    check_http_counterpart: document.querySelector("#check-http").checked,
    allow_private_networks: document.querySelector("#allow-private").checked,
    save_history: document.querySelector("#save-history").checked,
    history_label: document.querySelector("#history-label").value.trim(),
    timeout_seconds: document.querySelector("#timeout").value,
    max_redirects: document.querySelector("#max-redirects").value,
    modules,
    crawler: {
      max_depth: document.querySelector("#max-depth").value,
      max_pages: document.querySelector("#max-pages").value,
      delay_seconds: document.querySelector("#delay").value,
    },
  };
}

function collectReportMetadata() {
  return {
    client: document.querySelector("#report-client").value.trim(),
    auditor: document.querySelector("#report-auditor").value.trim(),
    engagement: document.querySelector("#report-engagement").value.trim(),
    scope_summary: document.querySelector("#report-scope").value.trim(),
    notes: document.querySelector("#report-notes").value.trim(),
  };
}

function currentAiAnalysisForReport() {
  const manual = parseOptionalJson(document.querySelector("#ai-analysis").value);
  return manual || state.aiAnalysis;
}

async function postJson(url, payload) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  if (!response.ok || !data.ok) {
    throw new Error(data.error || "Operacion fallida.");
  }
  return data;
}

async function getJson(url) {
  const response = await fetch(url, { method: "GET", headers: { "Accept": "application/json" } });
  const data = await response.json();
  if (!response.ok || !data.ok) {
    throw new Error(data.error || "Operacion fallida.");
  }
  return data;
}

function renderScan(scan) {
  const findings = Array.isArray(scan.findings) ? scan.findings : [];
  const modules = Array.isArray(scan.modules) ? scan.modules : [];
  const requests = Array.isArray(scan.requests) ? scan.requests : [];

  statusText.textContent = scan.status || "completed";
  targetPill.textContent = scan.target?.normalized_url || scan.target?.host || "Sin objetivo";
  renderSeverityCounts(findings);
  renderSummary(scan, findings, modules, requests);
  renderFindings(findings);
  renderModules(modules);
  jsonOutput.textContent = JSON.stringify(scan, null, 2);
  loadHistory();
}

async function loadHistory() {
  try {
    const suffix = currentProjectId() ? `?project=${encodeURIComponent(currentProjectId())}` : "";
    const response = await getJson(`/api/history${suffix}`);
    state.history = Array.isArray(response.items) ? response.items : [];
    renderHistory(state.history);
    populateCompareSelectors(state.history);
  } catch (error) {
    showMessage(error.message);
  }
}

async function loadProjects(selectedId = "") {
  try {
    const response = await getJson("/api/projects");
    state.projects = Array.isArray(response.items) ? response.items : [];
    renderProjects(state.projects, selectedId || currentProjectId());
  } catch (error) {
    showMessage(error.message);
  }
}

function renderProjects(projects, selectedId) {
  const options = ['<option value="">Sin proyecto</option>']
    .concat(
      projects.map((project) => {
        const selected = project.id === selectedId ? " selected" : "";
        return `<option value="${escapeHtml(project.id)}"${selected}>${escapeHtml(project.name || project.id)}</option>`;
      })
    )
    .join("");
  projectSelect.innerHTML = options;
  state.projectId = projectSelect.value;
}

function currentProjectId() {
  return projectSelect.value || "";
}

function currentProject() {
  const projectId = currentProjectId();
  return state.projects.find((project) => project.id === projectId) || null;
}

function applyProject(project) {
  if (!project) {
    return;
  }

  projectNameInput.value = project.name || "";
  projectClientInput.value = project.client || "";
  projectAuditorInput.value = project.auditor || "";
  projectEngagementInput.value = project.engagement || "";

  document.querySelector("#report-client").value = project.client || "";
  document.querySelector("#report-auditor").value = project.auditor || "";
  document.querySelector("#report-engagement").value = project.engagement || "";
  document.querySelector("#report-scope").value = project.scope_summary || project.target_url || "";

  const config = project.config || {};
  if (config.target?.url) {
    document.querySelector("#target").value = config.target.url;
  }
  if (config.scope) {
    document.querySelector("#allowed-hosts").value = joinList(config.scope.allowed_hosts);
    document.querySelector("#include-paths").value = joinList(config.scope.include_paths) || "/";
    document.querySelector("#exclude-paths").value = joinList(config.scope.exclude_paths);
    setChecked("#allow-subdomains", config.scope.allow_subdomains);
    setChecked("#resolve-dns", config.scope.resolve_dns);
    setChecked("#allow-private", config.scope.allow_private_networks);
  }
  if (config.http) {
    document.querySelector("#timeout").value = config.http.timeout_seconds ?? 10;
    document.querySelector("#max-redirects").value = config.http.max_redirects ?? 10;
    setChecked("#check-http", config.http.check_http_counterpart);
  }
  if (config.crawler) {
    document.querySelector("#max-depth").value = config.crawler.max_depth ?? 1;
    document.querySelector("#max-pages").value = config.crawler.max_pages ?? 25;
    document.querySelector("#delay").value = config.crawler.delay_seconds ?? 0;
  }
  if (config.modules) {
    document.querySelectorAll("[data-module]").forEach((input) => {
      if (Object.prototype.hasOwnProperty.call(config.modules, input.dataset.module)) {
        input.checked = Boolean(config.modules[input.dataset.module]);
      }
    });
  }
}

function joinList(value) {
  return Array.isArray(value) ? value.join(", ") : "";
}

function setChecked(selector, value) {
  if (typeof value === "boolean") {
    document.querySelector(selector).checked = value;
  }
}

function renderSeverityCounts(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((finding) => {
    const severity = normalizeSeverity(finding.severity);
    counts[severity] = (counts[severity] || 0) + 1;
  });
  severityOrder.forEach((severity) => {
    document.querySelector(`#count-${severity}`).textContent = String(counts[severity] || 0);
  });
}

function renderSummary(scan, findings, modules, requests) {
  summaryEmpty.hidden = true;
  summaryContent.hidden = false;
  summaryContent.innerHTML = "";

  const values = [
    ["Objetivo", scan.target?.normalized_url || "unknown"],
    ["Host", scan.target?.host || "unknown"],
    ["Estado", scan.status || "unknown"],
    ["Modulos", modules.length],
    ["Hallazgos", findings.length],
    ["Peticiones", requests.length],
  ];

  values.forEach(([label, value]) => {
    const item = document.createElement("div");
    item.className = "metric";
    item.innerHTML = `<span>${escapeHtml(label)}</span><strong>${escapeHtml(String(value))}</strong>`;
    summaryContent.appendChild(item);
  });
}

function renderFindings(findings) {
  findingsList.innerHTML = "";
  if (!findings.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "Sin hallazgos.";
    findingsList.appendChild(empty);
    return;
  }

  findings
    .slice()
    .sort((a, b) => severityOrder.indexOf(normalizeSeverity(a.severity)) - severityOrder.indexOf(normalizeSeverity(b.severity)))
    .forEach((finding) => {
      const severity = normalizeSeverity(finding.severity);
      const item = document.createElement("article");
      item.className = "finding-item";
      const evidence = Array.isArray(finding.evidence) ? finding.evidence.slice(0, 4) : [];
      item.innerHTML = `
        <span class="badge ${severity}">${escapeHtml(severity)}</span>
        <h3>${escapeHtml(finding.title || "Untitled finding")}</h3>
        <p><strong>ID:</strong> <code>${escapeHtml(finding.id || "unknown")}</code></p>
        <p><strong>Modulo:</strong> ${escapeHtml(finding.module || "unknown")}</p>
        <p>${escapeHtml(finding.description || "")}</p>
        <p><strong>Recomendacion:</strong> ${escapeHtml(finding.recommendation || "")}</p>
        ${renderEvidence(evidence)}
      `;
      findingsList.appendChild(item);
    });
}

function renderEvidence(evidence) {
  if (!evidence.length) {
    return "";
  }
  const items = evidence
    .map((item) => `<li>${escapeHtml(item.label || "evidence")}: <code>${escapeHtml(String(item.value || ""))}</code></li>`)
    .join("");
  return `<ul>${items}</ul>`;
}

function renderModules(modules) {
  modulesTable.innerHTML = "";
  modules.forEach((module) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td><strong>${escapeHtml(module.name || "unknown")}</strong></td>
      <td>${escapeHtml(module.status || "unknown")}</td>
      <td>${escapeHtml(module.summary || "")}</td>
    `;
    modulesTable.appendChild(row);
  });
}

function renderAiAnalysis(analysisResult) {
  aiOutput.textContent = analysisResult ? JSON.stringify(analysisResult, null, 2) : "{}";
  aiSummary.innerHTML = "";
  if (!analysisResult) {
    aiSummary.innerHTML = '<div class="empty-inline">Sin analisis IA.</div>';
    return;
  }

  const analysis = analysisResult.analysis || {};
  if (analysisResult.status === "dry_run") {
    aiSummary.innerHTML = `
      <div class="metric"><span>Estado</span><strong>dry-run</strong></div>
      <div class="metric"><span>Caracteres prompt</span><strong>${escapeHtml(String(analysis.prompt_chars || 0))}</strong></div>
    `;
    return;
  }

  const priorityFindings = Array.isArray(analysis.priority_findings) ? analysis.priority_findings : [];
  aiSummary.innerHTML = `
    <div class="metric"><span>Riesgo</span><strong>${escapeHtml(analysis.risk_level || "unknown")}</strong></div>
    <div class="metric"><span>Prioridades</span><strong>${escapeHtml(String(priorityFindings.length))}</strong></div>
    <div class="metric wide"><span>Resumen</span><strong>${escapeHtml(analysis.executive_summary || analysis.text || "Sin resumen.")}</strong></div>
    ${renderAiPriorityList(priorityFindings)}
  `;
}

function renderAiPriorityList(items) {
  if (!items.length) {
    return "";
  }
  const cards = items
    .map((item) => {
      const severity = normalizeSeverity(item.severity);
      return `<article class="finding-item"><span class="badge ${severity}">${escapeHtml(severity)}</span><h3>${escapeHtml(item.rank || "?")}. ${escapeHtml(item.title || "Untitled")}</h3><p>${escapeHtml(item.why_it_matters || "")}</p><p><strong>Accion:</strong> ${escapeHtml(item.recommended_action || "")}</p></article>`;
    })
    .join("");
  return `<div class="list wide">${cards}</div>`;
}

function renderHistory(items) {
  historyTable.innerHTML = "";
  historyCount.textContent = `${items.length} auditoria${items.length === 1 ? "" : "s"}`;
  if (!items.length) {
    const row = document.createElement("tr");
    row.innerHTML = '<td colspan="7">Sin auditorias guardadas.</td>';
    historyTable.appendChild(row);
    return;
  }
  items.forEach((item) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td><code>${escapeHtml(item.id)}</code></td>
      <td>${escapeHtml(item.generated_at || "unknown")}</td>
      <td>${escapeHtml(item.host || "unknown")}</td>
      <td>${escapeHtml(String(item.finding_count || 0))}</td>
      <td>${item.has_ai_analysis ? "Si" : "No"}</td>
      <td>${escapeHtml(item.status || "unknown")}</td>
      <td><button class="ghost compact" type="button" data-load-history="${escapeHtml(item.id)}">Abrir</button></td>
    `;
    historyTable.appendChild(row);
  });
}

function populateCompareSelectors(items) {
  const options = items
    .map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.generated_at || "unknown")} | ${escapeHtml(item.host || "unknown")} | ${escapeHtml(item.id)}</option>`)
    .join("");
  compareBaseline.innerHTML = options;
  compareCurrent.innerHTML = options;
  if (items.length > 1) {
    compareBaseline.selectedIndex = 1;
    compareCurrent.selectedIndex = 0;
  }
  runCompareButton.disabled = items.length < 2;
}

function renderComparison(comparison) {
  const summary = comparison.summary || {};
  compareOutput.innerHTML = `
    <div class="compare-grid">
      <div class="metric"><span>Nuevos</span><strong>${escapeHtml(String(summary.new || 0))}</strong></div>
      <div class="metric"><span>Resueltos</span><strong>${escapeHtml(String(summary.resolved || 0))}</strong></div>
      <div class="metric"><span>Persistentes</span><strong>${escapeHtml(String(summary.persistent || 0))}</strong></div>
      <div class="metric"><span>Cambio severidad</span><strong>${escapeHtml(String(summary.severity_changed || 0))}</strong></div>
    </div>
    ${renderCompareFindingGroup("Hallazgos nuevos", comparison.new_findings)}
    ${renderCompareFindingGroup("Hallazgos resueltos", comparison.resolved_findings)}
    ${renderCompareFindingGroup("Hallazgos persistentes", comparison.persistent_findings)}
  `;
}

function renderCompareFindingGroup(title, findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (!list.length) {
    return `<section class="compare-group"><h3>${escapeHtml(title)}</h3><p class="empty-inline">Sin elementos.</p></section>`;
  }
  const items = list
    .slice(0, 20)
    .map((finding) => {
      const severity = normalizeSeverity(finding.severity);
      return `<article class="finding-item"><span class="badge ${severity}">${escapeHtml(severity)}</span><h3>${escapeHtml(finding.title || "Untitled")}</h3><p><code>${escapeHtml(finding.id || "unknown")}</code></p></article>`;
    })
    .join("");
  return `<section class="compare-group"><h3>${escapeHtml(title)}</h3><div class="list">${items}</div></section>`;
}

function activateTab(name) {
  document.querySelectorAll(".tab").forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === name);
  });
  document.querySelectorAll(".view").forEach((view) => {
    view.classList.toggle("active", view.id === `${name}-view`);
  });
}

function parseOptionalJson(value) {
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  const parsed = JSON.parse(trimmed);
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error("El analisis IA debe ser un objeto JSON.");
  }
  return parsed;
}

function setBusy(isBusy) {
  const button = document.querySelector("#run-scan");
  button.disabled = isBusy;
  button.textContent = isBusy ? "Auditando..." : "Ejecutar auditoria";
}

function showMessage(text) {
  message.textContent = text;
  message.hidden = false;
}

function clearMessage() {
  message.textContent = "";
  message.hidden = true;
}

function normalizeSeverity(value) {
  const severity = String(value || "info").toLowerCase();
  if (severity === "informational") {
    return "info";
  }
  return severityOrder.includes(severity) ? severity : "info";
}

function downloadText(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function downloadBase64(filename, base64, type) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  const blob = new Blob([bytes], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
