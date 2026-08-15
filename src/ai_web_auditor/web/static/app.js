const state = {
  scan: null,
  report: "",
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
const generateReportButton = document.querySelector("#generate-report");
const downloadJsonButton = document.querySelector("#download-json");
const downloadMdButton = document.querySelector("#download-md");
const printReportButton = document.querySelector("#print-report");

document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => activateTab(button.dataset.tab));
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearMessage();
  setBusy(true);
  try {
    const response = await postJson("/api/scan", collectPayload());
    state.scan = response.result;
    state.report = "";
    renderScan(state.scan);
    reportOutput.value = "";
    generateReportButton.disabled = false;
    downloadJsonButton.disabled = false;
    downloadMdButton.disabled = true;
    printReportButton.disabled = true;
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
    const aiAnalysis = parseOptionalJson(document.querySelector("#ai-analysis").value);
    const title = document.querySelector("#report-title").value.trim();
    const response = await postJson("/api/report", {
      scan: state.scan,
      ai_analysis: aiAnalysis,
      title,
    });
    state.report = response.markdown;
    reportOutput.value = state.report;
    downloadMdButton.disabled = false;
    printReportButton.disabled = false;
    activateTab("report");
  } catch (error) {
    showMessage(error.message);
  } finally {
    generateReportButton.disabled = false;
  }
});

downloadJsonButton.addEventListener("click", () => {
  if (state.scan) {
    downloadText("audit-result.json", JSON.stringify(state.scan, null, 2) + "\n", "application/json");
  }
});

downloadMdButton.addEventListener("click", () => {
  if (state.report) {
    downloadText("audit-report.md", state.report, "text/markdown");
  }
});

printReportButton.addEventListener("click", () => {
  if (!state.report) {
    return;
  }
  const win = window.open("", "_blank");
  if (!win) {
    showMessage("No se pudo abrir la ventana de impresion.");
    return;
  }
  win.document.write(`<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>AI Web Auditor Report</title>
<style>
body { font-family: Arial, sans-serif; color: #17202a; margin: 32px; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; font-size: 12px; line-height: 1.45; }
</style>
</head>
<body><pre>${escapeHtml(state.report)}</pre></body>
</html>`);
  win.document.close();
  win.focus();
  win.print();
});

function collectPayload() {
  const modules = {};
  document.querySelectorAll("[data-module]").forEach((input) => {
    modules[input.dataset.module] = input.checked;
  });

  return {
    target: document.querySelector("#target").value.trim(),
    allowed_hosts: document.querySelector("#allowed-hosts").value.trim(),
    include_paths: document.querySelector("#include-paths").value.trim(),
    exclude_paths: document.querySelector("#exclude-paths").value.trim(),
    allow_subdomains: document.querySelector("#allow-subdomains").checked,
    resolve_dns: document.querySelector("#resolve-dns").checked,
    check_http_counterpart: document.querySelector("#check-http").checked,
    allow_private_networks: document.querySelector("#allow-private").checked,
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

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
