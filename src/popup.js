const els = {
  pageTitle: document.getElementById("pageTitle"),
  riskScore: document.getElementById("riskScore"),
  scoreRing: document.getElementById("scoreRing"),
  scorePanel: document.getElementById("scorePanel"),
  severity: document.getElementById("severity"),
  summary: document.getElementById("summary"),
  aiSummary: document.getElementById("aiSummary"),
  phishingCount: document.getElementById("phishingCount"),
  privacyCount: document.getElementById("privacyCount"),
  malwareCount: document.getElementById("malwareCount"),
  dataCount: document.getElementById("dataCount"),
  findingCount: document.getElementById("findingCount"),
  findingsList: document.getElementById("findingsList"),
  recommendationsList: document.getElementById("recommendationsList"),
  historyList: document.getElementById("historyList"),
  rescanButton: document.getElementById("rescanButton"),
  exportButton: document.getElementById("exportButton"),
  clearButton: document.getElementById("clearButton"),
  optionsButton: document.getElementById("optionsButton")
};

let reports = [];
let currentReport = null;

document.addEventListener("DOMContentLoaded", init);
els.rescanButton.addEventListener("click", rescan);
els.exportButton.addEventListener("click", exportReports);
els.clearButton.addEventListener("click", clearReports);
els.optionsButton.addEventListener("click", () => chrome.runtime.openOptionsPage());

async function init() {
  await loadCurrentReport();
  await loadHistory();
}

async function loadCurrentReport() {
  const response = await chrome.runtime.sendMessage({ type: "GET_CURRENT_REPORT" });
  currentReport = response.report;
  if (!currentReport) {
    renderLoading(response.tabUrl);
    setTimeout(loadCurrentReport, 1200);
    return;
  }
  renderReport(currentReport);
}

async function loadHistory() {
  const response = await chrome.runtime.sendMessage({ type: "GET_REPORTS" });
  reports = response.reports || [];
  renderHistory(reports);
}

async function rescan() {
  els.rescanButton.disabled = true;
  els.rescanButton.textContent = "Scanning";
  await chrome.runtime.sendMessage({ type: "RESCAN_CURRENT_TAB" }).catch(() => undefined);
  setTimeout(async () => {
    await loadCurrentReport();
    await loadHistory();
    els.rescanButton.disabled = false;
    els.rescanButton.textContent = "Rescan";
  }, 1200);
}

async function clearReports() {
  await chrome.runtime.sendMessage({ type: "CLEAR_REPORTS" });
  reports = [];
  renderHistory(reports);
}

function exportReports() {
  const payload = JSON.stringify({ exportedAt: new Date().toISOString(), reports }, null, 2);
  const url = URL.createObjectURL(new Blob([payload], { type: "application/json" }));
  chrome.downloads.download({
    url,
    filename: `security-auditor-reports-${new Date().toISOString().slice(0, 10)}.json`,
    saveAs: true
  }, () => setTimeout(() => URL.revokeObjectURL(url), 5000));
}

function renderLoading(tabUrl) {
  els.pageTitle.textContent = titleFromUrl(tabUrl) || "Current page";
  els.riskScore.textContent = "--";
  els.severity.textContent = "Scanning";
  els.summary.textContent = "Scanning this page...";
  els.aiSummary.textContent = "A plain-language summary will appear after the scan completes.";
  setRiskState("waiting", 0);
}

function renderReport(report) {
  const categories = report.categories || {};
  els.pageTitle.textContent = report.title || titleFromUrl(report.url) || "Current page";
  els.riskScore.textContent = report.riskScore;
  els.severity.textContent = report.severity;
  els.summary.textContent = report.summary;
  els.aiSummary.textContent = report.aiSummary || report.summary;
  els.phishingCount.textContent = categories.phishing || 0;
  els.privacyCount.textContent = categories.privacy || 0;
  els.malwareCount.textContent = categories.malware || 0;
  els.dataCount.textContent = categories.dataLeakage || 0;
  els.findingCount.textContent = report.findings?.length || 0;
  setRiskState(report.severity, report.riskScore);
  renderFindings(report.findings || []);
  renderRecommendations(report.recommendations || []);
}

function setRiskState(severity, score) {
  const state = (severity || "waiting").toLowerCase();
  els.scorePanel.className = `score-panel risk-${state}`;
  const color = state === "critical" ? "#8f2240" : state === "high" ? "#c2413a" : state === "medium" ? "#b7791f" : state === "low" ? "#16845b" : "#d9dee7";
  els.scoreRing.style.borderColor = color;
  els.scoreRing.style.background = `conic-gradient(${color} ${score || 0}%, #edf1f5 0)`;
  els.severity.style.background = color;
}

function renderFindings(findings) {
  if (!findings.length) {
    els.findingsList.className = "list empty";
    els.findingsList.textContent = "No notable findings.";
    return;
  }
  els.findingsList.className = "list";
  els.findingsList.replaceChildren(...findings.map((item) => {
    const node = document.createElement("article");
    node.className = `finding risk-${item.severity}`;
    node.innerHTML = `
      <div class="finding-top">
        <strong class="finding-title"></strong>
        <span class="finding-severity"></span>
      </div>
      <p></p>
    `;
    node.querySelector(".finding-title").textContent = item.title;
    node.querySelector(".finding-severity").textContent = item.severity;
    node.querySelector("p").textContent = item.description;
    return node;
  }));
}

function renderRecommendations(recommendations) {
  if (!recommendations.length) {
    els.recommendationsList.className = "list empty";
    els.recommendationsList.textContent = "No recommendations.";
    return;
  }
  els.recommendationsList.className = "list";
  els.recommendationsList.replaceChildren(...recommendations.map((text) => {
    const node = document.createElement("div");
    node.className = "recommendation";
    node.textContent = text;
    return node;
  }));
}

function renderHistory(items) {
  if (!items.length) {
    els.historyList.className = "history-list empty";
    els.historyList.textContent = "No saved reports.";
    return;
  }
  els.historyList.className = "history-list";
  els.historyList.replaceChildren(...items.slice(0, 8).map((item) => {
    const node = document.createElement("article");
    node.className = "history-item";
    node.innerHTML = `
      <div class="history-top">
        <strong class="history-title"></strong>
        <span class="finding-severity"></span>
      </div>
      <p class="history-url"></p>
    `;
    node.querySelector(".history-title").textContent = `${item.riskScore}/100 · ${item.title || titleFromUrl(item.url)}`;
    node.querySelector(".finding-severity").textContent = item.severity;
    node.querySelector(".history-url").textContent = new URL(item.url).hostname;
    node.addEventListener("click", () => renderReport(item));
    return node;
  }));
}

function titleFromUrl(value) {
  try {
    return new URL(value).hostname;
  } catch {
    return "";
  }
}
