import { analyzeScan, buildLocalAssistantSummary } from "./securityEngine.js";

const MAX_REPORTS = 100;
const latestReportsByTab = new Map();
const runtimeEventsByTab = new Map();

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create("security-scan", { periodInMinutes: 30 });
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== "security-scan") return;
  const tabs = await chrome.tabs.query({ url: ["http://*/*", "https://*/*"] });
  for (const tab of tabs) {
    if (tab.id) {
      chrome.tabs.sendMessage(tab.id, { type: "SCAN_NOW" }).catch(() => undefined);
    }
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  latestReportsByTab.delete(tabId);
  runtimeEventsByTab.delete(tabId);
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.url) {
    latestReportsByTab.delete(tabId);
    runtimeEventsByTab.delete(tabId);
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse).catch((error) => {
    sendResponse({ ok: false, error: error.message || "Unexpected error" });
  });
  return true;
});

async function handleMessage(message, sender) {
  if (message?.type === "PAGE_SCAN") {
    const tabId = sender.tab?.id;
    const events = tabId ? runtimeEventsByTab.get(tabId) || [] : [];
    const report = analyzeScan(message.scan, events);
    report.aiSummary = await enrichWithAiIfEnabled(report);

    if (tabId) latestReportsByTab.set(tabId, report);
    await storeReport(report);
    return { ok: true, report };
  }

  if (message?.type === "SECURITY_EVENT") {
    const tabId = sender.tab?.id;
    if (!tabId) return { ok: true };
    const events = runtimeEventsByTab.get(tabId) || [];
    events.push({ ...message.event, timestamp: Date.now() });
    runtimeEventsByTab.set(tabId, events.slice(-30));
    chrome.tabs.sendMessage(tabId, { type: "SCAN_NOW" }).catch(() => undefined);
    return { ok: true };
  }

  if (message?.type === "GET_CURRENT_REPORT") {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return { ok: true, report: null };
    if (!isSupportedUrl(tab.url)) return { ok: true, report: null, tabUrl: tab.url, supported: false };
    const cached = latestReportsByTab.get(tab.id);
    const report = cached?.url === tab.url ? cached : await findReportForUrl(tab.url);
    if (!report) chrome.tabs.sendMessage(tab.id, { type: "SCAN_NOW" }).catch(() => undefined);
    return { ok: true, report: report || null, tabUrl: tab.url, supported: true };
  }

  if (message?.type === "RESCAN_CURRENT_TAB") {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id || !isSupportedUrl(tab.url)) return { ok: false, error: "This page cannot be scanned." };
    await chrome.tabs.sendMessage(tab.id, { type: "SCAN_NOW" });
    return { ok: true };
  }

  if (message?.type === "GET_REPORTS") {
    const { reports = [] } = await chrome.storage.local.get("reports");
    return { ok: true, reports };
  }

  if (message?.type === "CLEAR_REPORTS") {
    await chrome.storage.local.set({ reports: [] });
    return { ok: true };
  }

  if (message?.type === "GET_SETTINGS") {
    const { settings = defaultSettings() } = await chrome.storage.local.get("settings");
    return { ok: true, settings: { ...defaultSettings(), ...settings, apiKey: settings.apiKey || "" } };
  }

  if (message?.type === "SAVE_SETTINGS") {
    await chrome.storage.local.set({ settings: { ...defaultSettings(), ...message.settings } });
    return { ok: true };
  }

  return { ok: false, error: "Unknown message type" };
}

async function storeReport(report) {
  const { reports = [] } = await chrome.storage.local.get("reports");
  const next = [report, ...reports.filter((item) => item.url !== report.url || Date.now() - item.timestamp > 60_000)].slice(0, MAX_REPORTS);
  await chrome.storage.local.set({ reports: next });
}

async function findReportForUrl(url) {
  const { reports = [] } = await chrome.storage.local.get("reports");
  return reports.find((item) => item.url === url) || null;
}

async function enrichWithAiIfEnabled(report) {
  const { settings = defaultSettings() } = await chrome.storage.local.get("settings");
  const config = { ...defaultSettings(), ...settings };
  if (!config.aiEnabled || !config.apiKey) return buildLocalAssistantSummary(report);

  const prompt = buildAiPrompt(report);
  try {
    if (config.provider === "gemini") {
      return await callGemini(config, prompt);
    }
    return await callOpenAi(config, prompt);
  } catch {
    return buildLocalAssistantSummary(report);
  }
}

async function callOpenAi(config, prompt) {
  const response = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${config.apiKey}`
    },
    body: JSON.stringify({
      model: config.model || "gpt-4.1-mini",
      input: prompt,
      max_output_tokens: 160
    })
  });
  if (!response.ok) throw new Error("AI request failed");
  const data = await response.json();
  return data.output_text || data.output?.flatMap((item) => item.content || []).map((part) => part.text).filter(Boolean).join(" ") || "";
}

async function callGemini(config, prompt) {
  const model = config.model || "gemini-1.5-flash";
  const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(config.apiKey)}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
  });
  if (!response.ok) throw new Error("AI request failed");
  const data = await response.json();
  return data.candidates?.[0]?.content?.parts?.map((part) => part.text).join(" ") || "";
}

function buildAiPrompt(report) {
  const findings = report.findings.slice(0, 8).map((item) => `- ${item.title}: ${item.description}`).join("\n");
  return `Explain this browser security scan in plain language. Keep it under 90 words, avoid panic, and include one practical action.\n\nURL: ${report.url}\nRisk score: ${report.riskScore}/100\nSeverity: ${report.severity}\nFindings:\n${findings || "- No notable findings"}`;
}

function defaultSettings() {
  return {
    aiEnabled: false,
    provider: "openai",
    model: "gpt-4.1-mini",
    apiKey: ""
  };
}

function isSupportedUrl(url = "") {
  return url.startsWith("http://") || url.startsWith("https://");
}
