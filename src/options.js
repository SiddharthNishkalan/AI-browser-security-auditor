const aiEnabled = document.getElementById("aiEnabled");
const provider = document.getElementById("provider");
const model = document.getElementById("model");
const apiKey = document.getElementById("apiKey");
const saveButton = document.getElementById("saveButton");
const status = document.getElementById("status");

document.addEventListener("DOMContentLoaded", loadSettings);
provider.addEventListener("change", setDefaultModel);
saveButton.addEventListener("click", saveSettings);

async function loadSettings() {
  const response = await chrome.runtime.sendMessage({ type: "GET_SETTINGS" });
  const settings = response.settings || {};
  aiEnabled.checked = Boolean(settings.aiEnabled);
  provider.value = settings.provider || "openai";
  model.value = settings.model || defaultModel(provider.value);
  apiKey.value = settings.apiKey || "";
}

async function saveSettings() {
  const settings = {
    aiEnabled: aiEnabled.checked,
    provider: provider.value,
    model: model.value.trim() || defaultModel(provider.value),
    apiKey: apiKey.value.trim()
  };
  await chrome.runtime.sendMessage({ type: "SAVE_SETTINGS", settings });
  status.textContent = "Saved";
  setTimeout(() => {
    status.textContent = "";
  }, 1800);
}

function setDefaultModel() {
  if (!model.value || model.value === "gpt-4.1-mini" || model.value === "gemini-1.5-flash") {
    model.value = defaultModel(provider.value);
  }
}

function defaultModel(value) {
  return value === "gemini" ? "gemini-1.5-flash" : "gpt-4.1-mini";
}
