"use strict";

const form = document.getElementById("config-form");
const fields = document.getElementById("config-fields");
const saveButton = document.getElementById("save-config");
const reloadButton = document.getElementById("reload-config");
const status = document.getElementById("admin-status");
const scannerNames = ["gitleaks", "bandit", "pip-audit", "trivy", "zap"];
let snapshot = null;
let dirty = false;
let busy = false;

function announce(message, state) {
  status.textContent = message;
  status.className = "admin-status " + state;
}
function updateConnections() {
  let count = 0;
  for (const scanner of scannerNames) {
    const enabled = document.getElementById("enabled-" + scanner).checked;
    if (enabled) count++;
    document.getElementById("url-" + scanner).disabled = !enabled;
    document.getElementById("credential-" + scanner).disabled = !enabled;
    document.getElementById("credential-help-" + scanner).hidden = !enabled || !document.getElementById("credential-" + scanner).value;
    document.querySelector('[data-scanner="' + scanner + '"]').classList.toggle("connected", enabled);
  }
  document.getElementById("connector-count").textContent = count + " из 5 подключены";
}
function fill(data) {
  snapshot = data;
  for (const scanner of scannerNames) {
    const connector = data.config.connectors[scanner];
    document.getElementById("enabled-" + scanner).checked = connector.enabled;
    document.getElementById("url-" + scanner).value = connector.url;
    document.getElementById("credential-" + scanner).value = connector.credential_env || "";
    document.getElementById("threshold-" + scanner).value = data.config.thresholds[scanner];
  }
  for (const [id, key] of [["connect-seconds", "connect_seconds"], ["read-seconds", "read_seconds"], ["total-seconds", "total_seconds"], ["workers", "workers"]]) {
    document.getElementById(id).value = data.config.timeouts[key];
  }
  dirty = false;
  document.getElementById("save-state").textContent = "Сохранённая конфигурация";
  document.getElementById("config-revision").textContent = "Версия: " + data.revision;
  const mcp = document.getElementById("mcp-state");
  mcp.textContent = data.mcp.enabled ? "Включён" : "Требуется токен сервера";
  mcp.className = "status-badge " + (data.mcp.enabled ? "success" : "review");
  document.getElementById("mcp-example").textContent = JSON.stringify({ type: "http", url: window.location.origin + "/mcp", headers: { Authorization: "Bearer <ваш MCP-токен>" } }, null, 2);
  updateConnections();
}
function collect() {
  const config = { schema_version: 1, thresholds: {}, connectors: {}, timeouts: {} };
  for (const scanner of scannerNames) {
    config.thresholds[scanner] = document.getElementById("threshold-" + scanner).value;
    config.connectors[scanner] = {
      enabled: document.getElementById("enabled-" + scanner).checked,
      url: document.getElementById("url-" + scanner).value.trim(),
      credential_env: document.getElementById("credential-" + scanner).value || null
    };
  }
  for (const [id, key] of [["connect-seconds", "connect_seconds"], ["read-seconds", "read_seconds"], ["total-seconds", "total_seconds"], ["workers", "workers"]]) {
    config.timeouts[key] = Number(document.getElementById(id).value);
  }
  return config;
}
async function requestConfig(options = {}) {
  const response = await fetch("/api/security/config", {
    ...options, redirect: "error", credentials: "same-origin",
    headers: { "X-Assistant-Token": form.dataset.token, ...options.headers }
  });
  const data = await response.json();
  if (!response.ok) {
    const message = data.error && typeof data.error.message === "string" ? data.error.message : "Не удалось прочитать настройки. Повторите загрузку.";
    throw new Error(message);
  }
  return data;
}
function setBusy(value) {
  busy = value;
  fields.disabled = value || !snapshot;
  saveButton.disabled = value || !snapshot;
  reloadButton.disabled = value;
  form.setAttribute("aria-busy", String(value));
}
async function load() {
  if (busy) return;
  if (dirty && !window.confirm("Перезагрузить настройки? Несохранённые изменения будут потеряны.")) return;
  setBusy(true);
  announce("Загружаем настройки…", "pending");
  try {
    fill(await requestConfig());
    announce("Настройки загружены. Изменения применяются только после сохранения.", "");
  } catch (error) {
    announce(error instanceof Error ? error.message : "Не удалось загрузить настройки.", "error");
  } finally { setBusy(false); }
}
form.addEventListener("input", () => {
  dirty = true;
  document.getElementById("save-state").textContent = "Есть несохранённые изменения";
  updateConnections();
});
form.addEventListener("change", updateConnections);
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy || !snapshot) return;
  const config = collect();
  setBusy(true);
  announce("Сохраняем настройки…", "pending");
  try {
    const data = await requestConfig({ method: "PUT", body: JSON.stringify(config), headers: { "Content-Type": "application/json", "If-Match": snapshot.revision } });
    fill(data);
    announce("Настройки сохранены. Новые разборы используют эту версию.", "success");
  } catch (error) {
    announce(error instanceof Error ? error.message : "Не удалось сохранить настройки.", "error");
  } finally { setBusy(false); }
});
reloadButton.addEventListener("click", load);
window.addEventListener("beforeunload", (event) => { if (dirty) { event.preventDefault(); event.returnValue = ""; } });
load();
