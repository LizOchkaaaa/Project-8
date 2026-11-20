"use strict";

const adminDesk = document.getElementById("admin-workspace");
const section = adminDesk.dataset.section;
const legacySections = { "#connections": "connections", "#policy": "policy", "#environment": "environment", "#mcp-settings": "mcp" };
if (section === "model" && Object.hasOwn(legacySections, location.hash)) location.replace("/admin/" + legacySections[location.hash]);
const timeoutFields = [["connect-seconds", "connect_seconds"], ["read-seconds", "read_seconds"], ["total-seconds", "total_seconds"], ["workers", "workers"]];
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
  if (section !== "connections") return;
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
  if (section === "connections") {
    for (const scanner of scannerNames) {
      const connector = data.config.connectors[scanner];
      document.getElementById("enabled-" + scanner).checked = connector.enabled;
      document.getElementById("url-" + scanner).value = connector.url;
      document.getElementById("credential-" + scanner).value = connector.credential_env || "";
    }
    updateConnections();
  } else if (section === "policy") {
    for (const scanner of scannerNames) document.getElementById("threshold-" + scanner).value = data.config.thresholds[scanner];
  } else if (section === "environment") {
    for (const [id, key] of timeoutFields) document.getElementById(id).value = data.config.timeouts[key];
  }
  dirty = false;
  document.getElementById("save-state").textContent = "Сохранённая конфигурация";
  document.getElementById("config-revision").textContent = "Версия: " + data.revision;
}
function fillMcp(data) {
  const mcp = document.getElementById("mcp-state");
  mcp.textContent = data.mcp.enabled ? "Включён" : "Требуется токен сервера";
  mcp.className = "status-badge " + (data.mcp.enabled ? "success" : "review");
  document.getElementById("mcp-example").textContent = JSON.stringify({ type: "http", url: window.location.origin + "/mcp", headers: { Authorization: "Bearer <ваш MCP-токен>" } }, null, 2);
}
function collect() {
  const config = structuredClone(snapshot.config);
  if (section === "connections") {
    for (const scanner of scannerNames) {
      config.connectors[scanner] = {
        enabled: document.getElementById("enabled-" + scanner).checked,
        url: document.getElementById("url-" + scanner).value.trim(),
        credential_env: document.getElementById("credential-" + scanner).value || null
      };
    }
  } else if (section === "policy") {
    for (const scanner of scannerNames) config.thresholds[scanner] = document.getElementById("threshold-" + scanner).value;
  } else if (section === "environment") {
    for (const [id, key] of timeoutFields) config.timeouts[key] = Number(document.getElementById(id).value);
  }
  return config;
}
async function requestAdmin(path, options = {}) {
  const response = await fetch(path, {
    ...options, redirect: "error", credentials: "same-origin",
    headers: { "X-Assistant-Token": adminDesk.dataset.token, ...options.headers }
  });
  const data = await response.json();
  if (!response.ok) {
    const message = data.error && typeof data.error.message === "string" ? data.error.message : "Не удалось прочитать настройки. Повторите загрузку.";
    throw new Error(message);
  }
  return data;
}
function requestConfig(options) {
  return requestAdmin("/api/security/config", options);
}
function setBusy(value) {
  busy = value;
  fields.disabled = value || !snapshot;
  saveButton.disabled = value || !snapshot || !dirty;
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
    announce("", "");
  } catch (error) {
    announce(error instanceof Error ? error.message : "Не удалось загрузить настройки.", "error");
  } finally { setBusy(false); }
}
function initConfig() {
  form.addEventListener("input", () => {
    dirty = true;
    saveButton.disabled = false;
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
  load();
}

function initProfile() {
  const profileForm = document.getElementById("model-profile-form");
  const profileFields = document.getElementById("model-profile-fields");
  const profileEndpoint = document.getElementById("model-profile-endpoint");
  const profileName = document.getElementById("model-profile-name");
  const profileTimeout = document.getElementById("model-profile-timeout");
  const profileKey = document.getElementById("model-profile-key");
  const clearProfileKey = document.getElementById("model-profile-clear-key");
  const deleteProfile = document.getElementById("model-profile-delete");
  const profileStatus = document.getElementById("model-profile-status");
  let profileLoaded = false;

  function fillProfile(profile) {
    dirty = false;
    profileEndpoint.value = profile.endpoint || "";
    profileName.value = profile.model || "";
    profileTimeout.value = profile.timeout;
    profileKey.value = "";
    profileKey.disabled = false;
    clearProfileKey.checked = false;
    clearProfileKey.disabled = !profile.has_api_key;
    deleteProfile.disabled = !profile.endpoint;
    const keyState = document.getElementById("model-key-state");
    keyState.textContent = profile.has_api_key ? "Ключ в памяти" : "Ключ не задан";
    keyState.className = "status-badge " + (profile.has_api_key ? "success" : "review");
  }

  async function updateProfile(options, pendingMessage, successMessage) {
    profileFields.disabled = true;
    profileForm.setAttribute("aria-busy", "true");
    profileStatus.textContent = pendingMessage;
    profileStatus.className = "admin-status pending";
    try {
      fillProfile(await requestAdmin("/api/security/model-profile", options));
      profileLoaded = true;
      profileStatus.textContent = successMessage;
      profileStatus.className = "admin-status success";
    } catch (error) {
      profileStatus.textContent = error instanceof Error ? error.message : "Не удалось обновить профиль.";
      profileStatus.className = "admin-status error";
      if (!profileLoaded) document.getElementById("model-key-state").textContent = "Состояние ключа неизвестно";
    } finally {
      profileFields.disabled = !profileLoaded;
      profileForm.setAttribute("aria-busy", "false");
    }
  }

  profileForm.addEventListener("input", () => { dirty = true; });
  clearProfileKey.addEventListener("change", () => {
    if (clearProfileKey.checked) profileKey.value = "";
    profileKey.disabled = clearProfileKey.checked;
  });
  profileForm.addEventListener("submit", (event) => {
    event.preventDefault();
    if (profileFields.disabled) return;
    const data = {
      endpoint: profileEndpoint.value.trim(),
      model: profileName.value.trim(),
      timeout: profileTimeout.valueAsNumber
    };
    if (clearProfileKey.checked) data.api_key = "";
    else if (profileKey.value) data.api_key = profileKey.value;
    profileKey.value = "";
    updateProfile({ method: "PUT", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, "Сохраняем профиль…", "Профиль сохранён. Проверьте состояние ключа перед разбором.");
  });
  deleteProfile.addEventListener("click", () => {
    if (!window.confirm("Удалить адрес, модель, тайм-аут и ключ из сохранённого профиля?")) return;
    profileKey.value = "";
    updateProfile({ method: "DELETE" }, "Удаляем профиль…", "Профиль и ключ удалены.");
  });
  updateProfile(undefined, "Загружаем профиль…", "Настройки профиля загружены.");
}

window.addEventListener("beforeunload", (event) => { if (dirty) { event.preventDefault(); event.returnValue = ""; } });
if (section === "model") initProfile();
else if (section === "mcp") requestConfig().then(data => {
  fillMcp(data);
  announce("", "");
}).catch(error => {
  document.getElementById("mcp-state").textContent = "Нет данных";
  announce(error.message, "error");
});
else initConfig();
