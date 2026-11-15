"use strict";

const fileInput = document.getElementById("analysis-file");
const fileStatus = document.getElementById("file-status");
const result = document.getElementById("analysis-result");
const scanners = ["gitleaks", "bandit", "pip-audit", "trivy", "zap"];
const severities = ["critical", "high", "unknown", "medium", "low", "info"];
const scanLabels = { clean: "без замечаний", findings: "есть замечания", error: "ошибка или нет отчёта" };
let selection = 0;
let currentAnalysis = null;
let activeRevision = null;
let analysisSource = "Импорт файла";

function text(value, max = 800) {
  if (typeof value !== "string" || value.length > max) throw new Error("schema");
  return value;
}
function list(value, max = 2000) {
  if (!Array.isArray(value) || value.length > max) throw new Error("schema");
  return value;
}
function node(tag, value, className) {
  const element = document.createElement(tag);
  element.textContent = value;
  if (className) element.className = className;
  return element;
}
function validate(data) {
  if (!data || data.schema_version !== 1 || !data.gate || !data.advisory || !data.scans) throw new Error("schema");
  if (!["passed", "blocked"].includes(data.gate.status) || !["reports_only", "pipeline"].includes(data.gate.scope)) throw new Error("schema");
  list(data.gate.failures).forEach((v) => text(v));
  list(data.gate.blocked_finding_ids).forEach((v) => text(v, 100));
  if (!["model", "fallback"].includes(data.advisory.mode)) throw new Error("schema");
  text(data.advisory.message);
  for (const scanner of scanners) {
    const state = data.scans[scanner];
    if (!state || !Object.hasOwn(scanLabels, state.status) || !Number.isInteger(state.count) || state.count < 0 || state.count > 2000) throw new Error("schema");
  }
  const groups = new Map();
  let totalEvidence = 0;
  for (const group of list(data.groups)) {
    const id = text(group.id, 80);
    if (groups.has(id) || !severities.includes(group.severity)) throw new Error("schema");
    [group.title, group.package, group.version, group.ecosystem].forEach((v) => text(v, 500));
    list(group.primary_ids).forEach((v) => text(v, 200));
    list(group.fixed_versions).forEach((v) => text(v, 200));
    list(group.scanners, 5).forEach((v) => { if (!scanners.includes(v)) throw new Error("schema"); });
    list(group.finding_ids).forEach((v) => text(v, 100));
    for (const evidence of list(group.evidence)) {
      if (!scanners.includes(evidence.scanner) || !Number.isInteger(evidence.line) || evidence.line < 0) throw new Error("schema");
      [evidence.file, evidence.target, evidence.primary_id, evidence.package, evidence.version].forEach((v) => text(v, 500));
      totalEvidence += 1;
    }
    groups.set(id, group);
  }
  if (totalEvidence > 2000) throw new Error("schema");
  const used = new Set();
  const recommendations = list(data.advisory.recommendations);
  if (recommendations.length !== groups.size) throw new Error("schema");
  recommendations.sort((a, b) => a.order - b.order).forEach((recommendation, index) => {
    if (!groups.has(recommendation.group_id) || used.has(recommendation.group_id) || recommendation.order !== index + 1) throw new Error("schema");
    text(recommendation.reason); text(recommendation.action);
    used.add(recommendation.group_id);
  });
  return groups;
}

function render(data, groups) {
  currentAnalysis = data;
  document.getElementById("analysis-empty").hidden = true;
  document.getElementById("group-count").textContent = String(groups.size);
  document.getElementById("advisory-source").textContent = (data.advisory.mode === "model" ? "Модельный API" : "Локальные правила (fallback)") + ": " + data.advisory.message;
  const blocked = data.gate.status === "blocked";
  const review = !blocked && groups.size > 0;
  document.getElementById("report-gate").textContent = blocked ? "Выпуск заблокирован" : review ? "Порог пройден — нужна проверка" : "Проверки пройдены";
  document.getElementById("gate-summary").className = "gate-summary " + (review ? "review" : data.gate.status);
  document.getElementById("gate-icon").textContent = blocked || review ? "!" : "✓";
  document.getElementById("gate-scope").textContent = data.gate.scope === "pipeline" ? "Область проверки: pipeline" : "Проверка по отчётам. Фактический выпуск контролирует CI.";
  const scannerNames = { gitleaks: "Gitleaks", bandit: "Bandit", "pip-audit": "pip-audit", trivy: "Trivy", zap: "ZAP" };
  const blockedIds = new Set(data.gate.blocked_finding_ids);
  document.getElementById("scan-states").replaceChildren(...scanners.map((scanner) => {
    const state = data.scans[scanner];
    const item = document.createElement("li");
    item.append(node("span", scannerNames[scanner], "scan-name"));
    const label = state.status === "clean" ? "Чисто" : state.status === "error" ? "Нет данных" : "Найдено: " + state.count;
    const status = node("span", label, "scan-state " + state.status);
    if (Array.from(groups.values()).some((group) => group.scanners.includes(scanner) && group.finding_ids.some((id) => blockedIds.has(id)))) status.classList.add("blocked");
    status.title = scanLabels[state.status] + ": " + state.count;
    item.append(status);
    return item;
  }));
  document.getElementById("failure-list").replaceChildren(...data.gate.failures.map((failure) => node("li", failure)));
  document.getElementById("pipeline-errors").hidden = !data.gate.failures.length;
  const severityNames = { critical: "Критическая", high: "Высокая", unknown: "Не определена", medium: "Средняя", low: "Низкая", info: "Информация" };
  const fragment = document.createDocumentFragment();
  for (const recommendation of data.advisory.recommendations) {
    const group = groups.get(recommendation.group_id);
    const li = document.createElement("li");
    const body = document.createElement("div");
    body.className = "recommendation-body";
    const heading = document.createElement("div");
    heading.className = "finding-heading";
    heading.append(node("h3", group.package ? group.package + " " + group.version : group.title), node("span", severityNames[group.severity], "severity " + group.severity));
    const tags = document.createElement("div");
    tags.className = "finding-tags";
    tags.append(node("span", group.scanners.map((scanner) => scannerNames[scanner]).join(", ")));
    if (group.primary_ids.length) tags.append(node("span", group.primary_ids.join(", ")));
    body.append(heading, tags, node("p", recommendation.reason), node("p", recommendation.action, "action"));
    if (group.fixed_versions.length) body.append(node("p", "Исправленные версии: " + group.fixed_versions.join(", ") + ". Проверьте применимость к каждому источнику.", "meta"));
    const details = document.createElement("details");
    details.className = "evidence";
    details.append(node("summary", "Источники: " + group.evidence.length));
    const sources = document.createElement("ul");
    for (const evidence of group.evidence) {
      sources.append(node("li", evidence.scanner + " / " + evidence.primary_id + "\n" + (evidence.file || evidence.target) + (evidence.line ? ", строка " + evidence.line : "") + (evidence.package ? "\n" + evidence.package + " " + evidence.version : "")));
    }
    details.append(sources); body.append(details); li.append(body); fragment.append(li);
  }
  document.getElementById("recommendations").replaceChildren(fragment);
  document.getElementById("no-findings").hidden = groups.size > 0;
  const metadata = [analysisSource];
  if (Number.isSafeInteger(data.duration_ms) && data.duration_ms >= 0 && data.duration_ms <= 3600000) metadata.push("Обработка: " + new Intl.NumberFormat("ru-RU").format(data.duration_ms) + " мс");
  if (typeof data.runtime_revision === "string" && /^(0|[a-f0-9]{32})$/.test(data.runtime_revision)) metadata.push("Настройки: " + data.runtime_revision.slice(0, 8));
  document.getElementById("analysis-meta").textContent = metadata.join(". ");
  updateRevisionWarning();
  const fetchStates = document.getElementById("fetch-states");
  fetchStates.replaceChildren();
  const fetchLabels = { fetched: "Получен", disabled: "Не подключён", credential_error: "Не задан токен", credential_reflection: "Секрет в ответе: отклонён", timeout: "Истёк таймаут", fetch_error: "Ошибка получения" };
  const connectors = data.tool_fetch && data.tool_fetch.connectors;
  if (connectors && typeof connectors === "object") {
    for (const scanner of scanners) {
      const state = connectors[scanner];
      if (!state || !Object.hasOwn(fetchLabels, state.status)) continue;
      const timing = Number.isSafeInteger(state.elapsed_ms) && state.elapsed_ms >= 0 && state.elapsed_ms <= 3600000 ? " (" + state.elapsed_ms + " мс)" : "";
      fetchStates.append(node("li", scannerNames[scanner] + ": " + fetchLabels[state.status] + timing));
    }
  }
  document.getElementById("fetch-details").hidden = !fetchStates.childElementCount;
  result.hidden = false;
}

function resetAnalysis() {
  currentAnalysis = null;
  result.hidden = true;
  document.getElementById("analysis-empty").hidden = false;
  return ++selection;
}

function updateRevisionWarning() {
  document.getElementById("revision-warning").hidden = !currentAnalysis || !currentAnalysis.runtime_revision || !activeRevision || currentAnalysis.runtime_revision === activeRevision;
}

fileInput.addEventListener("change", async () => {
  const current = ++selection;
  analysisSource = "Импорт файла. Происхождение и свежесть не подтверждены";
  result.hidden = true;
  document.getElementById("analysis-empty").hidden = false;
  const file = fileInput.files[0];
  if (!file) { fileStatus.textContent = "Выберите файл, чтобы увидеть результат."; return; }
  fileStatus.textContent = "Читаем и проверяем файл…";
  try {
    if (!file.size || file.size > 8 * 1024 * 1024) throw new Error("size");
    const data = JSON.parse(await file.text());
    if (current !== selection) return;
    const groups = validate(data);
    render(data, groups);
    fileStatus.textContent = "Файл открыт локально. Рекомендации доступны ниже.";
  } catch {
    if (current !== selection) return;
    result.hidden = true;
    fileStatus.textContent = "Не удалось открыть файл. Выберите analysis.json версии 1 размером до 8 МБ, созданный помощником.";
  }
});

const assistantForm = document.getElementById("assistant-form");
const assistantStatus = document.getElementById("assistant-status");
const demoButtons = document.querySelectorAll("[data-demo]");
const runToolsButton = document.getElementById("run-tools");
let running = false;

async function runAnalysis(url, options, pendingMessage) {
  if (running) return;
  running = true;
  analysisSource = url.includes("/demo/") ? "Учебный синтетический пример" : url.includes("/tools/") ? "Отчёты HTTP API. Свежесть сканов не подтверждена" : "Загруженные отчёты";
  const current = resetAnalysis();
  assistantStatus.textContent = pendingMessage;
  assistantStatus.classList.remove("error");
  document.getElementById("processing-state").hidden = false;
  document.getElementById("output-column").setAttribute("aria-busy", "true");
  if (runToolsButton) runToolsButton.disabled = true;
  fileInput.disabled = true;
  demoButtons.forEach((button) => { button.disabled = true; });
  const submit = document.getElementById("analyze-button");
  if (submit) submit.disabled = true;
  try {
    const response = await fetch(url, { ...options, redirect: "error", credentials: "same-origin" });
    const data = await response.json();
    if (!response.ok) throw new Error(typeof data.error === "string" ? data.error : data.error && typeof data.error.message === "string" ? data.error.message : "Не удалось выполнить анализ.");
    if (current !== selection) return;
    render(data, validate(data));
    if (assistantForm) refreshConnections();
    assistantStatus.textContent = "";
    result.tabIndex = -1;
    result.focus({ preventScroll: true });
    if (window.matchMedia("(max-width: 760px)").matches) result.scrollIntoView({ block: "start" });
  } catch (error) {
    if (current !== selection) return;
    result.hidden = true;
    assistantStatus.classList.add("error");
    assistantStatus.textContent = error instanceof Error && error.message.length < 300
      ? error.message : "Не удалось выполнить анализ. Проверьте файлы и доступность приложения.";
  } finally {
    running = false;
    document.getElementById("processing-state").hidden = true;
    document.getElementById("output-column").setAttribute("aria-busy", "false");
    if (runToolsButton) runToolsButton.disabled = false;
    fileInput.disabled = false;
    demoButtons.forEach((button) => { button.disabled = false; });
    if (submit) submit.disabled = false;
  }
}

demoButtons.forEach((button) => {
  button.addEventListener("click", () => {
    runAnalysis("/api/security/demo/" + button.dataset.demo, {}, "Открываем учебный пример…");
  });
});

async function refreshConnections() {
  if (!assistantForm) return;
  try {
    const response = await fetch("/api/security/config", { headers: { "X-Assistant-Token": assistantForm.dataset.token }, credentials: "same-origin", redirect: "error" });
    const data = await response.json();
    if (!response.ok) throw new Error("config");
    activeRevision = data.revision;
    const count = scanners.filter((scanner) => data.config.connectors[scanner].enabled).length;
    document.getElementById("tools-summary").textContent = count ? "Подключено " + count + " из 5 источников. Получим готовые JSON-отчёты." : "Источники ещё не настроены. Добавьте адреса в настройках стенда.";
    updateRevisionWarning();
  } catch {
    document.getElementById("tools-summary").textContent = "Не удалось прочитать настройки. Откройте панель и проверьте конфигурацию.";
  }
}
if (runToolsButton) {
  runToolsButton.addEventListener("click", () => runAnalysis("/api/security/tools/run", { method: "POST", headers: { "Content-Type": "application/json", "X-Assistant-Token": assistantForm.dataset.token }, body: "{}" }, "Получаем отчёты подключённых инструментов…"));
  refreshConnections();
  window.addEventListener("focus", refreshConnections);
}

if (assistantForm) {
  const reportFiles = document.getElementById("report-files");
  const uploadZone = document.getElementById("upload-zone");
  reportFiles.addEventListener("change", () => {
    if (!running) resetAnalysis();
    reportFiles.removeAttribute("aria-invalid");
    const files = Array.from(reportFiles.files);
    document.getElementById("selected-files").textContent = files.length
      ? files.map((file) => file.name).join(", ") : "Файлы не выбраны";
  });
  uploadZone.addEventListener("dragenter", () => uploadZone.classList.add("drag-over"));
  for (const eventName of ["dragleave", "drop", "dragend"]) {
    uploadZone.addEventListener(eventName, () => uploadZone.classList.remove("drag-over"));
  }
  const useModel = document.getElementById("use-model");
  const settings = document.getElementById("model-settings");
  const keyInput = document.getElementById("api-key");
  useModel.addEventListener("change", () => {
    settings.hidden = !useModel.checked;
    settings.disabled = !useModel.checked;
    if (!useModel.checked) keyInput.value = "";
  });
  assistantForm.addEventListener("invalid", () => {
    if (!running) resetAnalysis();
  }, true);
  assistantForm.addEventListener("submit", (event) => {
    event.preventDefault();
    if (running) return;
    resetAnalysis();
    const files = Array.from(document.getElementById("report-files").files);
    const allowed = scanners.map((scanner) => scanner + ".json");
    if (!files.length || files.length > 5 || new Set(files.map((file) => file.name)).size !== files.length
      || files.some((file) => !allowed.includes(file.name) || !file.size || file.size > 8 * 1024 * 1024)) {
      assistantStatus.textContent = "Выберите до пяти разных непустых JSON-файлов с именами сканеров, до 8 МиБ каждый.";
      reportFiles.setAttribute("aria-invalid", "true");
      document.getElementById("selected-files").textContent = assistantStatus.textContent;
      reportFiles.focus();
      return;
    }
    const body = new FormData(assistantForm);
    keyInput.value = "";
    runAnalysis("/api/security/analyze", {
      method: "POST", body, headers: { "X-Assistant-Token": assistantForm.dataset.token }
    }, useModel.checked ? "Разбираем отчёты и запрашиваем модель…" : "Разбираем отчёты без обращения к модели…");
  });
}

document.getElementById("download-analysis").addEventListener("click", () => {
  if (!currentAnalysis) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(currentAnalysis, null, 2)], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "analysis.json";
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
