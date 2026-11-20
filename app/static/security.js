"use strict";

const fileInput = document.getElementById("analysis-file");
const result = document.getElementById("analysis-result");
const scanners = ["gitleaks", "bandit", "pip-audit", "trivy", "zap"];
const scannerNames = { gitleaks: "Gitleaks", bandit: "Bandit", "pip-audit": "pip-audit", trivy: "Trivy", zap: "OWASP ZAP" };
const reportNames = new Set(scanners.map((scanner) => scanner + ".json"));
const reportAliases = new Map([["sast.json", "bandit.json"], ["sca.json", "pip-audit.json"], ["report.json", "zap.json"]]);
const severities = ["critical", "high", "unknown", "medium", "low", "info"];
const scanLabels = { clean: "без замечаний", findings: "есть замечания", error: "ошибка или нет отчёта" };
const severityNames = { critical: "Критическая", high: "Высокая", unknown: "Не определена", medium: "Средняя", low: "Низкая", info: "Информация" };
const tabs = Array.from(document.querySelectorAll('[role="tab"]'));
const resultColumns = document.querySelectorAll("[data-result-column]");
const recommendationsList = document.getElementById("recommendations");
const nextFinding = document.getElementById("next-finding");
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

function showView(view, focus = false) {
  for (const tab of tabs) {
    const panel = tab.getAttribute("aria-controls");
    const active = panel === view;
    tab.setAttribute("aria-selected", String(active));
    tab.tabIndex = active ? 0 : -1;
    document.getElementById(panel).hidden = !active;
    if (active && focus) tab.focus();
  }
}

tabs.forEach((tab, index) => {
  tab.addEventListener("click", () => showView(tab.getAttribute("aria-controls")));
  tab.addEventListener("keydown", (event) => {
    const destinations = { Home: 0, End: tabs.length - 1, ArrowLeft: (index + tabs.length - 1) % tabs.length, ArrowRight: (index + 1) % tabs.length };
    if (!Object.hasOwn(destinations, event.key)) return;
    event.preventDefault();
    showView(tabs[destinations[event.key]].getAttribute("aria-controls"), true);
  });
});
document.getElementById("workspace-actions").addEventListener("keydown", (event) => {
  const menu = event.target.closest("details[open]");
  if (event.key !== "Escape" || !menu) return;
  menu.open = false;
  menu.firstElementChild.focus();
});
nextFinding.addEventListener("click", () => {
  const finding = recommendationsList.children[Number(nextFinding.dataset.order) - 1].firstElementChild;
  showView("findings");
  finding.open = true;
  finding.firstElementChild.focus();
});

function evidenceLocation(evidence) {
  return (evidence.file || evidence.target || "Место не указано") + (evidence.line ? ":" + evidence.line : "");
}

function reportName(file) {
  return reportAliases.get(file.name) || file.name;
}

function findingContext(group, blockedIds) {
  const first = group.evidence.find((evidence) => blockedIds.has(evidence.id)) || group.evidence[0];
  const source = first ? scannerNames[first.scanner] : group.scanners.map((scanner) => scannerNames[scanner]).join(", ");
  const rule = first?.primary_id || group.primary_ids.join(", ") || "Правило не указано";
  return [source, rule, first ? evidenceLocation(first) : "Место не указано"].filter(Boolean).join(" / ");
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
  tabs[0].parentElement.hidden = false;
  document.getElementById("intake-caption").hidden = true;
  document.getElementById("audit-title").textContent = "Результат проверки";
  document.getElementById("analysis-overview").hidden = false;
  const groupCount = document.getElementById("group-count");
  groupCount.textContent = String(groups.size);
  groupCount.hidden = false;
  document.getElementById("advisory-source").textContent = (data.advisory.mode === "model" ? "Рекомендации модели" : "Локальные рекомендации") + ": " + data.advisory.message;
  const blocked = data.gate.status === "blocked";
  const pipeline = data.gate.scope === "pipeline";
  const review = !blocked && groups.size > 0;
  document.getElementById("report-gate").textContent = blocked
    ? (pipeline ? "Допуск CI заблокирован" : "По отчётам допуск не пройден")
    : (pipeline ? "Допуск CI пройден" : "Отчёты прошли пороги");
  document.getElementById("gate-summary").className = "gate-summary " + (review ? "review" : data.gate.status);
  document.getElementById("gate-icon").textContent = blocked || review ? "!" : "✓";
  const validReports = scanners.filter((name) => ["clean", "findings"].includes(data.scans[name].status)).length;
  document.getElementById("gate-scope").textContent = pipeline
    ? "По данным импортированного файла. Развёртывание проверяется отдельно."
    : "Разбор файлов не подтверждает развёртывание в CI.";
  document.getElementById("result-origin").textContent = analysisSource;
  document.getElementById("report-total").textContent = validReports + "/" + scanners.length;
  document.getElementById("group-total").textContent = String(groups.size);
  const blockedIds = new Set(data.gate.blocked_finding_ids);
  const blockedGroups = new Set(Array.from(groups.values()).filter((group) => group.finding_ids.some((id) => blockedIds.has(id))));
  document.getElementById("blocked-total").textContent = String(blockedGroups.size);
  const blockedScanners = new Set();
  for (const group of blockedGroups) {
    for (const evidence of group.evidence) {
      if (blockedIds.has(evidence.id)) blockedScanners.add(evidence.scanner);
    }
  }
  for (const scanner of scanners) {
    const state = data.scans[scanner];
    const status = document.querySelector(`[data-scanner="${scanner}"] .scan-state`);
    const scannerBlocked = blockedScanners.has(scanner);
    status.className = "scan-state " + state.status + (scannerBlocked ? " blocked" : "");
    status.textContent = state.status === "clean" ? "Без замечаний" : state.status === "error" ? "Нет корректного отчёта" : "Найдено: " + state.count + (scannerBlocked ? " · Блокирует" : "");
  }
  resultColumns.forEach((cell) => { cell.hidden = false; });
  document.getElementById("failure-list").replaceChildren(...data.gate.failures.map((failure) => node("li", failure)));
  document.getElementById("pipeline-errors").hidden = !data.gate.failures.length;
  const first = blocked ? data.advisory.recommendations.find((item) => blockedGroups.has(groups.get(item.group_id))) : data.advisory.recommendations[0];
  const context = document.getElementById("next-evidence");
  context.hidden = !first;
  nextFinding.hidden = !first;
  if (first) {
    const group = groups.get(first.group_id);
    context.textContent = "№ " + first.order + " · " + severityNames[group.severity] + " — " + findingContext(group, blockedIds);
    nextFinding.dataset.order = first.order;
  }
  document.getElementById("next-action").textContent = first ? first.action : blocked
    ? "Устраните причины отказа и повторите проверку."
    : pipeline ? "Проверьте этап Deploy в том же запуске GitHub Actions."
      : "Проверьте итоговый барьер выпуска в GitHub Actions.";
  const fragment = document.createDocumentFragment();
  for (const recommendation of data.advisory.recommendations) {
    const group = groups.get(recommendation.group_id);
    const li = document.createElement("li");
    const details = document.createElement("details");
    const summary = document.createElement("summary");
    const heading = node("span", "", "finding-heading");
    heading.append(node("strong", group.package ? group.package + " " + group.version : group.title), node("span", findingContext(group, blockedIds), "finding-context"));
    const severity = node("span", severityNames[group.severity] + (blockedGroups.has(group) ? " · Блокирует" : ""), "severity " + group.severity);
    summary.append(node("span", "№ " + recommendation.order, "finding-order"), heading, severity);
    const body = node("div", "", "recommendation-body");
    body.append(node("h3", data.advisory.mode === "model" ? "Рекомендация модели" : "Рекомендация по локальным правилам"), node("p", recommendation.reason), node("p", recommendation.action, "action"));
    if (group.fixed_versions.length) body.append(node("p", "Исправленные версии: " + group.fixed_versions.join(", ") + ". Проверьте применимость к каждому источнику.", "meta"));
    if (group.evidence.length) {
      body.append(node("h3", "Источники замечания"));
      const sources = node("ul", "", "evidence");
      for (const evidence of group.evidence) {
        sources.append(node("li", scannerNames[evidence.scanner] + " / " + (evidence.primary_id || "Правило не указано") + " / " + evidenceLocation(evidence) + (evidence.package ? " / " + evidence.package + " " + evidence.version : "")));
      }
      body.append(sources);
    }
    details.append(summary, body);
    li.append(details);
    fragment.append(li);
  }
  recommendationsList.replaceChildren(fragment);
  document.getElementById("no-findings").hidden = groups.size > 0;
  document.getElementById("no-findings").textContent = "В этом разборе нет замечаний. Проверьте результат допуска и наличие всех отчётов во вкладке «Источники».";
  const metadata = [];
  if (Number.isSafeInteger(data.duration_ms) && data.duration_ms >= 0 && data.duration_ms <= 3600000) metadata.push("Обработка: " + new Intl.NumberFormat("ru-RU").format(data.duration_ms) + " мс");
  if (typeof data.runtime_revision === "string" && /^(0|[a-f0-9]{32})$/.test(data.runtime_revision)) metadata.push("Настройки: " + data.runtime_revision.slice(0, 8));
  const meta = document.getElementById("analysis-meta");
  meta.textContent = metadata.join(" · ");
  meta.hidden = !metadata.length;
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
  showView("overview");
}

function resetAnalysis() {
  reportRequest?.abort();
  reportRequest = null;
  retryReport.hidden = true;
  processing.hidden = true;
  historyWarning.hidden = true;
  currentAnalysis = null;
  result.hidden = true;
  result.classList.remove("result-ready");
  tabs[0].parentElement.hidden = true;
  document.getElementById("intake-caption").hidden = false;
  document.getElementById("audit-title").textContent = "Проверка выпуска";
  showView("sources");
  document.getElementById("analysis-overview").hidden = true;
  document.getElementById("group-count").hidden = true;
  document.getElementById("no-findings").hidden = false;
  document.getElementById("no-findings").textContent = "Замечания появятся после разбора.";
  recommendationsList.replaceChildren();
  document.getElementById("fetch-details").hidden = true;
  resultColumns.forEach((cell) => { cell.hidden = true; });
  updateRevisionWarning();
  return ++selection;
}

function updateRevisionWarning() {
  document.getElementById("revision-warning").hidden = !currentAnalysis || !currentAnalysis.runtime_revision || !activeRevision || currentAnalysis.runtime_revision === activeRevision;
}

const assistantForm = document.getElementById("assistant-form");
const assistantStatus = document.getElementById("assistant-status");
const operation = document.getElementById("operation");
const processing = document.getElementById("processing-state");
const retryReport = document.getElementById("retry-history-report");
const historyWarning = document.getElementById("history-warning");
const validReportId = /^[A-Za-z0-9_-]{1,128}$/;
let reportRequest = null;
let reportLocation = new URL(location.href);
const demoButtons = document.querySelectorAll("[data-demo]");
const demoMenu = document.getElementById("demo-menu");
const runToolsButton = document.getElementById("run-tools");
const submit = document.getElementById("analyze-button");
let running = false;
let hasHttpSources = false;

function showStatus(message, error = false, focus = error) {
  assistantStatus.textContent = message;
  operation.classList.toggle("error", error);
  if (focus) operation.focus();
}

function revealModelReply() {
  const action = document.getElementById("next-action");
  if (matchMedia("(prefers-reduced-motion: reduce)").matches || !action.animate) return;
  const message = action.textContent;
  const visual = node("span", "");
  visual.setAttribute("aria-hidden", "true");
  const accessible = node("span", message, "sr-only");
  action.replaceChildren(accessible, visual);
  const words = message.split(/(\s+)/u);
  const animations = [];
  for (const part of words) {
    if (!part || /^\s+$/u.test(part)) { visual.append(part); continue; }
    const word = node("span", part, "reply-word");
    visual.append(word);
    animations.push(word.animate([{ opacity: 0, transform: "translateY(3px)" }, { opacity: 1, transform: "none" }],
      { duration: 170, delay: 440 * animations.length / Math.max(1, Math.ceil(words.length / 2)), fill: "backwards", easing: "ease-out" }).finished);
  }
  Promise.allSettled(animations).then(() => { if (visual.parentNode === action) action.textContent = message; });
}

function showResult(data, { focus = true, findings = false, animate = false } = {}) {
  render(data, validate(data));
  showStatus("");
  if (animate) {
    result.classList.add("result-ready");
    if (data.advisory.mode === "model" && data.advisory.recommendations.length) revealModelReply();
  }
  if (findings) {
    showView("findings");
    const first = recommendationsList.querySelector("details");
    if (first) {
      first.open = true;
      if (focus) first.firstElementChild.focus();
      return;
    }
    if (focus) document.getElementById("tab-findings").focus();
  } else if (focus) result.focus();
}

function updateReportLocation(reportId, fromDrawer = false) {
  const url = new URL(location.href);
  if (reportId === null) url.searchParams.delete("report");
  else url.searchParams.set("report", reportId);
  if (url.hash === "#findings") url.hash = "";
  if (url.href !== location.href) history.pushState(null, "", url);
  reportLocation = url;
  document.dispatchEvent(new CustomEvent("workspace:report-changed", { detail: { fromDrawer } }));
}

async function openHistoryReport(reportId, focus = false) {
  const active = resetAnalysis();
  const token = document.getElementById("workspace-history").dataset.token;
  if (typeof reportId !== "string" || !validReportId.test(reportId) || !token) {
    showStatus(!token ? "История доступна только при локальном запуске." : "Некорректная ссылка на сохранённый разбор.", true, focus);
    return;
  }
  const controller = new AbortController();
  reportRequest = controller;
  processing.hidden = false;
  showStatus("Открываем сохранённый разбор…", false, focus);
  try {
    const response = await fetch("/api/security/history/" + encodeURIComponent(reportId), {
      headers: { "X-Assistant-Token": token }, credentials: "same-origin", redirect: "error", signal: controller.signal
    });
    if (!response.ok) throw new Error(response.status);
    const data = await response.json();
    if (active !== selection) return;
    analysisSource = "Сохранённый разбор из локальной истории";
    const findings = location.hash === "#findings";
    showResult(data, { focus: document.activeElement === operation || (findings && document.activeElement === document.body), findings });
  } catch (error) {
    if (active !== selection) return;
    const forbidden = error.message === "403" || error.message === "401";
    const missing = error.message === "404";
    retryReport.hidden = forbidden || missing;
    showStatus(forbidden ? "Нет доступа к журналу. Откройте локальный стенд или перезагрузите страницу."
      : missing ? "Разбор не найден в локальной истории." : "Не удалось открыть сохранённый разбор. Попробуйте ещё раз.", true, false);
  } finally {
    if (reportRequest === controller) {
      reportRequest = null;
      processing.hidden = true;
    }
  }
}

document.getElementById("workspace-history").addEventListener("click", (event) => {
  const link = event.target.closest("[data-workspace-report]");
  if (!link || event.defaultPrevented || event.button !== 0 || event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;
  event.preventDefault();
  updateReportLocation(link.dataset.workspaceReport, true);
  openHistoryReport(link.dataset.workspaceReport, true);
});
retryReport.addEventListener("click", () => openHistoryReport(reportLocation.searchParams.get("report"), true));
window.addEventListener("popstate", () => {
  const previous = reportLocation;
  reportLocation = new URL(location.href);
  const reportId = reportLocation.searchParams.get("report");
  if (previous.searchParams.get("report") === reportId && previous.hash === reportLocation.hash) return;
  document.dispatchEvent(new Event("workspace:report-changed"));
  if (reportId !== null) openHistoryReport(reportId);
  else if (previous.searchParams.has("report")) {
    resetAnalysis();
    showStatus("");
    showView("sources");
  }
});

fileInput.addEventListener("change", async () => {
  const file = fileInput.files[0];
  if (!file || running) return;
  fileInput.value = "";
  updateReportLocation(null);
  const current = resetAnalysis();
  analysisSource = "Импортированный разбор";
  showStatus("Читаем и проверяем файл…");
  try {
    if (!file.size || file.size > 8 * 1024 * 1024) throw new Error("size");
    const data = JSON.parse(await file.text());
    if (current !== selection) return;
    showResult(data);
    document.getElementById("import-analysis").open = false;
  } catch {
    if (current !== selection) return;
    showStatus("Не удалось открыть файл. Выберите analysis.json версии 1 размером до 8 МиБ, созданный помощником.", true);
  }
});

async function runAnalysis(url, options, pendingMessage) {
  if (running) return;
  running = true;
  analysisSource = url.endsWith("/demo/fail") ? "Учебный сценарий / до исправления" : url.endsWith("/demo/fixed") ? "Учебный сценарий / после исправления" : url.includes("/tools/") ? "Отчёты из HTTP-источников" : "Загрузка файлов";
  updateReportLocation(null);
  const active = resetAnalysis();
  processing.hidden = false;
  showStatus(pendingMessage);
  operation.focus();
  if (runToolsButton) runToolsButton.disabled = true;
  fileInput.disabled = true;
  demoButtons.forEach((button) => { button.disabled = true; });
  if (submit) submit.disabled = true;
  try {
    const response = await fetch(url, { ...options, redirect: "error", credentials: "same-origin" });
    const data = await response.json();
    if (!response.ok) throw new Error(typeof data.error === "string" ? data.error : data.error && typeof data.error.message === "string" ? data.error.message : "Не удалось выполнить анализ.");
    const realAnalysis = options.method === "POST";
    const reportId = response.headers.get("X-Report-Id");
    const unavailable = response.headers.get("X-Report-History") === "unavailable";
    const saved = realAnalysis && !unavailable && reportId && validReportId.test(reportId);
    if (active === selection) {
      showResult(data, { animate: realAnalysis, focus: !document.getElementById("workspace-navigation").contains(document.activeElement) });
      if (saved) updateReportLocation(reportId);
      historyWarning.hidden = !realAnalysis || !unavailable;
    }
    if (saved) document.dispatchEvent(new Event("workspace:history-changed"));
    if (assistantForm) refreshConnections();
  } catch (error) {
    if (active === selection) showStatus(error instanceof Error && error.message.length < 300 && error.message !== "schema" && !(error instanceof SyntaxError)
      ? error.message : "Не удалось выполнить анализ. Проверьте файлы и доступность приложения.", true);
  } finally {
    running = false;
    if (active === selection) processing.hidden = true;
    if (runToolsButton) runToolsButton.disabled = !hasHttpSources;
    fileInput.disabled = false;
    demoButtons.forEach((button) => { button.disabled = false; });
    if (submit) submit.disabled = !document.getElementById("report-files").files.length;
  }
}

demoButtons.forEach((button) => {
  button.addEventListener("click", () => {
    demoMenu.open = false;
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
    hasHttpSources = count > 0;
    runToolsButton.disabled = running || !hasHttpSources;
    document.getElementById("tools-summary").textContent = count ? "Подключено " + count + " из 5 источников. Получим готовые JSON-отчёты." : "Источники ещё не настроены. Добавьте адреса в настройках стенда.";
    updateRevisionWarning();
  } catch {
    hasHttpSources = false;
    runToolsButton.disabled = true;
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
    reportFiles.removeAttribute("aria-invalid");
    const files = Array.from(reportFiles.files);
    submit.disabled = running || !files.length;
    const selected = new Set(files.map(reportName));
    for (const scanner of scanners) {
      const cell = document.querySelector(`[data-scanner="${scanner}"] .queue-state`);
      const present = selected.has(scanner + ".json");
      cell.textContent = present ? "Выбран" : "Нет файла";
      cell.classList.toggle("queued", present);
    }
    const unknown = files.filter((file) => !reportNames.has(reportName(file)));
    document.getElementById("selected-files").textContent = unknown.length
      ? "Не распознаны: " + unknown.map((file) => file.name).join(", ") : files.length ? "Выбрано файлов: " + files.length : "";
  });
  uploadZone.addEventListener("dragenter", () => uploadZone.classList.add("drag-over"));
  for (const eventName of ["dragleave", "drop", "dragend"]) {
    uploadZone.addEventListener(eventName, () => uploadZone.classList.remove("drag-over"));
  }
  const useModel = document.getElementById("use-model");
  const settings = document.getElementById("model-settings");
  const keyInput = document.getElementById("api-key");
  const mode = document.getElementById("model-mode");
  const profileTarget = document.getElementById("profile-target");
  const revision = document.getElementById("profile-revision");
  let profileReady = false;
  let loadId = 0;
  function syncModelFields() {
    const once = mode.value === "once";
    settings.hidden = !once;
    settings.disabled = !once;
    for (const field of settings.querySelectorAll("input")) field.required = once && useModel.checked;
    document.getElementById("profile-description").hidden = once;
    useModel.disabled = !once && !profileReady;
    revision.disabled = once || !useModel.checked;
  }
  async function loadProfile() {
    const id = ++loadId;
    profileReady = false;
    if (mode.value === "profile") useModel.checked = false;
    syncModelFields();
    try {
      const response = await fetch("/api/security/model-profile", { headers: { "X-Assistant-Token": assistantForm.dataset.token }, credentials: "same-origin", redirect: "error" });
      if (!response.ok) throw new Error();
      const p = await response.json();
      if (id !== loadId) return;
      revision.value = p.revision;
      profileReady = Boolean(p.has_api_key && p.model && p.revision);
      profileTarget.textContent = [p.model || "Модель не выбрана", p.endpoint || "адрес не задан", `ожидание ${p.timeout} с`, p.has_api_key ? "ключ задан" : "ключ не задан"].join(" · ");
    } catch {
      if (id !== loadId) return;
      revision.value = "";
      profileTarget.textContent = "Не удалось прочитать профиль. Доступен локальный разбор.";
    }
    syncModelFields();
  }
  mode.addEventListener("change", () => {
    useModel.checked = false;
    keyInput.value = "";
    syncModelFields();
  });
  settings.addEventListener("input", () => { useModel.checked = false; syncModelFields(); });
  useModel.addEventListener("change", syncModelFields);
  document.getElementById("reload-profile").addEventListener("click", loadProfile);
  loadProfile();
  assistantForm.addEventListener("invalid", (event) => {
    if (settings.contains(event.target)) settings.closest("details").open = true;
  }, true);
  assistantForm.addEventListener("submit", (event) => {
    event.preventDefault();
    if (running) return;
    const files = Array.from(document.getElementById("report-files").files);
    if (!files.length || files.length > 5 || new Set(files.map(reportName)).size !== files.length
      || files.some((file) => !reportNames.has(reportName(file)) || !file.size || file.size > 8 * 1024 * 1024)) {
      reportFiles.setAttribute("aria-invalid", "true");
      document.getElementById("selected-files").textContent = "Выберите до пяти разных непустых JSON-файлов с именами сканеров, до 8 МиБ каждый.";
      reportFiles.focus();
      return;
    }
    const body = new FormData(assistantForm);
    if (!useModel.checked) for (const name of ["api_key", "base_url", "model", "model_revision"]) body.delete(name);
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

document.getElementById("workspace-actions").hidden = false;
document.getElementById("workbench").hidden = false;
if (reportLocation.searchParams.has("report")) openHistoryReport(reportLocation.searchParams.get("report"));
