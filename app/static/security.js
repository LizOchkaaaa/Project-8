"use strict";

const fileInput = document.getElementById("analysis-file");
const fileStatus = document.getElementById("file-status");
const result = document.getElementById("analysis-result");
const scanners = ["gitleaks", "bandit", "pip-audit", "trivy", "zap"];
const severities = ["critical", "high", "unknown", "medium", "low", "info"];
const scanLabels = { clean: "без замечаний", findings: "есть замечания", error: "ошибка или нет отчёта" };
let selection = 0;

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
  document.getElementById("advisory-source").textContent = `${data.advisory.mode === "model" ? "Модельный API" : "Детерминированный fallback"}: ${data.advisory.message}`;
  const gate = document.getElementById("report-gate");
  gate.textContent = `Состояние в файле: ${data.gate.status === "blocked" ? "выпуск заблокирован" : "policy пройдена"}. Область: ${data.gate.scope === "pipeline" ? "pipeline" : "только отчёты"}.`;
  gate.className = data.gate.status === "blocked" ? "danger" : "success";
  document.getElementById("scan-states").replaceChildren(...scanners.map((scanner) => node("li", `${scanner}: ${scanLabels[data.scans[scanner].status]} (${data.scans[scanner].count})`)));
  document.getElementById("failure-list").replaceChildren(...data.gate.failures.map((failure) => node("li", failure)));
  document.getElementById("pipeline-errors").hidden = !data.gate.failures.length;
  const fragment = document.createDocumentFragment();
  for (const recommendation of data.advisory.recommendations) {
    const group = groups.get(recommendation.group_id);
    const li = document.createElement("li");
    const body = document.createElement("div");
    body.className = "recommendation-body";
    body.append(node("h3", group.package ? `${group.package} ${group.version}` : group.title));
    body.append(node("p", `${group.severity} · ${group.scanners.join(", ")} · ${group.primary_ids.join(", ")}`, "meta"));
    body.append(node("p", recommendation.reason), node("p", recommendation.action));
    body.append(node("p", group.fixed_versions.length ? `Исправленные версии из evidence: ${group.fixed_versions.join(", ")}. Проверяйте применимость к каждому источнику.` : "Исправленная версия в evidence не указана.", "meta"));
    const details = document.createElement("details");
    details.append(node("summary", `Источники: ${group.evidence.length}`));
    const sources = document.createElement("ul");
    for (const evidence of group.evidence) {
      sources.append(node("li", `${evidence.scanner} / ${evidence.primary_id}\n${evidence.file || evidence.target}${evidence.line ? `, строка ${evidence.line}` : ""}${evidence.package ? `\n${evidence.package} ${evidence.version}` : ""}`));
    }
    details.append(sources); body.append(details); li.append(body); fragment.append(li);
  }
  document.getElementById("recommendations").replaceChildren(fragment);
  document.getElementById("no-findings").hidden = groups.size > 0;
  result.hidden = false;
}

fileInput.addEventListener("change", async () => {
  const current = ++selection;
  result.hidden = true;
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
