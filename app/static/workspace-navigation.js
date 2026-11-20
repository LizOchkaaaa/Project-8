"use strict";

(() => {
  const drawer = document.getElementById("workspace-navigation");
  const openButton = document.getElementById("workspace-open");
  const closeButton = document.getElementById("workspace-close");
  const shade = document.getElementById("workspace-shade");
  const shell = document.querySelector(".app-shell");
  const skip = document.querySelector(".skip");
  const mobile = matchMedia("(max-width: 760px)");
  const historyPanel = document.getElementById("workspace-history");
  let desktopOpen = false;
  try { desktopOpen = localStorage.getItem("project8-navigation") === "open"; } catch {}
  let mobileOpen = false;
  let drawerOpener = openButton;

  const token = historyPanel.dataset.token;
  const filter = document.getElementById("workspace-history-gate");
  const refresh = document.getElementById("workspace-history-refresh");
  const list = document.getElementById("workspace-history-list");
  const status = document.getElementById("workspace-history-status");
  const more = document.getElementById("workspace-history-more");
  const sources = { upload: "Загрузка", http: "HTTP", mcp: "MCP" };
  const scannerLabels = { gitleaks: "Gitleaks", bandit: "Bandit", "pip-audit": "pip-audit", trivy: "Trivy", zap: "OWASP ZAP" };
  const date = new Intl.DateTimeFormat("ru-RU", { dateStyle: "medium", timeStyle: "short" });
  let request;
  let nextOffset = null;
  let dirty = true;

  function selectedReport() {
    const report = location.pathname === "/security" ? new URLSearchParams(location.search).get("report") : null;
    list?.querySelectorAll("[data-workspace-report]").forEach((link) => {
      if (link.dataset.workspaceReport === report) link.setAttribute("aria-current", "true");
      else link.removeAttribute("aria-current");
    });
  }

  function historyEntry(item) {
    if (!item || !["string", "number"].includes(typeof item.id) || !/^[A-Za-z0-9_-]{1,128}$/.test(String(item.id)) || typeof item.passed !== "boolean"
      || !Number.isSafeInteger(item.groups_count) || item.groups_count < 0) throw new Error("history");
    const row = document.createElement("li");
    const link = document.createElement("a");
    const rowHead = document.createElement("span");
    const gate = document.createElement("strong");
    const source = document.createElement("span");
    const title = document.createElement("span");
    const detail = document.createElement("span");
    const time = document.createElement("time");
    rowHead.className = "history-row-head";
    gate.className = item.passed ? "history-pass" : "history-fail";
    gate.textContent = item.passed ? "Пройден" : "Заблокирован";
    source.className = "history-source";
    source.textContent = Object.hasOwn(sources, item.source) ? sources[item.source] : "Анализ";
    const scanners = Array.isArray(item.scanners) ? item.scanners.filter((scanner) => typeof scanner === "string" && scanner.length) : [];
    const first = scanners[0];
    title.className = "history-row-title";
    title.textContent = first ? (Object.hasOwn(scannerLabels, first) ? scannerLabels[first] : first.slice(0, 48))
      + (scanners.length > 1 ? ` + ещё ${scanners.length - 1}` : "") : "Без полученных файлов";
    detail.className = "history-row-detail";
    const timestamp = typeof item.created_at === "string" ? new Date(item.created_at) : new Date(NaN);
    if (Number.isFinite(timestamp.getTime())) {
      time.dateTime = item.created_at;
      time.textContent = date.format(timestamp);
    } else {
      time.textContent = "Без даты";
    }
    link.href = "/security?report=" + encodeURIComponent(item.id);
    link.dataset.workspaceReport = item.id;
    rowHead.append(gate, source);
    detail.append(time, ` · ${item.groups_count} гр. · № ${String(item.id).slice(0, 8)}`);
    link.append(rowHead, title, detail);
    row.append(link);
    return row;
  }

  async function loadHistory(offset = 0) {
    if (!token) return;
    request?.abort();
    const controller = new AbortController();
    request = controller;
    dirty = false;
    if (!offset) {
      if (list.contains(document.activeElement) || document.activeElement === more) refresh.focus();
      list.replaceChildren();
      more.hidden = true;
      nextOffset = null;
    }
    status.textContent = offset ? "Загружаем ещё записи…" : "Загружаем историю…";
    list.setAttribute("aria-busy", "true");
    try {
      const query = new URLSearchParams({ offset, gate: filter.value });
      const response = await fetch("/api/security/history?" + query, {
        headers: { "X-Assistant-Token": token }, credentials: "same-origin", redirect: "error", signal: controller.signal
      });
      if (!response.ok) throw new Error(response.status);
      const data = await response.json();
      if (request !== controller) return;
      if (!Array.isArray(data.items) || (data.next_offset !== null &&
        (!Number.isSafeInteger(data.next_offset) || data.next_offset <= offset))) throw new Error("history");
      const rows = data.items.map(historyEntry);
      const known = new Set(Array.from(list.querySelectorAll("[data-workspace-report]"), (link) => link.dataset.workspaceReport));
      const additions = rows.filter((row) => {
        const id = row.firstElementChild.dataset.workspaceReport;
        if (known.has(id)) return false;
        known.add(id);
        return true;
      });
      list.append(...additions);
      selectedReport();
      nextOffset = data.next_offset;
      if (document.activeElement === more) (additions[0]?.firstElementChild || (nextOffset === null ? refresh : more)).focus();
      more.hidden = nextOffset === null;
      status.textContent = list.children.length ? `Показано записей: ${list.children.length}`
        : filter.value === "all" ? "Сохранённых анализов пока нет." : "Нет анализов с таким решением.";
    } catch (error) {
      if (request !== controller) return;
      status.textContent = error.message === "403" || error.message === "401"
        ? "Нет доступа. Откройте локальный стенд или перезагрузите страницу."
        : offset ? "Не удалось загрузить следующую страницу. Попробуйте ещё раз."
          : "Не удалось загрузить историю. Нажмите «Обновить историю» для повтора.";
    } finally {
      if (request === controller) {
        request = null;
        list.removeAttribute("aria-busy");
      }
    }
  }

  function syncDrawer() {
    const open = mobile.matches ? mobileOpen : desktopOpen;
    const modal = mobile.matches && open;
    const restoreFocus = !open && drawer.contains(document.activeElement);
    document.body.classList.toggle("drawer-open", open);
    document.body.classList.toggle("drawer-modal", modal);
    drawer.inert = !open;
    shell.inert = modal;
    skip.inert = modal;
    shade.hidden = !modal;
    if (modal) {
      drawer.setAttribute("role", "dialog");
      drawer.setAttribute("aria-modal", "true");
    } else {
      drawer.removeAttribute("role");
      drawer.removeAttribute("aria-modal");
    }
    openButton.setAttribute("aria-expanded", String(open));
    const label = open ? "Закрыть журнал" : "Открыть журнал";
    openButton.setAttribute("aria-label", label);
    openButton.title = label;
    if (restoreFocus) openButton.focus();
    if (open && dirty) loadHistory();
  }

  function setDrawer(open, trigger = openButton) {
    if (open) drawerOpener = trigger;
    if (mobile.matches) mobileOpen = open;
    else {
      desktopOpen = open;
      try { localStorage.setItem("project8-navigation", open ? "open" : "closed"); } catch {}
    }
    syncDrawer();
    (open ? closeButton : drawerOpener).focus({ preventScroll: true });
    if (!open && document.activeElement !== drawerOpener) openButton.focus({ preventScroll: true });
  }

  drawer.hidden = openButton.hidden = closeButton.hidden = historyPanel.hidden = false;
  openButton.addEventListener("click", () => setDrawer(openButton.getAttribute("aria-expanded") !== "true"));
  closeButton.addEventListener("click", () => setDrawer(false));
  shade.addEventListener("click", () => setDrawer(false));
  mobile.addEventListener("change", () => {
    mobileOpen = false;
    syncDrawer();
  });
  document.addEventListener("keydown", (event) => {
    if (event.defaultPrevented || drawer.inert) return;
    if (event.key === "Escape" && drawer.contains(document.activeElement)) {
      event.preventDefault();
      setDrawer(false);
    } else if (event.key === "Tab" && mobileOpen) {
      const controls = Array.from(drawer.querySelectorAll("a[href], button, select")).filter((control) => !control.hidden && !control.disabled);
      const edge = event.shiftKey ? controls[0] : controls.at(-1);
      if (document.activeElement === edge || !drawer.contains(document.activeElement)) {
        event.preventDefault();
        (event.shiftKey ? controls.at(-1) : controls[0]).focus();
      }
    }
  });
  filter?.addEventListener("change", () => loadHistory());
  refresh?.addEventListener("click", () => loadHistory());
  more?.addEventListener("click", () => { if (!request && nextOffset !== null) loadHistory(nextOffset); });
  document.addEventListener("workspace:history-changed", () => {
    dirty = true;
    if (!drawer.inert) loadHistory();
  });
  document.addEventListener("workspace:report-changed", (event) => {
    if (mobileOpen && event.detail?.fromDrawer) setDrawer(false);
    selectedReport();
  });
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) document.dispatchEvent(new Event("workspace:history-changed"));
  });

  document.body.classList.add("workspace-ready");
  syncDrawer();
})();
