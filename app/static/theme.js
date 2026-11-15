"use strict";

(() => {
  let theme = "dark";
  try {
    const saved = localStorage.getItem("project8-theme");
    if (saved === "light" || saved === "dark") theme = saved;
  } catch { /* Theme switching also works when storage is unavailable. */ }
  const apply = () => {
    document.documentElement.dataset.theme = theme;
    const color = document.getElementById("theme-color");
    if (color) color.content = theme === "dark" ? "#15171B" : "#F5F5F7";
    const button = document.getElementById("theme-toggle");
    if (button) {
      button.setAttribute("aria-label", theme === "dark" ? "Переключить на светлую тему" : "Переключить на тёмную тему");
      document.getElementById("theme-label").textContent = theme === "dark" ? "Светлая тема" : "Тёмная тема";
    }
  };
  apply();
  document.addEventListener("DOMContentLoaded", () => {
    apply();
    document.getElementById("theme-toggle").addEventListener("click", () => {
      theme = theme === "dark" ? "light" : "dark";
      apply();
      try { localStorage.setItem("project8-theme", theme); } catch { /* Optional preference. */ }
    });
  });
})();
