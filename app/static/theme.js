"use strict";

(() => {
  let theme = "light";
  try {
    const saved = localStorage.getItem("project8-theme");
    if (saved === "light" || saved === "dark") theme = saved;
  } catch {}
  const apply = () => {
    document.documentElement.dataset.theme = theme;
    const color = document.getElementById("theme-color");
    if (color) color.content = theme === "dark" ? "#1b1c1d" : "#f5f5f5";
    const button = document.getElementById("theme-toggle");
    if (button) {
      button.hidden = false;
      button.setAttribute("aria-pressed", String(theme === "dark"));
    }
  };
  apply();
  document.addEventListener("DOMContentLoaded", () => {
    apply();
    document.getElementById("theme-toggle")?.addEventListener("click", () => {
      theme = theme === "dark" ? "light" : "dark";
      apply();
      try { localStorage.setItem("project8-theme", theme); } catch {}
    });
  });
})();
