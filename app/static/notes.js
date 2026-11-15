"use strict";

const noteForm = document.getElementById("note-form");
const noteText = document.getElementById("note-text");
const noteStatus = document.getElementById("note-status");
const notes = document.getElementById("notes");

async function notesRequest(url, options = {}) {
  const response = await fetch(url, { ...options, credentials: "same-origin" });
  if (!response.ok) throw new Error("request");
  return response.json();
}

async function loadNotes() {
  const data = await notesRequest("/api/items");
  const fragment = document.createDocumentFragment();
  for (const item of data.items) {
    const li = document.createElement("li");
    const text = document.createElement("span");
    text.textContent = item.text;
    const remove = document.createElement("button");
    remove.type = "button";
    remove.textContent = "Удалить";
    remove.setAttribute("aria-label", `Удалить заметку: ${item.text}`);
    remove.addEventListener("click", async () => {
      if (!window.confirm("Удалить эту заметку? Восстановить её не получится.")) return;
      remove.disabled = true;
      try {
        await notesRequest(`/api/items/${item.id}`, { method: "DELETE" });
        await loadNotes();
        noteText.focus();
      } catch {
        noteStatus.textContent = "Не удалось удалить заметку. Обновите страницу и повторите.";
        remove.disabled = false;
      }
    });
    li.append(text, remove);
    fragment.append(li);
  }
  notes.replaceChildren(fragment);
  noteStatus.textContent = data.items.length ? `Заметок: ${data.items.length}.` : "Заметок пока нет. Добавьте первую запись.";
}

noteForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = noteForm.querySelector("button");
  const text = noteText.value.trim();
  if (!text) {
    noteStatus.textContent = "Введите текст заметки.";
    noteText.focus();
    return;
  }
  button.disabled = true;
  try {
    await notesRequest("/api/items", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text }) });
    noteText.value = "";
    await loadNotes();
    noteText.focus();
  } catch {
    noteStatus.textContent = "Не удалось сохранить заметку. Проверьте соединение и лимит хранилища (1000 записей).";
  } finally {
    button.disabled = false;
  }
});
loadNotes().catch(() => { noteStatus.textContent = "Не удалось загрузить заметки. Обновите страницу."; });
