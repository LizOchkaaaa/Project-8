document.addEventListener('DOMContentLoaded', loadNotes)

async function loadNotes() {
    const res = await fetch('/api/items')
    const data = await res.json()
    const list = document.getElementById('notesList')
    list.innerHTML = ''

    data.items.forEach(item => {
        const li = document.createElement('li')
        li.innerHTML = `<span>${item.text}</span>
                <div>
                    <small class="note-id">#${item.id}</small>
                    <button class="delete-btn" onclick="deleteNote(${item.id})" title="Удалить">✖</button>
                </div>`
        list.appendChild(li)
    })
}

async function addNote() {
    const input = document.getElementById('noteInput')
    const errorDiv = document.getElementById('error')
    const text = input.value.trim()
    
    if (!text) return

    const res = await fetch('/api/items', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: text })
    })

    if (res.status === 201) {
        input.value = ''
        errorDiv.textContent = ''
        loadNotes()
    } else {
        const data = await res.json()
        errorDiv.textContent = data.error || 'Ошибка при добавлении'
    }
}

async function deleteNote(id) {
    if (confirm('Удалить эту заметку?')) {
        const res = await fetch(`/api/items/${id}`, {
            method: 'DELETE'
        })
        if (res.ok) {
            loadNotes()
        } else {
            alert('Ошибка при удалении')
        }
    }
}

document.getElementById('noteInput').addEventListener('keypress', function (e) {
    if (e.key === 'Enter') addNote()
})