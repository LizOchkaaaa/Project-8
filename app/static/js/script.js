document.addEventListener('DOMContentLoaded', () => {
    loadNotes()
    document.getElementById('addBtn').addEventListener('click', addNote)
    document.getElementById('noteInput').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault()
            addNote()
        }
    })
})

function createNoteElement(item) {
    const li = document.createElement('li')
    li.dataset.id = item.id

    const span = document.createElement('span')
    span.textContent = item.text

    const div = document.createElement('div')

    const small = document.createElement('small')
    small.className = 'note-id'
    small.textContent = `#${item.id}`

    const delBtn = document.createElement('button')
    delBtn.className = 'delete-btn'
    delBtn.type = 'button'
    delBtn.title = 'Удалить'
    delBtn.textContent = '✖'
    delBtn.addEventListener('click', () => deleteNote(item.id, li))

    div.appendChild(small)
    div.appendChild(delBtn)
    li.appendChild(span)
    li.appendChild(div)
    return li
}

async function loadNotes() {
    const res = await fetch('/api/items')
    if (!res.ok) return
    const data = await res.json()
    const list = document.getElementById('notesList')
    list.textContent = ''

    data.items.forEach(item => {
        list.appendChild(createNoteElement(item))
    })
}

async function addNote() {
    const input = document.getElementById('noteInput')
    const btn = document.getElementById('addBtn')
    const errorDiv = document.getElementById('error')
    const text = input.value.trim()

    if (!text || btn.disabled) return

    btn.disabled = true
    errorDiv.textContent = ''

    try {
        const res = await fetch('/api/items', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text })
        })

        if (res.status === 201) {
            const newItem = await res.json()
            document.getElementById('notesList').appendChild(createNoteElement(newItem))
            input.value = ''
            input.focus()
        } else {
            const data = await res.json()
            errorDiv.textContent = data.error || 'Ошибка при добавлении'
        }
    } catch {
        errorDiv.textContent = 'Ошибка соединения с сервером'
    } finally {
        btn.disabled = false
    }
}

async function deleteNote(id, liElement) {
    if (!confirm('Удалить эту заметку?')) return

    const res = await fetch(`/api/items/${id}`, {
        method: 'DELETE'
    })
    if (res.ok) {
        liElement.remove()
    } else {
        alert('Ошибка при удалении')
    }
}
