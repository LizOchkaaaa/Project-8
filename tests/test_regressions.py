from pathlib import Path

from app.main import create_app

ROOT = Path(__file__).resolve().parent.parent


def test_create_delete_gap_create_delete_targets_correct_note():
    client = create_app().test_client()
    first = client.post("/api/items", json={"text": "first"}).json
    keep = client.post("/api/items", json={"text": "keep"}).json
    assert client.delete(f"/api/items/{first['id']}").status_code == 200
    new = client.post("/api/items", json={"text": "new"}).json
    assert new["id"] > keep["id"]
    assert client.delete(f"/api/items/{new['id']}").status_code == 200
    assert client.get("/api/items").json == {"items": [keep]}


def test_security_page_is_read_only_and_strict_csp():
    client = create_app().test_client()
    for route in ("/", "/security"):
        response = client.get(route)
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert 'lang="ru"' in html and 'name="viewport"' in html
        assert "unsafe-inline" not in response.headers["Content-Security-Policy"]
        assert "unsafe-eval" not in response.headers["Content-Security-Policy"]
        assert 'aria-live="polite"' in html
    for filename in ("notes.js", "security.js"):
        js = client.get("/static/" + filename).get_data(as_text=True)
        assert "textContent" in js
        assert not any(
            s in js
            for s in ("innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "OPENAI_API_KEY")
        )
    js = (ROOT / "app/static/security.js").read_text(encoding="utf-8")
    assert "fetch(" not in js and "XMLHttpRequest" not in js
    assert client.post("/security", json={}).status_code == 405
    assert client.get("/api/security").status_code == 404


def test_note_xss_stays_json_and_is_not_server_rendered():
    client = create_app().test_client()
    value = '<img src=x onerror="alert(1)">'
    assert client.post("/api/items", json={"text": value}).status_code == 201
    assert client.get("/api/items").json["items"][0]["text"] == value
    assert value not in client.get("/").get_data(as_text=True)
