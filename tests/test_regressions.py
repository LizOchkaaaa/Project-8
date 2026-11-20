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


def test_security_page_keeps_strict_csp_and_safe_rendering():
    client = create_app().test_client()
    for route in ("/", "/security", "/notes"):
        response = client.get(route, follow_redirects=True)
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert 'lang="ru"' in html and 'name="viewport"' in html
        assert "unsafe-inline" not in response.headers["Content-Security-Policy"]
        assert "unsafe-eval" not in response.headers["Content-Security-Policy"]
        assert "camera=()" in response.headers["Permissions-Policy"]
        assert response.headers["Cross-Origin-Embedder-Policy"] == "require-corp"
        assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
        assert response.headers["Cross-Origin-Resource-Policy"] == "same-origin"
        assert 'aria-live="polite"' in html
    for filename in ("notes.js", "security.js"):
        js = client.get("/static/" + filename).get_data(as_text=True)
        assert "textContent" in js
        assert not any(
            s in js
            for s in ("innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "OPENAI_API_KEY")
        )
    js = (ROOT / "app/static/security.js").read_text(encoding="utf-8")
    assert "localStorage" not in js and "sessionStorage" not in js
    assert client.post("/security", json={}).status_code == 405
    assert client.get("/api/security").status_code == 404


def test_note_xss_stays_json_and_is_not_server_rendered():
    client = create_app().test_client()
    value = '<img src=x onerror="alert(1)">'
    assert client.post("/api/items", json={"text": value}).status_code == 201
    assert client.get("/api/items").json["items"][0]["text"] == value
    assert value not in client.get("/notes").get_data(as_text=True)
