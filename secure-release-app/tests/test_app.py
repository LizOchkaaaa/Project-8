import pytest

from app.main import MAX_TEXT_LENGTH, create_app


@pytest.fixture()
def client():
    return create_app().test_client()


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json() == {"status": "ok"}


def test_index(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.get_json()["name"] == "secure-release-app"


def test_list_empty(client):
    assert client.get("/api/items").get_json() == {"items": []}


def test_create_and_list(client):
    r = client.post("/api/items", json={"text": "  привет  "})
    assert r.status_code == 201
    assert r.get_json() == {"id": 1, "text": "привет"}
    assert client.get("/api/items").get_json()["items"] == [{"id": 1, "text": "привет"}]


@pytest.mark.parametrize("payload", [
    {}, {"text": ""}, {"text": "   "}, {"text": 123}, {"text": None}, [],
])
def test_create_rejects_bad_payload(client, payload):
    assert client.post("/api/items", json=payload).status_code == 400


def test_create_rejects_non_json(client):
    r = client.post("/api/items", data="text=abc",
                    content_type="application/x-www-form-urlencoded")
    assert r.status_code == 400


def test_create_rejects_too_long(client):
    r = client.post("/api/items", json={"text": "a" * (MAX_TEXT_LENGTH + 1)})
    assert r.status_code == 400


def test_body_too_large(client):
    r = client.post("/api/items", json={"text": "a" * 20000})
    assert r.status_code == 413


def test_not_found_and_method_not_allowed(client):
    assert client.get("/nope").status_code == 404
    assert client.delete("/api/items").status_code == 405


def test_security_headers(client):
    h = client.get("/health").headers
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in h["Content-Security-Policy"]
    assert h["Cache-Control"] == "no-store"
