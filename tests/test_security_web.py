import io
import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.main import create_app
from security_assistant.parsers import MAX_BYTES


@pytest.fixture
def web():
    app = create_app()
    app.testing = True
    client = app.test_client()
    html = client.get("/security").get_data(as_text=True)
    token = re.search(r'data-token="([^"]+)"', html).group(1)
    return app, client, {"X-Assistant-Token": token}


def uploads(bandit_rule="B602"):
    reports = {
        "gitleaks": [],
        "bandit": {
            "errors": [],
            "metrics": {"_totals": {"loc": 4}},
            "results": [
                {
                    "test_id": bandit_rule,
                    "issue_severity": "HIGH",
                    "filename": "private.py",
                    "line_number": 4,
                    "code": "PRIVATE_SOURCE",
                    "issue_text": "PRIVATE_DESCRIPTION",
                }
            ],
        },
        "pip-audit": {"dependencies": [{"name": "demo", "version": "1.0", "vulns": []}]},
        "trivy": {
            "SchemaVersion": 2,
            "ArtifactName": "demo:image",
            "ArtifactType": "container_image",
            "Results": [
                {
                    "Target": "demo",
                    "Class": "lang-pkgs",
                    "Type": "python-pkg",
                    "Vulnerabilities": [],
                }
            ],
        },
        "zap": {"@version": "2.16.1", "site": [{"@name": "http://localhost", "alerts": []}]},
    }
    return [
        (io.BytesIO(json.dumps(value).encode()), name + ".json") for name, value in reports.items()
    ]


def test_demo_and_document_download(web):
    _, client, _ = web
    fail = client.get("/api/security/demo/fail").get_json()
    fixed = client.get("/api/security/demo/fixed").get_json()
    assert fail["gate"]["status"] == "blocked"
    assert fail["groups"][0]["primary_ids"] == ["B324"]
    assert "SHA-256" in fail["advisory"]["recommendations"][0]["action"]
    assert fixed["gate"]["status"] == "passed"
    assert all(state["status"] == "clean" for state in fixed["scans"].values())
    assert "синтетические" in fail["advisory"]["message"]
    assert client.get("/api/security/demo/unknown").status_code == 404
    document = client.get("/documentation")
    assert document.status_code == 200 and document.data.startswith(b"PK")
    assert "attachment" in document.headers["Content-Disposition"]


@pytest.mark.parametrize(
    "remote,host,token",
    [
        ("127.0.0.1", "localhost", ""),
        ("127.0.0.1", "localhost", "wrong"),
        ("127.0.0.1", "localhost", "é"),
        ("192.0.2.1", "localhost", None),
        ("127.0.0.1", "attacker.example", None),
    ],
)
def test_local_host_and_token_required(web, remote, host, token):
    _, client, headers = web
    if token is not None:
        headers = {"X-Assistant-Token": token}
    response = client.post(
        "/api/security/analyze",
        headers=headers,
        base_url="http://" + host,
        environ_overrides={"REMOTE_ADDR": remote},
    )
    assert response.status_code == 403
    if remote != "127.0.0.1" or host != "localhost":
        html = client.get(
            "/security", base_url="http://" + host, environ_overrides={"REMOTE_ADDR": remote}
        ).get_data(as_text=True)
        assert 'id="api-key"' not in html and "data-token=" not in html


def test_upload_analysis_does_not_inherit_server_key(web, monkeypatch):
    _, client, headers = web
    monkeypatch.setenv("OPENAI_API_KEY", "server-key-must-not-be-used")
    response = client.post("/api/security/analyze", headers=headers, data={"reports": uploads()})
    analysis = response.get_json()
    assert response.status_code == 200
    assert analysis["gate"]["status"] == "blocked"
    assert analysis["advisory"]["mode"] == "fallback"
    assert analysis["groups"][0]["primary_ids"] == ["B602"]
    assert all(scan["status"] != "error" for scan in analysis["scans"].values())
    assert "server-key-must-not-be-used" not in response.get_data(as_text=True)


def test_overlapping_analysis_is_rejected_and_lock_is_released(web, monkeypatch):
    app, client, headers = web
    started, finish = threading.Event(), threading.Event()
    responses = []

    def slow_analysis(*args, **kwargs):
        started.set()
        if not finish.wait(timeout=5):
            raise TimeoutError("test provider did not finish")
        return {"finished": True}

    monkeypatch.setattr("app.security.analyze", slow_analysis)

    def first_request():
        with app.test_client() as other_client:
            responses.append(
                other_client.post(
                    "/api/security/analyze", headers=headers, data={"reports": uploads()}
                ).status_code
            )

    thread = threading.Thread(target=first_request)
    thread.start()
    try:
        assert started.wait(timeout=3)
        assert client.post("/api/security/analyze", headers=headers).status_code == 429
    finally:
        finish.set()
        thread.join(timeout=5)
    assert not thread.is_alive() and responses == [200]
    assert (
        client.post(
            "/api/security/analyze", headers=headers, data={"reports": uploads()}
        ).status_code
        == 200
    )


@pytest.mark.parametrize(
    "files",
    [
        [],
        [(b"[]", "../gitleaks.json")],
        [(b"[]", "gitleaks.json"), (b"[]", "gitleaks.json")],
        [(b"", "gitleaks.json")],
    ],
)
def test_invalid_uploads_rejected(web, files):
    _, client, headers = web
    response = client.post(
        "/api/security/analyze",
        headers=headers,
        data={"reports": [(io.BytesIO(raw), name) for raw, name in files]},
    )
    assert response.status_code == 400


def test_missing_malformed_and_large_reports_fail_closed(web):
    _, client, headers = web
    malformed = client.post(
        "/api/security/analyze",
        headers=headers,
        data={"reports": [(io.BytesIO(b"{}"), "bandit.json")]},
    )
    assert malformed.get_json()["gate"]["status"] == "blocked"
    assert all(scan["status"] == "error" for scan in malformed.get_json()["scans"].values())
    large = client.post(
        "/api/security/analyze",
        headers=headers,
        data={"reports": [(io.BytesIO(b" " * (MAX_BYTES + 1)), "gitleaks.json")]},
    )
    assert large.status_code == 400
    notes = client.post("/api/items", json={"text": "a" * 17000})
    assert notes.status_code == 413


@pytest.mark.parametrize("base", ["http://remote.example/v1", "https://user:pass@example.org/v1"])
def test_unsafe_model_endpoint_rejected(web, base):
    _, client, headers = web
    response = client.post(
        "/api/security/analyze",
        headers=headers,
        data={
            "reports": uploads(),
            "use_model": "on",
            "api_key": "fake-web-key",
            "base_url": base,
            "model": "test-model",
        },
    )
    assert response.status_code == 400
    assert "fake-web-key" not in response.get_data(as_text=True)


@pytest.mark.parametrize("status", [200, 401])
def test_real_http_model_roundtrip_and_error(web, monkeypatch, status):
    _, client, headers = web
    observed = {}
    monkeypatch.setenv("OPENAI_API_KEY", "independent-server-key")

    class Provider(BaseHTTPRequestHandler):
        def do_POST(self):
            observed["path"] = self.path
            observed["auth"] = self.headers.get("Authorization")
            data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            observed["body"] = data
            groups = json.loads(data["messages"][1]["content"])["untrusted_groups"]
            content = {
                "recommendations": [
                    {
                        "group_id": group["id"],
                        "order": index + 1,
                        "reason": "Слабый алгоритм хеширования требует проверки.",
                        "action": "Замените слабый хеш и повторите сканирование.",
                    }
                    for index, group in enumerate(groups)
                ]
            }
            answer = {"choices": [{"message": {"content": json.dumps(content)}}]}
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(answer).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = client.post(
            "/api/security/analyze",
            headers=headers,
            data={
                "reports": uploads("B324"),
                "use_model": "on",
                "api_key": "fake-web-key",
                "base_url": f"http://127.0.0.1:{server.server_port}/v1",
                "model": "test-model",
            },
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    analysis = response.get_json()
    assert response.status_code == 200 and analysis["gate"]["status"] == "blocked"
    assert analysis["advisory"]["mode"] == ("model" if status == 200 else "fallback")
    assert observed["auth"] == "Bearer fake-web-key"
    assert observed["path"] == "/v1/chat/completions"
    assert observed["body"]["model"] == "test-model"
    [sent_group] = json.loads(observed["body"]["messages"][1]["content"])["untrusted_groups"]
    assert sent_group["category"] == "weak-hash"
    compact = json.dumps(observed["body"])
    assert all(
        value not in compact
        for value in ["PRIVATE_SOURCE", "PRIVATE_DESCRIPTION", "private.py", "fake-web-key"]
    )
    assert "fake-web-key" not in response.get_data(as_text=True)
    assert os.environ["OPENAI_API_KEY"] == "independent-server-key"
