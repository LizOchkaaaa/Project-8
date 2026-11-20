import io
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from security_assistant import connectors
from security_assistant.parsers import MAX_BYTES, SCANNERS
from security_assistant.runtime import credential_name, default_config


@pytest.fixture
def provider():
    settings = {"status": 200, "type": "application/json", "body": b"[]"}
    observed = []
    stop = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            observed.append(
                {
                    "path": self.path,
                    "auth": self.headers.get("Authorization"),
                    "encoding": self.headers.get("Accept-Encoding"),
                }
            )
            try:
                if settings.get("slow_headers"):
                    for byte in b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n":
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        if stop.wait(0.04):
                            return
                else:
                    self.send_response(settings["status"])
                    self.send_header("Content-Type", settings["type"])
                    for key, value in settings.get("headers", {}).items():
                        self.send_header(key, value)
                    self.end_headers()
                if settings.get("slow_body"):
                    for _ in range(100):
                        self.wfile.write(b" ")
                        self.wfile.flush()
                        if stop.wait(0.04):
                            return
                else:
                    self.wfile.write(settings["body"])
            except (OSError, ConnectionError):
                return

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/report", settings, observed
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        thread.join(2)


def fetch(url, credential=None, total=3):
    return connectors.fetch_one(
        {"enabled": True, "url": url, "credential_env": credential},
        {"connect_seconds": 1, "read_seconds": 1},
        time.monotonic() + total,
    )


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "http://example.com/r",
        "https://user:password@example.com/r",
        "https://example.com/?token=x",
        "https://example.com/#x",
        "https://example.com/\\x",
        "https://example.com/\nx",
        "https://example.com/\tx",
        "https://example.com/%0d%0a",
        "https://example.com/%5cprivate",
        "https://example.com/bad%path",
        "https://example.com:0/r",
        "https://example.com:65536/r",
        "https://example.com:/r",
        "https://127.0.0.1/r",
        "https://10.0.0.1/r",
        "https://169.254.169.254/r",
        "https://[::ffff:127.0.0.1]/r",
        "https://[::]/r",
        "https://[ff02::1]/r",
        "http://2130706433/r",
        "http://127.1/r",
        "http://localhost.evil/r",
    ],
)
def test_invalid_connector_destinations(url):
    with pytest.raises(ValueError):
        connectors.validate_url(url)


def test_real_get_no_ambient_proxy_and_auth_only_explicit_ref(provider, monkeypatch):
    url, _, observed = provider
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("OPENAI_API_KEY", "private-model")
    monkeypatch.setenv("PROJECT8_MCP_TOKEN", "private-mcp")
    monkeypatch.setenv(credential_name("gitleaks"), "dedicated-connector")
    raw, metadata = fetch(url)
    assert raw == b"[]" and metadata["status"] == "fetched"
    assert observed[-1] == {"path": "/report", "auth": None, "encoding": "identity"}
    assert fetch(url, credential_name("gitleaks"))[1]["status"] == "fetched"
    assert observed[-1]["auth"] == "Bearer dedicated-connector"


def test_encoded_path_is_preserved_and_chunked_json_supported(provider):
    url, settings, observed = provider
    settings.update(headers={"Transfer-Encoding": "chunked"}, body=b"2\r\n[]\r\n0\r\n\r\n")
    raw, metadata = fetch(url + "/project%2D8.json")
    assert raw == b"[]" and metadata["status"] == "fetched"
    assert observed[-1]["path"].endswith("/project%2D8.json")


@pytest.mark.parametrize("credential", ["", "bad key", "é", "a\r\nb"])
def test_bad_or_missing_credentials_never_get(provider, monkeypatch, credential):
    url, _, observed = provider
    monkeypatch.setenv(credential_name("gitleaks"), credential)
    raw, metadata = fetch(url, credential_name("gitleaks"))
    assert raw is None and metadata["status"] == "credential_error" and not observed


@pytest.mark.parametrize(
    "secret,escaped",
    [
        ("dedicated-connector", False),
        ("dedicated-connector", True),
        ('dedicated-"connector', False),
        ("dedicated-\\connector", False),
    ],
)
def test_reflected_credential_discards_entire_report(provider, monkeypatch, secret, escaped):
    url, settings, _ = provider
    monkeypatch.setenv(credential_name("gitleaks"), secret)
    raw = json.dumps([{"RuleID": secret, "File": "x", "StartLine": 1}]).encode()
    settings["body"] = raw.replace(b"dedicated", b"\\u0064edicated") if escaped else raw
    result, metadata = fetch(url, credential_name("gitleaks"))
    assert result is None and metadata["status"] == "credential_reflection"
    assert secret not in json.dumps(metadata)


@pytest.mark.parametrize(
    "changes",
    [
        {"status": 302, "headers": {"Location": "http://127.0.0.1/private"}},
        {"status": 401, "body": b"private response and secret"},
        {"type": "text/plain"},
        {"headers": {"Content-Encoding": "gzip"}},
        {"headers": {"Content-Encoding": "br"}},
        {"headers": {"Content-Length": str(MAX_BYTES + 1)}},
        {"headers": {"Content-Length": "-1"}},
        {"headers": {"Content-Length": "4"}, "body": b"[]"},
        {"body": b"bad private JSON"},
        {"body": b'{"x":1,"x":2}'},
        {"body": b"[" * 65 + b"]" * 65},
        {"body": b" " * (MAX_BYTES + 1)},
    ],
)
def test_invalid_responses_discarded_without_error_details(provider, changes):
    url, settings, observed = provider
    settings.update(changes)
    raw, metadata = fetch(url)
    assert raw is None and metadata["status"] == "fetch_error"
    assert len(observed) == 1
    assert url not in json.dumps(metadata) and "private" not in json.dumps(metadata)


@pytest.mark.parametrize("mode", ["slow_body", "slow_headers"])
def test_monotonic_deadline_stops_trickled_body_and_headers(provider, mode):
    url, settings, _ = provider
    settings[mode] = True
    start = time.monotonic()
    raw, metadata = fetch(url, total=0.2)
    elapsed = time.monotonic() - start
    assert raw is None and metadata["status"] == "timeout"
    assert 0.15 <= elapsed < 1


@pytest.mark.parametrize(
    "scheme,addresses",
    [
        ("https", ["93.184.216.34", "10.0.0.1"]),
        ("https", ["::ffff:127.0.0.1"]),
        ("https", ["169.254.169.254"]),
        ("http", ["127.0.0.1", "93.184.216.34"]),
    ],
)
def test_all_dns_answers_must_pass_before_connect(monkeypatch, scheme, addresses):
    monkeypatch.setattr(
        connectors.RESOLVER,
        "resolve",
        lambda *args: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443)) for address in addresses
        ],
    )

    def forbidden(*args):
        pytest.fail("Must not open any socket for a mixed/forbidden DNS answer")

    monkeypatch.setattr(connectors.socket, "socket", forbidden)
    raw, metadata = fetch(
        scheme + "://" + ("localhost" if scheme == "http" else "reports.example") + "/report"
    )
    assert raw is None and metadata["status"] == "fetch_error"


def test_pinned_numeric_connection_preserves_tls_sni_and_host(monkeypatch):
    observed = {}
    wire = io.BytesIO(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n[]"
    )

    class PinnedSocket:
        def settimeout(self, value):
            assert 0 < value <= 3

        def connect(self, address):
            observed["address"] = address

        def sendall(self, raw):
            observed["request"] = raw

        def recv_into(self, buffer):
            return wire.readinto(buffer)

        def close(self):
            observed["closed"] = True

    class TLS:
        def wrap_socket(self, sock, server_hostname):
            observed["sni"] = server_hostname
            return sock

    def resolve(host, port, deadline):
        observed["dns"] = (host, port)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(connectors.RESOLVER, "resolve", resolve)
    monkeypatch.setattr(connectors.socket, "socket", lambda *args: PinnedSocket())
    monkeypatch.setattr(connectors.ssl, "create_default_context", TLS)
    raw, metadata = fetch("https://reports.example:9443/report")
    assert raw == b"[]" and metadata["status"] == "fetched"
    assert observed["address"] == ("93.184.216.34", 9443)
    assert observed["dns"] == ("reports.example", 9443)
    assert observed["sni"] == "reports.example" and observed["closed"]
    assert b"Host: reports.example:9443\r\n" in observed["request"]


def test_dns_timeout_capacity_is_retained_until_os_lookup_finishes(monkeypatch):
    resolver = connectors.BoundedResolver()
    release = threading.Event()

    def stalled(*args, **kwargs):
        assert release.wait(3)
        return []

    monkeypatch.setattr(connectors.socket, "getaddrinfo", stalled)
    try:
        for _ in range(3):
            with pytest.raises(TimeoutError):
                resolver.resolve("reports.example", 443, time.monotonic() + 0.03)
        with pytest.raises(OSError, match="capacity"):
            resolver.resolve("reports.example", 443, time.monotonic() + 1)
        assert resolver.jobs.qsize() <= 3
    finally:
        release.set()
        resolver.jobs.join()


@pytest.mark.parametrize("workers", [1, 2, 3])
def test_fetch_parallelism_capped_with_all_five_reports(monkeypatch, workers):
    active = maximum = 0
    lock = threading.Lock()

    def one(connector, timeouts, deadline):
        nonlocal active, maximum
        with lock:
            active += 1
            maximum = max(maximum, active)
        time.sleep(0.02)
        with lock:
            active -= 1
        return b"[]", {"status": "fetched", "elapsed_ms": 20}

    monkeypatch.setattr(connectors, "fetch_one", one)
    config = default_config()
    config["timeouts"]["workers"] = workers
    reports, metadata = connectors.fetch_all(config)
    assert set(reports) == set(metadata) == set(SCANNERS)
    assert maximum == workers and active == 0
