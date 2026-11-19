"""HTTP smoke учебного контейнера без внешних зависимостей."""

import argparse
import json
import re
import urllib.request
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Smoke ephemeral учебного стенда")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--image-id", required=True)
    args = parser.parse_args()

    def request(path, method="GET", data=None, headers=None):
        req = urllib.request.Request(
            "http://127.0.0.1:8000" + path,
            method=method,
            data=data
            if isinstance(data, bytes)
            else json.dumps(data).encode()
            if data is not None
            else None,
            headers=headers or {"Content-Type": "application/json"},
        )
        # Origin фиксирован и доступен только на loopback учебного runner.
        with urllib.request.urlopen(req, timeout=5) as response:  # nosec B310
            return response.status, response.read(65536), response.headers

    checks = []
    for path in ("/", "/security", "/health"):
        status, body, _ = request(path)
        if status != 200 or not body:
            raise RuntimeError("HTTP smoke failed")
        if path == "/health" and json.loads(body) != {"status": "ok"}:
            raise RuntimeError("Health smoke failed")
        checks.append(path)
    status, raw, _ = request("/api/items", "POST", {"text": "deployment smoke"})
    created = json.loads(raw)
    if status != 201 or created["text"] != "deployment smoke":
        raise RuntimeError("Create smoke failed")
    _, raw, _ = request("/api/items")
    if created not in json.loads(raw)["items"]:
        raise RuntimeError("Read smoke failed")
    status, _, _ = request(f"/api/items/{created['id']}", "DELETE")
    _, raw, _ = request("/api/items")
    if status != 200 or created in json.loads(raw)["items"]:
        raise RuntimeError("Delete smoke failed")
    _, desk, _ = request("/security")
    match = re.search(rb'data-token="([A-Za-z0-9_-]+)"', desk)
    if match is None:
        raise RuntimeError("Local audit page cannot authorize requests")
    token_header = {"X-Assistant-Token": match[1].decode("ascii")}
    status, profile, _ = request("/api/security/model-profile", headers=token_header)
    if status != 200 or json.loads(profile)["has_api_key"] is not False:
        raise RuntimeError("Model profile smoke failed")
    report_body = (
        b'--report-smoke\r\nContent-Disposition: form-data; name="reports"; filename="bandit.json"\r\n'
        b"Content-Type: application/json\r\n\r\n"
        b'{"errors":[],"metrics":{"_totals":{"loc":1}},"results":[]}\r\n--report-smoke--\r\n'
    )
    status, report, headers = request(
        "/api/security/analyze",
        "POST",
        report_body,
        {**token_header, "Content-Type": "multipart/form-data; boundary=report-smoke"},
    )
    report_id = headers.get("X-Report-Id", "")
    if (
        status != 200
        or json.loads(report)["gate"]["status"] != "blocked"
        or not re.fullmatch(r"[a-f0-9]{32}", report_id)
    ):
        raise RuntimeError("Incomplete report must be blocked and saved in the journal")
    status, stored, _ = request(f"/api/security/history/{report_id}", headers=token_header)
    if status != 200 or json.loads(stored)["result"] != json.loads(report):
        raise RuntimeError("Report journal smoke failed")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            {
                "deployment": "ephemeral educational runner",
                "commit": args.commit,
                "image_id": args.image_id,
                "checks": checks
                + ["API create/read/delete", "model profile", "report upload and journal"],
                "status": "passed",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print("Ephemeral учебный стенд: HTTP/API smoke пройден.")


if __name__ == "__main__":
    main()
