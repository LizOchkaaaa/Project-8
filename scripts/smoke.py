"""HTTP smoke учебного контейнера без внешних зависимостей."""

import argparse
import json
import urllib.request
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Smoke ephemeral учебного стенда")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--image-id", required=True)
    args = parser.parse_args()

    def request(path, method="GET", data=None):
        req = urllib.request.Request(
            "http://127.0.0.1:8000" + path,
            method=method,
            data=json.dumps(data).encode() if data is not None else None,
            headers={"Content-Type": "application/json"},
        )
        # Origin фиксирован и доступен только на loopback учебного runner.
        with urllib.request.urlopen(req, timeout=5) as response:  # nosec B310
            return response.status, response.read(65536)

    checks = []
    for path in ("/", "/security", "/health"):
        status, body = request(path)
        if status != 200 or not body:
            raise RuntimeError("HTTP smoke failed")
        if path == "/health" and json.loads(body) != {"status": "ok"}:
            raise RuntimeError("Health smoke failed")
        checks.append(path)
    status, raw = request("/api/items", "POST", {"text": "deployment smoke"})
    created = json.loads(raw)
    if status != 201 or created["text"] != "deployment smoke":
        raise RuntimeError("Create smoke failed")
    _, raw = request("/api/items")
    if created not in json.loads(raw)["items"]:
        raise RuntimeError("Read smoke failed")
    status, _ = request(f"/api/items/{created['id']}", "DELETE")
    _, raw = request("/api/items")
    if status != 200 or created in json.loads(raw)["items"]:
        raise RuntimeError("Delete smoke failed")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            {
                "deployment": "ephemeral educational runner",
                "commit": args.commit,
                "image_id": args.image_id,
                "checks": checks + ["API create/read/delete"],
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
