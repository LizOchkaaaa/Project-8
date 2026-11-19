"""Private, local archive of completed server analyses (never raw scanner files)."""

import json
import sqlite3
import uuid
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path

from flask import jsonify, request

from app.local_security import api_error

PAGE_SIZE = 25


class ReportHistory:
    def __init__(self, path):
        self.path = Path(path)

    @contextmanager
    def connection(self):
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS report (
                id TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL, source TEXT NOT NULL,
                passed INTEGER NOT NULL, groups_count INTEGER NOT NULL, scanners TEXT NOT NULL,
                result TEXT NOT NULL)""")
            db.execute("CREATE INDEX IF NOT EXISTS report_gate ON report(passed)")
            yield db

    def save(self, result, source, scanners):
        report_id = uuid.uuid4().hex
        with self.connection() as db:
            db.execute(
                "INSERT INTO report VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    report_id,
                    datetime.now(UTC).isoformat(timespec="seconds"),
                    source,
                    int(result["gate"]["status"] == "passed"),
                    len(result["groups"]),
                    json.dumps(sorted(scanners)),
                    json.dumps(result, ensure_ascii=False, separators=(",", ":")),
                ),
            )
        return report_id

    def page(self, gate, offset):
        passed = None if gate == "all" else int(gate == "pass")
        with self.connection() as db:
            rows = db.execute(
                "SELECT id, created_at, source, passed, groups_count, scanners FROM report"
                " WHERE ? IS NULL OR passed = ? ORDER BY rowid DESC LIMIT ? OFFSET ?",
                (passed, passed, PAGE_SIZE + 1, offset),
            ).fetchall()
        return {
            "items": [
                dict(
                    id=i,
                    created_at=t,
                    source=s,
                    passed=bool(p),
                    groups_count=g,
                    scanners=json.loads(names),
                )
                for i, t, s, p, g, names in rows[:PAGE_SIZE]
            ],
            "next_offset": offset + PAGE_SIZE if len(rows) > PAGE_SIZE else None,
        }

    def read(self, report_id):
        with self.connection() as db:
            row = db.execute("SELECT result FROM report WHERE id = ?", (report_id,)).fetchone()
        return json.loads(row[0]) if row else None


def register_history(app, history, authorized):
    @app.get("/api/security/history")
    def list_history():
        if not authorized():
            return api_error("forbidden", 403)
        gate = request.args.get("gate", "all")
        offset = request.args.get("offset", "0")
        if gate not in {"all", "pass", "fail"} or not (
            offset.isascii() and offset.isdigit() and len(offset) <= 12
        ):
            return jsonify(error="Некорректный фильтр или номер страницы."), 400
        try:
            return jsonify(history.page(gate, int(offset)))
        except (OSError, sqlite3.Error, ValueError):
            return jsonify(error="Не удалось прочитать журнал."), 503

    @app.get("/api/security/history/<report_id>")
    def read_history(report_id):
        if not authorized():
            return api_error("forbidden", 403)
        try:
            data = history.read(report_id) if len(report_id) == 32 else None
        except (OSError, sqlite3.Error, ValueError):
            return jsonify(error="Не удалось прочитать журнал."), 503
        if data is None:
            return jsonify(error="Отчёт не найден в журнале."), 404
        return jsonify(data)
