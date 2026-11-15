"""One admission gate and one runtime policy snapshot for every external adapter."""

import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from .analysis import analyze
from .connectors import fetch_all
from .parsers import MAX_BYTES, SCANNERS, strict_json
from .policy import validate_policy

ANALYSIS_GATE = threading.BoundedSemaphore(1)


class BusyError(Exception):
    pass


class AnalysisService:
    def __init__(self, store):
        self.store = store

    @contextmanager
    def admission(self):
        if not ANALYSIS_GATE.acquire(blocking=False):
            raise BusyError()
        try:
            snapshot = self.store.snapshot()
            validate_policy(snapshot["effective_policy"])
            yield snapshot
        finally:
            ANALYSIS_GATE.release()

    def process(self, reports, snapshot, *, offline=True, model_config=None, analyzer=analyze):
        start = time.monotonic()
        validate_policy(snapshot["effective_policy"])
        if not reports.keys() <= set(SCANNERS) or sum(map(len, reports.values())) > 5 * MAX_BYTES:
            raise ValueError("Invalid reports")
        with tempfile.TemporaryDirectory(prefix="project8-reports-") as directory:
            for name, raw in reports.items():
                if not raw or len(raw) > MAX_BYTES:
                    raise ValueError("Invalid report size")
                try:
                    strict_json(raw, MAX_BYTES)
                except (ValueError, TypeError, RecursionError):
                    raw = b"!"  # Preserve the parser's fail-closed invalid-report state.
                (Path(directory) / f"{name}.json").write_bytes(raw)
            result = analyzer(
                directory,
                offline=offline,
                config=model_config or {},
                policy=snapshot["effective_policy"],
            )
        result["runtime_revision"] = snapshot["revision"]
        result["duration_ms"] = round((time.monotonic() - start) * 1000)
        return result

    def run_tools(self, snapshot):
        start = time.monotonic()
        reports, metadata = fetch_all(snapshot["config"])
        result = self.process(reports, snapshot)
        result["duration_ms"] = round((time.monotonic() - start) * 1000)
        result["tool_fetch"] = {"connectors": metadata}
        return result
