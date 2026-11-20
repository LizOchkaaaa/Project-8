"""Strict, non-secret runtime settings for the single-process local service."""

import copy
import json
import os
import tempfile
import threading
import uuid
from pathlib import Path

from .connectors import validate_url
from .parsers import SCANNERS, strict_json
from .policy import validate_policy

CONFIG_LIMIT = 64 * 1024
PROTOCOL_VERSION = "2025-11-25"


class ConfigError(ValueError):
    def __init__(self, code="config_unavailable", status=503):
        self.code, self.status = code, status
        super().__init__(code)


def credential_name(scanner):
    return "PROJECT8_CONNECTOR_" + scanner.upper().replace("-", "_") + "_TOKEN"


def default_config():
    return {
        "schema_version": 1,
        "thresholds": dict(zip(SCANNERS, ("low", "medium", "high", "high", "medium"))),
        "connectors": {
            name: {"enabled": False, "url": "", "credential_env": None} for name in SCANNERS
        },
        "timeouts": {"connect_seconds": 3, "read_seconds": 5, "total_seconds": 15, "workers": 3},
    }


def effective_policy(config):
    return validate_policy(
        {
            "version": 1,
            "required_scanners": list(SCANNERS),
            "fail_closed": True,
            "block_secrets": True,
            "block_unknown": True,
            "thresholds": copy.deepcopy(config["thresholds"]),
        }
    )


def exact_keys(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError("Invalid fields")


def validate_config(config):
    exact_keys(config, ("schema_version", "thresholds", "connectors", "timeouts"))
    if type(config["schema_version"]) is not int or config["schema_version"] != 1:
        raise ValueError("Invalid version")
    effective_policy(config)
    exact_keys(config["connectors"], SCANNERS)
    for name, connector in config["connectors"].items():
        exact_keys(connector, ("enabled", "url", "credential_env"))
        if type(connector["enabled"]) is not bool or type(connector["url"]) is not str:
            raise ValueError("Invalid connector")
        if connector["credential_env"] not in (None, credential_name(name)):
            raise ValueError("Invalid credential reference")
        if connector["url"] or connector["enabled"]:
            validate_url(connector["url"])
    bounds = {
        "connect_seconds": (1, 3),
        "read_seconds": (1, 5),
        "total_seconds": (1, 15),
        "workers": (1, 3),
    }
    exact_keys(config["timeouts"], bounds)
    for name, (low, high) in bounds.items():
        value = config["timeouts"][name]
        if type(value) is not int or not low <= value <= high:
            raise ValueError("Invalid timeout")
    return config


class RuntimeConfig:
    def __init__(self, path):
        self.path = Path(path).absolute()
        self.lock = threading.Lock()

    def _read(self):
        try:
            if self.path.is_symlink() or self.path.parent.is_symlink():
                raise ValueError("Invalid config file")
            with self.path.open("rb") as stream:
                stored = strict_json(stream.read(CONFIG_LIMIT + 1), CONFIG_LIMIT)
            exact_keys(stored, ("revision", "config"))
            revision = stored["revision"]
            if (
                type(revision) is not str
                or len(revision) != 32
                or any(c not in "0123456789abcdef" for c in revision)
            ):
                raise ValueError("Invalid revision")
            validate_config(stored["config"])
            return stored
        except FileNotFoundError:
            return {"revision": "0", "config": default_config()}
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            raise ConfigError() from None

    def snapshot(self):
        with self.lock:
            stored = self._read()
            return {**stored, "effective_policy": effective_policy(stored["config"])}

    def update(self, config, revision):
        try:
            validate_config(config)
            config = copy.deepcopy(config)
        except (ValueError, TypeError, KeyError, RecursionError):
            raise ConfigError("invalid_config", 400) from None
        with self.lock:
            current = self._read()
            if revision != current["revision"]:
                raise ConfigError("revision_conflict", 409)
            stored = {"revision": uuid.uuid4().hex, "config": config}
            raw = json.dumps(stored, ensure_ascii=True, allow_nan=False).encode()
            if len(raw) > CONFIG_LIMIT:
                raise ConfigError("invalid_config", 400)
            temporary = None
            try:
                self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                descriptor, temporary = tempfile.mkstemp(prefix=".runtime-", dir=self.path.parent)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.path)
            except OSError:
                raise ConfigError("config_write_failed", 503) from None
            finally:
                if temporary and os.path.exists(temporary):
                    try:
                        os.unlink(temporary)
                    except OSError:
                        raise ConfigError("config_write_failed", 503) from None
            return {**stored, "effective_policy": effective_policy(config)}
