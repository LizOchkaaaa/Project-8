import json
import os
import re
import secrets
import tempfile
from pathlib import Path
from threading import Lock

from security_assistant.model import MAX_PROFILE_TIMEOUT, endpoint
from security_assistant.parsers import strict_json
from security_assistant.runtime import ConfigError

PROFILE_LIMIT = 16 * 1024
PROFILE_FIELDS = {"endpoint", "model", "timeout"}
DEFAULT_PROFILE = {"endpoint": None, "model": None, "timeout": 30, "revision": "0"}


def validate_profile(profile):
    base, model, timeout = (profile[field] for field in ("endpoint", "model", "timeout"))
    if (
        not isinstance(base, str)
        or not 1 <= len(base) <= 2000
        or not base.isascii()
        or not base.isprintable()
        or any(character in base for character in "?#@")
        or not isinstance(model, str)
        or not 1 <= len(model) <= 200
        or not model.isprintable()
        or model != model.strip()
        or type(timeout) is not int
        or not 1 <= timeout <= MAX_PROFILE_TIMEOUT
    ):
        raise ValueError("Invalid model profile")
    endpoint(base)
    return {"endpoint": base.rstrip("/"), "model": model, "timeout": timeout}


class ModelProfile:
    def __init__(self, path):
        self.path = path
        self.lock = Lock()
        self.credential = None

    def _read(self):
        try:
            if self.path.is_symlink() or self.path.parent.is_symlink():
                raise ValueError("Invalid model profile file")
            with self.path.open("rb") as stream:
                stored = strict_json(stream.read(PROFILE_LIMIT + 1), PROFILE_LIMIT)
            if (
                not isinstance(stored, dict)
                or stored.keys() != PROFILE_FIELDS | {"revision"}
                or not isinstance(stored["revision"], str)
                or not re.fullmatch(r"[0-9a-f]{32}", stored["revision"])
            ):
                raise ValueError("Invalid model profile file")
            return {**validate_profile(stored), "revision": stored["revision"]}
        except FileNotFoundError:
            return DEFAULT_PROFILE
        except (OSError, ValueError, TypeError, RecursionError):
            raise ConfigError() from None

    def _key(self, profile):
        if self.credential and self.credential[:2] == (profile["endpoint"], profile["revision"]):
            return self.credential[2]
        self.credential = None
        return ""

    def snapshot(self):
        with self.lock:
            profile = self._read()
            return {**profile, "has_api_key": bool(self._key(profile))}

    def update(self, data):
        if not isinstance(data, dict) or data.keys() - {"api_key"} != PROFILE_FIELDS:
            raise ValueError("Invalid model profile fields")
        profile = validate_profile(data)
        key = data.get("api_key", "")
        if (
            not isinstance(key, str)
            or len(key) > 4096
            or any(not 33 <= ord(character) <= 126 for character in key)
        ):
            raise ValueError("Invalid model credential")
        with self.lock:
            previous_key = self.credential[2] if self.credential else ""
            if any(
                secret and secret in value
                for secret in (key, previous_key)
                for value in (profile["endpoint"], profile["model"])
            ):
                raise ValueError("Model profile metadata cannot contain the credential")
            if "api_key" not in data and self.credential:
                current = self._read()
                if current["endpoint"] == profile["endpoint"]:
                    key = self._key(current)
            revision = secrets.token_hex(16)
            profile["revision"] = revision
            self._write(profile)
            self.credential = (profile["endpoint"], revision, key) if key else None
            return {**profile, "has_api_key": bool(key)}

    def _write(self, profile):
        temporary = None
        try:
            if self.path.is_symlink() or self.path.parent.is_symlink():
                raise OSError("Invalid model profile file")
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                with tempfile.NamedTemporaryFile(
                    dir=self.path.parent, prefix=".model-", delete=False
                ) as stream:
                    temporary = Path(stream.name)
                    stream.write(json.dumps(profile).encode("ascii"))
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.path)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
        except OSError:
            raise ConfigError("config_write_failed", 503) from None

    def clear(self):
        with self.lock:
            self.credential = None
            try:
                if self.path.parent.is_symlink():
                    raise OSError("Invalid model profile directory")
                self.path.unlink(missing_ok=True)
            except OSError:
                raise ConfigError("config_write_failed", 503) from None
            return {**DEFAULT_PROFILE, "has_api_key": False}

    def resolve(self, revision):
        with self.lock:
            profile = self._read()
            if revision != profile["revision"]:
                raise ConfigError("revision_conflict", 409)
            key = self._key(profile)
            if not key:
                return None
            return {
                "OPENAI_BASE_URL": profile["endpoint"],
                "OPENAI_MODEL": profile["model"],
                "OPENAI_TIMEOUT": profile["timeout"],
                "OPENAI_API_KEY": key,
            }
