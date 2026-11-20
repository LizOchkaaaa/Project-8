"""GET-only report transport: vetted addresses, pinned sockets and bounded reads."""

import concurrent.futures
import http.client
import io
import ipaddress
import os
import queue
import socket
import ssl
import threading
import time
from urllib.parse import unquote_to_bytes, urlsplit

from .parsers import MAX_BYTES, SCANNERS, strict_json


def normalized_ip(value):
    address = ipaddress.ip_address(value)
    return (
        address.ipv4_mapped
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped
        else address
    )


def allowed_ip(value, scheme):
    address = normalized_ip(value)
    if scheme == "http":
        return address.is_loopback
    return address.is_global and not (
        address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
    )


def validate_url(url):
    if (
        type(url) is not str
        or not url
        or len(url) > 2000
        or not url.isascii()
        or any(ord(c) <= 32 or ord(c) == 127 for c in url)
        or any(c in url for c in ("\\", "?", "#"))
    ):
        raise ValueError("Invalid connector URL")
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port == 0
        or parsed.netloc.endswith(":")
    ):
        raise ValueError("Invalid connector URL")
    host = parsed.hostname
    path = parsed.path
    for index, character in enumerate(path):
        if character == "%" and (
            index + 2 >= len(path)
            or any(c not in "0123456789abcdefABCDEF" for c in path[index + 1 : index + 3])
        ):
            raise ValueError("Invalid URL encoding")
    if any(byte < 32 or byte in (92, 127) for byte in unquote_to_bytes(path)):
        raise ValueError("Invalid URL path")
    try:
        permitted = allowed_ip(host, parsed.scheme)
    except ValueError:
        permitted = parsed.scheme == "https" or host == "localhost"
        if not all(c.isalnum() or c in ".-" for c in host) or host.endswith("."):
            permitted = False
    if not permitted:
        raise ValueError("Invalid connector destination")
    return parsed


class BoundedResolver:
    """A timed-out OS lookup retains a slot until it really finishes."""

    def __init__(self):
        self.slots = threading.BoundedSemaphore(3)
        self.jobs = queue.Queue(maxsize=3)
        self.lock = threading.Lock()
        self.started = False

    def _worker(self):
        while True:
            future, host, port = self.jobs.get()
            try:
                future.set_result(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
            except Exception:
                future.set_exception(OSError("DNS unavailable"))
            finally:
                self.slots.release()
                self.jobs.task_done()

    def resolve(self, host, port, deadline):
        remaining(deadline)
        if not self.slots.acquire(blocking=False):
            raise OSError("DNS capacity exhausted")
        with self.lock:
            if not self.started:
                # OS DNS cannot be cancelled; three daemon workers bound lingering lookups.
                for _ in range(3):
                    threading.Thread(target=self._worker, daemon=True, name="report-dns").start()
                self.started = True
        future = concurrent.futures.Future()
        self.jobs.put_nowait((future, host, port))
        return future.result(timeout=remaining(deadline))


RESOLVER = BoundedResolver()
FETCH_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=3, thread_name_prefix="report-get")


def remaining(deadline, idle=None):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError("Report deadline exceeded")
    return min(value, idle) if idle is not None else value


class DeadlineReader(io.RawIOBase):
    def __init__(self, sock, deadline, idle):
        self.sock, self.deadline, self.idle = sock, deadline, idle
        self.received = 0
        self.reading_headers = True

    def readable(self):
        return True

    def readinto(self, buffer):
        self.sock.settimeout(remaining(self.deadline, self.idle))
        size = self.sock.recv_into(buffer)
        remaining(self.deadline)
        self.received += size
        if self.reading_headers and self.received > 64 * 1024:
            raise ValueError("Response headers too large")
        if self.received > MAX_BYTES + 64 * 1024:
            raise ValueError("Response too large")
        return size


class ResponseSocket:
    def __init__(self, sock, deadline, idle):
        self.reader = io.BufferedReader(DeadlineReader(sock, deadline, idle))

    def makefile(self, *args, **kwargs):
        return self.reader


def fetch_report(connector, timeouts, deadline):
    remaining(deadline)
    parsed = validate_url(connector["url"])
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    credential = None
    if connector["credential_env"] is not None:
        credential = os.environ.get(connector["credential_env"], "")
        if (
            not credential
            or len(credential) > 4096
            or not credential.isascii()
            or any(ord(c) < 33 or ord(c) > 126 for c in credential)
        ):
            return None, "credential_error"
    addresses = RESOLVER.resolve(parsed.hostname, port, deadline)
    if not addresses or any(not allowed_ip(row[4][0], parsed.scheme) for row in addresses):
        raise ValueError("Forbidden DNS answer")
    # All answers are vetted, then one numeric sockaddr is used without another DNS lookup.
    family, kind, protocol, _, sockaddr = addresses[0]
    if family not in {socket.AF_INET, socket.AF_INET6}:
        raise ValueError("Invalid address family")
    connect_deadline = min(deadline, time.monotonic() + timeouts["connect_seconds"])
    sock = socket.socket(family, kind, protocol)
    try:
        sock.settimeout(remaining(connect_deadline))
        sock.connect(sockaddr)
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            sock.settimeout(remaining(connect_deadline))
            sock = context.wrap_socket(sock, server_hostname=parsed.hostname)
        headers = [
            f"GET {parsed.path or '/'} HTTP/1.1",
            f"Host: {parsed.netloc}",
            "Accept: application/json",
            "Accept-Encoding: identity",
            "Connection: close",
        ]
        if credential:
            headers.append("Authorization: Bearer " + credential)
        sock.settimeout(remaining(deadline, timeouts["read_seconds"]))
        sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
        transport = ResponseSocket(sock, deadline, timeouts["read_seconds"])
        with http.client.HTTPResponse(transport) as response:
            response.begin()
            transport.reader.raw.reading_headers = False
            if (
                response.status != 200
                or response.headers.get_content_type() != "application/json"
                or response.headers.get("Content-Encoding", "identity").lower() != "identity"
                or response.headers.get("Transfer-Encoding", "").lower() not in {"", "chunked"}
            ):
                raise ValueError("Invalid response")
            lengths = response.headers.get_all("Content-Length", [])
            if len(lengths) > 1 or (
                lengths and (not lengths[0].isdigit() or int(lengths[0]) > MAX_BYTES)
            ):
                raise ValueError("Invalid response size")
            if lengths and response.headers.get("Transfer-Encoding"):
                raise ValueError("Ambiguous framing")
            data = bytearray()
            while True:
                remaining(deadline)
                chunk = response.read1(min(64 * 1024, MAX_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > MAX_BYTES:
                    raise ValueError("Response too large")
            if lengths and len(data) != int(lengths[0]):
                raise ValueError("Truncated response")
        remaining(deadline)
        decoded = strict_json(bytes(data), MAX_BYTES)
        if credential and (credential.encode() in data or contains_credential(decoded, credential)):
            return None, "credential_reflection"
        remaining(deadline)
        return bytes(data), "fetched"
    finally:
        sock.close()


def contains_credential(value, credential):
    if isinstance(value, str):
        return credential in value
    if isinstance(value, dict):
        return any(
            credential in key or contains_credential(item, credential)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(contains_credential(item, credential) for item in value)
    return False


def fetch_one(connector, timeouts, deadline):
    start = time.monotonic()
    raw = None
    if not connector["enabled"]:
        status = "disabled"
    else:
        try:
            raw, status = fetch_report(connector, timeouts, deadline)
        except TimeoutError:
            status = "timeout"
        except (OSError, ValueError, TypeError, http.client.HTTPException, RecursionError):
            status = "fetch_error"
    return raw, {"status": status, "elapsed_ms": round((time.monotonic() - start) * 1000)}


def fetch_all(config):
    """Only the admitted analysis submits work; at most three futures exist."""
    timeouts = config["timeouts"]
    deadline = time.monotonic() + timeouts["total_seconds"]
    reports, metadata = {}, {}
    workers = timeouts["workers"]
    names = iter(SCANNERS)
    futures = {}
    for name in names:
        futures[FETCH_POOL.submit(fetch_one, config["connectors"][name], timeouts, deadline)] = name
        if len(futures) == workers:
            break
    while futures:
        completed, _ = concurrent.futures.wait(
            futures, return_when=concurrent.futures.FIRST_COMPLETED
        )
        for future in completed:
            name = futures.pop(future)
            raw, metadata[name] = future.result()
            if raw is not None:
                reports[name] = raw
            next_name = next(names, None)
            if next_name is not None:
                futures[
                    FETCH_POOL.submit(
                        fetch_one, config["connectors"][next_name], timeouts, deadline
                    )
                ] = next_name
    return reports, metadata
