"""Agent Capsule harness SDK for Python (protocol capsule.v1).

A harness is the program that runs an agent inside its microVM. capsule-init,
the guest supervisor, starts it as an unprivileged user with:

* file descriptor 3: its boot record (JSON: identity, data directory, ...);
* file descriptor 4: a bound Unix listener on which the harness serves the
  private control protocol (health, capabilities, events, invocations, fences).

The harness keeps its state in its own SQLite database in the encrypted data
directory. Each incoming event or invocation is applied exactly once: the
harness's effect, the deduplication marker and the replayable result commit in
one transaction, and a revoked participant ("fence") blocks any later effect.
Outgoing calls to the platform (model, deferred results) go through a second
Unix socket and must never be made inside that transaction.

Only the Python standard library is used. Minimal harness::

    from agentcapsule_harness import Harness, text_result

    harness = Harness()

    @harness.on_invoke
    def invoke(invocation, tx):
        return text_result("echo: " + invocation.text)

    harness.run()

This module mirrors internal/capsuleprotocol and internal/harnessstore in the
Agent Capsule repository; the Go implementation is the reference.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import http.server
import json
import os
import re
import signal
import socket
import socketserver
import sqlite3
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

PROTOCOL = "capsule.v1"
MAX_MESSAGE_BYTES = 1 << 20
MAX_CONTENT_BYTES = 512 << 10
MAX_BOOT_BYTES = 4096
MAX_INVOCATION_ATTACHMENTS = 8
MAX_ATTACHMENT_BYTES = 8 << 20
LLM_CALL_TIMEOUT = 130.0
CALL_TIMEOUT = 20.0

WORKING = {"status": "working"}

_ATTACHMENT_ID = re.compile(r"^att_[0-9a-f]{32}$")
_MEDIA_TYPE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,62}/[a-z0-9][a-z0-9!#$&^_.+-]{0,62}$")
_PROTOCOL_OFFER = re.compile(r"^capsule\.v[1-9][0-9]{0,5}$")


class ProtocolError(Exception):
    """An envelope or record that does not follow capsule.v1."""


class Fenced(Exception):
    """A participant of the event has been revoked in this store."""


class Conflict(Exception):
    """An event ID was reused with a different envelope."""


class CommitUnknown(Exception):
    """The commit outcome is unknown; retry the identical event."""


class PlatformError(Exception):
    """The platform refused a call. code is an enumerated platform code."""

    def __init__(self, code: str):
        super().__init__("capsule platform: " + code)
        self.code = code


# --- boot record -----------------------------------------------------------


@dataclass(frozen=True)
class Identity:
    incarnation: int
    agent_id: str
    generation: int
    vm_id: str
    fence_only: bool = False

    def to_json(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"incarnation": self.incarnation, "agent_id": self.agent_id,
                               "generation": self.generation, "vm_id": self.vm_id}
        if self.fence_only:
            out["fence_only"] = True
        return out

    @classmethod
    def from_json(cls, v: Any) -> "Identity":
        _keys(v, {"incarnation", "agent_id", "generation", "vm_id"}, {"fence_only"})
        incarnation, generation = v["incarnation"], v["generation"]
        agent, vm, fence_only = v["agent_id"], v["vm_id"], v.get("fence_only", False)
        if not (_uint(incarnation) and _uint(generation) and isinstance(agent, str) and isinstance(vm, str)
                and isinstance(fence_only, bool)):
            raise ProtocolError("identity")
        if not agent or len(agent) > 256 or generation == 0 or incarnation == 0 or incarnation > (1 << 63) - 1 \
                or any(ord(c) < 33 or ord(c) > 126 for c in agent):
            raise ProtocolError("identity")
        return cls(incarnation, agent, generation, vm, fence_only)


@dataclass(frozen=True)
class Boot:
    identity: Identity
    data_directory: str
    supervisor_uid: int
    previous_shutdown: str
    platform_socket: str = ""


def read_boot(fd: int = 3) -> Boot:
    """Reads the boot record capsule-init passes on fd 3, strictly."""
    with os.fdopen(fd, "rb", closefd=True) as f:
        raw = f.read(MAX_BOOT_BYTES + 1)
    if len(raw) > MAX_BOOT_BYTES:
        raise ProtocolError("boot record too large")
    v = _strict_json(raw)
    _keys(v, {"protocol", "identity", "data_directory", "supervisor_uid", "previous_shutdown"}, {"platform_socket"})
    identity = Identity.from_json(v["identity"])
    data, uid, previous = v["data_directory"], v["supervisor_uid"], v["previous_shutdown"]
    platform = v.get("platform_socket", "")
    if v["protocol"] != PROTOCOL or not _clean_abs(data) or not _uint(uid) or uid > 0xFFFFFFFF \
            or previous not in ("clean", "unclean") or not isinstance(platform, str):
        raise ProtocolError("boot record")
    if platform and (identity.fence_only or not _clean_abs(platform)):
        raise ProtocolError("boot record")
    return Boot(identity, data, uid, previous, platform)


# --- durable store ---------------------------------------------------------


@dataclass(frozen=True)
class Event:
    id: str
    subjects: List[str]
    body: bytes


_SCHEMA = """
CREATE TABLE IF NOT EXISTS capsule_inbox (
  event_id TEXT PRIMARY KEY NOT NULL,
  envelope_hash BLOB NOT NULL CHECK(length(envelope_hash) = 32),
  result BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS capsule_fences (
  subject TEXT PRIMARY KEY NOT NULL
);
"""


def _go_json(v: Any) -> bytes:
    # encoding/json output, so a store written by the Go reference harness and
    # this one agree on envelope hashes: no spaces, HTML-safe escapes.
    s = json.dumps(v, ensure_ascii=False, separators=(",", ":"))
    s = s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    s = s.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return s.encode("utf-8")


def envelope_hash(event: Event) -> bytes:
    if not event.id or not event.subjects:
        raise ProtocolError("event ID and fence subjects are required")
    subjects = sorted(set(event.subjects))
    if subjects[0] == "":
        raise ProtocolError("empty fence subject")
    canonical = {"Version": 1, "Subjects": subjects, "Body": base64.b64encode(event.body).decode("ascii")}
    return hashlib.sha256(_go_json(canonical)).digest()


class Store:
    """The harness's SQLite database: effects, deduplication and fences.

    Every transaction is BEGIN IMMEDIATE on a connection in WAL mode with
    synchronous=FULL; a result is never acknowledged before its commit.
    Mutation callbacks may only use the connection they receive: no network
    call, no other file, no transaction control, no write to capsule_* tables.
    """

    def __init__(self, path: str):
        if not path or path == ":memory:" or not os.path.isdir(os.path.dirname(os.path.abspath(path))):
            raise ValueError("a durable database file in an existing directory is required")
        self.path = os.path.abspath(path)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        self._local = threading.local()
        conn = self._conn()
        self._begin(conn)
        try:
            # One statement at a time: executescript would commit implicitly.
            for statement in _SCHEMA.split(";"):
                if statement.strip():
                    conn.execute(statement)
            self._commit(conn)
        finally:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
        directory = os.open(os.path.dirname(self.path), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, isolation_level=None, timeout=5.0, check_same_thread=True)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
        return conn

    @staticmethod
    def _begin(conn: sqlite3.Connection) -> None:
        conn.execute("BEGIN IMMEDIATE")
        journal = conn.execute("PRAGMA journal_mode").fetchone()[0]
        synchronous = conn.execute("PRAGMA synchronous").fetchone()[0]
        if str(journal).lower() != "wal" or synchronous != 2:
            conn.execute("ROLLBACK")
            raise RuntimeError("unsafe SQLite settings")

    @staticmethod
    def _commit(conn: sqlite3.Connection) -> None:
        try:
            conn.execute("COMMIT")
        except sqlite3.Error as error:
            raise CommitUnknown(str(error)) from None

    @staticmethod
    def _check_fences(conn: sqlite3.Connection, subjects: List[str]) -> None:
        for subject in subjects:
            if conn.execute("SELECT EXISTS(SELECT 1 FROM capsule_fences WHERE subject=?)", (subject,)).fetchone()[0]:
                raise Fenced(subject)

    def apply(self, event: Event, mutate: Callable[[sqlite3.Connection], bytes]) -> "Receipt":
        """Applies event once; a replay returns the stored result."""
        digest = envelope_hash(event)
        conn = self._conn()
        self._begin(conn)
        committed = False
        try:
            self._check_fences(conn, sorted(set(event.subjects)))
            row = conn.execute("SELECT envelope_hash, result FROM capsule_inbox WHERE event_id=?", (event.id,)).fetchone()
            if row is not None:
                if bytes(row[0]) != digest:
                    raise Conflict(event.id)
                self._commit(conn)
                committed = True
                return Receipt(bytes(row[1]), True)
            result = mutate(conn)
            if result is None:
                result = b""
            conn.execute("INSERT INTO capsule_inbox(event_id, envelope_hash, result) VALUES (?,?,?)",
                          (event.id, digest, result))
            self._commit(conn)
            committed = True
            return Receipt(result, False)
        finally:
            if not committed and conn.in_transaction:
                conn.execute("ROLLBACK")

    def fence(self, subject: str) -> None:
        """Durably and irreversibly revokes subject in this store."""
        if not subject:
            raise ProtocolError("fence subject is required")
        conn = self._conn()
        self._begin(conn)
        try:
            conn.execute("INSERT INTO capsule_fences(subject) VALUES (?) ON CONFLICT(subject) DO NOTHING", (subject,))
            self._commit(conn)
        finally:
            if conn.in_transaction:
                conn.execute("ROLLBACK")

    def local(self, subjects: List[str], mutate: Callable[[sqlite3.Connection], Any]) -> Any:
        """Runs background bookkeeping in one transaction, unless a subject is fenced."""
        if not subjects or any(not s for s in subjects):
            raise ValueError("fence subjects are required")
        conn = self._conn()
        self._begin(conn)
        try:
            self._check_fences(conn, subjects)
            out = mutate(conn)
            self._commit(conn)
            return out
        finally:
            if conn.in_transaction:
                conn.execute("ROLLBACK")


@dataclass(frozen=True)
class Receipt:
    result: bytes
    replayed: bool


# --- envelopes -------------------------------------------------------------


@dataclass(frozen=True)
class Attachment:
    id: str
    name: str
    media_type: str
    size: int
    sha256: str


@dataclass(frozen=True)
class Invocation:
    """An owner's message to the agent (kind message.user)."""

    event_id: str
    operation_id: str
    mandate_id: str
    max_agent_requests: int
    expires_at: str
    content: List[Dict[str, str]]
    attachments: List[Attachment] = field(default_factory=list)

    @property
    def text(self) -> str:
        return "\n".join(c["text"] for c in self.content)


def _valid_subject(s: Any) -> bool:
    if not isinstance(s, str) or len(s.encode()) > 512:
        return False
    prefix, sep, tail = s.partition("/")
    return bool(sep) and tail != "" and prefix in ("agent", "request", "event", "notification")


def _valid_event(identity: Identity, e: Event) -> bool:
    if not e.id or len(e.id.encode()) > 256 or len(e.body) > MAX_CONTENT_BYTES or not 1 <= len(e.subjects) <= 16:
        return False
    return all(_valid_subject(s) for s in e.subjects) and ("agent/" + identity.agent_id) in e.subjects


def _valid_text_content(content: Any) -> bool:
    if not isinstance(content, list) or not 1 <= len(content) <= 32:
        return False
    total = 0
    for c in content:
        if not isinstance(c, dict) or set(c) != {"type", "text"} or c["type"] != "text" or not isinstance(c["text"], str):
            return False
        text = c["text"]
        if not text.strip() or "\x00" in text:
            return False
        try:
            total += len(text.encode("utf-8"))
        except UnicodeEncodeError:
            return False
    return total <= 32 * 1024


def _valid_attachment_name(n: str) -> bool:
    if not n or n in (".", "..") or "/" in n or "\\" in n:
        return False
    try:
        if len(n.encode("utf-8")) > 200:
            return False
    except UnicodeEncodeError:
        return False
    return all(ord(c) >= 0x20 and ord(c) != 0x7F for c in n)


_RFC3339 = re.compile(r"^(\d{4})-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$")


def _rfc3339(v: Any) -> bool:
    # Go writes time.Time as RFC 3339 with up to nine fractional digits; the
    # zero time (year 1) means "unset".
    m = _RFC3339.match(v) if isinstance(v, str) else None
    return m is not None and int(m.group(1)) > 1


def decode_invocation(e: Event, agent_id: str) -> Invocation:
    if len(e.subjects) != 2 or ("agent/" + agent_id) not in e.subjects or ("event/" + e.id) not in e.subjects:
        raise ProtocolError("invocation subjects")
    v = _strict_json(e.body)
    _keys(v, {"kind", "operation_id", "mandate", "content"}, {"attachments"})
    m = v["mandate"]
    _keys(m, {"id", "max_agent_requests", "expires_at"}, set())
    op, kind = v["operation_id"], v["kind"]
    if kind != "message.user" or not isinstance(op, str) or not op or len(op.encode()) > 100 \
            or not isinstance(m["id"], str) or not m["id"] or len(m["id"].encode()) > 100 \
            or not isinstance(m["max_agent_requests"], int) or isinstance(m["max_agent_requests"], bool) \
            or not 1 <= m["max_agent_requests"] <= 3 or not _rfc3339(m["expires_at"]):
        raise ProtocolError("invocation")
    raw_attachments = v.get("attachments") or []
    if not isinstance(raw_attachments, list) or len(raw_attachments) > MAX_INVOCATION_ATTACHMENTS:
        raise ProtocolError("attachments")
    attachments, seen = [], set()
    for a in raw_attachments:
        _keys(a, {"id", "name", "media_type", "size", "sha256"}, set())
        ok = isinstance(a["id"], str) and _ATTACHMENT_ID.match(a["id"]) and isinstance(a["name"], str) \
            and _valid_attachment_name(a["name"]) and isinstance(a["media_type"], str) and _MEDIA_TYPE.match(a["media_type"]) \
            and isinstance(a["size"], int) and not isinstance(a["size"], bool) and 1 <= a["size"] <= MAX_ATTACHMENT_BYTES \
            and isinstance(a["sha256"], str) and re.fullmatch(r"[0-9a-fA-F]{64}", a["sha256"])
        if not ok or a["id"] in seen:
            raise ProtocolError("attachment")
        seen.add(a["id"])
        attachments.append(Attachment(a["id"], a["name"], a["media_type"], a["size"], a["sha256"]))
    if not _valid_text_content(v["content"]):
        raise ProtocolError("content")
    return Invocation(e.id, op, m["id"], m["max_agent_requests"], m["expires_at"], v["content"], attachments)


def _is_invocation(e: Event) -> bool:
    try:
        v = json.loads(e.body)
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(v, dict) and v.get("kind") == "message.user"


def text_result(*texts: str) -> Dict[str, Any]:
    """The usual final answer: text content the requester reads."""
    return {"content": [{"type": "text", "text": t} for t in texts]}


# --- platform channel ------------------------------------------------------


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("harness.local", timeout=timeout)
        self._path = path

    def connect(self) -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


class Platform:
    """Outgoing calls through capsule-init. Each call carries an idempotency
    key: retrying with the same key and body replays the outcome."""

    def __init__(self, identity: Identity, path: str):
        if identity.fence_only or not _clean_abs(path):
            raise ProtocolError("platform channel")
        self.identity = identity
        self.path = path

    def _call(self, route: str, payload: Optional[Dict[str, Any]], timeout: float = CALL_TIMEOUT) -> Dict[str, Any]:
        conn = _UnixHTTPConnection(self.path, timeout)
        try:
            if payload is None:
                conn.request("GET", route, headers={"Content-Type": "application/json"})
            else:
                body = dict(payload, protocol=PROTOCOL, identity=self.identity.to_json())
                raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
                if len(raw) > MAX_MESSAGE_BYTES:
                    raise ProtocolError("request too large")
                conn.request("POST", route, body=raw, headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            data = resp.read(MAX_MESSAGE_BYTES + 1)
        except OSError as error:
            raise PlatformError("unavailable") from error
        finally:
            conn.close()
        if len(data) > MAX_MESSAGE_BYTES:
            raise ProtocolError("response too large")
        out = _strict_json(data)
        if not isinstance(out, dict) or out.get("protocol") != PROTOCOL or Identity.from_json(out.get("identity")) != self.identity:
            raise ProtocolError("response identity")
        if resp.status != 200 or out.get("code"):
            raise PlatformError(str(out.get("code") or "unavailable"))
        return out

    def health(self) -> None:
        self._call("/v1/health", None)

    def complete_llm(self, key: str, alias: str, messages: List[Dict[str, str]], max_tokens: int = 0,
                     temperature: Optional[float] = None) -> Dict[str, Any]:
        """Calls the organization's model through its alias. Returns text,
        finish_reason, input_tokens, output_tokens."""
        llm: Dict[str, Any] = {"alias": alias, "messages": messages}
        if max_tokens:
            llm["max_tokens"] = max_tokens
        if temperature is not None:
            llm["temperature"] = temperature
        out = self._call("/v1/llm/complete", {"idempotency_key": key, "llm": llm}, LLM_CALL_TIMEOUT)
        if not isinstance(out.get("llm_result"), dict):
            raise ProtocolError("llm result")
        return out["llm_result"]

    def complete_invocation(self, key: str, operation_id: str, outcome: str,
                            content: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
        """Posts the outcome of an invocation answered WORKING: "completed"
        with content, or "failed"."""
        completion: Dict[str, Any] = {"operation_id": operation_id, "outcome": outcome}
        if outcome == "completed":
            if not _valid_text_content(content):
                raise ProtocolError("completion content")
            completion["content"] = content
        elif outcome != "failed" or content:
            raise ProtocolError("completion outcome")
        out = self._call("/v1/invocations/complete", {"idempotency_key": key, "completion": completion})
        if not isinstance(out.get("completion"), dict) or out["completion"].get("operation_id") != operation_id:
            raise ProtocolError("completion receipt")
        return out["completion"]


# --- control server --------------------------------------------------------


class _ControlServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    address_family = socket.AF_UNIX

    def __init__(self, sock: socket.socket, handler: type, harness: "Harness"):
        socketserver.BaseServer.__init__(self, "", handler)
        self.socket = sock
        self.harness = harness

    def server_bind(self) -> None:  # the listener is inherited, already bound
        pass

    def server_activate(self) -> None:
        pass

    def get_request(self):
        conn, _ = self.socket.accept()
        return conn, ""


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 20
    server: _ControlServer

    def log_message(self, *args: Any) -> None:  # stdout and stderr are discarded
        pass

    def _peer_is_supervisor(self) -> bool:
        try:
            raw = self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        except OSError:
            return False
        _, uid, _ = struct.unpack("iII", raw)
        return uid == self.server.harness.boot.supervisor_uid

    def _reply(self, status: int, payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> None:
        h = self.server.harness
        body = dict(payload, protocol=PROTOCOL, identity=h.boot.identity.to_json())
        raw = json.dumps(body, separators=(",", ":")).encode("utf-8") + b"\n"
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _code(self, status: int, code: str) -> None:
        self._reply(status, {"code": code})

    def _admitted(self) -> bool:
        if not self._peer_is_supervisor():
            self._code(401, "unauthenticated")
            return False
        if not self.server.harness._slots.acquire(blocking=False):
            self._code(503, "busy")
            return False
        return True

    def do_GET(self) -> None:
        if not self._admitted():
            return
        try:
            path = self.path
            if path.split("?", 1)[0] == "/v1/capabilities":
                self._capabilities()
            elif path == "/v1/health":
                self._reply(200, {"previous_shutdown": self.server.harness.boot.previous_shutdown})
            else:
                self._code(404, "unknown_operation")
        finally:
            self.server.harness._slots.release()

    def do_POST(self) -> None:
        if not self._admitted():
            return
        try:
            if self.path == "/v1/capabilities":
                self._capabilities()
            elif self.path in ("/v1/events", "/v1/invoke", "/v1/fences"):
                self._mutation()
            else:
                self._code(404, "unknown_operation")
        finally:
            self.server.harness._slots.release()

    def _capabilities(self) -> None:
        offers = self.headers.get_all("X-Capsule-Accept-Protocol") or []
        length = self.headers.get("Content-Length")
        if self.command != "GET" or "?" in self.path or (length not in (None, "0")) \
                or self.headers.get("Transfer-Encoding") or len(offers) != 1 or len(offers[0]) > 256:
            self._code(400, "invalid_negotiation")
            return
        versions = [v.strip(" \t") for v in offers[0].split(",")]
        if not 1 <= len(versions) <= 8 or len(set(versions)) != len(versions) \
                or not all(_PROTOCOL_OFFER.match(v) for v in versions) or len(",".join(versions)) > 256:
            self._code(400, "invalid_negotiation")
            return
        if PROTOCOL not in versions:
            self._code(406, "unsupported_protocol")
            return
        features = ["health", "fences"]
        if not self.server.harness.boot.identity.fence_only:
            features += ["events", "invoke.message.user.text"]
        self._reply(200, {"features": features, "limits": {"message_bytes": MAX_MESSAGE_BYTES, "content_bytes": MAX_CONTENT_BYTES}},
                    {"X-Capsule-Protocol": PROTOCOL})

    def _body(self) -> Optional[bytes]:
        length = self.headers.get("Content-Length")
        if self.headers.get("Transfer-Encoding") or length is None or not length.isdigit() or int(length) > MAX_MESSAGE_BYTES:
            return None
        return self.rfile.read(int(length))

    def _mutation(self) -> None:
        h = self.server.harness
        identity = h.boot.identity
        raw = self._body()
        try:
            if raw is None:
                raise ProtocolError("body")
            v = _strict_json(raw)
            _keys(v, {"protocol", "identity"}, {"event", "subject"})
        except ProtocolError:
            self._code(400, "invalid_envelope")
            return
        try:
            same = v["protocol"] == PROTOCOL and Identity.from_json(v["identity"]) == identity
        except ProtocolError:
            same = False
        if not same:
            self._code(403, "wrong_identity")
            return
        try:
            if self.path == "/v1/fences":
                subject = v.get("subject", "")
                if "event" in v or not _valid_subject(subject):
                    raise ProtocolError("fence")
                h.store.fence(subject)
                self._reply(200, {})
                return
            if identity.fence_only:
                self._code(403, "fence_only")
                return
            if v.get("subject") or not isinstance(v.get("event"), dict):
                raise ProtocolError("event")
            event = _decode_event(v["event"])
            if not _valid_event(identity, event):
                raise ProtocolError("event")
            invocation = None
            if self.path == "/v1/invoke":
                invocation = decode_invocation(event, identity.agent_id)
            elif _is_invocation(event):
                raise ProtocolError("invocation sent as an event")
        except ProtocolError:
            self._code(400, "invalid_envelope")
            return
        except Fenced:
            self._code(409, "fenced")
            return
        except CommitUnknown:
            self._code(503, "commit_unknown")
            return
        except Exception:
            self._code(503, "unavailable")
            return
        try:
            receipt = h.store.apply(event, lambda tx: h._dispatch(event, invocation, tx))
        except Fenced:
            self._code(409, "fenced")
            return
        except Conflict:
            self._code(409, "conflict")
            return
        except CommitUnknown:
            self._code(503, "commit_unknown")
            return
        except Exception:
            self._code(503, "unavailable")
            return
        self._reply(200, {"receipt": {"Result": base64.b64encode(receipt.result).decode("ascii"), "Replayed": receipt.replayed}})
        h._wake.set()


def _decode_event(v: Dict[str, Any]) -> Event:
    _keys(v, {"ID", "Subjects", "Body"}, set())
    eid, subjects, body = v["ID"], v["Subjects"], v["Body"]
    if not isinstance(eid, str) or not isinstance(subjects, list) or not all(isinstance(s, str) for s in subjects):
        raise ProtocolError("event")
    if body is None:
        data = b""
    elif isinstance(body, str):
        try:
            data = base64.b64decode(body, validate=True)
        except ValueError:
            raise ProtocolError("event body") from None
    else:
        raise ProtocolError("event body")
    return Event(eid, list(subjects), data)


# --- harness ---------------------------------------------------------------


class Harness:
    """Serves the control protocol and runs the harness's handlers.

    on_invoke(invocation, tx) and on_event(event, tx) run inside the store
    transaction that records the result: they must only use tx (an
    sqlite3.Connection already in a transaction) and return the result, a
    dict or bytes. An invocation result is JSON; return WORKING to answer
    later through platform.complete_invocation. on_background(harness) runs in
    a separate thread after each committed event and periodically, and may
    call the platform; it returns True while it still has work.
    """

    def __init__(self, boot: Optional[Boot] = None, listener_fd: int = 4, database: str = "harness.db"):
        self.boot = boot or read_boot(3)
        self.store = Store(os.path.join(self.boot.data_directory, database))
        self.platform: Optional[Platform] = None
        if self.boot.platform_socket:
            self.platform = Platform(self.boot.identity, self.boot.platform_socket)
        self._listener = socket.socket(fileno=listener_fd)
        self._slots = threading.BoundedSemaphore(16)
        self._invoke: Optional[Callable[[Invocation, sqlite3.Connection], Any]] = None
        self._event: Optional[Callable[[Event, sqlite3.Connection], Any]] = None
        self._background: Optional[Callable[["Harness"], bool]] = None
        self._wake = threading.Event()
        self._stop = threading.Event()

    @property
    def agent_id(self) -> str:
        return self.boot.identity.agent_id

    def on_invoke(self, fn: Callable[[Invocation, sqlite3.Connection], Any]) -> Callable:
        self._invoke = fn
        return fn

    def on_event(self, fn: Callable[[Event, sqlite3.Connection], Any]) -> Callable:
        self._event = fn
        return fn

    def on_background(self, fn: Callable[["Harness"], bool]) -> Callable:
        self._background = fn
        return fn

    def _dispatch(self, event: Event, invocation: Optional[Invocation], tx: sqlite3.Connection) -> bytes:
        if invocation is not None:
            if self._invoke is None:
                raise ProtocolError("no invocation handler")
            result = self._invoke(invocation, tx)
            raw = result if isinstance(result, bytes) else json.dumps(result, separators=(",", ":")).encode("utf-8")
            json.loads(raw)  # an invocation result must be JSON
        else:
            if self._event is None:
                raise ProtocolError("no event handler")
            result = self._event(event, tx)
            raw = result if isinstance(result, bytes) else json.dumps(result, separators=(",", ":")).encode("utf-8")
        if len(raw) > MAX_CONTENT_BYTES:
            raise ProtocolError("result too large")
        return raw

    def _background_loop(self) -> None:
        delay = 1.0
        while not self._stop.is_set():
            self._wake.wait(timeout=delay)
            self._wake.clear()
            if self._stop.is_set() or self._background is None:
                continue
            try:
                busy = self._background(self)
                delay = 0.05 if busy else 5.0
            except Exception:
                delay = min(delay * 2, 30.0) if delay >= 1.0 else 1.0

    def run(self) -> None:
        """Serves until capsule-init sends SIGTERM, then drains and returns."""
        server = _ControlServer(self._listener, _Handler, self)
        stopping = threading.Event()

        def terminate(*_: Any) -> None:
            if not stopping.is_set():
                stopping.set()
                self._stop.set()
                self._wake.set()
                threading.Thread(target=server.shutdown, daemon=True).start()

        signal.signal(signal.SIGTERM, terminate)
        signal.signal(signal.SIGINT, terminate)
        worker = threading.Thread(target=self._background_loop, daemon=True)
        worker.start()
        self._wake.set()
        try:
            server.serve_forever(poll_interval=0.2)
        finally:
            self._stop.set()
            self._wake.set()
            server.server_close()
            worker.join(timeout=10)
            # Let in-flight requests (bounded by the slots) finish their commit.
            deadline = time.monotonic() + 5
            acquired = 0
            while acquired < 16 and time.monotonic() < deadline:
                if self._slots.acquire(timeout=0.1):
                    acquired += 1


# --- helpers ---------------------------------------------------------------


def _strict_json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw)
    except (ValueError, UnicodeDecodeError):
        raise ProtocolError("JSON") from None


def _keys(v: Any, required: set, optional: set) -> None:
    if not isinstance(v, dict) or not required.issubset(v) or not set(v).issubset(required | optional):
        raise ProtocolError("unexpected fields")


def _uint(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _clean_abs(p: Any) -> bool:
    return isinstance(p, str) and p.startswith("/") and os.path.normpath(p) == p
