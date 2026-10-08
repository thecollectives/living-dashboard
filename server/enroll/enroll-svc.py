#!/usr/bin/env python3
"""Living dashboard enrollment service — backend for the Add-host flow.

Listens on a unix socket (LIVING_ENROLL_SOCK, default
/home/brrew/srv/living/sock/enroll.sock), proxied by dash-nginx at
/living/enroll/ via `proxy_pass http://unix:...` — the same pattern as
the teamchat/litellm-proxy sockets. No TCP surface at all: a container's
127.0.0.1 is not the host's loopback, and the host firewall drops
container-to-host TCP, so a TCP bind is unreachable from dash-nginx.
Falls back to TCP (LIVING_ENROLL_BIND/LIVING_ENROLL_PORT) only when
LIVING_ENROLL_SOCK is unset.

Endpoints:
  POST /jobs          {host, port, username, label?, auth:{type,password|key}}
                      -> 202 {job_id, status:"running"} — runs enroll_ssh.sh
                         asynchronously, streams its stdout as the job log.
  GET  /jobs          recent jobs (no secrets, no logs)
  GET  /jobs/<id>     {job_id, status, stage, log[], ...}
  POST /tokens        {label?} -> {token, label, expires_at, one_liners}
                      mints a single-use token for the copy-paste flow.
  DELETE /hosts/<id>  remove a host and all its inventory, events,
                      bookmarks, scans and history (one transaction), and
                      revoke its host_id so stray agent check-ins and
                      re-enrollment with the same id are rejected.
  GET  /health        {ok:true}

Credential handling (strict):
  - The SSH password / private key lives ONLY in process memory and in
    600-perm temp files that are deleted the moment the SSH session ends.
  - It is never written to disk unencrypted elsewhere, never logged,
    never stored in the DB, never echoed in any response.
  - All subprocess calls use arg arrays — no shell, no string
    interpolation of user input.

Stdlib only. Run as the brrew user (needs docker access for mint-token.sh
and SSH access to targets).
"""
import json
import os
import re
import select
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Transport: unix socket by default (see module docstring). TCP fallback
# kept for local testing: set LIVING_ENROLL_SOCK="" and
# LIVING_ENROLL_BIND/LIVING_ENROLL_PORT as needed.
SOCK_PATH = os.environ.get("LIVING_ENROLL_SOCK",
                           "/home/brrew/srv/living/sock/enroll.sock")
LISTEN_HOST = os.environ.get("LIVING_ENROLL_BIND", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("LIVING_ENROLL_PORT", "8097"))
LIVING_DIR = os.environ.get("LIVING_DIR", "/home/brrew/srv/living")
ENROLL_SCRIPT = os.environ.get(
    "LIVING_ENROLL_SCRIPT",
    os.path.join(LIVING_DIR, "repo", "installer", "enroll_ssh.sh"),
)
MINT_SCRIPT = os.path.join(LIVING_DIR, "repo", "installer", "mint-token.sh")
INSTALL_BASE = "http://100.104.7.48:8092/install"

JOB_TIMEOUT_S = 420
MAX_BODY = 65536
MAX_JOBS = 50
MAX_CONCURRENT = 3
MAX_LOG_LINES = 500

HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")
IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
IPV6_RE = re.compile(r"^\[([0-9a-fA-F:]+)\]$")
USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
LABEL_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
TOKEN_RE = re.compile(r"TOKEN=([0-9a-f]{32})")
HOST_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# Single-transaction host removal. Children before parents to satisfy
# the FKs (bookmarks->events, events->scans, everything->hosts).
# : 'hid' is psql's safely-quoted variable interpolation; the UUID
# regex above makes injection impossible regardless.
DELETE_HOST_SQL = """\
BEGIN;
INSERT INTO host_revocations (host_id, reason)
  VALUES (:'hid', 'removed via dashboard')
  ON CONFLICT (host_id) DO UPDATE
    SET revoked_at = now(), reason = EXCLUDED.reason;
DELETE FROM inventory_current WHERE host_id = :'hid';
DELETE FROM inventory_history WHERE host_id = :'hid';
DELETE FROM metrics_ts WHERE host_id = :'hid';
DELETE FROM metrics_5m WHERE host_id = :'hid';
DELETE FROM metrics_1h WHERE host_id = :'hid';
DELETE FROM log_sources WHERE host_id = :'hid';
DELETE FROM bookmarks WHERE host_id = :'hid';
DELETE FROM events WHERE host_id = :'hid';
DELETE FROM scan_staging WHERE host_id = :'hid';
DELETE FROM scans WHERE host_id = :'hid';
DELETE FROM enrollment_tokens WHERE used_by_host_id = :'hid';
DELETE FROM hosts WHERE host_id = :'hid';
COMMIT;
"""

jobs = {}
jobs_lock = threading.Lock()


def db_password():
    """Read POSTGRES_PASSWORD from the living .env (600, brrew-owned)."""
    try:
        with open(os.path.join(LIVING_DIR, ".env")) as f:
            for line in f:
                line = line.strip()
                if line.startswith("POSTGRES_PASSWORD="):
                    return line.split("=", 1)[1].strip().strip("'\"")
    except OSError:
        pass
    return None


def psql_run(extra_args, sql_input=None, timeout=60):
    """Run psql inside the living-postgres container (same path as
    mint-token.sh: docker exec, PGPASSWORD from .env). Returns
    (stdout, None) or (None, error_string) — never leaks the secret."""
    pw = db_password()
    if not pw:
        return None, "db credentials unavailable"
    env = dict(os.environ)
    env["PGPASSWORD"] = pw
    try:
        p = subprocess.run(
            ["docker", "exec", "-i", "living-postgres", "psql",
             "-h", "127.0.0.1", "-U", "living_admin", "-d", "livingdb",
             "-v", "ON_ERROR_STOP=1", "-X", "-q", "-t", "-A"] + extra_args,
            input=sql_input, capture_output=True, text=True,
            timeout=timeout, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return None, "db call failed"
    if p.returncode != 0:
        return None, "db error"
    return (p.stdout or "").strip(), None


def delete_host(host_id):
    """Delete a host and every row that references it, in one
    transaction. Returns (True, None) or (False, error_string)."""
    # NB: psql does not expand :'var' in -c strings on this build;
    # pass everything via stdin where substitution works.
    out, err = psql_run(["-v", "hid=" + host_id],
                        sql_input="SELECT 1 FROM hosts"
                                  " WHERE host_id = :'hid';")
    if err:
        return False, err
    if out != "1":
        return False, "unknown host"
    _, err = psql_run(["-v", "hid=" + host_id], sql_input=DELETE_HOST_SQL,
                      timeout=120)
    if err:
        return False, err
    return True, None


def valid_host(h):
    if not isinstance(h, str) or not h:
        return False
    if HOST_RE.match(h):
        return True
    if IPV6_RE.match(h):
        return True
    if IPV4_RE.match(h):
        try:
            return all(0 <= int(p) <= 255 for p in h.split("."))
        except ValueError:
            return False
    return False


def validate_enroll(body):
    errs = []
    if not isinstance(body, dict):
        return None, ["body must be a JSON object"]
    host = body.get("host", "")
    port = body.get("port", 22)
    username = body.get("username", "")
    label = body.get("label") or host
    auth = body.get("auth") or {}

    if not valid_host(host):
        errs.append("host: invalid hostname or IP")
    try:
        port = int(port)
        if not 1 <= port <= 65535:
            errs.append("port: must be 1-65535")
    except (TypeError, ValueError):
        errs.append("port: must be a number 1-65535")
        port = 22
    if not isinstance(username, str) or not USER_RE.match(username):
        errs.append("username: 1-64 chars, letters/digits/._- only")
    if not isinstance(label, str) or not LABEL_RE.match(label):
        errs.append("label: 1-64 chars, letters/digits/._- only "
                    "(defaults to the host address)")

    atype = auth.get("type")
    secret = None
    if atype == "password":
        secret = auth.get("password")
        if not isinstance(secret, str) or not 1 <= len(secret) <= 512:
            errs.append("auth.password: required, 1-512 chars")
    elif atype == "key":
        secret = auth.get("key")
        if (not isinstance(secret, str) or "PRIVATE KEY" not in secret
                or len(secret) > 16384):
            errs.append("auth.key: must be a private key (PEM text)")
    else:
        errs.append('auth.type: must be "password" or "key"')

    if errs:
        return None, errs
    return {"host": host, "port": port, "username": username,
            "label": label, "auth_type": atype, "secret": secret}, []


def stage_from_line(line):
    l = line.lower()
    if "token minted" in l:
        return "token"
    if "remote os detected" in l:
        return "installing"
    if "verifying check-in" in l:
        return "verifying"
    if "cannot reach" in l or "token mint failed" in l:
        return "failed"
    if l.startswith("enroll: warning"):
        return "failed"
    return None


def run_job(job, req):
    tmpdir = tempfile.mkdtemp(prefix="living-enroll-")
    try:
        env = dict(os.environ)
        env["LIVING_SSH_PORT"] = str(req["port"])
        env["LIVING_SSH_STRICT"] = "accept-new"
        if req["auth_type"] == "key":
            keyf = os.path.join(tmpdir, "id_enroll")
            with open(keyf, "w") as f:
                f.write(req["secret"])
                if not req["secret"].endswith("\n"):
                    f.write("\n")
            os.chmod(keyf, 0o600)
            env["LIVING_SSH_KEYFILE"] = keyf
        else:
            # password via SSH_ASKPASS helper — never on a command line,
            # never in the environment.
            askf = os.path.join(tmpdir, "askpass.sh")
            pw = req["secret"].replace("'", "'\\''")
            with open(askf, "w") as f:
                f.write("#!/bin/sh\nprintf '%%s' '%s'\n" % pw)
            os.chmod(askf, 0o700)  # must be executable: enroll_ssh.sh runs it directly for sudo -S
            env["LIVING_SSH_ASKPASS"] = askf

        target = "%s@%s" % (req["username"], req["host"])
        p = subprocess.Popen(
            [ENROLL_SCRIPT, target, req["label"]],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, env=env, start_new_session=True,
        )
        job["stage"] = "starting"
        deadline = time.time() + JOB_TIMEOUT_S
        out = p.stdout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                job["log"].append("enroll: TIMEOUT after %ds — job killed"
                                  % JOB_TIMEOUT_S)
                job["status"] = "error"
                job["stage"] = "failed"
                job["error"] = "timed out"
                break
            r, _, _ = select.select([out], [], [], min(remaining, 5))
            if not r:
                if p.poll() is not None:
                    break
                continue
            line = out.readline()
            if line == "":
                break
            line = line.rstrip("\n")
            if len(job["log"]) < MAX_LOG_LINES:
                job["log"].append(line)
            st = stage_from_line(line)
            if st:
                job["stage"] = st
        # drain anything left, then reap
        try:
            rest, _ = p.communicate(timeout=10)
            for line in rest.splitlines():
                if len(job["log"]) < MAX_LOG_LINES:
                    job["log"].append(line)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            p.wait()
        rc = p.returncode
        if job["status"] == "running":
            if rc == 0:
                job["status"] = "ok"
                job["stage"] = "done"
            else:
                job["status"] = "error"
                job["stage"] = "failed"
                if not job.get("error"):
                    job["error"] = "enroll_ssh.sh exited %d" % rc
    except Exception as e:  # never leak the secret in the error text
        job["status"] = "error"
        job["stage"] = "failed"
        job["error"] = "internal error: %s" % type(e).__name__
    finally:
        # The credential material dies with the job — memory only from here.
        req["secret"] = None
        shutil.rmtree(tmpdir, ignore_errors=True)
        job["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                           time.gmtime())


class Handler(BaseHTTPRequestHandler):
    server_version = "living-enroll/1"

    def log_message(self, *a):
        pass  # access log would risk echoing paths; keep quiet

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = 0
        if n > MAX_BODY:
            return None, "body too large"
        raw = self.rfile.read(n) if n else b"{}"
        try:
            return json.loads(raw.decode("utf-8")), None
        except (ValueError, UnicodeDecodeError):
            return None, "invalid JSON"

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"ok": True})
        if self.path == "/jobs":
            with jobs_lock:
                items = [{k: j[k] for k in
                          ("job_id", "label", "host", "status", "stage",
                           "created_at", "finished_at", "error")
                          if k in j} for j in jobs.values()]
            return self._send(200, {"jobs": items})
        m = re.fullmatch(r"/jobs/([0-9a-f]{32})", self.path)
        if m:
            with jobs_lock:
                job = jobs.get(m.group(1))
            if not job:
                return self._send(404, {"error": "unknown job"})
            return self._send(200, job)
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/jobs":
            body, err = self._read_json()
            if err:
                return self._send(400, {"error": err})
            req, errs = validate_enroll(body)
            if errs:
                return self._send(400, {"error": "; ".join(errs)})
            with jobs_lock:
                running = sum(1 for j in jobs.values()
                              if j["status"] == "running")
                if running >= MAX_CONCURRENT:
                    return self._send(429, {"error": "too many enrollments "
                                                     "in flight, try again"})
                job_id = uuid.uuid4().hex
                job = {"job_id": job_id, "label": req["label"],
                       "host": req["host"], "status": "running",
                       "stage": "starting", "log": [],
                       "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                   time.gmtime())}
                jobs[job_id] = job
                while len(jobs) > MAX_JOBS:  # drop oldest finished
                    old = min((j for j in jobs.values()
                               if j["status"] != "running"),
                              key=lambda j: j["created_at"], default=None)
                    if old is None:
                        break
                    del jobs[old["job_id"]]
            t = threading.Thread(target=run_job, args=(job, req),
                                 daemon=True)
            t.start()
            return self._send(202, {"job_id": job_id, "status": "running"})

        if self.path == "/tokens":
            body, err = self._read_json()
            if err:
                return self._send(400, {"error": err})
            label = (body or {}).get("label") or "manual"
            if not isinstance(label, str) or not LABEL_RE.match(label):
                return self._send(400, {"error": "label: 1-64 chars, "
                                                 "letters/digits/._- only"})
            try:
                p = subprocess.run(
                    [MINT_SCRIPT, "manual:%s" % label, "24"],
                    capture_output=True, text=True, timeout=30)
            except (OSError, subprocess.TimeoutExpired):
                return self._send(500, {"error": "token mint failed"})
            m = TOKEN_RE.search(p.stdout or "")
            if p.returncode != 0 or not m:
                return self._send(500, {"error": "token mint failed"})
            token = m.group(1)
            expires = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                    time.gmtime(time.time() + 24 * 3600))
            one_liners = {
                "sh": ("curl -fsSL %s/install.sh | sudo bash -s -- "
                       "--token %s --label %s"
                       % (INSTALL_BASE, token, label)),
                "ps1": ("irm %s/install.ps1 -OutFile $env:TEMP\\living-install.ps1; "
                        "& $env:TEMP\\living-install.ps1 "
                        "-Token \"%s\" -Label \"%s\""
                        % (INSTALL_BASE, token, label)),
            }
            return self._send(200, {"token": token, "label": label,
                                    "expires_at": expires,
                                    "one_liners": one_liners})
        return self._send(404, {"error": "not found"})

    def do_DELETE(self):
        m = re.fullmatch(
            r"/hosts/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})", self.path)
        if not m:
            return self._send(404, {"error": "not found"})
        host_id = m.group(1)
        ok, err = delete_host(host_id)
        if not ok:
            if err == "unknown host":
                return self._send(404, {"error": "unknown host"})
            return self._send(500, {"error": err})
        return self._send(200, {"ok": True, "deleted": host_id})


class UnixHTTPServer(ThreadingHTTPServer):
    address_family = socket.AF_UNIX


def main():
    # Fail fast if the enroll tooling isn't where the service expects it.
    for f in (ENROLL_SCRIPT, MINT_SCRIPT):
        if not os.access(f, os.X_OK):
            raise SystemExit("not executable: %s" % f)
    if SOCK_PATH:
        os.makedirs(os.path.dirname(SOCK_PATH), exist_ok=True)
        try:
            os.unlink(SOCK_PATH)
        except FileNotFoundError:
            pass
        srv = UnixHTTPServer(SOCK_PATH, Handler)
        # The nginx worker (different uid in the container) must be able to
        # CONNECT, which needs write permission on the socket. Same as the
        # teamchat/litellm-proxy sockets (world-writable); nginx's basic
        # auth remains the gate.
        os.chmod(SOCK_PATH, 0o777)
        print("living-enroll listening on unix:%s" % SOCK_PATH, flush=True)
    else:
        srv = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
        # Allow quick restarts.
        srv.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print("living-enroll listening on %s:%d" % (LISTEN_HOST, LISTEN_PORT),
              flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
