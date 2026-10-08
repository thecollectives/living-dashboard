#!/usr/bin/env python3
"""
living-agent.py — Living Dashboard watcher for Linux and macOS.
Single file, stdlib only. Installed by install.sh as a persistent service
(systemd on Linux, LaunchDaemon on macOS).

Behavior:
  - On first run: claims the install's enrollment token via
    POST {API}/rpc/claim_enrollment_token  -> registers this host.
  - Every METRICS_INTERVAL (5 min): posts light metrics to scan_staging.
  - Every DEEP_INTERVAL (60 min): posts a full deep scan to scan_staging.
  - The server-side differ (living-sync.py) does new/gone/changed detection.

Config file: /etc/living-agent/config.json (Linux) or
             /usr/local/etc/living-agent/config.json (macOS)
  { "api": "http://100.104.7.48:8092/living/api",
    "host_id": "<uuid>", "label": "<label>",
    "jwt": "<living_writer JWT>", "install_token": "<one-time token>" }

Payload v2: base metrics + deep inventory sections. Item keys are STABLE
(no PIDs, no timestamps, no byte counters in keys) — the differ depends on it.
"""
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
import uuid

AGENT_VERSION = "1.0.0"
METRICS_INTERVAL = 300      # 5 min
DEEP_INTERVAL = 3600        # 60 min
PLATFORM = "darwin" if sys.platform == "darwin" else "linux"
CONF_PATHS = ["/etc/living-agent/config.json",
              "/usr/local/etc/living-agent/config.json"]


def sh(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout).stdout
    except Exception:
        return ""


def load_config():
    override = os.environ.get("LIVING_AGENT_CONFIG")
    paths = [override] if override else CONF_PATHS
    for p in paths:
        try:
            with open(p) as f:
                cfg = json.load(f)
                cfg["_config_path"] = p
                return cfg
        except Exception:
            continue
    sys.stderr.write("living-agent: no config found\n")
    sys.exit(2)


def api_post(cfg, path, obj, timeout=30):
    req = urllib.request.Request(
        cfg["api"].rstrip("/") + path,
        data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + cfg["jwt"]},
        method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode()


# ---------------------------------------------------------------- base metrics
def base_metrics():
    m = {"agent_version": AGENT_VERSION, "platform": PLATFORM}
    try:
        m["hostname"] = socket.gethostname()
    except Exception:
        m["hostname"] = ""
    # cpu: 1s delta
    def cpu_times():
        out = {}
        try:
            with open("/proc/stat") as f:
                for line in f:
                    if line.startswith("cpu "):
                        p = line.split()
                        vals = list(map(int, p[1:8]))
                        out["idle"] = vals[3] + vals[4]
                        out["total"] = sum(vals)
        except Exception:
            pass
        return out
    a, t0 = cpu_times(), time.time()
    time.sleep(1)
    b = cpu_times()
    try:
        da = b["idle"] - a["idle"]
        dt = b["total"] - a["total"]
        m["cpu_pct"] = round((1 - da / dt) * 100, 1) if dt else 0.0
    except Exception:
        m["cpu_pct"] = 0.0
    try:
        with open("/proc/meminfo") as f:
            mem = {}
            for line in f:
                n, _, v = line.partition(":")
                if n in ("MemTotal", "MemAvailable"):
                    mem[n] = int(v.split()[0])
        m["mem_pct"] = round(
            (mem["MemTotal"] - mem["MemAvailable"]) * 100.0 / mem["MemTotal"], 1)
    except Exception:
        m["mem_pct"] = 0.0
    try:
        m["load1"] = round(os.getloadavg()[0], 2)
    except Exception:
        m["load1"] = 0.0
    # gpu
    smi = sh(["nvidia-smi",
              "--query-gpu=utilization.gpu,temperature.gpu,memory.used",
              "--format=csv,noheader,nounits"]).strip()
    if smi:
        try:
            g = [x.strip() for x in smi.split(",", 2)]
            m["gpu_util"] = float(g[0])
            m["gpu_temp"] = float(g[1])
            m["gpu_mem_used"] = int(float(g[2]) * 1048576)
        except Exception:
            pass
    # disks: worst pct across physical filesystems
    worst = 0
    for line in sh(["df", "-B1", "--output=pcent"]).splitlines()[1:]:
        try:
            worst = max(worst, int(line.strip().rstrip("%")))
        except Exception:
            pass
    m["disk_used_pct"] = worst
    # net counters: sum non-loopback
    rx = tx = 0
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                if ":" not in line:
                    continue
                iface, rest = line.split(":", 1)
                iface = iface.strip()
                if iface == "lo" or iface.startswith("veth"):
                    continue
                nums = rest.split()
                if len(nums) >= 9:
                    rx += int(nums[0])
                    tx += int(nums[8])
    except Exception:
        pass
    m["net_rx"], m["net_tx"] = rx, tx
    return m


# ---------------------------------------------------------------- deep scan
def stable_key(*parts):
    return "|".join(str(p) for p in parts)


def hash_cmd(cmd):
    return hashlib.sha256(cmd.encode()).hexdigest()[:12]


def deep_scan():
    inv = []  # list of (category, item_key, item)
    seen_keys = set()

    def add(entry):
        category, key, item = entry
        if (category, key) not in seen_keys:
            seen_keys.add((category, key))
            inv.append(entry)  # NOTE: do not sed-replace this line

    meta = {"agent_version": AGENT_VERSION, "platform": PLATFORM,
            "payload_version": 2}

    # ---- identity ----
    try:
        meta["hostname"] = socket.gethostname()
    except Exception:
        meta["hostname"] = ""
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    meta["os"] = line.split("=", 1)[1].strip().strip('"')
                    break
    except Exception:
        pass
    if PLATFORM == "darwin":
        meta["os"] = sh(["sw_vers", "-productName"]).strip() + " " + \
            sh(["sw_vers", "-productVersion"]).strip()
    # serial
    serial = ""
    for src in (["cat", "/sys/class/dmi/id/product_serial"],
                ["dmidecode", "-s", "system-serial-number"]):
        serial = sh(src).strip().splitlines()[0:1]
        serial = serial[0].strip() if serial else ""
        if serial and serial.lower() not in ("", "none", "unknown",
                                             "not specified"):
            break
    if PLATFORM == "darwin" and not serial:
        out = sh(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
        mm = re.search(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"', out)
        if mm:
            serial = mm.group(1)
    meta["serial"] = serial

    # ---- cron (linux) / launchd (macos) ----
    if PLATFORM == "linux":
        users = []
        try:
            with open("/etc/passwd") as f:
                for line in f:
                    p = line.split(":")
                    if len(p) > 6:
                        users.append(p[0])
        except Exception:
            pass
        for u in users:
            out = sh(["crontab", "-u", u, "-l"], timeout=15)
            for line in out.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" in line.split()[0:1]:
                    continue
                parts = line.split(None, 5)
                if len(parts) < 6:
                    continue
                sched, cmd = " ".join(parts[:5]), parts[5]
                add(("cron", stable_key("cron", u, sched, hash_cmd(cmd)),
                            {"user": u, "schedule": sched, "command": cmd}))
        for path in ["/etc/crontab"] + \
                ["/etc/cron.d/" + f for f in os.listdir("/etc/cron.d")
                 if os.path.isfile("/etc/cron.d/" + f)] \
                if os.path.isdir("/etc/cron.d") else []:
            try:
                with open(path) as f:
                    content = f.read()
            except Exception:
                continue
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 6)
                if len(parts) < 7:
                    continue
                u, sched, cmd = parts[5], " ".join(parts[:5]), parts[6]
                add(("cron", stable_key("cron", u, sched, hash_cmd(cmd)),
                            {"user": u, "schedule": sched, "command": cmd,
                             "file": path}))
        # systemd timers
        for line in sh(["systemctl", "list-timers", "--all", "--no-legend",
                        "--no-pager"], timeout=15).splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].endswith(".timer"):
                name = parts[1]
                add(("cron", stable_key("timer", name),
                            {"user": "systemd", "schedule": "timer",
                             "command": name}))
    else:  # darwin: launchd
        for d in ("/Library/LaunchDaemons", "/Library/LaunchAgents",
                  os.path.expanduser("~/Library/LaunchAgents")):
            try:
                names = os.listdir(d)
            except Exception:
                continue
            for n in names:
                if n.endswith(".plist"):
                    add(("sched_task", stable_key("launchd", n),
                                {"path": d, "name": n, "state": "loaded?"}))

    # ---- scheduled tasks: systemd enabled units (linux) ----
    if PLATFORM == "linux":
        for line in sh(["systemctl", "list-unit-files", "--state=enabled",
                        "--no-legend", "--no-pager"], timeout=15).splitlines():
            parts = line.split()
            if len(parts) >= 1 and parts[0].endswith(".service"):
                add(("startup_svc", stable_key("svc", parts[0]),
                            {"name": parts[0], "state": "enabled"}))

    # ---- software ----
    if PLATFORM == "linux":
        out = sh(["dpkg", "-l"], timeout=60)
        if out:
            for line in out.splitlines():
                if line.startswith("ii"):
                    p = line.split()
                    if len(p) >= 3:
                        add(("software", stable_key("pkg", p[1]),
                                    {"name": p[1], "version": p[2]}))
        else:
            for line in sh(["rpm", "-qa", "--queryformat",
                            "%{NAME} %{VERSION}-%{RELEASE}\n"],
                           timeout=60).splitlines():
                p = line.split(None, 1)
                if len(p) == 2:
                    add(("software", stable_key("pkg", p[0]),
                                {"name": p[0], "version": p[1]}))
    else:
        try:
            for n in os.listdir("/Applications"):
                if n.endswith(".app"):
                    add(("software", stable_key("app", n),
                                {"name": n, "version": ""}))
        except Exception:
            pass

    # ---- users ----
    if PLATFORM == "linux":
        try:
            with open("/etc/passwd") as f:
                for line in f:
                    p = line.rstrip("\n").split(":")
                    if len(p) >= 7:
                        add(("users", stable_key("user", p[0]),
                                    {"name": p[0], "uid": p[2], "gid": p[3],
                                     "shell": p[6], "home": p[5]}))
        except Exception:
            pass
    else:
        for line in sh(["dscl", ".", "list", "/Users"]).splitlines():
            u = line.strip()
            if u and not u.startswith("_"):
                add(("users", stable_key("user", u), {"name": u}))

    # ---- disks ----
    for line in sh(["df", "-B1", "--output=target,fstype,size,used,pcent"]
                   ).splitlines()[1:]:
        p = line.split()
        if len(p) < 5 or p[1] in ("tmpfs", "devtmpfs", "overlay",
                                  "squashfs", "efivarfs"):
            continue
        try:
            add(("disk", stable_key("disk", p[0]),
                        {"mount": p[0], "fstype": p[1],
                         "totalBytes": int(p[2]), "usedBytes": int(p[3]),
                         "pct": int(p[4].rstrip("%"))}))
        except Exception:
            continue

    # ---- network interfaces ----
    addrs = {}
    for line in sh(["ip", "-brief", "addr"]).splitlines():
        p = line.split()
        if len(p) >= 3:
            addrs[p[0]] = [x for x in p[2:] if "/" in x]
    if not addrs and PLATFORM == "darwin":
        for line in sh(["ifconfig"]).splitlines():
            mm = re.match(r"^(\w+):", line)
            if mm:
                cur = mm.group(1)
                addrs.setdefault(cur, [])
            mm = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
            if mm and cur:
                addrs[cur].append(mm.group(1))
    for iface, al in addrs.items():
        add(("net_iface", stable_key("iface", iface),
                    {"iface": iface, "addrs": al}))

    # ---- listening ports + docker ----
    docker_ports = set()
    for line in sh(["docker", "ps", "--format", "{{json .}}"],
                   timeout=10).splitlines():
        try:
            c = json.loads(line)
        except Exception:
            continue
        ports = []
        for tok in (c.get("Ports", "") or "").split(","):
            pm = re.match(r"(?:\d+\.\d+\.\d+\.\d+|\[::\]):(\d+)->(\d+)/(\w+)",
                          tok.strip())
            if pm:
                ports.append({"host": int(pm.group(1)),
                              "container": int(pm.group(2)),
                              "proto": pm.group(3)})
                docker_ports.add(int(pm.group(1)))
        add(("docker_app", stable_key("docker", c.get("Names", "")),
                    {"name": c.get("Names", ""),
                     "image": (c.get("Image", "") or "").split("@")[0],
                     "state": c.get("State", ""),
                     "status": c.get("Status", ""), "ports": ports}))
    listeners = []  # (port, process)
    for line in sh(["ss", "-tlnp"]).splitlines():
        lm = re.match(r"LISTEN\s+\d+\s+\d+\s+(\S+)", line)
        if not lm:
            continue
        host, _, port = lm.group(1).rpartition(":")
        try:
            port = int(port)
        except ValueError:
            continue
        proc = ""
        pm = re.search(r'\(\("([^"]+)",pid=\d+', line)
        if pm:
            proc = pm.group(1)
        listeners.append((port, proc))
        if port not in docker_ports:
            add(("listening_port",
                        stable_key("tcp", port, proc or "unknown"),
                        {"port": port, "proto": "tcp", "bind": host,
                         "process": proc}))
    # also macOS netstat fallback
    if PLATFORM == "darwin" and not listeners:
        for line in sh(["netstat", "-anv", "-p", "tcp"]).splitlines():
            if "LISTEN" in line:
                p = line.split()
                try:
                    port = int(p[3].rsplit(".", 1)[1])
                    listeners.append((port, ""))
                    add(("listening_port", stable_key("tcp", port),
                                {"port": port, "proto": "tcp",
                                 "bind": "", "process": ""}))
                except Exception:
                    pass

    # ---- web-service classification: HTTP probe each listener ----
    for port, proc in sorted(set(listeners)):
        if port in docker_ports:
            continue
        title, status, server = probe_http(port)
        if status:
            add(("web_service", stable_key("web", port),
                        {"port": port, "process": proc, "title": title,
                         "status": status, "server": server, "path": "/"}))

    # ---- log sources ----
    if PLATFORM == "linux":
        logdir = "/var/log"
        try:
            for n in os.listdir(logdir):
                p = os.path.join(logdir, n)
                try:
                    st = os.stat(p)
                    if st.st_size >= 0:
                        add(("log_source", stable_key("file", n),
                                    {"name": n, "path": p, "kind": "file",
                                     "bytes": st.st_size,
                                     "sensitive": n.startswith("mail") or
                                     n in ("auth.log", "secure")}))
                except Exception:
                    pass
        except Exception:
            pass
        for line in sh(["journalctl", "--list-units", "--no-pager"],
                       timeout=15).splitlines():
            p = line.split()
            if p and p[0].endswith(".service"):
                add(("log_source", stable_key("journald", p[0]),
                            {"name": p[0], "kind": "journald"}))
    else:
        for d in ("/var/log", "/Library/Logs",
                  os.path.expanduser("~/Library/Logs")):
            try:
                for n in os.listdir(d)[:50]:
                    add(("log_source", stable_key("file", n),
                                {"name": n, "path": os.path.join(d, n),
                                 "kind": "file"}))
            except Exception:
                pass

    # ---- gpu inventory ----
    smi = sh(["nvidia-smi", "--query-gpu=name,memory.total",
              "--format=csv,noheader,nounits"]).strip()
    if smi and "[N/A]" not in smi:
        g = [x.strip() for x in smi.split(",", 1)]
        try:
            mem_total = int(float(g[1]) * 1048576) if len(g) > 1 else None
        except (ValueError, IndexError):
            mem_total = None
        add(("gpu", stable_key("gpu", g[0]),
                    {"name": g[0], "memTotalBytes": mem_total}))

    return meta, inv


def probe_http(port, timeout=4):
    """GET / on localhost:port. Returns (title, status, server) or (None,None,None)."""
    import http.client
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        c.request("GET", "/")
        r = c.getresponse()
        body = r.read(65536).decode("utf-8", "replace")
        c.close()
        mm = re.search(r"<title[^>]*>(.*?)</title>", body,
                       re.IGNORECASE | re.DOTALL)
        title = (mm.group(1).strip()[:120] if mm else "")
        return title, r.status, r.getheader("Server", "")
    except Exception:
        return None, None, None


# ---------------------------------------------------------------- main loop
def post_scan(cfg, kind, payload):
    body = {"host_id": cfg["host_id"], "kind": kind, "payload": payload}
    try:
        st, _ = api_post(cfg, "/scan_staging", body, timeout=60)
        return st in (200, 201)
    except Exception as e:
        sys.stderr.write("living-agent: post failed: %s\n" % e)
        return False


def main():
    cfg = load_config()
    if not cfg.get("host_id"):
        cfg["host_id"] = str(uuid.uuid4())
    # first run: claim enrollment token
    if cfg.get("install_token") and not cfg.get("enrolled"):
        try:
            st, raw = api_post(cfg, "/rpc/claim_enrollment_token", {
                "p_token": cfg["install_token"],
                "p_host_id": cfg["host_id"],
                "p_label": cfg.get("label", ""),
                "p_platform": PLATFORM,
                "p_os": deep_os_name(),
            }, timeout=30)
            res = json.loads(raw)
            if res.get("ok"):
                cfg["enrolled"] = True
                cfg.pop("install_token", None)
                save_config(cfg)
            else:
                sys.stderr.write("living-agent: claim failed: %s\n"
                                 % res.get("error"))
        except Exception as e:
            sys.stderr.write("living-agent: claim error: %s\n" % e)

    if "--oneshot" in sys.argv:
        mode = sys.argv[sys.argv.index("--oneshot") + 1] \
            if len(sys.argv) > sys.argv.index("--oneshot") + 1 else "deep"
        if mode == "deep":
            meta, inv = deep_scan()
            meta["host_id"] = cfg["host_id"]
            meta["label"] = cfg.get("label", "")
            ok = post_scan(cfg, "deep",
                           {"meta": meta,
                            "inventory": [{"category": c, "key": k, "item": i}
                                          for c, k, i in inv]})
        else:
            ok = post_scan(cfg, "metrics", base_metrics())
        sys.exit(0 if ok else 1)

    last_deep = 0
    while True:
        now = time.time()
        if now - last_deep >= DEEP_INTERVAL:
            try:
                meta, inv = deep_scan()
                meta["host_id"] = cfg["host_id"]
                meta["label"] = cfg.get("label", "")
                post_scan(cfg, "deep",
                          {"meta": meta,
                           "inventory": [{"category": c, "key": k, "item": i}
                                         for c, k, i in inv]})
            except Exception as e:
                sys.stderr.write("living-agent: deep scan failed: %s\n" % e)
            last_deep = now
        try:
            post_scan(cfg, "metrics", base_metrics())
        except Exception as e:
            sys.stderr.write("living-agent: metrics failed: %s\n" % e)
        time.sleep(METRICS_INTERVAL)


def deep_os_name():
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    if PLATFORM == "darwin":
        return "macOS " + sh(["sw_vers", "-productVersion"]).strip()
    return PLATFORM


def save_config(cfg):
    paths = [cfg.get("_config_path")] if cfg.get("_config_path") else []
    paths += [p for p in CONF_PATHS if p not in paths]
    for p in paths:
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                json.dump({k: v for k, v in cfg.items()
                           if not k.startswith("_")}, f)
            os.chmod(p, 0o600)
            return
        except Exception:
            continue


if __name__ == "__main__":
    main()
