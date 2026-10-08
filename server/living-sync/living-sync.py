#!/usr/bin/env python3
"""
living-sync.py — the Living Dashboard differ engine (spark, systemd timer, 5 min).

Reads unprocessed rows from scan_staging (posted by installed agents via
PostgREST), then:
  - kind=metrics -> metrics_ts row + hosts.last_seen
  - kind=deep    -> scans row, inventory_current upsert, inventory_history,
                    new|gone|changed events with flap protection,
                    auto-bookmarks for new web services
  - rollups: metrics_ts -> metrics_5m (48h) -> metrics_1h (30d); prune.

Only STABLE_FIELDS per category participate in `changed` detection —
volatile fields (byte counters, pct) never fire events.

DB: living-postgres on 127.0.0.1:5433; password from /home/brrew/srv/living/.env
"""
import json
import os
import sys
import time

import psycopg2
import psycopg2.extras

LIVING_DIR = "/home/brrew/srv/living"
GONE_AFTER_MISSES = 3  # consecutive deep scans missing before `gone` fires

# Stable (event-worthy) fields per inventory category. Everything else is
# volatile and only updates last_seen.
STABLE_FIELDS = {
    "cron":           ["user", "schedule", "command"],
    "sched_task":     ["path", "name", "state", "triggers", "actions"],
    "software":       ["name", "version"],
    "users":          ["name", "uid", "enabled", "admin", "shell"],
    "listening_port": ["port", "proto", "bind", "process"],
    "docker_app":     ["name", "image", "state", "ports"],
    # NOTE: "status" deliberately excluded — it embeds uptime
    # ("Up 3 hours") and would fire a `changed` event every scan.
    "disk":           ["mount", "fstype", "totalBytes"],
    "net_iface":      ["iface", "addrs"],
    "web_service":    ["port", "process", "title", "status", "server", "path"],
    "log_source":     ["name", "path", "kind", "enabled", "sensitive"],
    "gpu":            ["name", "memTotalBytes"],
    "startup_svc":    ["name", "status", "start_type"],
}

METRIC_COLS = ["cpu_pct", "mem_pct", "load1", "gpu_util", "gpu_temp",
               "gpu_mem_used", "net_rx", "net_tx", "disk_used_pct"]


def db():
    env = {}
    with open(os.path.join(LIVING_DIR, ".env")) as f:
        for line in f:
            line = line.strip()
            if line and "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                env[k] = v
    return psycopg2.connect(host="127.0.0.1", port=5433, dbname="livingdb",
                            user="living_admin", password=env["POSTGRES_PASSWORD"])


def stable_part(category, item):
    fields = STABLE_FIELDS.get(category)
    if not fields:
        return item
    return {k: item.get(k) for k in fields}


def summarize(category, kind, key, item, old_item=None):
    """Human-readable one-liner for an event."""
    if category == "web_service":
        title = item.get("title") or "(no title)"
        return "Web service '%s' on port %s (%s)" % (
            title, item.get("port"), item.get("process") or "unknown")
    if category == "cron":
        return "Cron [%s] %s %s" % (item.get("user"), item.get("schedule"),
                                    (item.get("command") or "")[:80])
    if category == "sched_task":
        return "Scheduled task %s%s (%s)" % (item.get("path"),
                                             item.get("name"), item.get("state"))
    if category == "software":
        if kind == "changed" and old_item:
            return "%s: %s -> %s" % (item.get("name"),
                                     old_item.get("version"),
                                     item.get("version"))
        return "Software: %s %s" % (item.get("name"), item.get("version") or "")
    if category == "users":
        return "User %s (uid %s)" % (item.get("name"), item.get("uid"))
    if category == "listening_port":
        return "Listening port %s/%s (%s)" % (item.get("port"),
                                              item.get("proto"),
                                              item.get("process") or "unknown")
    if category == "docker_app":
        return "Container %s (%s)" % (item.get("name"), item.get("image"))
    if category == "disk":
        return "Disk %s (%s)" % (item.get("mount"), item.get("fstype"))
    if category == "startup_svc":
        return "Service %s (%s)" % (item.get("name"), item.get("status"))
    if category == "net_iface":
        return "Interface %s" % item.get("iface")
    if category == "log_source":
        return "Log source %s" % item.get("name")
    if category == "gpu":
        return "GPU %s" % item.get("name")
    return "%s: %s" % (category, key)


def tailnet_ip(cur, host_id):
    cur.execute("SELECT item FROM inventory_current "
                "WHERE host_id=%s AND category='net_iface'", (host_id,))
    addrs = []
    for (item,) in cur.fetchall():
        addrs.extend(item.get("addrs") or [])
    for a in addrs:
        ip = a.split("/")[0]
        if ip.startswith("100."):
            return ip
    for a in addrs:
        ip = a.split("/")[0]
        if ip and not ip.startswith("127.") and ":" not in ip:
            return ip
    return None


def process_deep(cur, host_id, payload, staging_ts):
    meta = payload.get("meta", {}) or {}
    items = payload.get("inventory", []) or []

    # baseline? (first deep scan ever for this host)
    cur.execute("SELECT baseline_scan_id FROM hosts WHERE host_id=%s",
                (host_id,))
    row = cur.fetchone()
    is_baseline = not row or not row[0]

    started = time.time()
    cur.execute(
        "INSERT INTO scans (host_id, kind, status, payload_version)"
        " VALUES (%s, %s, 'ok', %s) RETURNING scan_id",
        (host_id, "baseline" if is_baseline else "deep",
         meta.get("payload_version", 1)))
    scan_id = cur.fetchone()[0]

    # host identity refresh
    tip = None
    cur.execute(
        "INSERT INTO hosts (host_id, label, platform, os, serial, last_seen)"
        " VALUES (%s,%s,%s,%s,%s,now())"
        " ON CONFLICT (host_id) DO UPDATE SET label=EXCLUDED.label,"
        " platform=EXCLUDED.platform, os=EXCLUDED.os, serial=EXCLUDED.serial,"
        " last_seen=now()",
        (host_id, meta.get("label") or host_id,
         meta.get("platform") or "linux", meta.get("os"),
         meta.get("serial")))

    # current inventory map
    cur.execute("SELECT category, item_key, item, miss_count FROM "
                "inventory_current WHERE host_id=%s", (host_id,))
    current = {(c, k): (i, m) for c, k, i, m in cur.fetchall()}
    seen = set()
    new_events = []

    for entry in items:
        category, key, item = entry["category"], entry["key"], entry["item"]
        seen.add((category, key))
        old = current.get((category, key))
        if old is None:
            cur.execute(
                "INSERT INTO inventory_current "
                " (host_id, category, item_key, item, first_seen, last_seen,"
                "  miss_count) VALUES (%s,%s,%s,%s,now(),now(),0)",
                (host_id, category, key, json.dumps(item)))
            if not is_baseline:
                summary = summarize(category, "new", key, item)
                cur.execute(
                    "INSERT INTO events (host_id, kind, category, item_key,"
                    " summary, scan_id) VALUES (%s,'new',%s,%s,%s,%s)"
                    " RETURNING event_id",
                    (host_id, category, key, summary, scan_id))
                new_events.append((cur.fetchone()[0], category, key, item))
        else:
            old_item, _miss = old
            if stable_part(category, old_item) != stable_part(category, item):
                if not is_baseline:
                    summary = summarize(category, "changed", key, item,
                                        old_item)
                    cur.execute(
                        "INSERT INTO events (host_id, kind, category,"
                        " item_key, summary, scan_id)"
                        " VALUES (%s,'changed',%s,%s,%s,%s)",
                        (host_id, category, key, summary, scan_id))
            cur.execute(
                "UPDATE inventory_current SET item=%s, last_seen=now(),"
                " miss_count=0 WHERE host_id=%s AND category=%s AND item_key=%s",
                (json.dumps(item), host_id, category, key))
        cur.execute(
            "INSERT INTO inventory_history (scan_id, host_id, category,"
            " item_key, item) VALUES (%s,%s,%s,%s,%s)",
            (scan_id, host_id, category, key, json.dumps(item)))

    # gone detection with flap protection
    for (category, key), (old_item, miss) in current.items():
        if (category, key) in seen:
            continue
        miss = (miss or 0) + 1
        if miss >= GONE_AFTER_MISSES:
            if not is_baseline:
                summary = summarize(category, "gone", key, old_item)
                cur.execute(
                    "INSERT INTO events (host_id, kind, category, item_key,"
                    " summary, scan_id) VALUES (%s,'gone',%s,%s,%s,%s)",
                    (host_id, category, key, summary, scan_id))
            cur.execute("DELETE FROM inventory_current WHERE host_id=%s"
                        " AND category=%s AND item_key=%s",
                        (host_id, category, key))
        else:
            cur.execute("UPDATE inventory_current SET miss_count=%s"
                        " WHERE host_id=%s AND category=%s AND item_key=%s",
                        (miss, host_id, category, key))

    # auto-bookmark web services (the user's example): iterate over ALL
    # current web_service items in inventory_current — not just this scan's
    # new events — so the silent baseline scan and hosts enrolled before
    # this fix get bookmarked too. Idempotent via
    # ON CONFLICT (host_id, url) DO NOTHING; detected_from_event carries
    # the event id for genuinely new services, NULL for backfilled ones.
    new_ws_events = {key: eid for eid, cat, key, _it in new_events
                     if cat == "web_service"}
    cur.execute("SELECT item_key, item FROM inventory_current"
                " WHERE host_id=%s AND category='web_service'", (host_id,))
    for key, item in cur.fetchall():
        if item.get("status") not in (200, 301, 302, 401, 403):
            continue
        if tip is None:
            tip = tailnet_ip(cur, host_id)
        if not tip:
            continue
        url = "http://%s:%s%s" % (tip, item["port"], item.get("path") or "/")
        title = (item.get("container")
                 or item.get("title")
                 or "%s:%s" % (tip, item["port"]))
        cur.execute(
            "INSERT INTO bookmarks (host_id, title, url,"
            " detected_from_event, auto) VALUES (%s,%s,%s,%s,TRUE)"
            " ON CONFLICT (host_id, url) DO NOTHING",
            (host_id, title, url, new_ws_events.get(key)))

    if is_baseline:
        cur.execute("UPDATE hosts SET baseline_scan_id=%s WHERE host_id=%s",
                    (scan_id, host_id))
    cur.execute("UPDATE scans SET duration_ms=%s WHERE scan_id=%s",
                (int((time.time() - started) * 1000), scan_id))
    return scan_id


def process_metrics(cur, host_id, payload):
    vals = [payload.get(c) for c in METRIC_COLS]
    cur.execute(
        "INSERT INTO metrics_ts (host_id, ts, cpu_pct, mem_pct, load1,"
        " gpu_util, gpu_temp, gpu_mem_used, net_rx, net_tx, disk_used_pct)"
        " VALUES (%s, now(), %s,%s,%s,%s,%s,%s,%s,%s,%s)"
        " ON CONFLICT (host_id, ts) DO NOTHING",
        (host_id, *vals))
    cur.execute(
        "INSERT INTO hosts (host_id, label, platform, last_seen)"
        " VALUES (%s,%s,'linux',now())"
        " ON CONFLICT (host_id) DO UPDATE SET last_seen=now()",
        (host_id, payload.get("hostname") or host_id))


def rollups(cur):
    # raw -> 5m (older than 48h), 5m -> 1h (older than 30d), prune
    cur.execute("""
        INSERT INTO metrics_5m
        SELECT host_id, date_trunc('hour', ts) + date_part('minute', ts)::int / 5 * interval '5 min',
               avg(cpu_pct), avg(mem_pct), avg(load1), avg(gpu_util),
               avg(gpu_temp), avg(gpu_mem_used)::bigint,
               max(net_rx), max(net_tx), avg(disk_used_pct)
        FROM metrics_ts WHERE ts < now() - interval '48 hours'
        GROUP BY 1, 2
        ON CONFLICT DO NOTHING""")
    cur.execute("DELETE FROM metrics_ts WHERE ts < now() - interval '48 hours'")
    cur.execute("""
        INSERT INTO metrics_1h
        SELECT host_id, date_trunc('hour', ts),
               avg(cpu_pct), avg(mem_pct), avg(load1), avg(gpu_util),
               avg(gpu_temp), avg(gpu_mem_used)::bigint,
               max(net_rx), max(net_tx), avg(disk_used_pct)
        FROM metrics_5m WHERE ts < now() - interval '30 days'
        GROUP BY 1, 2
        ON CONFLICT DO NOTHING""")
    cur.execute("DELETE FROM metrics_5m WHERE ts < now() - interval '30 days'")
    cur.execute("DELETE FROM metrics_1h WHERE ts < now() - interval '1 year'")


def main():
    conn = db()
    conn.autocommit = False
    cur = conn.cursor()
    cur.execute("ALTER TABLE inventory_current ADD COLUMN IF NOT EXISTS"
                " miss_count INT NOT NULL DEFAULT 0")
    cur.execute("SELECT staging_id, host_id, kind, payload FROM scan_staging"
                " WHERE NOT processed ORDER BY staging_id LIMIT 200")
    rows = cur.fetchall()
    done = failed = 0
    for staging_id, host_id, kind, payload in rows:
        try:
            if isinstance(payload, str):
                payload = json.loads(payload)
            if kind == "deep":
                process_deep(cur, host_id, payload, None)
            elif kind == "metrics":
                process_metrics(cur, host_id, payload)
            else:
                raise ValueError("unknown kind %r" % kind)
            cur.execute("UPDATE scan_staging SET processed=TRUE"
                        " WHERE staging_id=%s", (staging_id,))
            done += 1
        except Exception as e:
            conn.rollback()
            cur.execute("UPDATE scan_staging SET processed=TRUE, error=%s"
                        " WHERE staging_id=%s", (str(e)[:500], staging_id))
            failed += 1
    try:
        rollups(cur)
    except Exception as e:
        sys.stderr.write("living-sync: rollup failed: %s\n" % e)
    conn.commit()
    print("living-sync: processed=%d failed=%d" % (done, failed))


if __name__ == "__main__":
    main()
