"""Host-only read-only load check; tokens and mailbox contents never leave the host.

Run with access to the live database: python3 check-mail-concurrency.py DB ORIGIN.
Four simultaneous list_folders calls per round, spread across existing accounts.
No sends, message bodies, subscriptions or configuration changes. A temporary
read token is always removed; output contains only timing/status/resource counts.
"""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

database, origin = sys.argv[1:]
db = sqlite3.connect(database)
accounts = [row[0] for row in db.execute("SELECT id FROM runtime_accounts ORDER BY id")]
assert accounts, "No configured accounts"
token = secrets.token_urlsafe(32)
digest = hashlib.sha256(token.encode()).hexdigest()
db.execute("INSERT INTO tokens VALUES (?,?,?,?,?,?)", (digest, "access", "concurrency-check", origin + "/mcp", "mail:read", int(time.time()) + 300))
db.commit()
stop = threading.Event()
peak = {"rss_kib": 0, "hwm_kib": 0, "fds": 0}

def sample():
    pid = subprocess.check_output(["systemctl", "show", "mail-bridge-rust", "-p", "MainPID", "--value"], text=True).strip()
    root = Path("/proc") / pid
    while not stop.is_set():
        try:
            values = dict(line.split(":", 1) for line in (root / "status").read_text().splitlines() if ":" in line)
            peak["rss_kib"] = max(peak["rss_kib"], int(values["VmRSS"].split()[0]))
            peak["hwm_kib"] = max(peak["hwm_kib"], int(values["VmHWM"].split()[0]))
            peak["fds"] = max(peak["fds"], len(list((root / "fd").iterdir())))
        except (FileNotFoundError, ProcessLookupError):
            break
        stop.wait(0.02)

def call(index, barrier):
    payload = {"jsonrpc": "2.0", "id": index + 1, "method": "tools/call", "params": {"name": "list_folders", "arguments": {"account_id": accounts[index % len(accounts)]}}}
    request = urllib.request.Request(origin + "/mcp", data=json.dumps(payload).encode(), headers={"Authorization": "Bearer " + token, "Content-Type": "application/json", "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18"})
    barrier.wait()
    start = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            reply = json.load(response)
        result = reply.get("result", {})
        if "error" in reply:
            outcome = "rpc_error"
        elif result.get("isError"):
            message = " ".join(item.get("text", "") for item in result.get("content", []))
            outcome = "queue_timeout" if "queue wait timed out" in message else "busy" if "busy" in message else "tool_error"
        else:
            outcome = "success"
    except urllib.error.HTTPError as error:
        outcome = "http_" + str(error.code)
    except (OSError, ValueError):
        outcome = "transport_error"
    return {"outcome": outcome, "seconds": round(time.monotonic() - start, 3)}

sampler = threading.Thread(target=sample)
try:
    sampler.start()
    rounds = []
    for _ in range(2):
        barrier = threading.Barrier(4)
        start = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            calls = list(pool.map(lambda i: call(i, barrier), range(4)))
        rounds.append({"seconds": round(time.monotonic() - start, 3), "calls": calls})
    print(json.dumps({"concurrency": 4, "account_count": len(accounts), "rounds": rounds, "peak": peak}))
finally:
    stop.set()
    if sampler.ident is not None:
        sampler.join()
    db.execute("DELETE FROM tokens WHERE hash=?", (digest,))
    db.commit()
    db.close()
