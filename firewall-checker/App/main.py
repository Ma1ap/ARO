import os
import time
import asyncio
import socket
import logging
from dataclasses import dataclass, asdict
from typing import List, Optional
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from apscheduler.schedulers.asyncio import AsyncIOScheduler

APP_PORT = int(os.getenv("APP_PORT", "3100"))
CONFIG_PATH = os.getenv("CONFIG_PATH", "/app/config/checks.conf")
INTERVAL_SECONDS = int(os.getenv("INTERVAL_SECONDS", "60"))
TIMEOUT_SECONDS = float(os.getenv("TIMEOUT_SECONDS", "5"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("firewall-checker")

app = FastAPI(title="Firewall Connectivity Checker")

@dataclass
class Target:
    kind: str
    target: str
    port: int

@dataclass
class Result:
    kind: str
    target: str
    port: int
    ok: bool
    latency_ms: int
    message: str
    http_status: Optional[int]
    timestamp: float

_last_results: List[Result] = []
_last_run: Optional[float] = None
_lock = asyncio.Lock()

def load_targets() -> List[Target]:
    targets = []
    with open(CONFIG_PATH) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            sep = "," if "," in line else None
            _, kind, target, port = ([""] + line.split(sep))
            targets.append(Target(kind.lower(), target.strip(), int(port)))
    return targets

def normalize_url(target: str, port: int) -> str:
    if "://" not in target:
        target = f"http://{target}"
    u = urlparse(target)
    host = u.netloc.split(":")[0]
    return f"{u.scheme}://{host}:{port}{u.path}"

async def check_curl(t: Target) -> Result:
    url = normalize_url(t.target, t.port)
    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
            r = await client.get(url)
        ok = r.status_code < 400
        msg = f"HTTP {r.status_code}"
        status = r.status_code
    except Exception as e:
        ok = False
        msg = str(e)
        status = None

    return Result(
        "curl", t.target, t.port, ok,
        int((time.perf_counter() - start) * 1000),
        msg, status, time.time()
    )

async def check_telnet(t: Target) -> Result:
    start = time.perf_counter()
    try:
        s = socket.create_connection((t.target, t.port), timeout=TIMEOUT_SECONDS)
        s.close()
        ok = True
        msg = "TCP connect OK"
    except Exception as e:
        ok = False
        msg = str(e)

    return Result(
        "telnet", t.target, t.port, ok,
        int((time.perf_counter() - start) * 1000),
        msg, None, time.time()
    )

async def run_checks():
    results = []
    for t in load_targets():
        if t.kind == "curl":
            results.append(await check_curl(t))
        else:
            results.append(await check_telnet(t))

    global _last_results, _last_run
    async with _lock:
        _last_results = results
        _last_run = time.time()

    for r in results:
        log.info("[%s] %s:%s OK=%s %s", r.kind, r.target, r.port, r.ok, r.message)

scheduler = AsyncIOScheduler()

@app.on_event("startup")
async def startup():
    scheduler.add_job(lambda: asyncio.create_task(run_checks()),
                      "interval", seconds=INTERVAL_SECONDS)
    scheduler.start()
    await run_checks()

@app.on_event("shutdown")
async def shutdown():
    scheduler.shutdown()

@app.get("/")
async def ui():
    rows = ""
    for r in _last_results:
        rows += f"<tr><td>{'✅' if r.ok else '❌'}</td><td>{r.kind}</td><td>{r.target}</td><td>{r.port}</td><td>{r.latency_ms}</td><td>{r.message}</td></tr>"

    return HTMLResponse(f"""
    <html>
    <title>Firewall Checker</title>
    <body>
    <h2>Firewall Connectivity Checker</h2>
    <p>Last run: {time.ctime(_last_run) if _last_run else "never"}</p>
    <a href="/run">Run now</a>
    <table border="1">
      <tr><th>OK</th><th>Type</th><th>Target</th><th>Port</th><th>Latency ms</th><th>Result</th></tr>
      {rows}
    </table>
    </body>
    </html>
    """)

@app.get("/run")
async def run_now():
    asyncio.create_task(run_checks())
    return RedirectResponse("/")

@app.get("/api/results")
async def api():
    return JSONResponse([asdict(r) for r in _last_results])
``
