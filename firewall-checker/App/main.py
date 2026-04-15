import os
import time
import asyncio
import socket
import logging
import secrets
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from prometheus_client import Counter, Histogram, make_asgi_app
from prometheus_fastapi_instrumentator import Instrumentator

# Optional OAuth/OIDC (enabled only if AUTH_MODE=oidc)
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from authlib.integrations.starlette_client import OAuth

APP_PORT = int(os.getenv("APP_PORT", "3100"))
CONFIG_PATH = os.getenv("CONFIG_PATH", "/app/config/checks.conf")
INTERVAL_SECONDS = int(os.getenv("INTERVAL_SECONDS", "60"))
TIMEOUT_SECONDS = float(os.getenv("TIMEOUT_SECONDS", "5"))

AUTH_MODE = os.getenv("AUTH_MODE", "none").lower()  # none | basic | oidc

BASIC_USER = os.getenv("BASIC_AUTH_USER", "admin")
BASIC_PASS = os.getenv("BASIC_AUTH_PASS", "admin")

OIDC_NAME = os.getenv("OIDC_NAME", "oidc")
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "")
OIDC_DISCOVERY_URL = os.getenv("OIDC_DISCOVERY_URL", "")  # https://<provider>/.well-known/openid-configuration
OIDC_REDIRECT_URI = os.getenv("OIDC_REDIRECT_URI", "")    # e.g. https://<route>/auth/callback
SESSION_SECRET = os.getenv("SESSION_SECRET", "change-me")

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("fw-check")

app = FastAPI(title="Firewall Connectivity Validator", version="1.1.0")

# -------------------------
# Prometheus metrics
# -------------------------
CHECKS_TOTAL = Counter(
    "fw_checks_total",
    "Total number of firewall checks executed",
    ["kind", "result"]
)
CHECK_LATENCY_MS = Histogram(
    "fw_check_latency_ms",
    "Latency in milliseconds for each firewall check",
    ["kind"],
    buckets=(10, 25, 50, 100, 250, 500, 1000, 2000, 5000, 10000)
)

# Instrument FastAPI HTTP request metrics and expose /metrics
Instrumentator().instrument(app).expose(app, endpoint="/metrics")  # quick-start pattern [3](https://pypi.org/project/prometheus-fastapi-instrumentator/)

# Also mount the official prometheus_client ASGI metrics app (keeps compatibility)
# This is a documented FastAPI pattern for client_python. [2](http://prometheus.github.io/client_python/exporting/http/fastapi-gunicorn/)
metrics_app = make_asgi_app()
app.mount("/metrics-client", metrics_app)


# -------------------------
# Auth (Basic)
# -------------------------
security = HTTPBasic()

def require_basic(credentials: HTTPBasicCredentials = Depends(security)) -> None:
    ok_user = secrets.compare_digest(credentials.username, BASIC_USER)
    ok_pass = secrets.compare_digest(credentials.password, BASIC_PASS)
    if not (ok_user and ok_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

def auth_guard(credentials: HTTPBasicCredentials = Depends(security)) -> None:
    # Unified guard, based on AUTH_MODE
    if AUTH_MODE == "basic":
        require_basic(credentials)
    # oidc is handled via session in routes
    return


# -------------------------
# OAuth/OIDC (Authlib) - only used if AUTH_MODE=oidc
# -------------------------
oauth: Optional[OAuth] = None

if AUTH_MODE == "oidc":
    # Session middleware required for OAuth state handling (Authlib pattern) [5](https://docs.authlib.org/en/v0.15.4/client/fastapi.html)
    app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)
    oauth = OAuth()
    if OIDC_DISCOVERY_URL:
        oauth.register(
            name=OIDC_NAME,
            client_id=OIDC_CLIENT_ID,
            client_secret=OIDC_CLIENT_SECRET,
            server_metadata_url=OIDC_DISCOVERY_URL,
            client_kwargs={"scope": "openid profile email"},
        )

def require_oidc_session(request: Request) -> Dict[str, Any]:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


# -------------------------
# Config parsing + checks
# -------------------------
@dataclass
class CheckTarget:
    kind: str          # curl|telnet
    target: str        # url or host
    port: int

@dataclass
class CheckResult:
    kind: str
    target: str
    port: int
    ok: bool
    timestamp: float
    latency_ms: int
    details: str
    http_status: Optional[int] = None

_last_results: List[CheckResult] = []
_last_run_ts: Optional[float] = None
_lock = asyncio.Lock()

def parse_config_line(line: str) -> Optional[CheckTarget]:
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None

    parts = [p.strip() for p in (raw.split(",") if "," in raw else raw.split()) if p.strip()]
    if len(parts) != 3:
        raise ValueError(f"Invalid config line (expected 3 fields): {raw}")

    kind = parts[0].lower()
    if kind not in ("curl", "telnet"):
        raise ValueError(f"Invalid test type '{parts[0]}' (must be curl or telnet): {raw}")

    target = parts[1]
    port = int(parts[2])
    return CheckTarget(kind=kind, target=target, port=port)

def load_targets(config_path: str) -> List[CheckTarget]:
    targets: List[CheckTarget] = []
    with open(config_path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            try:
                t = parse_config_line(line)
                if t:
                    targets.append(t)
            except Exception as e:
                log.warning("Config parse error at line %d: %s", i, e)
    return targets

def normalize_curl_url(url_or_host: str, port: int) -> str:
    if "://" not in url_or_host:
        url_or_host = f"http://{url_or_host}"
    u = urlparse(url_or_host)
    netloc = u.netloc
    if ":" not in netloc:
        netloc = f"{netloc}:{port}"
    return u._replace(netloc=netloc).geturl()

async def do_curl(url_or_host: str, port: int) -> CheckResult:
    url = normalize_curl_url(url_or_host, port)
    start = time.perf_counter()
    status_code = None
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=TIMEOUT_SECONDS) as client:
            r = await client.get(url)
            status_code = r.status_code
            ok = 200 <= status_code < 400
            details = f"HTTP {status_code}"
    except Exception as e:
        ok = False
        details = f"HTTP error: {type(e).__name__}: {e}"
    latency = int((time.perf_counter() - start) * 1000)

    CHECKS_TOTAL.labels(kind="curl", result="ok" if ok else "fail").inc()
    CHECK_LATENCY_MS.labels(kind="curl").observe(latency)

    return CheckResult(
        kind="curl", target=url_or_host, port=port, ok=ok,
        timestamp=time.time(), latency_ms=latency, details=details, http_status=status_code
    )

async def do_telnet(host: str, port: int) -> CheckResult:
    start = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT_SECONDS)
        sock.close()
        ok = True
        details = "TCP connect OK"
    except Exception as e:
        ok = False
        details = f"TCP error: {type(e).__name__}: {e}"
    latency = int((time.perf_counter() - start) * 1000)

    CHECKS_TOTAL.labels(kind="telnet", result="ok" if ok else "fail").inc()
    CHECK_LATENCY_MS.labels(kind="telnet").observe(latency)

    return CheckResult(
        kind="telnet", target=host, port=port, ok=ok,
        timestamp=time.time(), latency_ms=latency, details=details
    )

async def run_all_checks() -> List[CheckResult]:
    targets = load_targets(CONFIG_PATH)
    if not targets:
        return [CheckResult(
            kind="system", target=CONFIG_PATH, port=0, ok=False,
            timestamp=time.time(), latency_ms=0,
            details="No valid targets found (check config path / contents)."
        )]

    tasks = []
    for t in targets:
        tasks.append(do_curl(t.target, t.port) if t.kind == "curl" else do_telnet(t.target, t.port))

    return await asyncio.gather(*tasks)

async def store_and_log(results: List[CheckResult]) -> None:
    global _last_results, _last_run_ts
    async with _lock:
        _last_results = results
        _last_run_ts = time.time()

    for r in results:
        extra = f" status={r.http_status}" if r.http_status is not None else ""
        log.info("[%s] %s:%s ok=%s latency=%sms%s details=%s",
                 r.kind, r.target, r.port, r.ok, r.latency_ms, extra, r.details)

scheduler = AsyncIOScheduler()

@app.on_event("startup")
async def startup():
    scheduler.add_job(lambda: asyncio.create_task(job_tick()), "interval", seconds=INTERVAL_SECONDS, max_instances=1)
    scheduler.start()
    await job_tick()

@app.on_event("shutdown")
async def shutdown():
    scheduler.shutdown(wait=False)

async def job_tick():
    results = await run_all_checks()
    await store_and_log(results)

# -------------------------
# Routes
# -------------------------
@app.get("/healthz")
async def healthz():
    return {"ok": True}

@app.get("/run")
async def run_now(request: Request, _: Any = Depends(auth_guard)):
    if AUTH_MODE == "oidc":
        require_oidc_session(request)
    asyncio.create_task(job_tick())
    return RedirectResponse(url="/", status_code=302)

@app.get("/api/results")
async def api_results(request: Request, _: Any = Depends(auth_guard)):
    if AUTH_MODE == "oidc":
        require_oidc_session(request)
    async with _lock:
        return JSONResponse({
            "last_run_ts": _last_run_ts,
            "results": [asdict(r) for r in _last_results]
        })

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, _: Any = Depends(auth_guard)):
    if AUTH_MODE == "oidc":
        user = require_oidc_session(request)
    else:
        user = None

    async with _lock:
        results = list(_last_results)
        last_run = _last_run_ts

    rows = []
    for r in results:
        badge = "✅" if r.ok else "❌"
        extra = f" (HTTP {r.http_status})" if r.http_status is not None else ""
        rows.append(
            f"<tr><td>{badge}</td><td>{r.kind}</td><td>{r.target}</td><td>{r.port}</td>"
            f"<td>{r.latency_ms}</td><td>{r.details}{extra}</td></tr>"
        )

    last = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_run)) if last_run else "never"
    who = f"<p>Logged in as: <b>{user.get('email','user')}</b></p>" if user else ""

    html = f"""
    <html>
      <head>
        <title>Firewall Connectivity Validator</title>
        <style>
          body {{ font-family: Arial, sans-serif; margin: 20px; }}
          table {{ border-collapse: collapse; width: 100%; }}
          th, td {{ border: 1px solid #ddd; padding: 8px; }}
          th {{ background: #f5f5f5; }}
          .topbar {{ display:flex; gap:12px; align-items:center; flex-wrap:wrap; }}
          .pill {{ padding:6px 10px; background:#eef; border-radius:16px; }}
          a.button {{ padding:8px 12px; background:#2d6cdf; color:white; border-radius:8px; text-decoration:none; }}
        </style>
      </head>
      <body>
        <div class="topbar">
          <h2 style="margin:0;">Firewall Connectivity Validator</h2>
          <span class="pill">Last run: {last}</span>
          <span class="pill">Interval: {INTERVAL_SECONDS}s</span>
          <a class="button" href="/run">Run now</a>
          <a class="button" href="/api/results">JSON</a>
          <a class="button" href="/metrics">Metrics</a>
        </div>
        {who}
        <p>Config: <code>{CONFIG_PATH}</code></p>
        <table>
          <tr><th>OK</th><th>Test</th><th>Target</th><th>Port</th><th>Latency (ms)</th><th>Details</th></tr>
          {''.join(rows)}
        </table>
      </body>
    </html>
    """
    return HTMLResponse(html)

# -------------------------
# OAuth/OIDC endpoints (only if enabled)
# -------------------------
if AUTH_MODE == "oidc":

    @app.get("/login")
    async def login(request: Request):
        if not oauth or not OIDC_DISCOVERY_URL:
            raise HTTPException(500, "OIDC not configured (missing OIDC_DISCOVERY_URL)")
        if not OIDC_REDIRECT_URI:
            raise HTTPException(500, "OIDC not configured (missing OIDC_REDIRECT_URI)")
        client = oauth.create_client(OIDC_NAME)
        return await client.authorize_redirect(request, OIDC_REDIRECT_URI)  # [5](https://docs.authlib.org/en/v0.15.4/client/fastapi.html)

    @app.get("/auth/callback")
    async def auth_callback(request: Request):
        client = oauth.create_client(OIDC_NAME)
        token = await client.authorize_access_token(request)
        userinfo = await client.parse_id_token(request, token)
        request.session["user"] = dict(userinfo)
        return RedirectResponse("/", status_code=302)

    @app.get("/logout")
    async def logout(request: Request):
        request.session.clear()
        return RedirectResponse("/", status_code=302)