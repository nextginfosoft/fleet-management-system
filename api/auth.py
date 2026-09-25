"""
Session login for the web app: landing page, login/logout, and the guard
that protects the dashboard, map and API. Uses a signed cookie (stdlib only).
"""

import base64
import hashlib
import hmac
import json
import time
from urllib.parse import parse_qs, quote

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

from api.dashboard import templates
from config.settings import settings

COOKIE_NAME = "fleet_session"
PUBLIC_PATHS = {"/", "/login", "/logout", "/health", "/favicon.ico"}
PUBLIC_POSTS = {"/api/v1/telemetry/ingest"}  # devices and the simulator post here

router = APIRouter(tags=["Auth"], include_in_schema=False)


def _sign(payload: str) -> str:
    key = settings.api.SECRET_KEY.encode()
    return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()


def make_session_token(username: str) -> str:
    expires = int(time.time()) + settings.auth.SESSION_HOURS * 3600
    raw = json.dumps({"u": username, "exp": expires}).encode()
    payload = base64.urlsafe_b64encode(raw).decode()
    return f"{payload}.{_sign(payload)}"


def read_session(token: str | None) -> str | None:
    if not token or "." not in token:
        return None
    payload, signature = token.rsplit(".", 1)
    if not hmac.compare_digest(signature, _sign(payload)):
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(payload.encode()))
    except ValueError:
        return None
    if data.get("exp", 0) < time.time():
        return None
    return data.get("u")


def _safe_next(value: str | None) -> str:
    if value and value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    return "/dashboard"


async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if (
        path in PUBLIC_PATHS
        or request.method == "OPTIONS"
        or (request.method == "POST" and path in PUBLIC_POSTS)
        or read_session(request.cookies.get(COOKIE_NAME))
    ):
        return await call_next(request)
    if path.startswith("/api/"):
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    return RedirectResponse(f"/login?next={quote(path)}", status_code=303)


def _render_login(request: Request, next_url: str, error: str | None = None,
                  username: str | None = None, status_code: int = 200):
    demo = settings.auth.DEMO_MODE
    return templates.TemplateResponse(request, "login.html", {
        "next": next_url,
        "error": error,
        "demo_mode": demo,
        "prefill_user": username if username is not None else (settings.auth.USERNAME if demo else ""),
        "prefill_pass": settings.auth.PASSWORD if demo else "",
    }, status_code=status_code)


@router.get("/")
def landing(request: Request):
    return templates.TemplateResponse(request, "landing.html", {
        "logged_in": bool(read_session(request.cookies.get(COOKIE_NAME))),
        "demo_mode": settings.auth.DEMO_MODE,
        "demo_user": settings.auth.USERNAME,
        "demo_pass": settings.auth.PASSWORD,
    })


@router.get("/login")
def login_page(request: Request, next: str = "/dashboard"):
    next_url = _safe_next(next)
    if read_session(request.cookies.get(COOKIE_NAME)):
        return RedirectResponse(next_url, status_code=303)
    return _render_login(request, next_url)


@router.post("/login")
async def login_submit(request: Request):
    form = parse_qs((await request.body()).decode("utf-8", "ignore"))
    username = form.get("username", [""])[0].strip()
    password = form.get("password", [""])[0]
    next_url = _safe_next(form.get("next", [""])[0])

    user_ok = hmac.compare_digest(username.encode(), settings.auth.USERNAME.encode())
    pass_ok = hmac.compare_digest(password.encode(), settings.auth.PASSWORD.encode())
    if not (user_ok and pass_ok):
        return _render_login(request, next_url, error="Incorrect username or password.",
                             username=username, status_code=401)

    response = RedirectResponse(next_url, status_code=303)
    secure = request.headers.get("x-forwarded-proto", request.url.scheme) == "https"
    response.set_cookie(
        COOKIE_NAME, make_session_token(username),
        max_age=settings.auth.SESSION_HOURS * 3600,
        httponly=True, samesite="lax", secure=secure, path="/",
    )
    return response


@router.api_route("/logout", methods=["GET", "POST"])
def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(COOKIE_NAME, path="/")
    return response
