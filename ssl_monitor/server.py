"""FastAPI web dashboard — auth, history, folders, real-time scanning."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional

from fastapi import Cookie, Depends, FastAPI, HTTPException, Response, status
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .auth import (
    ACCESS_EXPIRE_MINUTES,
    REFRESH_EXPIRE_DAYS,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    get_optional_user,
    hash_password,
    verify_password,
)
from .checker import check_domain
from .db import Folder, Scan, User, get_db, init_db
from .models import CertificateResult
from .reporter import to_html

app = FastAPI(title="SSL Certificate Monitor", docs_url="/api/docs", redoc_url=None)


@app.on_event("startup")
async def _startup() -> None:
    await init_db()


# ------------------------------------------------------------------ #
# Pydantic request models
# ------------------------------------------------------------------ #

class RegisterRequest(BaseModel):
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class FolderCreate(BaseModel):
    name: str

class FolderRename(BaseModel):
    name: str

class MoveScanRequest(BaseModel):
    folder_id: Optional[str] = None

class ScanRequest(BaseModel):
    domains: list[str]
    warn_days: int = 30
    critical_days: int = 7
    timeout: int = 10


# ------------------------------------------------------------------ #
# Internal helpers
# ------------------------------------------------------------------ #

def _parse_domain(raw: str, warn: int, crit: int) -> tuple[str, int, int, int]:
    raw = raw.strip()
    if ":" in raw:
        host, port_str = raw.rsplit(":", 1)
        try:
            return host.strip(), int(port_str), warn, crit
        except ValueError:
            pass
    return raw, 443, warn, crit


def _serialize(r: CertificateResult) -> dict:
    return {
        "domain": r.domain,
        "port": r.port,
        "host_label": r.host_label,
        "status": r.status,
        "status_css_color": r.status_css_color,
        "status_icon": r.status_icon,
        "is_valid": r.is_valid,
        "days_remaining": r.days_remaining,
        "expiry_date": r.expiry_date.strftime("%Y-%m-%d") if r.expiry_date else None,
        "issued_to": r.issued_to,
        "issued_by": r.issued_by,
        "serial_number": r.serial_number,
        "subject_alt_names": r.subject_alt_names,
        "error": r.error,
        "checked_at": r.checked_at.isoformat(),
    }


def _deserialize(d: dict) -> CertificateResult:
    expiry = None
    if d.get("expiry_date"):
        expiry = datetime.strptime(d["expiry_date"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    ca = datetime.fromisoformat(d["checked_at"])
    if ca.tzinfo is None:
        ca = ca.replace(tzinfo=timezone.utc)
    return CertificateResult(
        domain=d["domain"], port=d["port"], checked_at=ca,
        is_valid=d["is_valid"], days_remaining=d["days_remaining"],
        expiry_date=expiry, issued_to=d.get("issued_to"),
        issued_by=d.get("issued_by"), serial_number=d.get("serial_number"),
        subject_alt_names=d.get("subject_alt_names", []), error=d.get("error"),
    )


def _scan_dict(s: Scan) -> dict:
    return {
        "id": s.id,
        "created_at": s.created_at.isoformat(),
        "domains_checked": s.domains_checked,
        "summary": s.summary,
        "folder_id": s.folder_id,
        "folder_name": s.folder.name if s.folder else None,
    }


async def _save_scan(db: AsyncSession, user_id: str, results: list[dict]) -> str:
    summary = {
        st: sum(1 for r in results if r["status"] == st)
        for st in ["OK", "WARNING", "CRITICAL", "EXPIRED", "ERROR"]
    }
    scan = Scan(user_id=user_id, domains_checked=len(results), summary=summary, results=results)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan.id


def _set_tokens(response: Response, user_id: str, email: str) -> None:
    response.set_cookie(
        key="access_token", value=create_access_token(user_id, email),
        httponly=True, max_age=ACCESS_EXPIRE_MINUTES * 60, samesite="lax",
    )
    response.set_cookie(
        key="refresh_token", value=create_refresh_token(user_id, email),
        httponly=True, max_age=REFRESH_EXPIRE_DAYS * 24 * 60 * 60,
        samesite="lax", path="/api/auth/refresh",
    )


# ------------------------------------------------------------------ #
# Frontend
# ------------------------------------------------------------------ #

@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return _HTML


# ------------------------------------------------------------------ #
# Auth routes
# ------------------------------------------------------------------ #

@app.post("/api/auth/register", status_code=201)
async def register(req: RegisterRequest, response: Response, db: AsyncSession = Depends(get_db)):
    if len(req.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    exists = await db.scalar(select(User).where(User.email == req.email.lower()))
    if exists:
        raise HTTPException(400, "Email already registered")
    user = User(email=req.email.lower(), password_hash=hash_password(req.password))
    db.add(user)
    await db.commit()
    await db.refresh(user)
    _set_tokens(response, user.id, user.email)
    return {"id": user.id, "email": user.email}


@app.post("/api/auth/login")
async def login(req: LoginRequest, response: Response, db: AsyncSession = Depends(get_db)):
    user = await db.scalar(select(User).where(User.email == req.email.lower()))
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(401, "Invalid email or password")
    _set_tokens(response, user.id, user.email)
    return {"id": user.id, "email": user.email}


@app.post("/api/auth/refresh")
async def refresh(
    response: Response,
    refresh_token: Optional[str] = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
):
    """Issue a new access token using the refresh token cookie."""
    exc = HTTPException(status_code=401, detail="Session expired — please log in again")
    if not refresh_token:
        raise exc
    data = decode_token(refresh_token, "refresh")
    if not data:
        raise exc
    user = await db.get(User, data["sub"])
    if not user:
        raise exc
    # Issue fresh access token only (refresh token keeps its original expiry)
    response.set_cookie(
        key="access_token", value=create_access_token(user.id, user.email),
        httponly=True, max_age=ACCESS_EXPIRE_MINUTES * 60, samesite="lax",
    )
    return {"ok": True}


@app.post("/api/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token", path="/api/auth/refresh")
    return {"ok": True}


@app.get("/api/auth/me")
async def me(current_user: User = Depends(get_current_user)):
    return {"id": current_user.id, "email": current_user.email}


# ------------------------------------------------------------------ #
# Folder routes
# ------------------------------------------------------------------ #

@app.get("/api/folders")
async def list_folders(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    rows = await db.execute(
        select(Folder).where(Folder.user_id == user.id).order_by(Folder.created_at)
    )
    return [{"id": f.id, "name": f.name, "created_at": f.created_at.isoformat()}
            for f in rows.scalars()]


@app.post("/api/folders", status_code=201)
async def create_folder(req: FolderCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    folder = Folder(user_id=user.id, name=req.name.strip())
    db.add(folder)
    await db.commit()
    await db.refresh(folder)
    return {"id": folder.id, "name": folder.name, "created_at": folder.created_at.isoformat()}


@app.put("/api/folders/{folder_id}")
async def rename_folder(folder_id: str, req: FolderRename, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    f = await db.get(Folder, folder_id)
    if not f or f.user_id != user.id:
        raise HTTPException(404, "Folder not found")
    f.name = req.name.strip()
    await db.commit()
    return {"id": f.id, "name": f.name}


@app.delete("/api/folders/{folder_id}", status_code=204)
async def delete_folder(folder_id: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    f = await db.get(Folder, folder_id)
    if not f or f.user_id != user.id:
        raise HTTPException(404, "Folder not found")
    await db.delete(f)
    await db.commit()


# ------------------------------------------------------------------ #
# History routes
# ------------------------------------------------------------------ #

@app.get("/api/history")
async def list_history(
    folder_id: Optional[str] = None,
    page: int = 1,
    per_page: int = 20,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    q = select(Scan).where(Scan.user_id == user.id)
    if folder_id:
        q = q.where(Scan.folder_id == folder_id)
    total = await db.scalar(select(func.count()).select_from(q.subquery()))
    rows = await db.execute(
        q.order_by(Scan.created_at.desc()).offset((page - 1) * per_page).limit(per_page)
    )
    return {"items": [_scan_dict(s) for s in rows.scalars()], "total": total, "page": page, "per_page": per_page}


@app.get("/api/history/{scan_id}")
async def get_scan(scan_id: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    s = await db.get(Scan, scan_id)
    if not s or s.user_id != user.id:
        raise HTTPException(404, "Scan not found")
    return {**_scan_dict(s), "results": s.results}


@app.delete("/api/history/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    s = await db.get(Scan, scan_id)
    if not s or s.user_id != user.id:
        raise HTTPException(404, "Scan not found")
    await db.delete(s)
    await db.commit()


@app.patch("/api/history/{scan_id}")
async def move_scan(scan_id: str, req: MoveScanRequest, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    s = await db.get(Scan, scan_id)
    if not s or s.user_id != user.id:
        raise HTTPException(404, "Scan not found")
    if req.folder_id:
        f = await db.get(Folder, req.folder_id)
        if not f or f.user_id != user.id:
            raise HTTPException(400, "Invalid folder")
    s.folder_id = req.folder_id
    await db.commit()
    await db.refresh(s)
    return _scan_dict(s)


# ------------------------------------------------------------------ #
# Scan + export routes
# ------------------------------------------------------------------ #

@app.post("/api/scan")
async def scan_endpoint(
    req: ScanRequest,
    user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    targets = [_parse_domain(d, req.warn_days, req.critical_days) for d in req.domains if d.strip()]
    collected: list[dict] = []

    async def generate() -> AsyncGenerator[str, None]:
        queue: asyncio.Queue[CertificateResult] = asyncio.Queue()

        async def _check(domain: str, port: int, warn: int, crit: int) -> None:
            result = await check_domain(domain, port, req.timeout, warn, crit)
            await queue.put(result)

        tasks = [asyncio.create_task(_check(d, p, w, c)) for d, p, w, c in targets]

        for _ in range(len(targets)):
            result = await queue.get()
            data = _serialize(result)
            collected.append(data)
            yield f"data: {json.dumps(data)}\n\n"

        await asyncio.gather(*tasks)

        scan_id = None
        if user and collected:
            scan_id = await _save_scan(db, user.id, collected)

        yield f"data: {json.dumps({'done': True, 'scan_id': scan_id})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/export/html")
async def export_html(results_data: list[dict]) -> Response:
    html = to_html([_deserialize(r) for r in results_data])
    return Response(content=html, media_type="text/html",
                    headers={"Content-Disposition": "attachment; filename=ssl-report.html"})


# ------------------------------------------------------------------ #
# Embedded SPA
# ------------------------------------------------------------------ #

_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SSL Certificate Monitor</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg: #0f172a; --surface: #1e293b; --surface2: #162032;
      --border: #334155; --text: #e2e8f0; --muted: #94a3b8;
      --accent: #3b82f6; --accent-h: #2563eb;
      --ok: #22c55e; --warning: #eab308; --critical: #ef4444;
      --expired: #dc2626; --error: #a855f7; --danger: #ef4444;
      --sidebar-w: 220px;
    }
    body { background: var(--bg); color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 14px; line-height: 1.6; min-height: 100vh; }

    /* ── Auth screen ───────────────────────────────────────────── */
    #auth-screen {
      min-height: 100vh; display: flex; align-items: center;
      justify-content: center; padding: 24px;
      background: radial-gradient(ellipse at 60% 30%, #1e3a5f 0%, var(--bg) 70%);
    }
    .auth-card {
      width: 100%; max-width: 400px;
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 16px; padding: 36px; box-shadow: 0 8px 40px rgba(0,0,0,.5);
    }
    .auth-logo { font-size: 2rem; margin-bottom: 12px; text-align: center; }
    .auth-card h1 { font-size: 1.25rem; font-weight: 700; text-align: center; margin-bottom: 24px; }
    .auth-tabs { display: flex; gap: 4px; background: var(--surface2);
      border-radius: 8px; padding: 4px; margin-bottom: 20px; }
    .auth-tab { flex: 1; padding: 8px; border: none; background: none;
      color: var(--muted); cursor: pointer; border-radius: 6px;
      font-size: .875rem; font-weight: 500; transition: all .15s; }
    .auth-tab.active { background: var(--accent); color: #fff; }
    .form-field { margin-bottom: 12px; }
    .form-field input { width: 100%; padding: 10px 12px;
      background: var(--surface2); border: 1px solid var(--border);
      border-radius: 8px; color: var(--text); font-size: .9rem; outline: none;
      transition: border-color .15s; }
    .form-field input:focus { border-color: var(--accent); }
    .form-error { color: var(--danger); font-size: .8rem; min-height: 18px; margin: 4px 0 8px; }

    /* ── App shell ──────────────────────────────────────────────── */
    #app-screen { display: flex; flex-direction: column; min-height: 100vh; }
    header {
      height: 56px; display: flex; align-items: center; justify-content: space-between;
      padding: 0 20px; background: var(--surface); border-bottom: 1px solid var(--border);
      flex-shrink: 0; position: sticky; top: 0; z-index: 10;
    }
    .hdr-brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 1rem; }
    .hdr-logo { width: 32px; height: 32px; border-radius: 8px;
      background: linear-gradient(135deg, #3b82f6, #8b5cf6);
      display: flex; align-items: center; justify-content: center; font-size: 16px; }
    .hdr-user { display: flex; align-items: center; gap: 10px; }
    .hdr-email { color: var(--muted); font-size: .85rem; }

    .app-body { display: flex; flex: 1; overflow: hidden; }

    /* ── Sidebar ────────────────────────────────────────────────── */
    #sidebar {
      width: var(--sidebar-w); flex-shrink: 0; background: var(--surface2);
      border-right: 1px solid var(--border); padding: 12px 8px;
      display: flex; flex-direction: column; gap: 2px;
      overflow-y: auto;
    }
    .nav-item {
      display: flex; align-items: center; gap: 8px; width: 100%;
      padding: 9px 10px; border: none; background: none; color: var(--muted);
      border-radius: 7px; cursor: pointer; font-size: .875rem;
      text-align: left; transition: background .1s, color .1s;
    }
    .nav-item:hover { background: rgba(255,255,255,.06); color: var(--text); }
    .nav-item.active { background: rgba(59,130,246,.15); color: #93c5fd; }
    .nav-icon { font-size: 1rem; flex-shrink: 0; }
    .sidebar-sep { height: 1px; background: var(--border); margin: 8px 4px; }
    .sidebar-sec-hdr {
      display: flex; align-items: center; justify-content: space-between;
      padding: 6px 10px 4px; font-size: .7rem; text-transform: uppercase;
      letter-spacing: .08em; color: var(--muted);
    }
    .folder-item {
      display: flex; align-items: center; width: 100%;
      padding: 8px 10px; border: none; background: none; color: var(--muted);
      border-radius: 7px; cursor: pointer; font-size: .875rem;
      text-align: left; transition: background .1s, color .1s; gap: 6px;
    }
    .folder-item:hover { background: rgba(255,255,255,.06); color: var(--text); }
    .folder-item:hover .f-actions { opacity: 1; }
    .folder-item.active { background: rgba(59,130,246,.15); color: #93c5fd; }
    .folder-name-txt { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .f-actions { opacity: 0; display: flex; gap: 2px; transition: opacity .1s; }
    .f-btn { background: none; border: none; cursor: pointer; color: var(--muted);
      font-size: .85rem; padding: 1px 3px; border-radius: 3px; }
    .f-btn:hover { color: var(--text); background: rgba(255,255,255,.1); }
    .f-btn.danger:hover { color: var(--danger); }

    /* ── Main area ──────────────────────────────────────────────── */
    #main-view { flex: 1; overflow-y: auto; padding: 24px; }
    .view-hdr {
      display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
      margin-bottom: 20px;
    }
    .view-hdr h2 { font-size: 1.1rem; font-weight: 700; flex: 1; }

    /* ── Cards ──────────────────────────────────────────────────── */
    .card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 12px; padding: 20px; margin-bottom: 16px;
    }
    .card-lbl { font-size: .7rem; text-transform: uppercase; letter-spacing: .08em;
      color: var(--muted); margin-bottom: 10px; font-weight: 600; }

    /* ── Buttons ────────────────────────────────────────────────── */
    .btn { padding: 9px 18px; border-radius: 8px; font-size: .875rem;
      font-weight: 600; cursor: pointer; border: none; transition: opacity .15s, background .15s; }
    .btn:disabled { opacity: .45; cursor: not-allowed; }
    .btn-primary { background: var(--accent); color: #fff; }
    .btn-primary:hover:not(:disabled) { background: var(--accent-h); }
    .btn-ghost { background: transparent; color: var(--muted); border: 1px solid var(--border); }
    .btn-ghost:hover:not(:disabled) { border-color: var(--text); color: var(--text); }
    .btn-danger { background: rgba(239,68,68,.15); color: var(--danger); border: 1px solid rgba(239,68,68,.3); }
    .btn-danger:hover:not(:disabled) { background: rgba(239,68,68,.25); }
    .btn-sm { padding: 6px 12px; font-size: .8rem; }
    .btn-full { width: 100%; }
    .btn-row { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 16px; }
    .icon-btn { background: none; border: none; cursor: pointer; color: var(--muted);
      font-size: 1rem; padding: 2px 4px; border-radius: 4px; line-height: 1; }
    .icon-btn:hover { color: var(--text); background: rgba(255,255,255,.08); }
    .link-btn { background: none; border: none; cursor: pointer; color: var(--accent);
      font-size: inherit; padding: 0; text-decoration: underline; }

    /* ── Form elements ──────────────────────────────────────────── */
    .chips-wrap {
      display: flex; flex-wrap: wrap; gap: 6px; padding: 8px 10px;
      background: var(--surface2); border: 1px solid var(--border);
      border-radius: 8px; min-height: 44px; cursor: text;
      transition: border-color .15s;
    }
    .chips-wrap:focus-within { border-color: var(--accent); }
    .chip { display: inline-flex; align-items: center; gap: 4px;
      background: rgba(59,130,246,.15); color: #93c5fd;
      border: 1px solid rgba(59,130,246,.25); border-radius: 6px;
      padding: 2px 7px; font-size: .8rem; font-weight: 500; }
    .chip-x { background: none; border: none; cursor: pointer; color: #93c5fd;
      font-size: 13px; line-height: 1; padding: 0 1px; opacity: .7; }
    .chip-x:hover { opacity: 1; }
    #domain-input { background: none; border: none; outline: none;
      color: var(--text); font-size: .9rem; min-width: 180px; flex: 1; }
    #domain-input::placeholder { color: var(--muted); }
    .hint { font-size: .75rem; color: var(--muted); margin-top: 5px; }

    .settings-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px,1fr));
      gap: 12px; margin-top: 14px; }
    .setting label { display: block; font-size: .75rem; color: var(--muted);
      margin-bottom: 4px; font-weight: 500; }
    .setting input[type=number] { width: 100%; padding: 8px 10px;
      background: var(--surface2); border: 1px solid var(--border);
      border-radius: 7px; color: var(--text); font-size: .875rem; outline: none;
      transition: border-color .15s; }
    .setting input[type=number]:focus { border-color: var(--accent); }

    /* ── Progress ───────────────────────────────────────────────── */
    .prog-hdr { display: flex; justify-content: space-between; font-size: .8rem;
      color: var(--muted); margin-bottom: 7px; }
    .prog-track { height: 4px; background: var(--border); border-radius: 2px; overflow: hidden; }
    .prog-fill { height: 100%; background: linear-gradient(90deg, var(--accent), #8b5cf6);
      border-radius: 2px; transition: width .3s ease; width: 0%; }

    /* ── Status badges ──────────────────────────────────────────── */
    .badge { padding: 4px 10px; border-radius: 999px; font-size: .72rem;
      font-weight: 700; letter-spacing: .05em; text-transform: uppercase; }
    .badge-ok       { background: rgba(34,197,94,.15);  color: var(--ok); }
    .badge-warning  { background: rgba(234,179,8,.15);  color: var(--warning); }
    .badge-critical { background: rgba(239,68,68,.15);  color: var(--critical); }
    .badge-expired  { background: rgba(220,38,38,.15);  color: var(--expired); }
    .badge-error    { background: rgba(168,85,247,.15); color: var(--error); }

    /* ── Results table ──────────────────────────────────────────── */
    .table-wrap { overflow-x: auto; border-radius: 10px; border: 1px solid var(--border); }
    table { width: 100%; border-collapse: collapse; background: var(--surface2); }
    thead tr { background: rgba(255,255,255,.03); }
    th { padding: 11px 14px; text-align: left; font-size: .7rem; text-transform: uppercase;
      letter-spacing: .07em; color: var(--muted); border-bottom: 1px solid var(--border);
      white-space: nowrap; }
    td { padding: 11px 14px; border-bottom: 1px solid var(--border); vertical-align: middle; }
    tr:last-child td { border-bottom: none; }
    tbody tr:hover td { background: rgba(255,255,255,.02); }
    @keyframes rowIn { from { opacity:0; transform:translateY(-3px); } to { opacity:1; transform:none; } }
    .row-in { animation: rowIn .2s ease forwards; }
    .domain-cell { font-weight: 600; }
    .status-pill { display: inline-flex; align-items: center; gap: 4px; padding: 3px 9px;
      border-radius: 999px; font-size: .7rem; font-weight: 700; text-transform: uppercase;
      letter-spacing: .04em; white-space: nowrap; }
    .s-ok       { background: rgba(34,197,94,.15);  color: var(--ok); }
    .s-warning  { background: rgba(234,179,8,.15);  color: var(--warning); }
    .s-critical { background: rgba(239,68,68,.15);  color: var(--critical); }
    .s-expired  { background: rgba(220,38,38,.15);  color: var(--expired); }
    .s-error    { background: rgba(168,85,247,.15); color: var(--error); }
    .days-cell { display: flex; align-items: center; gap: 7px; }
    .bar-track { width: 60px; height: 4px; background: var(--border); border-radius: 2px; flex-shrink: 0; }
    .bar-fill  { height: 100%; border-radius: 2px; }
    .san-cell  { color: var(--muted); font-size: .8rem; max-width: 200px; }
    .error-txt { color: var(--error); font-size: .8rem; }

    /* ── History cards ──────────────────────────────────────────── */
    .history-card {
      display: flex; align-items: center; gap: 12px;
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 10px; padding: 14px 16px; margin-bottom: 10px;
      transition: border-color .15s;
    }
    .history-card:hover { border-color: #475569; }
    .history-main { flex: 1; cursor: pointer; }
    .history-meta { display: flex; align-items: center; gap: 10px;
      margin-bottom: 6px; flex-wrap: wrap; }
    .history-date { font-size: .8rem; color: var(--muted); }
    .history-domains { font-size: .8rem; color: var(--muted); }
    .folder-tag { font-size: .72rem; background: rgba(59,130,246,.1);
      color: #93c5fd; border: 1px solid rgba(59,130,246,.2);
      padding: 1px 7px; border-radius: 999px; }
    .history-badges { display: flex; gap: 6px; flex-wrap: wrap; }
    .history-actions { display: flex; gap: 6px; flex-shrink: 0; }

    /* ── Save notice ────────────────────────────────────────────── */
    .save-notice { margin-top: 14px; padding: 10px 14px; background: rgba(34,197,94,.1);
      border: 1px solid rgba(34,197,94,.2); border-radius: 8px; color: var(--ok);
      font-size: .85rem; }

    /* ── Empty state ────────────────────────────────────────────── */
    .empty-state { padding: 40px; text-align: center; color: var(--muted); }

    /* ── Pagination ─────────────────────────────────────────────── */
    .pagination { display: flex; justify-content: center; align-items: center;
      gap: 12px; margin-top: 16px; }

    /* ── Modal ──────────────────────────────────────────────────── */
    #modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,.6);
      z-index: 100; }
    #modal-box { position: fixed; top: 50%; left: 50%; transform: translate(-50%,-50%);
      z-index: 101; background: var(--surface); border: 1px solid var(--border);
      border-radius: 12px; width: 100%; max-width: 380px; padding: 20px;
      box-shadow: 0 8px 32px rgba(0,0,0,.5); }
    .modal-hdr { display: flex; justify-content: space-between; align-items: center;
      margin-bottom: 16px; }
    .modal-hdr span { font-weight: 700; }
    .modal-close { background: none; border: none; cursor: pointer; color: var(--muted);
      font-size: 1.2rem; line-height: 1; padding: 2px; }
    .modal-input { width: 100%; padding: 9px 12px; background: var(--surface2);
      border: 1px solid var(--border); border-radius: 8px; color: var(--text);
      font-size: .9rem; outline: none; margin-bottom: 12px; }
    .modal-input:focus { border-color: var(--accent); }
    .modal-actions { display: flex; justify-content: flex-end; gap: 8px; }

    /* ── Responsive ─────────────────────────────────────────────── */
    @media (max-width: 640px) {
      :root { --sidebar-w: 0px; }
      #sidebar { display: none; }
      #main-view { padding: 16px; }
      th:nth-child(5), td:nth-child(5),
      th:nth-child(6), td:nth-child(6) { display: none; }
    }
  </style>
</head>
<body>

<!-- ── Auth screen ──────────────────────────────────────────────── -->
<div id="auth-screen">
  <div class="auth-card">
    <div class="auth-logo">&#128274;</div>
    <h1>SSL Certificate Monitor</h1>
    <div class="auth-tabs">
      <button class="auth-tab active" id="tab-login" onclick="showAuthTab('login')">Sign In</button>
      <button class="auth-tab" id="tab-register" onclick="showAuthTab('register')">Create Account</button>
    </div>

    <form id="form-login" onsubmit="doLogin(event)">
      <div class="form-field"><input type="email" id="l-email" placeholder="Email address" required autocomplete="email" /></div>
      <div class="form-field"><input type="password" id="l-pass" placeholder="Password" required autocomplete="current-password" /></div>
      <p class="form-error" id="l-err"></p>
      <button type="submit" class="btn btn-primary btn-full">Sign In</button>
    </form>

    <form id="form-register" hidden onsubmit="doRegister(event)">
      <div class="form-field"><input type="email" id="r-email" placeholder="Email address" required autocomplete="email" /></div>
      <div class="form-field"><input type="password" id="r-pass" placeholder="Password (min 8 chars)" required minlength="8" autocomplete="new-password" /></div>
      <div class="form-field"><input type="password" id="r-confirm" placeholder="Confirm password" required autocomplete="new-password" /></div>
      <p class="form-error" id="r-err"></p>
      <button type="submit" class="btn btn-primary btn-full">Create Account</button>
    </form>
  </div>
</div>

<!-- ── App shell ────────────────────────────────────────────────── -->
<div id="app-screen" hidden>
  <header>
    <div class="hdr-brand">
      <div class="hdr-logo">&#128274;</div>
      SSL Certificate Monitor
    </div>
    <div class="hdr-user">
      <span class="hdr-email" id="hdr-email"></span>
      <button class="btn btn-ghost btn-sm" onclick="doLogout()">Sign out</button>
    </div>
  </header>

  <div class="app-body">
    <nav id="sidebar">
      <button class="nav-item active" id="nav-scan" onclick="setView('scan')">
        <span class="nav-icon">&#128269;</span> New Scan
      </button>
      <button class="nav-item" id="nav-history" onclick="setView('history')">
        <span class="nav-icon">&#128203;</span> All History
      </button>
      <div class="sidebar-sep"></div>
      <div class="sidebar-sec-hdr">
        Folders
        <button class="icon-btn" onclick="showCreateFolder()" title="New folder">&#43;</button>
      </div>
      <div id="folders-nav"></div>
    </nav>

    <main id="main-view"></main>
  </div>
</div>

<!-- ── Modal ────────────────────────────────────────────────────── -->
<div id="modal-overlay" hidden onclick="closeModal()"></div>
<div id="modal-box" hidden>
  <div class="modal-hdr">
    <span id="modal-title"></span>
    <button class="modal-close" onclick="closeModal()">&#215;</button>
  </div>
  <div id="modal-body"></div>
</div>

<script>
// ================================================================ //
// State
// ================================================================ //
const S = {
  user: null, folders: [], view: 'scan',
  activeFolderId: null,
  domains: [], results: [], scanning: false,
  historyItems: [], historyTotal: 0, historyPage: 1,
  detailScan: null,
};

// ================================================================ //
// API helper — auto-refresh on 401
// ================================================================ //
async function api(method, path, body, _retried = false) {
  const opts = { method, credentials: 'same-origin' };
  if (body !== undefined) {
    opts.headers = { 'Content-Type': 'application/json' };
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(path, opts);

  // Auth endpoints are never protected — let their 401s fall through as errors
  const isAuthEndpoint = path === '/api/auth/login' || path === '/api/auth/register' || path === '/api/auth/refresh';
  if (r.status === 401 && !_retried && !isAuthEndpoint) {
    // Silently attempt token refresh
    const ref = await fetch('/api/auth/refresh', { method: 'POST', credentials: 'same-origin' });
    if (ref.ok) return api(method, path, body, true);   // retry once
    // Refresh failed — session truly expired
    S.user = null;
    showAuth();
    return null;
  }
  if (r.status === 401 && !isAuthEndpoint) { S.user = null; showAuth(); return null; }
  if (r.status === 204) return null;
  if (!r.ok) {
    const e = await r.json().catch(() => ({ detail: 'Request failed' }));
    throw new Error(e.detail || 'Request failed');
  }
  return r.json();
}

// ================================================================ //
// Boot
// ================================================================ //
async function init() {
  const user = await fetch('/api/auth/me', { credentials: 'same-origin' })
    .then(r => r.ok ? r.json() : null).catch(() => null);
  user ? showApp(user) : showAuth();
}

// ================================================================ //
// Auth
// ================================================================ //
function showAuth() {
  document.getElementById('auth-screen').hidden = false;
  document.getElementById('app-screen').hidden = true;
}

async function showApp(user) {
  S.user = user;
  document.getElementById('auth-screen').hidden = true;
  document.getElementById('app-screen').hidden = false;
  document.getElementById('hdr-email').textContent = user.email;
  await loadFolders();
  setView('scan');
}

function showAuthTab(tab) {
  const login = tab === 'login';
  document.getElementById('tab-login').classList.toggle('active', login);
  document.getElementById('tab-register').classList.toggle('active', !login);
  document.getElementById('form-login').hidden = !login;
  document.getElementById('form-register').hidden = login;
}

async function doLogin(e) {
  e.preventDefault();
  const errEl = document.getElementById('l-err');
  const btn   = e.submitter || e.target.querySelector('button[type=submit]');
  errEl.textContent = '';
  btn.disabled = true; btn.textContent = 'Signing in…';
  try {
    const r = await fetch('/api/auth/login', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email:    document.getElementById('l-email').value,
        password: document.getElementById('l-pass').value,
      }),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) { errEl.textContent = data.detail || 'Sign in failed'; return; }
    showApp(data);
  } catch (err) {
    errEl.textContent = 'Could not reach server — is it running?';
  } finally {
    btn.disabled = false; btn.textContent = 'Sign In';
  }
}

async function doRegister(e) {
  e.preventDefault();
  const errEl = document.getElementById('r-err');
  const btn   = e.submitter || e.target.querySelector('button[type=submit]');
  errEl.textContent = '';
  const pass = document.getElementById('r-pass').value;
  if (pass !== document.getElementById('r-confirm').value) {
    errEl.textContent = 'Passwords do not match'; return;
  }
  btn.disabled = true; btn.textContent = 'Creating account…';
  try {
    const r = await fetch('/api/auth/register', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email:    document.getElementById('r-email').value,
        password: pass,
      }),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) { errEl.textContent = data.detail || 'Registration failed'; return; }
    // Account created — send user to login
    document.getElementById('r-email').value = '';
    document.getElementById('r-pass').value  = '';
    document.getElementById('r-confirm').value = '';
    showAuthTab('login');
    const ok = document.getElementById('l-err');
    if (ok) { ok.style.color = 'var(--ok)'; ok.textContent = 'Account created — please sign in'; }
  } catch (err) {
    errEl.textContent = 'Could not reach server — is it running?';
  } finally {
    btn.disabled = false; btn.textContent = 'Create Account';
  }
}

async function doLogout() {
  await api('POST', '/api/auth/logout');
  S.user = null;
  showAuth();
}

// ================================================================ //
// Navigation
// ================================================================ //
function setView(view, folderId = null) {
  S.view = view; S.activeFolderId = folderId;
  document.getElementById('nav-scan').classList.toggle('active', view === 'scan');
  document.getElementById('nav-history').classList.toggle('active', view === 'history');
  document.querySelectorAll('.folder-item').forEach(el =>
    el.classList.toggle('active', el.dataset.id === folderId));
  if (view === 'scan') { renderScanView(); }
  else if (view === 'history' || view === 'folder') { loadHistory(folderId); }
  else if (view === 'detail') { renderDetailView(); }
}

// ================================================================ //
// Folders
// ================================================================ //
async function loadFolders() {
  const f = await api('GET', '/api/folders');
  if (f) { S.folders = f; renderFolderNav(); }
}

function renderFolderNav() {
  document.getElementById('folders-nav').innerHTML = S.folders.map(f => `
    <button class="folder-item${S.activeFolderId === f.id ? ' active' : ''}"
            data-id="${f.id}" onclick="setView('folder','${f.id}')">
      <span>&#128193;</span>
      <span class="folder-name-txt">${esc(f.name)}</span>
      <span class="f-actions">
        <button class="f-btn" onclick="event.stopPropagation();showRenameFolder('${f.id}','${esc(f.name)}')" title="Rename">&#9998;</button>
        <button class="f-btn danger" onclick="event.stopPropagation();confirmDeleteFolder('${f.id}')" title="Delete">&#128465;</button>
      </span>
    </button>`).join('');
}

function showCreateFolder() {
  openModal('New Folder', `
    <input type="text" id="fi" class="modal-input" placeholder="Folder name" maxlength="50" />
    <div class="modal-actions">
      <button class="btn btn-ghost btn-sm" onclick="closeModal()">Cancel</button>
      <button class="btn btn-primary btn-sm" onclick="createFolder()">Create</button>
    </div>`);
  setTimeout(() => document.getElementById('fi')?.focus(), 50);
}

async function createFolder() {
  const name = document.getElementById('fi')?.value.trim();
  if (!name) return;
  try { await api('POST', '/api/folders', { name }); closeModal(); await loadFolders(); }
  catch (err) { alert(err.message); }
}

function showRenameFolder(id, current) {
  openModal('Rename Folder', `
    <input type="text" id="fi" class="modal-input" value="${esc(current)}" maxlength="50" />
    <div class="modal-actions">
      <button class="btn btn-ghost btn-sm" onclick="closeModal()">Cancel</button>
      <button class="btn btn-primary btn-sm" onclick="renameFolder('${id}')">Save</button>
    </div>`);
  setTimeout(() => { const el = document.getElementById('fi'); if(el){el.focus();el.select();} }, 50);
}

async function renameFolder(id) {
  const name = document.getElementById('fi')?.value.trim();
  if (!name) return;
  try {
    await api('PUT', `/api/folders/${id}`, { name });
    closeModal(); await loadFolders();
    if (S.activeFolderId === id && S.view === 'folder') loadHistory(id);
  } catch (err) { alert(err.message); }
}

function confirmDeleteFolder(id) {
  openModal('Delete Folder', `
    <p style="color:var(--muted);margin-bottom:16px">Scans in this folder will be moved back to History.</p>
    <div class="modal-actions">
      <button class="btn btn-ghost btn-sm" onclick="closeModal()">Cancel</button>
      <button class="btn btn-danger btn-sm" onclick="deleteFolder('${id}')">Delete</button>
    </div>`);
}

async function deleteFolder(id) {
  try {
    await api('DELETE', `/api/folders/${id}`);
    closeModal(); await loadFolders();
    if (S.activeFolderId === id) setView('history');
  } catch (err) { alert(err.message); }
}

// ================================================================ //
// History
// ================================================================ //
async function loadHistory(folderId = null, page = 1) {
  const params = new URLSearchParams({ page, per_page: 20 });
  if (folderId) params.set('folder_id', folderId);
  const data = await api('GET', `/api/history?${params}`);
  if (!data) return;
  S.historyItems = data.items; S.historyTotal = data.total; S.historyPage = data.page;
  renderHistoryView();
}

function renderHistoryView() {
  const folderName = S.activeFolderId
    ? (S.folders.find(f => f.id === S.activeFolderId)?.name || 'Folder') : null;
  const title = folderName ? `&#128193; ${esc(folderName)}` : '&#128203; All History';
  const totalPages = Math.ceil(S.historyTotal / 20);

  let html = `<div class="view-hdr"><h2>${title}</h2></div>`;
  if (!S.historyItems.length) {
    html += `<div class="empty-state">No scans yet. <button class="link-btn" onclick="setView('scan')">Run your first scan &#8594;</button></div>`;
  } else {
    html += S.historyItems.map(historyCard).join('');
    if (S.historyTotal > 20) {
      html += `<div class="pagination">
        ${S.historyPage > 1 ? `<button class="btn btn-ghost btn-sm" onclick="loadHistory('${S.activeFolderId}',${S.historyPage-1})">&#8592; Prev</button>` : ''}
        <span style="color:var(--muted)">Page ${S.historyPage} of ${totalPages}</span>
        ${S.historyPage < totalPages ? `<button class="btn btn-ghost btn-sm" onclick="loadHistory('${S.activeFolderId}',${S.historyPage+1})">Next &#8594;</button>` : ''}
      </div>`;
    }
  }
  document.getElementById('main-view').innerHTML = html;
}

function historyCard(s) {
  const d = new Date(s.created_at);
  const dateStr = d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
  const badges = Object.entries(s.summary).filter(([,n])=>n>0)
    .map(([st,n]) => `<span class="badge badge-${st.toLowerCase()}">${n} ${st}</span>`).join('');
  const folderTag = s.folder_name
    ? `<span class="folder-tag">&#128193; ${esc(s.folder_name)}</span>` : '';
  return `<div class="history-card">
    <div class="history-main" onclick="viewScan('${s.id}')">
      <div class="history-meta">
        <span class="history-date">${dateStr}</span>
        <span class="history-domains">${s.domains_checked} domain${s.domains_checked!==1?'s':''}</span>
        ${folderTag}
      </div>
      <div class="history-badges">${badges||'<span style="color:var(--muted);font-size:.8rem">—</span>'}</div>
    </div>
    <div class="history-actions">
      <button class="btn btn-ghost btn-sm" title="Move to folder" onclick="showMoveFolder('${s.id}')">&#128193;</button>
      <button class="btn btn-danger btn-sm" title="Delete" onclick="confirmDeleteScan('${s.id}')">&#128465;</button>
    </div>
  </div>`;
}

async function viewScan(id) {
  const scan = await api('GET', `/api/history/${id}`);
  if (!scan) return;
  S.detailScan = scan; S.view = 'detail'; renderDetailView();
}

function renderDetailView() {
  const scan = S.detailScan; if (!scan) return;
  const date = new Date(scan.created_at).toLocaleString();
  const back = S.activeFolderId ? `setView('folder','${S.activeFolderId}')` : "setView('history')";
  let html = `<div class="view-hdr">
    <button class="btn btn-ghost btn-sm" onclick="${back}">&#8592; Back</button>
    <h2>Scan &mdash; ${date}</h2>
    <button class="btn btn-ghost btn-sm" onclick="exportDetailJSON()">Export JSON</button>
    <button class="btn btn-ghost btn-sm" onclick="exportDetailHTML()">Export HTML</button>
    <button class="btn btn-ghost btn-sm" onclick="showMoveFolder('${scan.id}')">&#128193; Move</button>
    <button class="btn btn-danger btn-sm" onclick="confirmDeleteScan('${scan.id}')">Delete</button>
  </div>`;
  html += resultsTable(scan.results || []);
  document.getElementById('main-view').innerHTML = html;
}

function resultsTable(results) {
  if (!results.length) return '<p style="color:var(--muted);padding:24px">No results.</p>';
  const order = {OK:0,WARNING:1,CRITICAL:2,EXPIRED:3,ERROR:4};
  const rows = [...results].sort((a,b) => (order[a.status]||0)-(order[b.status]||0)||a.domain.localeCompare(b.domain))
    .map(r => {
      const days = r.days_remaining !== null
        ? `<div class="days-cell"><span>${r.days_remaining}</span><div class="bar-track"><div class="bar-fill" style="width:${Math.min(r.days_remaining/365*100,100).toFixed(0)}%;background:${r.status_css_color}"></div></div></div>` : '&mdash;';
      const san = r.error
        ? `<span class="error-txt" title="${esc(r.error)}">${esc((r.error||'').slice(0,55))}${(r.error||'').length>55?'&hellip;':''}</span>`
        : ((r.subject_alt_names||[]).slice(0,3).join(', ')+((r.subject_alt_names||[]).length>3?` <span style="color:var(--muted)">+${(r.subject_alt_names||[]).length-3}</span>`:''))||'&mdash;';
      return `<tr><td class="domain-cell">${esc(r.host_label)}</td>
        <td><span class="status-pill s-${r.status.toLowerCase()}">${r.status_icon} ${r.status}</span></td>
        <td>${r.expiry_date||'&mdash;'}</td><td>${days}</td>
        <td style="color:var(--muted)">${esc(r.issued_by||'&mdash;')}</td>
        <td class="san-cell">${san}</td></tr>`;
    }).join('');
  return `<div class="table-wrap"><table>
    <thead><tr><th>Domain</th><th>Status</th><th>Expires</th><th>Days Left</th><th>Issuer</th><th>Alt Names</th></tr></thead>
    <tbody>${rows}</tbody>
  </table></div>`;
}

// ── Move to folder ────────────────────────────────────────────────
function showMoveFolder(scanId) {
  const opts = [`<option value="">&#8212; No folder &#8212;</option>`,
    ...S.folders.map(f => `<option value="${f.id}">${esc(f.name)}</option>`)].join('');
  openModal('Move to Folder', `
    <select id="mf-sel" class="modal-input">${opts}</select>
    <div class="modal-actions">
      <button class="btn btn-ghost btn-sm" onclick="closeModal()">Cancel</button>
      <button class="btn btn-primary btn-sm" onclick="moveToFolder('${scanId}')">Move</button>
    </div>`);
}

async function moveToFolder(scanId) {
  const folderId = document.getElementById('mf-sel')?.value || null;
  try {
    await api('PATCH', `/api/history/${scanId}`, { folder_id: folderId || null });
    closeModal();
    if (S.view === 'history') loadHistory();
    else if (S.view === 'folder') loadHistory(S.activeFolderId);
  } catch (err) { alert(err.message); }
}

// ── Delete scan ───────────────────────────────────────────────────
function confirmDeleteScan(id) {
  openModal('Delete Scan', `
    <p style="color:var(--muted);margin-bottom:16px">This scan will be permanently deleted.</p>
    <div class="modal-actions">
      <button class="btn btn-ghost btn-sm" onclick="closeModal()">Cancel</button>
      <button class="btn btn-danger btn-sm" onclick="deleteScan('${id}')">Delete</button>
    </div>`);
}

async function deleteScan(id) {
  try {
    await api('DELETE', `/api/history/${id}`); closeModal();
    if (S.view === 'detail') setView(S.activeFolderId ? 'folder' : 'history', S.activeFolderId);
    else loadHistory(S.activeFolderId);
  } catch (err) { alert(err.message); }
}

// ================================================================ //
// Scan view
// ================================================================ //
function renderScanView() {
  const chips = S.domains.map(d =>
    `<span class="chip">${esc(d)}<button class="chip-x" onclick="removeDomain('${esc(d)}')">&#215;</button></span>`
  ).join('');
  document.getElementById('main-view').innerHTML = `
    <div class="view-hdr"><h2>New Scan</h2></div>
    <div class="card">
      <div class="card-lbl">Domains</div>
      <div class="chips-wrap" id="chips-wrap" onclick="document.getElementById('domain-input').focus()">
        <span id="chips-cont">${chips}</span>
        <input id="domain-input" type="text" placeholder="Type a domain and press Enter&hellip;"
               autocomplete="off" spellcheck="false" />
      </div>
      <p class="hint">Press Enter or comma after each domain &mdash; e.g. google.com, api.example.com:8443</p>
      <div class="settings-row">
        <div class="setting"><label>Warn when &le; days</label><input type="number" id="warn-days" value="30" min="1" /></div>
        <div class="setting"><label>Critical when &le; days</label><input type="number" id="critical-days" value="7" min="1" /></div>
        <div class="setting"><label>Timeout (seconds)</label><input type="number" id="timeout" value="10" min="1" /></div>
      </div>
      <div class="btn-row">
        <button class="btn btn-primary" id="scan-btn" onclick="startScan()">&#9654; Scan</button>
        <button class="btn btn-ghost btn-sm" onclick="loadExamples()">Load examples</button>
        <button class="btn btn-ghost btn-sm" onclick="clearDomains()">Clear</button>
      </div>
    </div>
    <div id="prog-card" class="card" hidden>
      <div class="prog-hdr"><span id="prog-lbl">Scanning&hellip;</span><span id="prog-cnt">0 / 0</span></div>
      <div class="prog-track"><div class="prog-fill" id="prog-fill"></div></div>
    </div>
    <div id="res-card" class="card" hidden>
      <div class="btn-row" style="margin-top:0;margin-bottom:12px">
        <div id="res-summary" style="flex:1;display:flex;gap:6px;flex-wrap:wrap"></div>
        <button class="btn btn-ghost btn-sm" onclick="exportScanJSON()">Export JSON</button>
        <button class="btn btn-ghost btn-sm" onclick="exportScanHTML()">Export HTML</button>
      </div>
      <div id="res-table"></div>
      <div id="save-notice" class="save-notice" hidden></div>
    </div>`;
  document.getElementById('domain-input').addEventListener('keydown', onDomainKey);
}

function onDomainKey(e) {
  if (e.key === 'Enter' || e.key === ',') {
    e.preventDefault();
    const v = e.target.value.replace(/,$/, '').trim().toLowerCase();
    if (v) { addDomain(v); e.target.value = ''; }
  } else if (e.key === 'Backspace' && !e.target.value && S.domains.length) {
    removeDomain(S.domains[S.domains.length - 1]);
  }
}

function addDomain(d) {
  d = d.replace(/\/$/, '').trim().toLowerCase();
  if (!d || S.domains.includes(d)) return;
  S.domains.push(d); refreshChips();
}
function removeDomain(d) { S.domains = S.domains.filter(x => x !== d); refreshChips(); }
function refreshChips() {
  const el = document.getElementById('chips-cont'); if (!el) return;
  el.innerHTML = S.domains.map(d =>
    `<span class="chip">${esc(d)}<button class="chip-x" onclick="removeDomain('${esc(d)}')">&#215;</button></span>`
  ).join('');
}
function loadExamples() { ['google.com','github.com','stripe.com','cloudflare.com'].forEach(addDomain); }
function clearDomains() { S.domains = []; refreshChips(); const el=document.getElementById('domain-input'); if(el) el.value=''; }

async function startScan() {
  if (S.scanning || !S.domains.length) { if(!S.domains.length) document.getElementById('domain-input')?.focus(); return; }
  S.scanning = true; S.results = [];
  const btn = document.getElementById('scan-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Scanning\u2026'; }
  const total = S.domains.length; let checked = 0;
  document.getElementById('prog-card').hidden = false;
  document.getElementById('res-card').hidden = false;
  document.getElementById('res-table').innerHTML = '';
  document.getElementById('res-summary').innerHTML = '';
  document.getElementById('save-notice').hidden = true;
  setProgress(0, total);

  const warnDays = parseInt(document.getElementById('warn-days')?.value)||30;
  const critDays = parseInt(document.getElementById('critical-days')?.value)||7;
  const timeout  = parseInt(document.getElementById('timeout')?.value)||10;

  try {
    const resp = await fetch('/api/scan', {
      method:'POST', credentials:'same-origin',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({domains:S.domains, warn_days:warnDays, critical_days:critDays, timeout}),
    });
    const reader = resp.body.getReader(); const dec = new TextDecoder(); let buf = '';
    while (true) {
      const {done, value} = await reader.read(); if (done) break;
      buf += dec.decode(value, {stream:true});
      const lines = buf.split('\n'); buf = lines.pop();
      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const data = JSON.parse(line.slice(6));
        if (data.done) {
          if (data.scan_id) {
            const n = document.getElementById('save-notice');
            if (n) { n.hidden=false; n.innerHTML=`&#10003; Saved to history &mdash; <button class="link-btn" onclick="viewScan('${data.scan_id}')">View &#8594;</button>`; }
          }
          continue;
        }
        S.results.push(data); checked++;
        setProgress(checked, total);
        appendRow(data); updateSummary();
      }
    }
  } catch (err) { console.error('Scan error:', err); }
  finally {
    S.scanning = false;
    if (btn) { btn.disabled=false; btn.textContent='\u25BA Scan'; }
    const lbl=document.getElementById('prog-lbl'); if(lbl) lbl.textContent='Done';
  }
}

function setProgress(c, t) {
  const pct = t ? c/t*100 : 0;
  const fill=document.getElementById('prog-fill'); if(fill) fill.style.width=pct+'%';
  const cnt=document.getElementById('prog-cnt'); if(cnt) cnt.textContent=`${c} / ${t}`;
  const lbl=document.getElementById('prog-lbl'); if(lbl&&c<t) lbl.textContent='Scanning\u2026';
}

function appendRow(r) {
  const wrap = document.getElementById('res-table'); if (!wrap) return;
  if (!wrap.querySelector('table')) {
    wrap.innerHTML = `<div class="table-wrap"><table>
      <thead><tr><th>Domain</th><th>Status</th><th>Expires</th><th>Days Left</th><th>Issuer</th><th>Alt Names</th></tr></thead>
      <tbody id="res-tbody"></tbody></table></div>`;
  }
  const tbody = document.getElementById('res-tbody'); if (!tbody) return;
  const tr = document.createElement('tr'); tr.className='row-in';
  const days = r.days_remaining !== null
    ? `<div class="days-cell"><span>${r.days_remaining}</span><div class="bar-track"><div class="bar-fill" style="width:${Math.min(r.days_remaining/365*100,100).toFixed(0)}%;background:${r.status_css_color}"></div></div></div>` : '&mdash;';
  const san = r.error
    ? `<span class="error-txt" title="${esc(r.error)}">${esc((r.error||'').slice(0,55))}${(r.error||'').length>55?'&hellip;':''}</span>`
    : ((r.subject_alt_names||[]).slice(0,3).join(', ')+((r.subject_alt_names||[]).length>3?` <span style="color:var(--muted)">+${(r.subject_alt_names||[]).length-3}</span>`:''))||'&mdash;';
  tr.innerHTML=`<td class="domain-cell">${esc(r.host_label)}</td>
    <td><span class="status-pill s-${r.status.toLowerCase()}">${r.status_icon} ${r.status}</span></td>
    <td>${r.expiry_date||'&mdash;'}</td><td>${days}</td>
    <td style="color:var(--muted)">${esc(r.issued_by||'&mdash;')}</td>
    <td class="san-cell">${san}</td>`;
  tbody.appendChild(tr);
}

function updateSummary() {
  const el = document.getElementById('res-summary'); if (!el) return;
  const counts = {};
  S.results.forEach(r => { counts[r.status]=(counts[r.status]||0)+1; });
  el.innerHTML = Object.entries(counts).filter(([,n])=>n>0)
    .map(([s,n]) => `<span class="badge badge-${s.toLowerCase()}">${n} ${s}</span>`).join('');
}

// ================================================================ //
// Export
// ================================================================ //
function exportScanJSON() {
  if (!S.results.length) return;
  dl(JSON.stringify({generated_at:new Date().toISOString(),total:S.results.length,results:S.results},null,2),'ssl-scan.json','application/json');
}
async function exportScanHTML() {
  if (!S.results.length) return;
  const r = await fetch('/api/export/html',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(S.results)});
  dl(await r.text(),'ssl-report.html','text/html');
}
function exportDetailJSON() {
  const s=S.detailScan; if(!s) return;
  dl(JSON.stringify({id:s.id,created_at:s.created_at,total:(s.results||[]).length,results:s.results},null,2),'ssl-scan.json','application/json');
}
async function exportDetailHTML() {
  const s=S.detailScan; if(!s) return;
  const r = await fetch('/api/export/html',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(s.results||[])});
  dl(await r.text(),'ssl-report.html','text/html');
}
function dl(content, name, mime) {
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([content],{type:mime}));
  a.download=name; a.click(); URL.revokeObjectURL(a.href);
}

// ================================================================ //
// Modal
// ================================================================ //
function openModal(title, body) {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-body').innerHTML = body;
  document.getElementById('modal-overlay').hidden = false;
  document.getElementById('modal-box').hidden = false;
}
function closeModal() {
  document.getElementById('modal-overlay').hidden = true;
  document.getElementById('modal-box').hidden = true;
}

// ================================================================ //
// Utils
// ================================================================ //
function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
document.addEventListener('keydown', e => {
  if ((e.metaKey||e.ctrlKey) && e.key==='Enter') startScan();
  if (e.key==='Escape') closeModal();
});

init();
</script>
</body>
</html>"""
