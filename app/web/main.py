"""
main.py

FastAPI-приложение: логин, аккаунты (CRUD + start/stop), выбор зон,
найденные IP, детальные логи по аккаунту.
"""

from __future__ import annotations

import logging
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .. import db
from ..config import settings
from ..manager import RollerManager
from ..ip_checker import run_registry_checker
from ..security import csrf_token, hash_password, is_authenticated, login, logout, require_login, verify_csrf, verify_password
from ..whitelist import Whitelist
from ..zones import ZoneCatalog

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("ip-roller.web")

templates = Jinja2Templates(directory=str((__import__("pathlib").Path(__file__).parent / "templates")))
static_dir = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_db(settings.db_path)
    whitelist = Whitelist.load(settings.whitelist_path)
    zone_catalog = ZoneCatalog.load(settings.zones_path)
    manager = RollerManager(db_path=settings.db_path, whitelist=whitelist, zone_catalog=zone_catalog, settings=settings)

    app.state.whitelist = whitelist
    app.state.zone_catalog = zone_catalog
    app.state.manager = manager
    checker_stop = asyncio.Event()
    checker_task = asyncio.create_task(run_registry_checker(settings.db_path, whitelist, checker_stop))

    log.info("ip-roller запущен, загружено CIDR: %d, зон: %d", whitelist.cidr_count(), len(zone_catalog.all_codes()))
    if not settings.admin_password_hash:
        log.warning(
            "ADMIN_PASSWORD_HASH не задан в .env — вход в веб-панель невозможен, "
            "сгенерируй хэш: python3 -m app.security_cli hash-password '<пароль>'"
        )

    try:
        await manager.resume_desired_running()
        yield
    finally:
        checker_stop.set()
        await checker_task
        await manager.shutdown()


app = FastAPI(lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret, same_site="lax", https_only=settings.session_https_only)


def render(request: Request, template: str, **ctx):
    ctx.setdefault("authenticated", is_authenticated(request))
    ctx.setdefault("flash", None)
    ctx.setdefault("csrf_token", csrf_token(request))
    return templates.TemplateResponse(request, template, ctx)


def account_view(account: db.AccountRow, is_running: bool) -> dict:
    """Only expose display fields to templates; never pass provider secrets."""
    return {
        "id": account.id, "label": account.label, "account_id": account.account_id,
        "project_id": account.project_id, "project_name": account.project_name,
        "selected_zones": account.selected_zones, "status": account.status,
        "status_detail": account.status_detail, "cooldown_until": account.cooldown_until,
        "total_attempts": account.total_attempts, "total_matches": account.total_matches,
        "is_running": is_running,
    }


# ------------------------------------------------------------------- auth

@app.get("/login")
async def login_page(request: Request):
    if is_authenticated(request):
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html")


@app.post("/login")
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    await verify_csrf(request)
    if username == settings.admin_username and verify_password(password, settings.admin_password_hash):
        login(request)
        await db.add_audit_event(settings.db_path, "login", settings.admin_username)
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html", flash={"kind": "error", "text": "Неверный логин или пароль"})


@app.post("/logout")
async def logout_submit(request: Request):
    await verify_csrf(request)
    await db.add_audit_event(settings.db_path, "logout", settings.admin_username)
    logout(request)
    return RedirectResponse("/login", status_code=303)


# --------------------------------------------------------------- dashboard

@app.get("/")
async def dashboard(request: Request):
    if (redirect := require_login(request)) is not None:
        return redirect
    manager: RollerManager = request.app.state.manager
    accounts = await db.list_accounts(settings.db_path)
    safety = await db.safety_summary(settings.db_path)
    circuit = await db.get_service_circuit(settings.db_path)
    analytics = await db.get_analytics(settings.db_path, hours=24,
                                       cost_per_ip_hour_rub=settings.floating_ip_cost_per_hour_rub)
    rows = []
    for a in accounts:
        rows.append(account_view(a, manager.is_running(a.id)))
    return render(request, "dashboard.html", accounts=rows, safety=safety, analytics=analytics,
                  circuit=circuit,
                  daily_create_limit=settings.max_create_operations_per_day,
                  active_ip_limit=settings.max_active_managed_ips, active_nav="dashboard",
                  flash=({"kind": "ok", "text": "Аварийная остановка выполнена. Floating IP остались в Selectel без изменений."}
                         if request.query_params.get("notice") == "emergency-stop" else None))


@app.get("/accounts/new")
async def new_account_page(request: Request):
    if (redirect := require_login(request)) is not None:
        return redirect
    return render(request, "add_account.html", active_nav="dashboard")


@app.post("/accounts/new")
async def new_account_submit(
    request: Request,
    label: str = Form(...),
    account_id: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    project_id: str = Form(...),
):
    await verify_csrf(request)
    if (redirect := require_login(request)) is not None:
        return redirect
    try:
        await db.create_account(
            settings.db_path,
            label=label.strip(), account_id=account_id.strip(), username=username.strip(),
            password=password, project_id=project_id.strip(),
        )
        await db.add_audit_event(settings.db_path, "account_created", label.strip())
    except Exception as exc:
        return render(
            request, "add_account.html", active_nav="dashboard",
            flash={"kind": "error", "text": f"Не удалось добавить: {exc}"},
        )
    return RedirectResponse("/", status_code=303)


@app.get("/accounts/{account_id}/edit")
async def edit_account_page(request: Request, account_id: int):
    if (redirect := require_login(request)) is not None:
        return redirect
    account = await db.get_account(settings.db_path, account_id)
    if account is None:
        return RedirectResponse("/", status_code=303)
    manager: RollerManager = request.app.state.manager
    return render(
        request, "edit_account.html", active_nav="dashboard",
        account=account_view(account, manager.is_running(account_id)), is_running=manager.is_running(account_id),
    )


@app.post("/accounts/{account_id}/edit")
async def edit_account_submit(
    request: Request,
    account_id: int,
    label: str = Form(...),
    selectel_account_id: str = Form(..., alias="account_id"),
    username: str = Form(...),
    password: str = Form(""),
    project_id: str = Form(...),
):
    await verify_csrf(request)
    if (redirect := require_login(request)) is not None:
        return redirect
    account = await db.get_account(settings.db_path, account_id)
    if account is None:
        return RedirectResponse("/", status_code=303)
    manager: RollerManager = request.app.state.manager
    try:
        await db.update_account(
            settings.db_path, account_id,
            label=label.strip(), account_id=selectel_account_id.strip(), username=username.strip(),
            password=password if password.strip() else None,
            project_id=project_id.strip(),
        )
        await db.add_audit_event(settings.db_path, "account_updated", label.strip(), "Учётные данные обновлены; значения секретов не записываются.")
    except Exception as exc:
        return render(
            request, "edit_account.html", active_nav="dashboard",
            account=account_view(account, manager.is_running(account_id)), is_running=manager.is_running(account_id),
            flash={"kind": "error", "text": f"Не удалось сохранить: {exc}"},
        )
    if manager.is_running(account_id):
        # Работающий воркер держит в памяти старый снимок аккаунта (креды,
        # ID) — после правки данных перезапускаем сами, чтобы новые значения
        # подхватились сразу же, а не только в БД до ручного старта.
        await manager.stop_account(account_id)
        try:
            await manager.start_account(account_id)
        except ValueError:
            pass
    return RedirectResponse("/", status_code=303)


@app.post("/accounts/{account_id}/delete")
async def delete_account_submit(request: Request, account_id: int):
    await verify_csrf(request)
    if (redirect := require_login(request)) is not None:
        return redirect
    manager: RollerManager = request.app.state.manager
    if manager.is_running(account_id):
        await manager.stop_account(account_id)
    try:
        await db.delete_account(settings.db_path, account_id)
    except ValueError as exc:
        accounts = await db.list_accounts(settings.db_path)
        rows = [account_view(a, manager.is_running(a.id)) for a in accounts]
        return render(request, "dashboard.html", accounts=rows, active_nav="dashboard",
                      flash={"kind": "error", "text": str(exc)})
    await db.add_audit_event(settings.db_path, "account_deleted", str(account_id))
    return RedirectResponse("/", status_code=303)


@app.post("/accounts/{account_id}/start")
async def start_account_submit(request: Request, account_id: int):
    await verify_csrf(request)
    if (redirect := require_login(request)) is not None:
        return redirect
    manager: RollerManager = request.app.state.manager
    try:
        await manager.start_account(account_id)
    except ValueError as exc:
        accounts = await db.list_accounts(settings.db_path)
        rows = [account_view(a, manager.is_running(a.id)) for a in accounts]
        return render(
            request, "dashboard.html", accounts=rows, active_nav="dashboard",
            flash={"kind": "error", "text": str(exc)},
        )
    await db.add_audit_event(settings.db_path, "worker_started", str(account_id))
    return RedirectResponse("/", status_code=303)


@app.post("/accounts/{account_id}/stop")
async def stop_account_submit(request: Request, account_id: int):
    await verify_csrf(request)
    if (redirect := require_login(request)) is not None:
        return redirect
    manager: RollerManager = request.app.state.manager
    await manager.stop_account(account_id)
    await db.add_audit_event(settings.db_path, "worker_stopped", str(account_id))
    return RedirectResponse("/", status_code=303)


@app.post("/emergency-stop")
async def emergency_stop_submit(request: Request):
    await verify_csrf(request)
    if (redirect := require_login(request)) is not None:
        return redirect
    manager: RollerManager = request.app.state.manager
    await manager.emergency_stop()
    await db.add_audit_event(settings.db_path, "emergency_stop", settings.admin_username,
                             "Все воркеры остановлены; управляемые IP не удалялись.")
    return RedirectResponse("/?notice=emergency-stop", status_code=303)


# -------------------------------------------------------------------- zones

@app.get("/accounts/{account_id}/zones")
async def zones_page(request: Request, account_id: int):
    if (redirect := require_login(request)) is not None:
        return redirect
    account = await db.get_account(settings.db_path, account_id)
    if account is None:
        return RedirectResponse("/", status_code=303)
    zone_catalog: ZoneCatalog = request.app.state.zone_catalog
    manager: RollerManager = request.app.state.manager
    return render(
        request, "zones.html", active_nav="dashboard",
        account=account_view(account, manager.is_running(account_id)), cities=zone_catalog.cities, city_labels=ZoneCatalog.CITY_LABELS,
        selected=set(account.selected_zones), is_running=manager.is_running(account_id),
    )


@app.post("/accounts/{account_id}/zones")
async def zones_submit(request: Request, account_id: int):
    await verify_csrf(request)
    if (redirect := require_login(request)) is not None:
        return redirect
    form = await request.form()
    zones = form.getlist("zones")
    zone_catalog: ZoneCatalog = request.app.state.zone_catalog
    enabled_codes = zone_catalog.enabled_codes()
    zones = [z for z in zones if z in enabled_codes]
    await db.update_account_zones(settings.db_path, account_id, zones)
    await db.add_audit_event(settings.db_path, "zones_updated", str(account_id), ",".join(zones))

    manager: RollerManager = request.app.state.manager
    if manager.is_running(account_id):
        # Работающий воркер держит старый список зон в памяти (снимок на
        # момент старта) — без перезапуска новый выбор не подхватится, пока
        # пользователь не остановит/запустит аккаунт руками. Перезапускаем
        # сами: быстро и прозрачно, новый список зон подхватится сразу же.
        await manager.stop_account(account_id)
        try:
            await manager.start_account(account_id)
        except ValueError:
            # Например, сняли все галочки — оставляем аккаунт остановленным.
            pass
    return RedirectResponse("/", status_code=303)


# ---------------------------------------------------------------------- logs

@app.get("/accounts/{account_id}/logs")
async def logs_page(request: Request, account_id: int):
    if (redirect := require_login(request)) is not None:
        return redirect
    account = await db.get_account(settings.db_path, account_id)
    if account is None:
        return RedirectResponse("/", status_code=303)
    attempts = await db.list_attempts(settings.db_path, account_id, limit=300)
    zone_catalog: ZoneCatalog = request.app.state.zone_catalog
    manager: RollerManager = request.app.state.manager
    return render(
        request, "logs.html", active_nav="dashboard", account=account_view(account, manager.is_running(account_id)), attempts=attempts,
        city_labels=ZoneCatalog.CITY_LABELS, zone_catalog=zone_catalog,
    )


# ----------------------------------------------------------------- all logs

@app.get("/logs")
async def all_logs_page(request: Request):
    if (redirect := require_login(request)) is not None:
        return redirect
    attempts = await db.list_attempts_with_accounts(settings.db_path, limit=400)
    zone_catalog: ZoneCatalog = request.app.state.zone_catalog
    return render(
        request, "logs_all.html", active_nav="logs", attempts=attempts,
        city_labels=ZoneCatalog.CITY_LABELS, zone_catalog=zone_catalog,
    )


# ------------------------------------------------------------------ audit log

@app.get("/audit")
async def audit_page(request: Request):
    if (redirect := require_login(request)) is not None:
        return redirect
    events = await db.list_audit_events(settings.db_path)
    return render(request, "audit.html", active_nav="audit", events=events)


# ------------------------------------------------------------------ found ips

@app.get("/found-ips")
async def found_ips_page(request: Request, q: str = ""):
    if (redirect := require_login(request)) is not None:
        return redirect
    items = await db.list_found_ips(settings.db_path, search=q)
    return render(request, "found_ips.html", active_nav="found", items=items, query=q)


@app.get("/ip-history")
async def ip_history_page(request: Request, q: str = "", status: str = "", page: int = 1):
    if (redirect := require_login(request)) is not None:
        return redirect
    page = max(1, page)
    page_size = 100
    total = await db.count_ip_registry(settings.db_path, search=q, status=status)
    page = min(page, max(1, (total + page_size - 1) // page_size))
    items = await db.list_ip_registry(settings.db_path, search=q, status=status,
                                      limit=page_size, offset=(page - 1) * page_size)
    summary = await db.get_analytics(settings.db_path, hours=24,
                                     cost_per_ip_hour_rub=settings.floating_ip_cost_per_hour_rub)
    return render(request, "ip_history.html", active_nav="history", items=items, query=q,
                  selected_status=status, summary=summary, page=page, page_size=page_size, total=total,
                  page_count=max(1, (total + page_size - 1) // page_size))


@app.get("/analytics")
async def analytics_page(request: Request, hours: int = 24):
    if (redirect := require_login(request)) is not None:
        return redirect
    hours = max(1, min(hours, 720))
    analytics = await db.get_analytics(settings.db_path, hours=hours,
                                       cost_per_ip_hour_rub=settings.floating_ip_cost_per_hour_rub)
    return render(request, "analytics.html", active_nav="analytics", analytics=analytics, hours=hours)


@app.get("/managed-resources")
async def managed_resources_page(request: Request):
    if (redirect := require_login(request)) is not None:
        return redirect
    items = await db.list_all_managed_resources(settings.db_path)
    uncertain = await db.list_uncertain_operations(settings.db_path)
    return render(request, "managed_resources.html", active_nav="resources", items=items, uncertain=uncertain)


@app.post("/managed-resources/uncertain/{operation_id}/resolve")
async def resolve_uncertain_resource(request: Request, operation_id: int, verified: str = Form("")):
    await verify_csrf(request)
    if (redirect := require_login(request)) is not None:
        return redirect
    if verified != "confirmed-no-resource":
        raise HTTPException(status_code=400, detail="Сначала подтвердите ручную проверку в Selectel")
    changed = await db.resolve_uncertain_operation(
        settings.db_path, operation_id,
        "Оператор подтвердил ручной проверкой, что неопределённый Floating IP отсутствует в Selectel.",
    )
    if not changed:
        raise HTTPException(status_code=404, detail="Неопределённая операция не найдена или уже закрыта")
    await db.add_audit_event(settings.db_path, "uncertain_operation_resolved", str(operation_id), "Оператор подтвердил ручную сверку в Selectel.")
    return RedirectResponse("/managed-resources", status_code=303)


@app.post("/managed-resources/{neutron_id}/release")
async def release_managed_resource(request: Request, neutron_id: str):
    await verify_csrf(request)
    if (redirect := require_login(request)) is not None:
        return redirect
    item = await db.get_managed_resource(settings.db_path, neutron_id)
    if item is None or item["state"] == "deleted":
        return RedirectResponse("/managed-resources", status_code=303)
    account = await db.get_account(settings.db_path, item["account_id"]) if item["account_id"] else None
    if account is None:
        raise HTTPException(status_code=409, detail="Нет учётных данных аккаунта-владельца; ресурс оставлен без изменений")
    manager: RollerManager = request.app.state.manager
    client = None
    try:
        if manager.is_running(account.id):
            await manager.stop_account(account.id)
        client = await manager._client_factory(account)
        resources = await client.list_floating_ips(item["zone"])
        found = next((resource for resource in resources if resource.id == neutron_id), None)
        if found is None:
            await db.update_managed_resource_state(settings.db_path, neutron_id, "deleted")
            message = "В Selectel ресурс уже отсутствует; запись инвентаря закрыта."
            kind = "ok"
        elif found.is_attached:
            raise ValueError("IP привязан к порту/серверу. Сначала отвяжите его в Selectel.")
        else:
            await db.update_managed_resource_state(settings.db_path, neutron_id, "delete_pending")
            await client.delete_floating_ip(neutron_id, item["zone"])
            await db.update_managed_resource_state(settings.db_path, neutron_id, "deleted")
            message, kind = "Управляемый Floating IP освобождён.", "ok"
    except Exception as exc:
        await db.update_managed_resource_state(settings.db_path, neutron_id, "delete_error")
        message, kind = f"Не удалось освободить ресурс: {exc}", "error"
    finally:
        if client is not None:
            await client.close()
    await db.add_audit_event(settings.db_path, "managed_ip_release", neutron_id,
                             f"result={kind}; ip={item['ip']}")
    items = await db.list_all_managed_resources(settings.db_path)
    uncertain = await db.list_uncertain_operations(settings.db_path)
    return render(request, "managed_resources.html", active_nav="resources", items=items, uncertain=uncertain,
                  flash={"kind": kind, "text": message})


# ---------------------------------------------------------------------- help

@app.get("/help")
async def help_page(request: Request):
    if (redirect := require_login(request)) is not None:
        return redirect
    return render(request, "help.html", active_nav="help")
