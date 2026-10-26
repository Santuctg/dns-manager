from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.database import get_engine
from app.api.auth import router as auth_router
from app.api.mappings import router as mappings_router
from app.api.audit import router as audit_router
from app.api.config_ops import router as config_ops_router
from app.api.system import router as system_router
from app.api.users import router as users_router
from app.api.roles import router as roles_router
from app.api.backups import router as backups_router
from app.api.ssl import router as ssl_router
from app.api.acme_dns import router as acme_dns_router
from app.api.firewall import router as firewall_router
from app.web import router as web_router


class RevalidatingStaticFiles(StaticFiles):
    """Serve static assets with revalidation so browsers pick up new files."""

    async def get_response(self, path: str, scope):  # type: ignore[override]
        response = await super().get_response(path, scope)
        if response.status_code == 200:
            response.headers.setdefault("cache-control", "no-cache")
        return response


app = FastAPI(title="DNS Manager", version="0.1.0")
app.mount(
    "/static",
    RevalidatingStaticFiles(directory=str(Path(__file__).resolve().parent / "static")),
    name="static",
)
app.include_router(auth_router)
app.include_router(mappings_router)
app.include_router(audit_router)
app.include_router(config_ops_router)
app.include_router(system_router)
app.include_router(users_router)
app.include_router(roles_router)
app.include_router(backups_router)
app.include_router(ssl_router)
app.include_router(acme_dns_router)
app.include_router(firewall_router)
app.include_router(web_router)


@app.get("/health")
def health() -> dict[str, str]:
    try:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError:
        return {"status": "error", "database": "error"}
    return {"status": "ok", "database": "ok"}
