import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.database import engine, Base
import app.models  # noqa: F401 — registers all models with Base before create_all
from app.seed import run_seed
from app.routers import auth_routes, crypto_lab, records, chat, call, design, files

# Create all tables on startup (idempotent)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="TeleMed Secure", docs_url=None, redoc_url=None)

app.add_middleware(
    SessionMiddleware,
    # Override SESSION_SECRET in production via environment variable.
    secret_key=os.environ.get("SESSION_SECRET", "dev-secret-please-change-in-production"),
    max_age=60 * 60 * 8,  # 8-hour sessions
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(auth_routes.router)
app.include_router(design.router)
app.include_router(crypto_lab.router)
app.include_router(records.router)
app.include_router(chat.router)
app.include_router(call.router)
app.include_router(files.router)


@app.on_event("startup")
async def on_startup():
    run_seed()


@app.get("/")
async def root():
    from fastapi.responses import RedirectResponse
    return RedirectResponse("/login", status_code=302)
