from __future__ import annotations

import os
import pytest

import app.db as db_module
import app.jobs as jobs_module


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Vide le store du rate limiter entre les tests pour éviter le blocage de login."""
    from app.auth import _login_limiter
    _login_limiter._store.clear()
    yield
    _login_limiter._store.clear()


@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    """Redirige la base de données et le répertoire jobs vers des chemins temporaires."""
    old_db   = db_module.DB_PATH
    old_jobs = db_module._JOBS_DIR
    old_wl   = db_module._WORDLISTS_DIR

    db_module.DB_PATH        = str(tmp_path / "test.db")
    db_module._JOBS_DIR      = str(tmp_path / "jobs")
    db_module._WORDLISTS_DIR = str(tmp_path / "wordlists")
    jobs_module._JOBS_DIR    = str(tmp_path / "jobs")

    os.makedirs(db_module._JOBS_DIR, exist_ok=True)
    os.makedirs(db_module._WORDLISTS_DIR, exist_ok=True)

    db_module.init_db()
    db_module.seed_default_admin()

    yield

    db_module.DB_PATH        = old_db
    db_module._JOBS_DIR      = old_jobs
    db_module._WORDLISTS_DIR = old_wl
    jobs_module._JOBS_DIR    = old_jobs


@pytest.fixture
def flask_app(tmp_path, isolated_db):
    """Application Flask configurée pour les tests."""
    from app import create_app
    application = create_app()
    application.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SECRET_KEY="test-secret",
    )
    return application


@pytest.fixture
def client(flask_app):
    return flask_app.test_client()


@pytest.fixture
def auth_client(flask_app):
    """Client HTTP déjà authentifié avec le compte admin par défaut."""
    with flask_app.test_client() as c:
        c.post("/login", data={"username": "admin", "password": "admin"})
        yield c


@pytest.fixture
def api_token(flask_app, isolated_db):
    """Crée un token API pour l'admin et le retourne."""
    import secrets as _sec
    from app.db import db_conn
    with db_conn() as conn:
        uid = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()["id"]
        tok = _sec.token_urlsafe(32)
        conn.execute(
            "INSERT INTO api_tokens (user_id, token, label) VALUES (?,?,?)",
            (uid, tok, "test"),
        )
        conn.commit()
    return tok
