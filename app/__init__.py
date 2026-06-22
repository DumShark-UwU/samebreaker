from __future__ import annotations

import json
import os
import secrets
import sqlite3
from datetime import timedelta
from typing import Any

from flask import Flask, Response, session
from flask_login import LoginManager, current_user
from flask_wtf.csrf import CSRFProtect

from .db import init_db, seed_default_admin, reset_stale_jobs
from .models import User

login_manager = LoginManager()
csrf = CSRFProtect()


def _load_instance_config(app: Flask) -> None:
    path = os.path.join(app.instance_path, "config.json")
    cfg: dict[str, Any] = {}

    if os.path.exists(path):
        try:
            with open(path) as f:
                cfg = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            app.logger.warning(f"config.json illisible : {exc}")

    secret: str = cfg.get("secret_key", "")
    if not secret:
        secret = secrets.token_hex(32)
        cfg["secret_key"] = secret
        os.makedirs(app.instance_path, exist_ok=True)
        try:
            with open(path, "w") as f:
                json.dump(cfg, f, indent=2)
        except OSError as exc:
            app.logger.error(f"Impossible d'écrire config.json : {exc}")
        else:
            app.logger.info("SECRET_KEY généré et sauvegardé dans instance/config.json")

    app.config["SECRET_KEY"]         = secret
    app.config["REQUIRE_2FA"]        = bool(cfg.get("require_2fa", False))
    app.config["MAX_CONTENT_LENGTH"] = int(cfg.get("max_upload_mb", 50)) * 1024 * 1024

    # Sessions permanentes avec timeout configurable (idle timeout via refresh à chaque requête)
    session_minutes = int(cfg.get("session_timeout_minutes", 60))
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=session_minutes)
    app.config["SESSION_PERMANENT"]          = True

    # Propagation des paramètres vers les modules concernés
    from . import hashcat_utils, jobs as jobs_module
    hashcat_utils.HASHCAT_FORCE      = bool(cfg.get("hashcat_force", True))
    jobs_module.MAX_CONCURRENT_JOBS  = int(cfg.get("max_concurrent_jobs", 5))


def create_app() -> Flask:
    app = Flask(__name__, instance_relative_config=True)

    login_manager.login_view = "auth.login"
    login_manager.init_app(app)
    csrf.init_app(app)

    _load_instance_config(app)
    init_db()
    reset_stale_jobs()
    seed_default_admin()

    from .auth  import bp as auth_bp
    from .main  import bp as main_bp
    from .admin import bp as admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)

    @app.before_request
    def _refresh_session() -> None:
        if current_user.is_authenticated:
            session.modified = True

    @app.after_request
    def _security_headers(resp: Response) -> Response:
        resp.headers.setdefault("X-Frame-Options",           "DENY")
        resp.headers.setdefault("X-Content-Type-Options",    "nosniff")
        resp.headers.setdefault("Referrer-Policy",           "strict-origin-when-cross-origin")
        resp.headers.setdefault("Permissions-Policy",        "geolocation=(), microphone=(), camera=()")
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return resp

    @app.context_processor
    def _inject_globals() -> dict[str, Any]:
        count = 0
        if current_user.is_authenticated:
            try:
                from .db import db_conn
                with db_conn() as conn:
                    count = conn.execute(
                        "SELECT COUNT(*) FROM jobs WHERE status='running'"
                    ).fetchone()[0]
            except sqlite3.OperationalError:
                pass
        return {"running_jobs_count": count}

    return app


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    return User.get(int(user_id))
