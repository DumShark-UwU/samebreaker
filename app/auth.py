from __future__ import annotations

import time
import threading
import pyotp
from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, session, current_app)
from flask_login import login_user, logout_user, login_required
from werkzeug.security import check_password_hash

from .models import User
from .db import db_conn

bp = Blueprint("auth", __name__)

_RATE_WINDOW_SECONDS = 300  # 5 minutes


class RateLimiter:
    """Compteur glissant par clé (IP). Thread-safe."""

    def __init__(self, max_calls: int, window_seconds: int) -> None:
        self._max    = max_calls
        self._window = window_seconds
        self._store: dict[str, list[float]] = {}
        self._lock   = threading.Lock()

    def is_limited(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            recent = [t for t in self._store.get(key, []) if now - t < self._window]
            if len(recent) >= self._max:
                self._store[key] = recent
                return True
            recent.append(now)
            self._store[key] = recent
            return False


_login_limiter = RateLimiter(max_calls=10, window_seconds=_RATE_WINDOW_SECONDS)


def _get_pending_row():
    """Retourne la row BDD de l'utilisateur en attente de vérification 2FA."""
    user_id = session.get("_2fa_pending_user_id")
    if not user_id:
        return None
    with db_conn() as conn:
        return conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()


def _login_user_from_row(row) -> None:
    user = User(
        row["id"], row["username"], row["role"],
        row["allowed_devices"], row["workload_profile"],
        row["must_change_password"],
    )
    login_user(user)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if _login_limiter.is_limited(ip):
            flash(
                f"Trop de tentatives. Réessayez dans {_RATE_WINDOW_SECONDS // 60} minutes.",
                "error",
            )
            return render_template("auth/login.html")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        row      = User.get_by_username(username)

        if row and check_password_hash(row["password"], password):
            if current_app.config.get("REQUIRE_2FA"):
                session["_2fa_pending_user_id"] = row["id"]
                if row["totp_secret"]:
                    return redirect(url_for("auth.two_fa_verify"))
                return redirect(url_for("auth.two_fa_setup"))

            _login_user_from_row(row)
            return redirect(url_for("main.index"))

        flash("Identifiants incorrects.", "error")
    return render_template("auth/login.html")


@bp.route("/2fa/setup", methods=["GET", "POST"])
def two_fa_setup():
    row = _get_pending_row()
    if not row:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code   = request.form.get("code", "").strip().replace(" ", "")
        secret = session.get("_2fa_temp_secret", "")
        if not secret:
            flash("Session expirée, reconnectez-vous.", "error")
            return redirect(url_for("auth.login"))

        if pyotp.TOTP(secret).verify(code, valid_window=1):
            with db_conn() as conn:
                conn.execute(
                    "UPDATE users SET totp_secret=? WHERE id=?",
                    (secret, row["id"]),
                )
                conn.commit()
            session.pop("_2fa_temp_secret", None)
            session.pop("_2fa_pending_user_id", None)
            _login_user_from_row(row)
            flash("2FA configuré avec succès !", "success")
            return redirect(url_for("main.index"))

        flash("Code invalide — vérifiez l'heure de votre appareil.", "error")

    # GET : générer ou réutiliser le secret temporaire de la session
    secret = session.get("_2fa_temp_secret") or pyotp.random_base32()
    session["_2fa_temp_secret"] = secret
    totp_uri = pyotp.TOTP(secret).provisioning_uri(
        name=row["username"],
        issuer_name="SameBreaker",
    )
    return render_template("auth/2fa_setup.html", secret=secret, totp_uri=totp_uri)


@bp.route("/2fa/verify", methods=["GET", "POST"])
def two_fa_verify():
    row = _get_pending_row()
    if not row or not row["totp_secret"]:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip().replace(" ", "")
        if pyotp.TOTP(row["totp_secret"]).verify(code, valid_window=1):
            session.pop("_2fa_pending_user_id", None)
            _login_user_from_row(row)
            return redirect(url_for("main.index"))
        flash("Code invalide.", "error")

    return render_template("auth/2fa_verify.html", username=row["username"])


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    session.pop("_2fa_pending_user_id", None)
    session.pop("_2fa_temp_secret", None)
    logout_user()
    return redirect(url_for("auth.login"))
