from __future__ import annotations

import sqlite3
from functools import wraps
from typing import Callable, Optional

from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash

from .db import db_conn
from .hashcat_utils import get_devices, ATTACK_MODES

bp = Blueprint("admin", __name__, url_prefix="/admin")

WORKLOAD_LABELS: dict[int, str] = {1: "Low", 2: "Default", 3: "High", 4: "Nightmare"}

_ALLOWED_ROLES     = frozenset({"admin", "user"})
_ALLOWED_WORKLOADS = frozenset({1, 2, 3, 4})
_MIN_PASSWORD_LEN  = 8


def admin_required(f: Callable) -> Callable:
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            flash("Accès réservé aux administrateurs.", "error")
            return redirect(url_for("main.index"))
        return f(*args, **kwargs)
    return decorated


def _validate_user_form(
    username: str,
    password: str,
    role: str,
    workload: int,
    require_password: bool = True,
) -> Optional[str]:
    """Valide les champs du formulaire utilisateur. Retourne un message d'erreur ou None."""
    if len(username) < 2:
        return "Le nom d'utilisateur doit faire au moins 2 caractères."
    if role not in _ALLOWED_ROLES:
        return "Rôle invalide."
    if workload not in _ALLOWED_WORKLOADS:
        return "Workload invalide."
    if require_password and len(password) < _MIN_PASSWORD_LEN:
        return f"Le mot de passe doit faire au moins {_MIN_PASSWORD_LEN} caractères."
    if not require_password and password and len(password) < _MIN_PASSWORD_LEN:
        return f"Le mot de passe doit faire au moins {_MIN_PASSWORD_LEN} caractères."
    return None


def _safe_workload(raw: str) -> int:
    try:
        value = int(raw)
    except (ValueError, TypeError):
        return 2
    return value if value in _ALLOWED_WORKLOADS else 2


@bp.route("/users")
@login_required
@admin_required
def users():
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM users ORDER BY role DESC, username"
        ).fetchall()
    detected = {d["id"]: d for d in get_devices()}
    return render_template(
        "admin/users.html",
        users=rows,
        detected=detected,
        workload_labels=WORKLOAD_LABELS,
        require_2fa=current_app.config.get("REQUIRE_2FA", False),
    )


@bp.route("/users/new", methods=["GET", "POST"])
@login_required
@admin_required
def new_user():
    devices = get_devices()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        role     = request.form.get("role", "user")
        allowed  = ",".join(request.form.getlist("devices"))
        workload = _safe_workload(request.form.get("workload_profile", "2"))

        err = _validate_user_form(username, password, role, workload, require_password=True)
        if err:
            flash(err, "error")
        else:
            try:
                with db_conn() as conn:
                    conn.execute(
                        "INSERT INTO users"
                        " (username, password, role, allowed_devices, workload_profile)"
                        " VALUES (?,?,?,?,?)",
                        (username, generate_password_hash(password), role, allowed, workload),
                    )
                    conn.commit()
                flash(f"Utilisateur '{username}' créé.", "success")
                return redirect(url_for("admin.users"))
            except sqlite3.IntegrityError:
                flash("Ce nom d'utilisateur existe déjà.", "error")
            except sqlite3.OperationalError as exc:
                flash(f"Erreur base de données : {exc}", "error")

    return render_template(
        "admin/user_form.html",
        user=None,
        devices=devices,
        workload_labels=WORKLOAD_LABELS,
        action="new",
    )


@bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def edit_user(user_id: int):
    with db_conn() as conn:
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        flash("Utilisateur introuvable.", "error")
        return redirect(url_for("admin.users"))

    devices = get_devices()
    if request.method == "POST":
        new_username = request.form.get("username", "").strip()
        role         = request.form.get("role", "user")
        allowed      = ",".join(request.form.getlist("devices"))
        new_pass     = request.form.get("password", "").strip()
        workload     = _safe_workload(request.form.get("workload_profile", "2"))

        err = _validate_user_form(new_username, new_pass, role, workload, require_password=False)
        if err:
            flash(err, "error")
            return redirect(url_for("admin.edit_user", user_id=user_id))

        try:
            with db_conn() as conn:
                if new_pass:
                    conn.execute(
                        "UPDATE users"
                        " SET username=?, role=?, allowed_devices=?, workload_profile=?, password=?"
                        " WHERE id=?",
                        (new_username, role, allowed, workload,
                         generate_password_hash(new_pass), user_id),
                    )
                else:
                    conn.execute(
                        "UPDATE users"
                        " SET username=?, role=?, allowed_devices=?, workload_profile=?"
                        " WHERE id=?",
                        (new_username, role, allowed, workload, user_id),
                    )
                conn.commit()
            flash("Utilisateur mis à jour.", "success")
        except sqlite3.IntegrityError:
            flash("Ce nom d'utilisateur existe déjà.", "error")
        except sqlite3.OperationalError as exc:
            flash(f"Erreur base de données : {exc}", "error")
        return redirect(url_for("admin.users"))

    return render_template(
        "admin/user_form.html",
        user=user,
        devices=devices,
        workload_labels=WORKLOAD_LABELS,
        action="edit",
    )


@bp.route("/jobs")
@login_required
@admin_required
def audit_jobs():
    with db_conn() as conn:
        rows = conn.execute("""
            SELECT j.*, u.username AS creator_name
            FROM jobs j
            LEFT JOIN users u ON j.created_by = u.id
            ORDER BY j.created_at DESC
        """).fetchall()
    return render_template("admin/jobs.html", jobs=rows, attack_modes=ATTACK_MODES)


@bp.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id: int):
    if user_id == current_user.id:
        flash("Impossible de supprimer votre propre compte.", "error")
        return redirect(url_for("admin.users"))
    with db_conn() as conn:
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
    flash("Utilisateur supprimé.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/reset-2fa", methods=["POST"])
@login_required
@admin_required
def reset_user_2fa(user_id: int):
    with db_conn() as conn:
        row = conn.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            flash("Utilisateur introuvable.", "error")
            return redirect(url_for("admin.users"))
        conn.execute("UPDATE users SET totp_secret=NULL WHERE id=?", (user_id,))
        conn.commit()
    flash(f"2FA réinitialisé pour '{row['username']}'. Il devra le reconfigurer à sa prochaine connexion.", "success")
    return redirect(url_for("admin.users"))
