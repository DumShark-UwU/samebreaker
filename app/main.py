from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Optional

from werkzeug.utils import secure_filename
from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, Response, stream_with_context, jsonify, current_app)
from flask_login import login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
import pyotp

from .db import db_conn
from .hashcat_utils import (hashcat_available, get_devices, get_wordlists,
                             detect_hash, ATTACK_MODES, WORDLIST_DIRS, HASHCAT_BIN,
                             HASHCAT_FORCE)
from .notify import send_webhook, test_payload
from . import jobs as job_mgr
from .jobs import TERMINAL_STATUSES
from .admin import WORKLOAD_LABELS
from .auth import RateLimiter

bp = Blueprint("main", __name__)

_detect_limiter = RateLimiter(max_calls=30, window_seconds=60)

_ALLOWED_ATTACK_MODES = set(ATTACK_MODES.keys())
_ALLOWED_WORKLOADS    = {1, 2, 3, 4}
_MIN_PASSWORD_LEN     = 8

# ── Benchmark ─────────────────────────────────────────────────────────────────
_bm_proc: subprocess.Popen | None = None
_bm_log   = os.path.join(tempfile.gettempdir(), "samebreaker_benchmark.log")
_bm_lock  = threading.Lock()


def _bm_status() -> str:
    with _bm_lock:
        if _bm_proc is None:
            return "idle"
        if _bm_proc.poll() is None:
            return "running"
        return "done"


def _bm_run() -> None:
    global _bm_proc
    cmd = [HASHCAT_BIN, "-b"]
    if HASHCAT_FORCE:
        cmd.append("--force")
    with open(_bm_log, "w") as f:
        with _bm_lock:
            _bm_proc = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT)
    _bm_proc.wait()


def _is_safe_path(path: str, allowed_dirs: list) -> bool:
    """Vérifie que le chemin est bien dans un des répertoires autorisés."""
    real = os.path.realpath(path)
    for d in allowed_dirs:
        real_d = os.path.realpath(d)
        if real.startswith(real_d + os.sep) or real == real_d:
            return True
    return False


_RULES_DIRS      = ["/usr/share/hashcat/rules", "/opt/hashcat/rules", "rules", "instance/rules"]
_WORDLIST_ALLOWED = WORDLIST_DIRS


def _can_access_job(job) -> bool:
    return current_user.is_admin() or job["created_by"] == current_user.id


# ── Routes principales ────────────────────────────────────────────────────────

@bp.route("/")
@login_required
def index():
    uid = None if current_user.is_admin() else current_user.id
    all_jobs = job_mgr.list_jobs(user_id=uid)
    ok, version = hashcat_available()
    return render_template("main/dashboard.html",
                           jobs=all_jobs,
                           hashcat_ok=ok,
                           hashcat_version=version)


@bp.route("/system")
@login_required
def system():
    ok, version = hashcat_available()
    devices   = get_devices()
    wordlists = get_wordlists()
    try:
        import name_that_hash  # noqa: F401
        nth_ok = True
    except ImportError:
        nth_ok = False
    return render_template("main/system.html",
                           hashcat_ok=ok,
                           hashcat_version=version,
                           devices=devices,
                           wordlists=wordlists,
                           nth_ok=nth_ok)


@bp.route("/attack/new", methods=["GET", "POST"])
@login_required
def new_attack():
    wordlists   = get_wordlists()
    all_devices = get_devices()
    busy_ids    = job_mgr.get_busy_devices()

    if current_user.is_admin():
        devices         = all_devices
        missing_devices = []
    else:
        allowed_ids  = current_user.get_allowed_device_ids()
        detected_ids = {d["id"] for d in all_devices}
        devices         = [d for d in all_devices if d["id"] in allowed_ids]
        missing_devices = [i for i in allowed_ids if i not in detected_ids]

    # ── Pré-remplissage depuis un job existant ─────────────────────────────
    prefill: Optional[dict] = None
    from_job_id = request.args.get("from_job")
    if from_job_id:
        try:
            prefill_job = job_mgr.get_job(int(from_job_id))
            if prefill_job and _can_access_job(prefill_job):
                prefill = dict(prefill_job)
        except (ValueError, TypeError):
            pass

    if request.method == "POST":
        name = request.form.get("name", "").strip() or "Attack"

        try:
            hash_type = int(request.form.get("hash_type", "0"))
            if hash_type < 0:
                raise ValueError
        except (ValueError, TypeError):
            flash("Type de hash invalide.", "error")
            return redirect(url_for("main.new_attack"))
        hash_type_name = request.form.get("hash_type_name", "").strip()

        try:
            attack_mode = int(request.form.get("attack_mode", 0))
            if attack_mode not in _ALLOWED_ATTACK_MODES:
                raise ValueError
        except (ValueError, TypeError):
            flash("Mode d'attaque invalide.", "error")
            return redirect(url_for("main.new_attack"))

        mask  = request.form.get("mask", "").strip()
        rules = request.form.get("rules", "").strip()
        if rules and not _is_safe_path(rules, _RULES_DIRS):
            flash("Chemin de règles non autorisé.", "error")
            return redirect(url_for("main.new_attack"))

        raw_devices = request.form.getlist("devices")
        valid_ids   = {d["id"] for d in all_devices} if current_user.is_admin() \
                      else set(current_user.get_allowed_device_ids())
        try:
            selected_ids = [int(d) for d in raw_devices if int(d) in valid_ids]
        except (ValueError, TypeError):
            selected_ids = []
        devices_sel = ",".join(str(i) for i in selected_ids) or None

        extra_args = None
        if current_user.is_admin():
            extra_args = request.form.get("extra_args", "").strip() or None

        hash_content  = request.form.get("hash_content", "").strip()
        hash_upload   = request.files.get("hash_file_upload")
        if hash_upload and hash_upload.filename:
            hash_content = hash_upload.read().decode("utf-8", errors="replace").strip()
        if not hash_content:
            flash("Aucun hash fourni.", "error")
            return redirect(url_for("main.new_attack"))

        wordlist   = request.form.get("wordlist", "")
        wl_upload  = request.files.get("wordlist_file_upload")
        if wl_upload and wl_upload.filename:
            filename   = secure_filename(wl_upload.filename)
            wl_dir     = os.path.join(current_app.instance_path, "wordlists")
            os.makedirs(wl_dir, exist_ok=True)
            save_path  = os.path.join(wl_dir, filename)
            wl_upload.save(save_path)
            wordlist   = save_path
        if wordlist and not _is_safe_path(wordlist, _WORDLIST_ALLOWED):
            flash("Chemin de wordlist non autorisé.", "error")
            return redirect(url_for("main.new_attack"))

        if current_user.is_admin():
            try:
                workload = int(request.form.get("workload_override") or 2)
                if workload not in _ALLOWED_WORKLOADS:
                    workload = 2
            except (ValueError, TypeError):
                workload = 2
        else:
            workload = current_user.workload_profile

        job_id = job_mgr.create_job(
            name=name, hash_type=hash_type, hash_type_name=hash_type_name,
            attack_mode=attack_mode, hash_content=hash_content,
            wordlist=wordlist or None, mask=mask or None,
            rules=rules or None, devices=devices_sel,
            extra_args=extra_args, created_by=current_user.id, workload=workload,
        )
        started = job_mgr.start_job(job_id)
        if started:
            flash(f"Job #{job_id} lancé.", "success")
        else:
            flash(
                f"Job #{job_id} créé en attente — limite de "
                f"{job_mgr.MAX_CONCURRENT_JOBS} jobs simultanés atteinte.",
                "warn",
            )
        return redirect(url_for("main.job_detail", job_id=job_id))

    return render_template("main/new_attack.html",
                           wordlists=wordlists,
                           devices=devices,
                           busy_ids=busy_ids,
                           missing_devices=missing_devices,
                           workload_labels=WORKLOAD_LABELS,
                           attack_modes=ATTACK_MODES,
                           prefill=prefill)


@bp.route("/attack/<int:job_id>")
@login_required
def job_detail(job_id: int):
    job = job_mgr.get_job(job_id)
    if not job or not _can_access_job(job):
        flash("Job introuvable.", "error")
        return redirect(url_for("main.index"))
    results    = job_mgr.get_results(job)
    resumable  = job_mgr.can_resume(job_id)
    return render_template("main/job_detail.html", job=job, results=results,
                           attack_modes=ATTACK_MODES, can_resume=resumable)


@bp.route("/attack/<int:job_id>/download")
@login_required
def download_results(job_id: int):
    job = job_mgr.get_job(job_id)
    if not job or not _can_access_job(job):
        flash("Job introuvable.", "error")
        return redirect(url_for("main.index"))
    results = job_mgr.get_results(job)
    if not results:
        flash("Aucun résultat à télécharger.", "error")
        return redirect(url_for("main.job_detail", job_id=job_id))
    content = "\n".join(results) + "\n"
    return Response(
        content, mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename=results_job{job_id}.txt"},
    )


@bp.route("/attack/<int:job_id>/stop", methods=["POST"])
@login_required
def stop_attack(job_id: int):
    job = job_mgr.get_job(job_id)
    if not job or not _can_access_job(job):
        flash("Job introuvable.", "error")
        return redirect(url_for("main.index"))
    job_mgr.stop_job(job_id)
    flash(f"Job #{job_id} arrêté.", "success")
    return redirect(url_for("main.job_detail", job_id=job_id))


@bp.route("/attack/<int:job_id>/hide", methods=["POST"])
@login_required
def hide_job(job_id: int):
    job = job_mgr.get_job(job_id)
    if not job or not _can_access_job(job):
        flash("Job introuvable.", "error")
        return redirect(url_for("main.index"))
    if job["status"] not in TERMINAL_STATUSES:
        flash("Seuls les jobs terminés peuvent être masqués.", "error")
        return redirect(url_for("main.index"))
    job_mgr.hide_job(job_id, current_user.id)
    flash(f"Job #{job_id} masqué du dashboard — conservé dans l'audit admin.", "success")
    return redirect(url_for("main.index"))


@bp.route("/attack/<int:job_id>/resume", methods=["POST"])
@login_required
def resume_attack(job_id: int):
    job = job_mgr.get_job(job_id)
    if not job or not _can_access_job(job):
        flash("Job introuvable.", "error")
        return redirect(url_for("main.index"))
    if job["status"] not in (job_mgr.STATUS_STOPPED, job_mgr.STATUS_FAILED):
        flash("Ce job ne peut pas être repris.", "error")
        return redirect(url_for("main.job_detail", job_id=job_id))
    try:
        started = job_mgr.resume_job(job_id)
        if started:
            flash(f"Job #{job_id} repris.", "success")
        else:
            flash(f"Job #{job_id} en attente — limite de {job_mgr.MAX_CONCURRENT_JOBS} jobs atteinte.", "warn")
    except FileNotFoundError:
        flash("Fichier de session introuvable — reprise impossible.", "error")
    return redirect(url_for("main.job_detail", job_id=job_id))


# ── API ───────────────────────────────────────────────────────────────────────

@bp.route("/api/jobs/<int:job_id>/results")
@login_required
def api_job_results(job_id: int):
    job = job_mgr.get_job(job_id)
    if not job or not _can_access_job(job):
        return jsonify({"results": [], "status": "not_found"})
    return jsonify({"results": job_mgr.get_results(job), "status": job["status"]})


@bp.route("/api/detect", methods=["POST"])
@login_required
def api_detect():
    if _detect_limiter.is_limited(request.remote_addr or "unknown"):
        return jsonify({"error": "Rate limit dépassé"}), 429
    data = request.get_json(silent=True) or {}
    h = data.get("hash", "").strip()
    if not h:
        return jsonify([])
    return jsonify(detect_hash(h))


@bp.route("/api/devices")
@login_required
def api_devices():
    return jsonify(get_devices())


@bp.route("/api/wordlists")
@login_required
def api_wordlists():
    return jsonify(get_wordlists())


# ── Benchmark ─────────────────────────────────────────────────────────────────

@bp.route("/benchmark")
@login_required
def benchmark():
    ok, version = hashcat_available()
    return render_template("main/benchmark.html", hashcat_ok=ok, hashcat_version=version)


@bp.route("/api/sysinfo")
@login_required
def api_sysinfo():
    info: dict = {}

    # ── CPU (load average → approx %) ────────────────────────────────────────
    try:
        with open("/proc/loadavg") as f:
            load1 = float(f.read().split()[0])
        cpu_count = os.cpu_count() or 1
        info["cpu_load1"] = round(load1, 2)
        info["cpu_pct"]   = min(100, round(load1 / cpu_count * 100, 1))
        info["cpu_count"] = cpu_count
    except OSError:
        info["cpu_load1"] = None
        info["cpu_pct"]   = None
        info["cpu_count"] = os.cpu_count()

    # ── RAM (/proc/meminfo) ────────────────────────────────────────────────────
    try:
        mem: dict[str, int] = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                mem[k.strip()] = int(v.split()[0]) * 1024
        total     = mem.get("MemTotal", 0)
        available = mem.get("MemAvailable", 0)
        used      = total - available
        info["ram_total_gb"]  = round(total / 1e9, 1)
        info["ram_used_gb"]   = round(used  / 1e9, 1)
        info["ram_pct"]       = round(used / total * 100, 1) if total else 0
    except OSError:
        info["ram_total_gb"] = info["ram_used_gb"] = info["ram_pct"] = None

    # ── Disk — racine + instance ──────────────────────────────────────────────
    def _disk(path: str) -> dict:
        try:
            u = shutil.disk_usage(path)
            return {
                "total_gb": round(u.total / 1e9, 1),
                "used_gb":  round(u.used  / 1e9, 1),
                "free_gb":  round(u.free  / 1e9, 1),
                "pct":      round(u.used / u.total * 100, 1) if u.total else 0,
            }
        except OSError:
            return {}

    info["disk_root"]     = _disk("/")
    info["disk_instance"] = _disk(current_app.instance_path)

    return jsonify(info)


@bp.route("/api/benchmark/start", methods=["POST"])
@login_required
def benchmark_start():
    if not current_user.is_admin():
        return jsonify({"error": "admin only"}), 403
    if _bm_status() == "running":
        return jsonify({"status": "already_running"})
    threading.Thread(target=_bm_run, daemon=True).start()
    return jsonify({"status": "started"})


@bp.route("/api/benchmark/stop", methods=["POST"])
@login_required
def benchmark_stop():
    if not current_user.is_admin():
        return jsonify({"error": "admin only"}), 403
    global _bm_proc
    with _bm_lock:
        if _bm_proc and _bm_proc.poll() is None:
            _bm_proc.terminate()
    return jsonify({"status": "stopped"})


@bp.route("/api/benchmark/status")
@login_required
def benchmark_status():
    status = _bm_status()
    output = ""
    if os.path.exists(_bm_log):
        with open(_bm_log) as f:
            output = f.read()
    return jsonify({"status": status, "output": output})


@bp.route("/api/benchmark/stream")
@login_required
def benchmark_stream():
    def generate():
        pos = 0
        while True:
            new_data = False
            if os.path.exists(_bm_log):
                with open(_bm_log) as f:
                    f.seek(pos)
                    chunk = f.read()
                    if chunk:
                        new_data = True
                        pos = f.tell()
                        for line in chunk.splitlines():
                            yield f"data: {line}\n\n"
            status = _bm_status()
            if status == "done" and not new_data:
                yield "data: [DONE]\n\n"
                break
            time.sleep(0.5)
    return Response(stream_with_context(generate()), mimetype="text/event-stream")


@bp.route("/api/jobs/<int:job_id>/stream")
@login_required
def stream_job(job_id: int):
    job = job_mgr.get_job(job_id)
    if not job or not job["log_file"] or not _can_access_job(job):
        return Response("data: [not found]\n\n", mimetype="text/event-stream")

    log_file = job["log_file"]

    def generate():
        pos  = 0
        idle = 0
        while True:
            j = job_mgr.get_job(job_id)
            if os.path.exists(log_file):
                with open(log_file) as f:
                    f.seek(pos)
                    chunk = f.read()
                    if chunk:
                        idle = 0
                        pos  = f.tell()
                        for line in chunk.splitlines():
                            yield f"data: {line}\n\n"
            if j and j["status"] in TERMINAL_STATUSES:
                yield "data: [DONE]\n\n"
                break
            time.sleep(1)
            idle += 1
            if idle > 300:
                break

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


# ── Profil ────────────────────────────────────────────────────────────────────

@bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw     = request.form.get("new_password", "").strip()
        confirm_pw = request.form.get("confirm_password", "").strip()

        with db_conn() as conn:
            row = conn.execute(
                "SELECT password FROM users WHERE id=?", (current_user.id,)
            ).fetchone()

        if not row or not check_password_hash(row["password"], current_pw):
            flash("Mot de passe actuel incorrect.", "error")
        elif len(new_pw) < _MIN_PASSWORD_LEN:
            flash(f"Le nouveau mot de passe doit faire au moins {_MIN_PASSWORD_LEN} caractères.", "error")
        elif new_pw != confirm_pw:
            flash("Les mots de passe ne correspondent pas.", "error")
        else:
            with db_conn() as conn:
                conn.execute(
                    "UPDATE users SET password=?, must_change_password=0 WHERE id=?",
                    (generate_password_hash(new_pw), current_user.id),
                )
                conn.commit()
            current_user.must_change_password = False
            flash("Mot de passe mis à jour.", "success")

    # Données 2FA pour le template
    with db_conn() as conn:
        urow = conn.execute(
            "SELECT totp_secret FROM users WHERE id=?",
            (current_user.id,)
        ).fetchone()
    has_2fa        = bool(urow and urow["totp_secret"])
    require_2fa    = current_app.config.get("REQUIRE_2FA", False)
    with db_conn() as conn:
        webhooks = conn.execute(
            "SELECT * FROM webhooks WHERE user_id=? ORDER BY created_at", (current_user.id,)
        ).fetchall()

    # Générer QR si demandé via ?setup=1 ou si déjà en cours de setup
    totp_uri    = None
    totp_secret = None
    show_setup  = request.args.get("setup") == "1"
    if show_setup:
        from flask import session as _session
        totp_secret = _session.get("_profile_2fa_secret") or pyotp.random_base32()
        _session["_profile_2fa_secret"] = totp_secret
        totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(
            name=current_user.username, issuer_name="SameBreaker"
        )

    return render_template(
        "main/profile.html",
        has_2fa=has_2fa,
        require_2fa=require_2fa,
        totp_uri=totp_uri,
        totp_secret=totp_secret,
        show_setup=show_setup,
        webhooks=webhooks,
    )


@bp.route("/profile/webhook/add", methods=["POST"])
@login_required
def profile_webhook_add():
    label        = request.form.get("label", "").strip()[:64]
    url          = request.form.get("url", "").strip()
    webhook_type = request.form.get("webhook_type", "auto").strip()
    events       = [e for e in request.form.getlist("events") if e in ("job_done", "password_found")]
    if not url:
        flash("URL manquante.", "error")
        return redirect(url_for("main.profile"))
    if webhook_type not in ("auto", "discord", "slack", "teams", "ntfy", "signal", "generic"):
        webhook_type = "auto"
    with db_conn() as conn:
        conn.execute(
            "INSERT INTO webhooks (user_id, label, url, events, webhook_type) VALUES (?,?,?,?,?)",
            (current_user.id, label, url, ",".join(events), webhook_type),
        )
        conn.commit()
    flash("Webhook ajouté.", "success")
    return redirect(url_for("main.profile"))


@bp.route("/profile/webhook/<int:wh_id>/delete", methods=["POST"])
@login_required
def profile_webhook_delete(wh_id: int):
    with db_conn() as conn:
        conn.execute(
            "DELETE FROM webhooks WHERE id=? AND user_id=?", (wh_id, current_user.id)
        )
        conn.commit()
    flash("Webhook supprimé.", "success")
    return redirect(url_for("main.profile"))


@bp.route("/profile/webhook/<int:wh_id>/test", methods=["POST"])
@login_required
def profile_webhook_test(wh_id: int):
    with db_conn() as conn:
        row = conn.execute(
            "SELECT url, webhook_type FROM webhooks WHERE id=? AND user_id=?",
            (wh_id, current_user.id),
        ).fetchone()
    if not row:
        flash("Webhook introuvable.", "error")
        return redirect(url_for("main.profile"))
    ok = send_webhook(row["url"], test_payload(current_user.username), row["webhook_type"] or "auto")
    flash("Test envoyé ✓" if ok else "Échec de l'envoi.", "success" if ok else "error")
    return redirect(url_for("main.profile"))


@bp.route("/profile/2fa/setup", methods=["POST"])
@login_required
def profile_2fa_setup():
    from flask import session as _session
    secret = _session.get("_profile_2fa_secret", "")
    code   = request.form.get("code", "").strip().replace(" ", "")
    if not secret:
        flash("Session expirée. Recommencez la configuration.", "error")
        return redirect(url_for("main.profile"))
    if pyotp.TOTP(secret).verify(code, valid_window=1):
        with db_conn() as conn:
            conn.execute("UPDATE users SET totp_secret=? WHERE id=?", (secret, current_user.id))
            conn.commit()
        _session.pop("_profile_2fa_secret", None)
        flash("2FA activé avec succès !", "success")
    else:
        flash("Code invalide — vérifiez l'heure de votre appareil.", "error")
        return redirect(url_for("main.profile") + "?setup=1")
    return redirect(url_for("main.profile"))


@bp.route("/profile/2fa/disable", methods=["POST"])
@login_required
def profile_2fa_disable():
    if current_app.config.get("REQUIRE_2FA"):
        flash("Le 2FA est obligatoire sur cette instance.", "error")
        return redirect(url_for("main.profile"))
    with db_conn() as conn:
        conn.execute("UPDATE users SET totp_secret=NULL WHERE id=?", (current_user.id,))
        conn.commit()
    flash("2FA désactivé.", "success")
    return redirect(url_for("main.profile"))
