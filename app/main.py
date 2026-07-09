from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
import zipfile
from typing import Optional

from werkzeug.utils import secure_filename
from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, Response, stream_with_context, jsonify, current_app)
from flask_login import login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
import pyotp

from .db import db_conn
from .hashcat_utils import (hashcat_available, get_devices, get_wordlists,
                             detect_hash, parse_hashes, ATTACK_MODES, WORDLIST_DIRS, HASHCAT_BIN,
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
_MASKS_DIRS      = ["instance/masks"]
_WORDLIST_ALLOWED = WORDLIST_DIRS


def _list_files(dirs: list[str], exts: tuple) -> list[dict]:
    seen: set[str] = set()
    result = []
    for d in dirs:
        p = os.path.abspath(d)
        if not os.path.isdir(p):
            continue
        for fn in sorted(os.listdir(p)):
            if fn.startswith(".") or fn in seen:
                continue
            if not fn.lower().endswith(exts):
                continue
            seen.add(fn)
            fp = os.path.join(p, fn)
            result.append({"name": fn, "size": os.path.getsize(fp), "path": fp})
    return result


def _get_rules() -> list[dict]:
    files = _list_files(_RULES_DIRS, (".rule", ".rules", ".hcr"))
    instance_rules = os.path.abspath(os.path.join("instance", "rules"))
    for f in files:
        f["deletable"] = f["path"].startswith(instance_rules)
    return files


def _get_masks() -> list[dict]:
    instance_masks = os.path.abspath(os.path.join("instance", "masks"))
    files = _list_files([instance_masks], (".hcmask", ".mask"))
    for f in files:
        f["deletable"] = True
    return files


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
    rules     = _get_rules()
    masks     = _get_masks()
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
                           rules=rules,
                           masks=masks,
                           nth_ok=nth_ok,
                           instance_path=current_app.instance_path)


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

    # ── Pré-remplissage depuis import ZIP ──────────────────────────────────
    if request.args.get("from_import") == "1" and not prefill:
        from flask import session as _session
        import_params = _session.pop("_import_params", None)
        if import_params:
            prefill = dict(import_params)
            tmp_id = _session.pop("_import_tmp", None)
            if tmp_id:
                tmp_path = os.path.join(current_app.instance_path, "import_tmp", f"{tmp_id}.txt")
                if os.path.exists(tmp_path):
                    with open(tmp_path) as _tf:
                        prefill["_import_hashes"] = _tf.read()
                    try:
                        os.unlink(tmp_path)
                    except OSError:
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

        # Custom charsets from mask builder — available to all roles
        # Safe: subprocess uses a list, no shell interpretation
        if mask:
            _charset_parts = []
            for _i in range(1, 5):
                _cv = request.form.get(f"custom_charset{_i}", "").strip()
                if _cv and f"?{_i}" in mask:
                    _cv = re.sub(r'[\x00-\x1f\x7f\s\'"\\]', '', _cv)[:128]
                    if _cv:
                        _charset_parts.append(f"--custom-charset{_i}={_cv}")
            if _charset_parts:
                _cs_str = " ".join(_charset_parts)
                extra_args = (extra_args + " " + _cs_str).strip() if extra_args else _cs_str

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

        scheduled_at_raw = request.form.get("scheduled_at", "").strip()
        if scheduled_at_raw:
            from datetime import datetime as _dt
            try:
                dt = _dt.fromisoformat(scheduled_at_raw)
                if dt > _dt.now():
                    job_mgr.schedule_job(job_id, dt.isoformat(sep=" "))
                    flash(
                        f"Job #{job_id} planifié pour le {scheduled_at_raw.replace('T', ' ')}.",
                        "success",
                    )
                    return redirect(url_for("main.job_detail", job_id=job_id))
            except ValueError:
                pass

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
                           rules=_get_rules(),
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


@bp.route("/attack/<int:job_id>/log")
@login_required
def download_log(job_id: int):
    job = job_mgr.get_job(job_id)
    if not job or not _can_access_job(job):
        flash("Job introuvable.", "error")
        return redirect(url_for("main.index"))
    log_file = job["log_file"]
    if not log_file or not os.path.exists(log_file):
        flash("Log introuvable.", "error")
        return redirect(url_for("main.job_detail", job_id=job_id))
    with open(log_file) as f:
        content = f.read()
    return Response(
        content, mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename=log_job{job_id}.txt"},
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


@bp.route("/attack/<int:job_id>/cancel", methods=["POST"])
@login_required
def cancel_scheduled(job_id: int):
    job = job_mgr.get_job(job_id)
    if not job or not _can_access_job(job):
        flash("Job introuvable.", "error")
        return redirect(url_for("main.index"))
    if job_mgr.cancel_scheduled(job_id):
        flash(f"Job #{job_id} annulé.", "success")
    else:
        flash("Ce job ne peut pas être annulé (non planifié).", "error")
    return redirect(url_for("main.index"))


# ── Suppression fichiers système ─────────────────────────────────────────────

@bp.route("/system/delete", methods=["POST"])
@login_required
def system_delete_file():
    from .library import CATALOG, _set_state
    ftype = request.form.get("type", "")        # wordlist | rule | mask
    fname = request.form.get("filename", "")
    if not fname or "/" in fname or ".." in fname:
        flash("Nom de fichier invalide.", "error")
        return redirect(url_for("main.system"))

    if ftype == "wordlist":
        dirs = [os.path.join(current_app.instance_path, "wordlists")]
    elif ftype == "rule":
        dirs = [os.path.join(current_app.instance_path, "rules")]
    elif ftype == "mask":
        dirs = [os.path.join(current_app.instance_path, "masks")]
    else:
        flash("Type invalide.", "error")
        return redirect(url_for("main.system"))

    deleted = False
    for d in dirs:
        fp = os.path.join(d, fname)
        if os.path.isfile(fp):
            os.unlink(fp)
            deleted = True
            break

    if deleted:
        # Sync bibliothèque : reset l'état si ce fichier correspond à une ressource du catalogue
        for rid, res in CATALOG.items():
            if res.get("filename") == fname and res.get("type") == ftype:
                _set_state(rid, status="idle", progress=0, error=None)
                break
        flash(f"{fname} supprimé.", "success")
    else:
        flash("Fichier introuvable.", "error")

    return redirect(url_for("main.system"))


# ── Export / Import ───────────────────────────────────────────────────────────

@bp.route("/attack/<int:job_id>/export")
@login_required
def export_job(job_id: int):
    job = job_mgr.get_job(job_id)
    if not job or not _can_access_job(job):
        flash("Job introuvable.", "error")
        return redirect(url_for("main.index"))

    params = {
        "name":           job["name"],
        "hash_type":      job["hash_type"],
        "hash_type_name": job["hash_type_name"],
        "attack_mode":    job["attack_mode"],
        "wordlist":       os.path.basename(job["wordlist"]) if job["wordlist"] else None,
        "mask":           job["mask"],
        "rules":          os.path.basename(job["rules"]) if job["rules"] else None,
        "workload":       job["workload"] or 2,
        "extra_args":     job["extra_args"],
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("job.json", json.dumps(params, indent=2, ensure_ascii=False))
        if job["hash_file"] and os.path.exists(job["hash_file"]):
            with open(job["hash_file"]) as f:
                zf.writestr("hashes.txt", f.read())
        results = job_mgr.get_results(job)
        if results:
            zf.writestr("results.txt", "\n".join(results) + "\n")
    buf.seek(0)

    safe_name = f"job{job_id}_{job['name'][:20].replace(' ', '_')}.zip"
    return Response(
        buf.read(), mimetype="application/zip",
        headers={"Content-Disposition": f"attachment; filename={safe_name}"},
    )


@bp.route("/attack/import", methods=["POST"])
@login_required
def import_job():
    from flask import session as _session
    f = request.files.get("import_file")
    if not f or not f.filename:
        flash("Aucun fichier fourni.", "error")
        return redirect(url_for("main.index"))

    try:
        buf = io.BytesIO(f.read())
        with zipfile.ZipFile(buf, "r") as zf:
            if "job.json" not in zf.namelist():
                raise ValueError("job.json manquant dans l'archive")
            params = json.loads(zf.read("job.json").decode("utf-8"))
            hashes = zf.read("hashes.txt").decode("utf-8", errors="replace") if "hashes.txt" in zf.namelist() else ""
    except zipfile.BadZipFile:
        flash("Fichier ZIP invalide.", "error")
        return redirect(url_for("main.index"))
    except (json.JSONDecodeError, ValueError) as e:
        flash(f"Archive invalide : {e}", "error")
        return redirect(url_for("main.index"))

    _session["_import_params"] = params
    if hashes:
        tmp_dir = os.path.join(current_app.instance_path, "import_tmp")
        os.makedirs(tmp_dir, exist_ok=True)
        tmp_id  = str(uuid.uuid4())
        with open(os.path.join(tmp_dir, f"{tmp_id}.txt"), "w") as tf:
            tf.write(hashes)
        _session["_import_tmp"] = tmp_id
    else:
        _session.pop("_import_tmp", None)

    return redirect(url_for("main.new_attack", from_import="1"))


# ── API ───────────────────────────────────────────────────────────────────────

@bp.route("/api/jobs/<int:job_id>/stream")
@login_required
def stream_job(job_id: int):
    """SSE : stream des lignes de log en temps réel."""
    job = job_mgr.get_job(job_id)
    if not job or not _can_access_job(job):
        return jsonify({"error": "not found"}), 404

    log_file = job["log_file"]

    def _generate():
        if not log_file or not os.path.exists(log_file):
            yield "data: [DONE]\n\n"
            return
        deadline = time.time() + 7200  # filet : 2h max même si client zombie
        try:
            with open(log_file) as f:
                for line in f:
                    yield f"data: {line.rstrip()}\n\n"
                while time.time() < deadline:
                    j = job_mgr.get_job(job_id)
                    if not j or j["status"] not in (job_mgr.STATUS_RUNNING, job_mgr.STATUS_PENDING):
                        yield "data: [DONE]\n\n"
                        return
                    line = f.readline()
                    if line:
                        yield f"data: {line.rstrip()}\n\n"
                    else:
                        time.sleep(0.5)
                        yield ": hb\n\n"
        except OSError:
            yield "data: [DONE]\n\n"

    return Response(
        stream_with_context(_generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


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

    fmt = request.args.get("format", "txt")
    if fmt == "json":
        return jsonify({"job_id": job_id, "name": job["name"], "results": results})
    if fmt == "csv":
        import csv as _csv
        buf = io.StringIO()
        w = _csv.writer(buf)
        w.writerow(["username", "password"])
        for line in results:
            parts = line.split(":", 1)
            w.writerow(parts if len(parts) == 2 else [line, ""])
        return Response(
            buf.getvalue(), mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=results_job{job_id}.csv"},
        )
    content = "\n".join(results) + "\n"
    return Response(
        content, mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename=results_job{job_id}.txt"},
    )


# ── Potfile global ────────────────────────────────────────────────────────────

@bp.route("/potfile")
@login_required
def potfile():
    uid = None if current_user.is_admin() else current_user.id
    all_jobs = job_mgr.list_jobs(user_id=uid)
    jobs_with_results = []
    for j in all_jobs:
        count = len(job_mgr.get_results(j))
        if count:
            jobs_with_results.append({**j, "result_count": count})
    return render_template("main/potfile.html", jobs=jobs_with_results)


# ── Job templates ─────────────────────────────────────────────────────────────

@bp.route("/api/templates")
@login_required
def api_templates():
    uid = None if current_user.is_admin() else current_user.id
    with db_conn() as conn:
        if uid:
            rows = conn.execute(
                "SELECT * FROM job_templates WHERE created_by=? ORDER BY created_at DESC", (uid,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM job_templates ORDER BY created_at DESC"
            ).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route("/templates/save", methods=["POST"])
@login_required
def template_save():
    name = request.form.get("name", "").strip() or "Template"
    try:
        hash_type = int(request.form.get("hash_type") or 0)
    except (ValueError, TypeError):
        hash_type = 0
    with db_conn() as conn:
        conn.execute(
            """INSERT INTO job_templates
               (name, hash_type, hash_type_name, attack_mode, wordlist, mask, rules, extra_args, created_by)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                name,
                hash_type,
                request.form.get("hash_type_name", "").strip(),
                int(request.form.get("attack_mode") or 0),
                request.form.get("wordlist", "").strip() or None,
                request.form.get("mask", "").strip() or None,
                request.form.get("rules", "").strip() or None,
                request.form.get("extra_args", "").strip() or None,
                current_user.id,
            ),
        )
        conn.commit()
    flash(f"Template « {name} » sauvegardé.", "success")
    return redirect(request.referrer or url_for("main.new_attack"))


@bp.route("/templates/<int:tpl_id>/delete", methods=["POST"])
@login_required
def template_delete(tpl_id: int):
    with db_conn() as conn:
        row = conn.execute("SELECT created_by FROM job_templates WHERE id=?", (tpl_id,)).fetchone()
        if not row or (not current_user.is_admin() and row["created_by"] != current_user.id):
            flash("Template introuvable.", "error")
            return redirect(url_for("main.new_attack"))
        conn.execute("DELETE FROM job_templates WHERE id=?", (tpl_id,))
        conn.commit()
    flash("Template supprimé.", "success")
    return redirect(url_for("main.new_attack"))


@bp.route("/api/jobs/status")
@login_required
def api_jobs_status():
    uid = None if current_user.is_admin() else current_user.id
    jobs = job_mgr.list_jobs(user_id=uid)
    return jsonify([{
        "id":          j["id"],
        "status":      j["status"],
        "started_at":  j.get("started_at"),
        "finished_at": j.get("finished_at"),
    } for j in jobs])


@bp.route("/api/jobs/<int:job_id>/results")
@login_required
def api_job_results(job_id: int):
    job = job_mgr.get_job(job_id)
    if not job or not _can_access_job(job):
        return jsonify({"results": [], "status": "not_found"})
    return jsonify({"results": job_mgr.get_results(job), "status": job["status"]})


@bp.route("/api/jobs/<int:job_id>/stats")
@login_required
def api_job_stats(job_id: int):
    job = job_mgr.get_job(job_id)
    if not job or not _can_access_job(job):
        return jsonify({"error": "not found"}), 404
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT ts, speed_hs, progress_pct, cracked FROM job_snapshots"
            " WHERE job_id=? ORDER BY ts",
            (job_id,),
        ).fetchall()
    return jsonify([dict(r) for r in rows])


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


@bp.route("/api/parse_hashes", methods=["POST"])
@login_required
def api_parse_hashes():
    content = ""
    if request.content_type and "multipart" in request.content_type:
        f = request.files.get("file")
        if f:
            content = f.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
    else:
        data = request.get_json(silent=True) or {}
        content = data.get("content", "")

    content = content.strip()
    if not content:
        return jsonify({"error": "Contenu vide"}), 400

    result = parse_hashes(content)

    # Auto-détection du type via le premier hash extrait
    candidates = []
    if result["hashes"]:
        candidates = detect_hash(result["hashes"][0])

    # Aperçu des lignes rejetées pertinentes (hors métadonnées mimikatz)
    SKIP_CAT = {"Métadonnées / contexte"}
    preview_rejected = [
        line for line, cat in result.get("rejected_details", [])
        if cat not in SKIP_CAT
    ][:10]
    # Fallback : tout est metadata → montrer quand même les 5 premières non-vides
    if not preview_rejected and result["rejected"]:
        preview_rejected = result["rejected"][:5]

    return jsonify({
        "format":          result["format"],
        "hash_count":      len(result["hashes"]),
        "hashes":          "\n".join(result["hashes"]),
        "usermap":         result["usermap"],
        "rejected_count":  len(result["rejected"]),
        "rejected_cat":    result["rejected_cat"],
        "rejected_preview":preview_rejected,
        "rejected_all":    result["rejected"],
        "candidates":      candidates,
    })


@bp.route("/api/devices")
@login_required
def api_devices():
    return jsonify(get_devices())


@bp.route("/api/wordlists")
@login_required
def api_wordlists():
    return jsonify(get_wordlists())


@bp.route("/api/rules/save", methods=["POST"])
@login_required
def api_rule_save():
    import re as _re
    data = request.get_json(silent=True) or {}
    rule_content = data.get("rule", "").strip()
    name = data.get("name", "custom").strip()
    if not rule_content:
        return jsonify({"error": "Règle vide"}), 400
    name = _re.sub(r"[^a-zA-Z0-9_\-]", "_", name) or "custom"
    rules_dir = os.path.join(current_app.instance_path, "rules")
    os.makedirs(rules_dir, exist_ok=True)
    path = os.path.join(rules_dir, f"{name}.rule")
    with open(path, "w") as f:
        f.write(rule_content + "\n")
    return jsonify({"path": path, "name": f"{name}.rule"})


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
        api_tokens = conn.execute(
            "SELECT * FROM api_tokens WHERE user_id=? ORDER BY created_at", (current_user.id,)
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

    from flask import session as _session
    new_token = _session.pop("_new_api_token", None)

    return render_template(
        "main/profile.html",
        has_2fa=has_2fa,
        require_2fa=require_2fa,
        totp_uri=totp_uri,
        totp_secret=totp_secret,
        show_setup=show_setup,
        webhooks=webhooks,
        api_tokens=api_tokens,
        new_token=new_token,
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


@bp.route("/profile/token/create", methods=["POST"])
@login_required
def profile_token_create():
    import secrets as _sec
    from flask import session as _session
    label = request.form.get("label", "").strip()[:64] or "Token"
    token = _sec.token_urlsafe(32)
    with db_conn() as conn:
        conn.execute(
            "INSERT INTO api_tokens (user_id, token, label) VALUES (?,?,?)",
            (current_user.id, token, label),
        )
        conn.commit()
    _session["_new_api_token"] = {"value": token, "label": label}
    return redirect(url_for("main.profile") + "#api-tokens")


@bp.route("/profile/token/<int:tok_id>/delete", methods=["POST"])
@login_required
def profile_token_delete(tok_id: int):
    with db_conn() as conn:
        conn.execute(
            "DELETE FROM api_tokens WHERE id=? AND user_id=?",
            (tok_id, current_user.id),
        )
        conn.commit()
    flash("Token supprimé.", "success")
    return redirect(url_for("main.profile") + "#api-tokens")


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
