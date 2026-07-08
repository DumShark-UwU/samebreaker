from __future__ import annotations

import os
import shutil
import subprocess
import threading
import urllib.request
from pathlib import Path
from typing import Optional

from flask import Blueprint, current_app, jsonify, render_template, request
from flask_login import login_required

bp = Blueprint("library", __name__, url_prefix="/library")

# ── Catalog ───────────────────────────────────────────────────────────────────

CATALOG: dict[str, dict] = {
    # ── Wordlists (tous issus de weakpass.com/weakpass) ───────────────────────
    "weakpass_4_merged": {
        "name": "Weakpass 4 Merged",
        "type": "wordlist",
        "rating": "S",
        "count": "3.58B mots",
        "size_dl": "6.8 GB",
        "size_raw": "40.5 GB",
        "rate": 35.8,
        "description": "Fusion de Weakpass 4 + 4AP — meilleur compromis couverture/qualité.",
        "url": "https://weakpass.com/download/2025/weakpass_4.merged.txt.7z",
        "filename": "weakpass_4.merged.txt",
        "compressed": "weakpass_4.merged.txt.7z",
        "extract": True,
    },
    "weakpass_4a": {
        "name": "Weakpass 4A",
        "type": "wordlist",
        "rating": "A",
        "count": "8.44B mots",
        "size_dl": "12.8 GB",
        "size_raw": "87.4 GB",
        "rate": 36.5,
        "description": "Version étendue — 8.4 milliards de mots de passe réels compilés.",
        "url": "https://weakpass.com/download/2015/weakpass_4a.txt.7z",
        "filename": "weakpass_4a.txt",
        "compressed": "weakpass_4a.txt.7z",
        "extract": True,
    },
    "weakpass_4a_latin": {
        "name": "Weakpass 4A Latin",
        "type": "wordlist",
        "rating": "A",
        "count": "8.28B mots",
        "size_dl": "12.3 GB",
        "size_raw": "85.3 GB",
        "rate": 36.2,
        "description": "4A filtré latin — 8.3B mots sans caractères unicode exotiques.",
        "url": "https://weakpass.com/download/2017/weakpass_4a.latin.txt.7z",
        "filename": "weakpass_4a.latin.txt",
        "compressed": "weakpass_4a.latin.txt.7z",
        "extract": True,
    },
    "weakpass_4": {
        "name": "Weakpass 4",
        "type": "wordlist",
        "rating": "A",
        "count": "2.19B mots",
        "size_dl": "5.4 GB",
        "size_raw": "24.1 GB",
        "rate": 35.0,
        "description": "Version raffinée — 2.1 milliards de mots de passe sans junk.",
        "url": "https://weakpass.com/download/2012/weakpass_4.txt.7z",
        "filename": "weakpass_4.txt",
        "compressed": "weakpass_4.txt.7z",
        "extract": True,
    },
    "weakpass_4_latin": {
        "name": "Weakpass 4 Latin",
        "type": "wordlist",
        "rating": "A",
        "count": "2.16B mots",
        "size_dl": "5.3 GB",
        "size_raw": "23.7 GB",
        "rate": 34.7,
        "description": "4 filtré latin — 2.16B mots, sans unicode exotique.",
        "url": "https://weakpass.com/download/2014/weakpass_4.latin.txt.7z",
        "filename": "weakpass_4.latin.txt",
        "compressed": "weakpass_4.latin.txt.7z",
        "extract": True,
    },
    "weakpass_4a_policy": {
        "name": "Weakpass 4A Policy",
        "type": "wordlist",
        "rating": "B",
        "count": "1.74B mots",
        "size_dl": "2.6 GB",
        "size_raw": "20.6 GB",
        "rate": 19.3,
        "description": "4A filtré policy — 1.7B passwords 8+ chars, latin, 3/4 catégories.",
        "url": "https://weakpass.com/download/2016/weakpass_4a.policy.txt.7z",
        "filename": "weakpass_4a.policy.txt",
        "compressed": "weakpass_4a.policy.txt.7z",
        "extract": True,
    },
    "weakpass_4_policy": {
        "name": "Weakpass 4 Policy",
        "type": "wordlist",
        "rating": "B",
        "count": "320M mots",
        "size_dl": "1.1 GB",
        "size_raw": "3.7 GB",
        "rate": 18.2,
        "description": "4 filtré policy — 320M passwords 8+ chars, 3/4 catégories.",
        "url": "https://weakpass.com/download/2028/weakpass_4.policy.txt.7z",
        "filename": "weakpass_4.policy.txt",
        "compressed": "weakpass_4.policy.txt.7z",
        "extract": True,
    },
    # ── RockYou ───────────────────────────────────────────────────────────────
    "rockyou": {
        "name": "RockYou (original)",
        "type": "wordlist",
        "rating": "C",
        "count": "14M mots",
        "size_dl": "53 MB",
        "size_raw": "134 MB",
        "rate": 7.8,
        "description": "Le classique — leak RockYou 2009. Inclus dans Kali. Référence universelle.",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz",
        "filename": "rockyou.txt",
        "compressed": "rockyou.txt.tar.gz",
        "extract": True,
    },
    "rockyou2021": {
        "name": "RockYou2021",
        "type": "wordlist",
        "rating": "A",
        "count": "8.46B mots",
        "size_dl": "13.6 GB",
        "size_raw": "98.4 GB",
        "rate": 31.2,
        "description": "Compilation massive 2021 — 8.4B mots de passe réels.",
        "url": "https://weakpass.com/download/1943/rockyou2021.7z",
        "filename": "rockyou2021.txt",
        "compressed": "rockyou2021.7z",
        "extract": True,
    },
    "rockyou2024": {
        "name": "RockYou2024",
        "type": "wordlist",
        "rating": "A",
        "count": "9.95B mots",
        "size_dl": "42.9 GB",
        "size_raw": "156 GB",
        "rate": 32.4,
        "description": "Compilation 2024 — 10B mots de passe. La plus grande compilation publique.",
        "url": "https://weakpass.com/download/2033/rockyou2024.txt.7z",
        "filename": "rockyou2024.txt",
        "compressed": "rockyou2024.txt.7z",
        "extract": True,
    },
    "onerule": {
        "name": "OneRuleToRuleThemAll",
        "type": "rule",
        "rating": "S",
        "count": "52K règles",
        "size_dl": "~1 MB",
        "size_raw": "~1 MB",
        "description": "Règle hashcat la plus efficace — testée sur des leaks réels.",
        "url": "https://raw.githubusercontent.com/NotSoSecure/password_cracking_rules/master/OneRuleToRuleThemAll.rule",
        "filename": "OneRuleToRuleThemAll.rule",
        "compressed": None,
        "extract": False,
    },
    "masks_all_in_one": {
        "name": "Masks — All In One",
        "type": "mask",
        "rating": "S",
        "count": "11 patterns",
        "size_dl": "< 1 KB",
        "size_raw": "< 1 KB",
        "description": "Top masks extraits du corpus all_in_one (3B mots de passe réels). Inclut patterns numériques longs.",
        "url": None,
        "filename": "weakpass_all_in_one.hcmask",
        "compressed": None,
        "extract": False,
        "generated": True,
        "masks": [
            "?d?d?d?d?d?d?d?d?d?d?d",
            "?d?d?d?d?d?d?d?d?d?d?d?d",
            "?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d",
            "?l?l?l?l?l?l?l?l?l?l",
            "?l?l?l?l?l?l",
            "?d?d?d?d?d?d?d?d?d",
            "?l?l?l?l?l?l?l?l",
            "?d?d?d?d?d?d?d?d?d?d",
            "?l?l?l?l?l?l?l?l?l",
            "?l?l?l?l?l?l?d?d?d?d",
            "?l?l?l?l?l?l?l?d?d?d?d",
        ],
    },
    "masks_policy": {
        "name": "Masks — Policy (Upper+Digit)",
        "type": "mask",
        "rating": "A",
        "count": "11 patterns",
        "size_dl": "< 1 KB",
        "size_raw": "< 1 KB",
        "description": "Top masks de weakpass_4.merged — inclut patterns Upper+lower+digit, idéal pour AD/policy.",
        "url": None,
        "filename": "weakpass_policy.hcmask",
        "compressed": None,
        "extract": False,
        "generated": True,
        "masks": [
            "?l?l?l?l?l?l?l?l",
            "?u?l?l?l?l?l?d?d?d?d",
            "?u?l?l?l?l?l?l?d?d?d?d",
            "?d?d?d?d?d?d?d?d?d?d",
            "?u?l?l?l?l?l?l?l?d?d?d?d",
            "?u?l?l?l?l?d?d?d?d",
            "?l?l?l?l?l?l?l?l?l?l",
            "?l?l?l?l?l?l?l?l?l",
            "?u?l?l?l?l?l?l?l?l?d?d?d?d",
            "?d?d?d?d?d?d?d?d",
            "?d?d?d?d?d?d?d?d?d",
        ],
    },
}

# ── In-memory download state ───────────────────────────────────────────────────

_state: dict[str, dict] = {}
_state_lock = threading.Lock()


def _set_state(rid: str, **kwargs) -> None:
    with _state_lock:
        _state[rid] = {**_state.get(rid, {}), **kwargs}


def _get_state(rid: str) -> dict:
    with _state_lock:
        return dict(_state.get(rid, {}))


# ── Filesystem helpers ────────────────────────────────────────────────────────

def _type_dir(app, rtype: str) -> Path:
    dirs = {
        "wordlist": Path(app.instance_path) / "wordlists",
        "rule":     Path(app.instance_path) / "rules",
        "mask":     Path(app.instance_path) / "masks",
    }
    d = dirs[rtype]
    d.mkdir(parents=True, exist_ok=True)
    return d


def _tmp_dir(app) -> Path:
    d = Path(app.instance_path) / "wordlists" / ".downloads"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _resource_path(app, rid: str) -> Optional[Path]:
    res = CATALOG.get(rid)
    if not res:
        return None
    return _type_dir(app, res["type"]) / res["filename"]


def _is_ready(app, rid: str) -> bool:
    p = _resource_path(app, rid)
    return p is not None and p.exists() and p.stat().st_size > 0


# ── Download thread ───────────────────────────────────────────────────────────

def _find_7z() -> Optional[str]:
    for cmd in ("7z", "7za", "7zz"):
        if shutil.which(cmd):
            return cmd
    return None


def _download_thread(app, rid: str) -> None:
    res = CATALOG[rid]
    _set_state(rid, status="downloading", progress=0, error=None)

    try:
        with app.app_context():
            out_dir = _type_dir(app, res["type"])

            # Generated files (no network required)
            if res.get("generated"):
                out_path = out_dir / res["filename"]
                out_path.write_text("\n".join(res["masks"]) + "\n")
                _set_state(rid, status="ready", progress=100)
                return

            url = res["url"]
            dest_final = out_dir / res["filename"]

            if res.get("extract") and res.get("compressed"):
                dest_dl = _tmp_dir(app) / res["compressed"]
            else:
                dest_dl = dest_final

            # Stream download
            req = urllib.request.Request(url, headers={"User-Agent": "SameBreaker/1.0"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                total = int(resp.headers.get("Content-Length", 0))
                downloaded = 0
                with open(dest_dl, "wb") as f:
                    while True:
                        chunk = resp.read(1024 * 1024)  # 1 MB chunks
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total:
                            pct = int(downloaded / total * 88)
                            _set_state(rid, progress=pct)

            # Extract if needed
            if res.get("extract"):
                _set_state(rid, status="extracting", progress=92)
                compressed_name = res.get("compressed", "")

                if compressed_name.endswith(".tar.gz") or compressed_name.endswith(".tgz"):
                    import tarfile as _tarfile
                    with _tarfile.open(str(dest_dl), "r:gz") as tf:
                        # Extract only regular files, no path traversal
                        for member in tf.getmembers():
                            if member.isfile() and ".." not in member.name:
                                member.name = Path(member.name).name
                                tf.extract(member, str(out_dir))
                    dest_dl.unlink(missing_ok=True)

                elif compressed_name.endswith(".gz"):
                    import gzip as _gzip
                    with _gzip.open(str(dest_dl), "rb") as gz_in:
                        with open(out_dir / res["filename"], "wb") as f_out:
                            while True:
                                chunk = gz_in.read(1024 * 1024)
                                if not chunk:
                                    break
                                f_out.write(chunk)
                    dest_dl.unlink(missing_ok=True)

                else:
                    # .7z via subprocess
                    z7 = _find_7z()
                    if not z7:
                        raise RuntimeError("7z introuvable — installez p7zip-full sur le serveur")
                    result = subprocess.run(
                        [z7, "e", str(dest_dl), f"-o{out_dir}", "-y"],
                        capture_output=True, timeout=7200,
                    )
                    dest_dl.unlink(missing_ok=True)
                    if result.returncode != 0:
                        raise RuntimeError(result.stderr.decode(errors="replace")[:300])

            _set_state(rid, status="ready", progress=100, error=None)

    except Exception as exc:
        _set_state(rid, status="error", progress=0, error=str(exc)[:300])
        # cleanup partial download
        try:
            if res.get("extract") and res.get("compressed"):
                p = _tmp_dir(app) / res["compressed"]
                p.unlink(missing_ok=True)
        except Exception:
            pass


# ── Routes ────────────────────────────────────────────────────────────────────

@bp.route("/")
@login_required
def index():
    app = current_app._get_current_object()
    by_type: dict[str, list] = {"wordlist": [], "rule": [], "mask": []}
    for rid, res in CATALOG.items():
        st = _get_state(rid)
        ready = _is_ready(app, rid)
        if ready and st.get("status") not in ("downloading", "extracting"):
            st = {"status": "ready", "progress": 100}
        elif not st:
            st = {"status": "idle", "progress": 0}
        by_type[res["type"]].append({
            **res,
            "id": rid,
            "state": st,
            "ready": ready,
        })
    return render_template("main/library.html", by_type=by_type)


@bp.route("/download/<rid>", methods=["POST"])
@login_required
def start_download(rid: str):
    res = CATALOG.get(rid)
    if not res:
        return jsonify({"error": "Ressource inconnue"}), 404
    if not res.get("url") and not res.get("generated"):
        return jsonify({"error": "URL non configurée pour cette ressource"}), 400

    st = _get_state(rid)
    if st.get("status") in ("downloading", "extracting"):
        return jsonify({"error": "Téléchargement déjà en cours"}), 409

    app = current_app._get_current_object()
    _set_state(rid, status="downloading", progress=0, error=None)
    threading.Thread(target=_download_thread, args=(app, rid), daemon=True).start()
    return jsonify({"ok": True})


@bp.route("/status/<rid>")
@login_required
def status(rid: str):
    if rid not in CATALOG:
        return jsonify({"error": "Ressource inconnue"}), 404
    app = current_app._get_current_object()
    st = _get_state(rid)
    ready = _is_ready(app, rid)
    if ready and st.get("status") not in ("downloading", "extracting"):
        st = {"status": "ready", "progress": 100}
    elif not st:
        st = {"status": "idle", "progress": 0}
    return jsonify({**st, "ready": ready})


@bp.route("/delete/<rid>", methods=["POST"])
@login_required
def delete_resource(rid: str):
    res = CATALOG.get(rid)
    if not res:
        return jsonify({"error": "Ressource inconnue"}), 404
    app = current_app._get_current_object()
    path = _resource_path(app, rid)
    if path and path.exists():
        path.unlink()
    with _state_lock:
        _state.pop(rid, None)
    return jsonify({"ok": True})
