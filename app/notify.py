from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error

log = logging.getLogger(__name__)


def send_webhook(url: str, payload: dict) -> bool:
    if not url:
        return False
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10):
            pass
        return True
    except Exception as exc:
        log.warning("Webhook failed (%s): %s", url, exc)
        return False


def job_done_payload(job_name: str, job_id: int, status: str, found: int) -> dict:
    ok = status == "completed"
    return {
        "content": f"{'✅' if ok else '❌'} **{job_name}** terminé — {found} mot(s) de passe trouvé(s)",
        "embeds": [{
            "title": f"Job #{job_id} — {status}",
            "color": 0x00b4d8 if ok else 0xe05252,
            "fields": [
                {"name": "Statut",         "value": status,      "inline": True},
                {"name": "Mots de passe",  "value": str(found),  "inline": True},
            ],
        }],
    }


def password_found_payload(job_name: str, job_id: int, cracked: list[str]) -> dict:
    preview = "\n".join(f"`{c}`" for c in cracked[:10])
    extra = f"\n… et {len(cracked) - 10} de plus" if len(cracked) > 10 else ""
    return {
        "content": f"🔓 **{job_name}** — {len(cracked)} nouveau(x) mot(s) de passe cracké(s) !",
        "embeds": [{
            "title": f"Job #{job_id} — Crack détecté",
            "color": 0x00ff88,
            "fields": [{"name": "Résultats", "value": preview + extra or "(vide)", "inline": False}],
        }],
    }


def test_payload(username: str) -> dict:
    return {
        "content": f"🔔 Test webhook SameBreaker — configuré par **{username}**",
        "embeds": [{
            "title": "Test de notification",
            "color": 0x00b4d8,
            "description": "Si vous voyez ce message, votre webhook est correctement configuré.",
        }],
    }
