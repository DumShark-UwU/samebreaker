from __future__ import annotations

import json
import logging
import urllib.parse
import urllib.request
import urllib.error

log = logging.getLogger(__name__)


def _detect_type(url: str) -> str:
    u = url.lower()
    if "discord.com/api/webhooks" in u or "discordapp.com/api/webhooks" in u:
        return "discord"
    if "hooks.slack.com" in u:
        return "slack"
    if "webhook.office.com" in u or "outlook.office.com" in u:
        return "teams"
    if "signal.callmebot.com" in u:
        return "signal"
    if "ntfy.sh" in u:
        return "ntfy"
    return "generic"


def _to_slack(payload: dict) -> dict:
    content = payload.get("content", "")
    embeds  = payload.get("embeds", [])
    attachments = []
    if embeds:
        e = embeds[0]
        hex_color = f"#{e.get('color', 0x00b4d8):06x}"
        fields = [
            {"title": f["name"], "value": f["value"], "short": f.get("inline", False)}
            for f in e.get("fields", [])
        ]
        text_parts = []
        if e.get("title"):
            text_parts.append(f"*{e['title']}*")
        if e.get("description"):
            text_parts.append(e["description"])
        attachments.append({
            "color":  hex_color,
            "text":   "\n".join(text_parts),
            "fields": fields,
        })
    return {"text": content, "attachments": attachments}


def _to_teams(payload: dict) -> dict:
    content = payload.get("content", "")
    embeds  = payload.get("embeds", [])
    card: dict = {
        "@type":     "MessageCard",
        "@context":  "http://schema.org/extensions",
        "themeColor": "00b4d8",
        "summary":    content,
    }
    if embeds:
        e = embeds[0]
        facts = [{"name": f["name"], "value": f["value"]} for f in e.get("fields", [])]
        section: dict = {"activityTitle": e.get("title", content)}
        if e.get("description"):
            section["activitySubtitle"] = e["description"]
        if facts:
            section["facts"] = facts
        card["sections"] = [section]
    return card


def _to_ntfy(payload: dict) -> dict:
    content = payload.get("content", "")
    embeds  = payload.get("embeds", [])
    title   = embeds[0].get("title", "SameBreaker") if embeds else "SameBreaker"
    return {"message": content, "title": title, "priority": 3, "tags": ["shark"]}


def send_webhook(url: str, payload: dict, webhook_type: str = "auto") -> bool:
    if not url:
        return False
    wtype = webhook_type if webhook_type and webhook_type != "auto" else _detect_type(url)

    try:
        if wtype == "signal":
            text     = payload.get("content", "SameBreaker notification")
            full_url = url + ("&" if "?" in url else "?") + "text=" + urllib.parse.quote(text)
            req = urllib.request.Request(full_url, method="GET")
            with urllib.request.urlopen(req, timeout=10):
                pass
            return True

        if wtype == "slack":
            formatted = _to_slack(payload)
        elif wtype == "teams":
            formatted = _to_teams(payload)
        elif wtype == "ntfy":
            formatted = _to_ntfy(payload)
        else:
            formatted = payload

        data = json.dumps(formatted).encode("utf-8")
        req  = urllib.request.Request(
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
                {"name": "Statut",        "value": status,     "inline": True},
                {"name": "Mots de passe", "value": str(found), "inline": True},
            ],
        }],
    }


def password_found_payload(job_name: str, job_id: int, cracked: list[str]) -> dict:
    preview = "\n".join(f"`{c}`" for c in cracked[:10])
    extra   = f"\n… et {len(cracked) - 10} de plus" if len(cracked) > 10 else ""
    return {
        "content": f"🔓 **{job_name}** — {len(cracked)} nouveau(x) mot(s) de passe cracké(s) !",
        "embeds": [{
            "title":  f"Job #{job_id} — Crack détecté",
            "color":  0x00ff88,
            "fields": [{"name": "Résultats", "value": preview + extra or "(vide)", "inline": False}],
        }],
    }


def test_payload(username: str) -> dict:
    return {
        "content": f"🔔 Test webhook SameBreaker — configuré par **{username}**",
        "embeds": [{
            "title":       "Test de notification",
            "color":       0x00b4d8,
            "description": "Si vous voyez ce message, votre webhook est correctement configuré.",
        }],
    }
