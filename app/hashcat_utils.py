from __future__ import annotations

import os
import re
import subprocess
import shutil
from typing import Optional

HASHCAT_BIN  = shutil.which("hashcat") or os.environ.get("HASHCAT_PATH", "hashcat")
HASHCAT_FORCE: bool = True  # peut être désactivé via config.json → hashcat_force: false

WORDLIST_DIRS: list[str] = [
    "/usr/share/wordlists",
    "/opt/wordlists",
    os.path.expanduser("~/wordlists"),
    "wordlists",
    "instance/wordlists",
]

ATTACK_MODES: dict[int, str] = {
    0: "Dictionnaire",
    1: "Combinateur",
    3: "Brute-force / Mask",
    6: "Hybride wordlist + mask",
    7: "Hybride mask + wordlist",
}

_DEVICE_ID_PATTERN   = re.compile(r"\s*Backend Device ID #(\d+)")
_DEVICE_NAME_PATTERN = re.compile(r"\s*Name\.{5,}:\s*(.+)")
_DEVICE_TYPE_PATTERN = re.compile(r"\s*Type\.{5,}:\s*(.+)")
_SECTION_PATTERN     = re.compile(r"^[A-Za-z]")

_MAX_HASH_CANDIDATES = 12


def hashcat_available() -> tuple[bool, Optional[str]]:
    try:
        result = subprocess.run(
            [HASHCAT_BIN, "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0, result.stdout.decode().strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False, None


def get_devices() -> list[dict]:
    ok, _ = hashcat_available()
    if not ok:
        return []
    try:
        result = subprocess.run([HASHCAT_BIN, "-I"], capture_output=True, timeout=10)
        output = result.stdout.decode()
        devices: list[dict] = []
        current: dict = {}
        for line in output.splitlines():
            # Header de section top-level (ex : "OpenCL Info:", "OpenCL Platform ID #1")
            # → clôture le device courant et remet le contexte à zéro
            if _SECTION_PATTERN.match(line) and not _DEVICE_ID_PATTERN.match(line):
                if current:
                    devices.append(current)
                current = {}
                continue
            m = _DEVICE_ID_PATTERN.match(line)
            if m:
                if current:
                    devices.append(current)
                current = {"id": int(m.group(1)), "name": "", "type": ""}
                continue
            m = _DEVICE_NAME_PATTERN.match(line)
            if m and current:
                current["name"] = m.group(1).strip()
                continue
            m = _DEVICE_TYPE_PATTERN.match(line)
            if m and current:
                current["type"] = m.group(1).strip()
        if current:
            devices.append(current)
        return [d for d in devices if d.get("type", "").upper() != "CPU"]
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []


def get_wordlists() -> list[dict]:
    found: list[dict] = []
    for directory in WORDLIST_DIRS:
        if not os.path.isdir(directory):
            continue
        for filename in sorted(os.listdir(directory)):
            full_path = os.path.join(directory, filename)
            if os.path.isfile(full_path) and not filename.endswith(".7z"):
                found.append({
                    "path": full_path,
                    "name": filename,
                    "size": os.path.getsize(full_path),
                })
    return found


def detect_hash(hash_str: str) -> list[dict]:
    """Identifie les types de hash possibles, classés par probabilité décroissante."""
    try:
        import name_that_hash as nth
        h = hash_str.strip()
        raw = nth.runner.api_return_hashes_as_dict([h])
        candidates: list[dict] = raw.get(h, [])

        def _sort_key(c: dict) -> tuple[int, int]:
            return (int(c.get("extended", False)), int(c.get("hashcat") is None))

        candidates = sorted(candidates, key=_sort_key)
        return [
            {
                "name":        c.get("name", ""),
                "hashcat":     c.get("hashcat"),
                "john":        c.get("john"),
                "description": c.get("description") or "",
                "extended":    c.get("extended", False),
            }
            for c in candidates[:_MAX_HASH_CANDIDATES]
        ]
    except ImportError:
        return []
    except Exception:
        return []


def build_command(job: dict) -> list[str]:
    cmd: list[str] = [HASHCAT_BIN]
    cmd += ["-m", str(job["hash_type"])]
    cmd += ["-a", str(job["attack_mode"])]
    cmd.append(job["hash_file"])

    mode = job["attack_mode"]
    # Positional args vary by attack mode (hashcat syntax):
    #   0: hash_file wordlist
    #   1: hash_file wordlist1 wordlist2
    #   3: hash_file mask
    #   6: hash_file wordlist mask
    #   7: hash_file mask wordlist
    if mode == 0 and job.get("wordlist"):
        cmd.append(job["wordlist"])
    elif mode == 1 and job.get("wordlist"):
        cmd += job["wordlist"].split("|")[:2]
    elif mode == 3 and job.get("mask"):
        cmd.append(job["mask"])
    elif mode == 6:
        if job.get("wordlist"):
            cmd.append(job["wordlist"])
        if job.get("mask"):
            cmd.append(job["mask"])
    elif mode == 7:
        if job.get("mask"):
            cmd.append(job["mask"])
        if job.get("wordlist"):
            cmd.append(job["wordlist"])

    if job.get("rules"):
        cmd += ["-r", job["rules"]]
    if job.get("devices"):
        cmd += ["-d", job["devices"]]
    if job.get("pot_file"):
        cmd += ["--potfile-path", job["pot_file"]]
    if job.get("restore_file"):
        cmd += ["--restore-file-path", job["restore_file"]]

    workload = job.get("workload") or 2
    cmd += [
        "--status",
        "--status-timer=2",
        "--outfile-format=2",
        "-w", str(workload),
    ]
    if HASHCAT_FORCE:
        cmd.append("--force")

    if job.get("extra_args"):
        cmd += job["extra_args"].split()

    return cmd
