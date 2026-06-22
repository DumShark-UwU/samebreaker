from __future__ import annotations

from typing import Optional
from flask_login import UserMixin
from .db import db_conn


class User(UserMixin):
    def __init__(
        self,
        id: int,
        username: str,
        role: str,
        allowed_devices: str = "",
        workload_profile: int = 2,
        must_change_password: bool = False,
    ) -> None:
        self.id                   = id
        self.username             = username
        self.role                 = role
        self.allowed_devices      = allowed_devices or ""
        self.workload_profile     = workload_profile if workload_profile in (1, 2, 3, 4) else 2
        self.must_change_password = bool(must_change_password)

    def is_admin(self) -> bool:
        return self.role == "admin"

    def get_allowed_device_ids(self) -> list[int]:
        if not self.allowed_devices:
            return []
        return [
            int(x.strip())
            for x in self.allowed_devices.split(",")
            if x.strip().isdigit()
        ]

    @staticmethod
    def get(user_id: int) -> Optional[User]:
        with db_conn() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        if not row:
            return None
        return User(
            row["id"], row["username"], row["role"],
            row["allowed_devices"], row["workload_profile"],
            row["must_change_password"],
        )

    @staticmethod
    def get_by_username(username: str):
        with db_conn() as conn:
            return conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
