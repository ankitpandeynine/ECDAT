"""
ECDAT Authentication, Authorization, and Session Management.
Enforces Role-Based Access Control (RBAC): OWNER, ADMIN, SECURITY_ANALYST, VIEWER.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import hmac
import os
import secrets
import sqlite3
from typing import Any, Dict, List, Optional


class UserRole(str, Enum):
    OWNER = "OWNER"
    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    VIEWER = "VIEWER"


# Permission hierarchy
ROLE_HIERARCHY = {
    UserRole.OWNER: 4,
    UserRole.ADMIN: 3,
    UserRole.SECURITY_ANALYST: 2,
    UserRole.VIEWER: 1,
}


def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    """Hash a password using PBKDF2-HMAC-SHA256 with 100,000 rounds."""
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    )
    return key.hex(), salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verify password in constant time."""
    computed_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(computed_hash, stored_hash)


class AuthService:
    def __init__(self, db_connector):
        self.connect = db_connector
        self._init_tables()
        self._seed_default_user()

    def _init_tables(self):
        with self.connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                name TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'SECURITY_ANALYST',
                created_at TEXT NOT NULL
            )''')
            db.execute('''CREATE TABLE IF NOT EXISTS user_sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )''')
            db.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                project_id TEXT,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                created_at TEXT NOT NULL
            )''')
            db.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_audit_project ON audit_logs(project_id)')

    def _seed_default_user(self):
        with self.connect() as db:
            row = db.execute("SELECT count(*) FROM users").fetchone()
            if row and row[0] == 0:
                p_hash, salt = hash_password("admin123")
                now_ts = datetime.now(timezone.utc).isoformat()
                user_id = "user-admin-default"
                db.execute(
                    "INSERT INTO users VALUES (?,?,?,?,?,?,?)",
                    (user_id, "admin@ecdat.local", p_hash, salt, "Enterprise Security Officer", UserRole.OWNER.value, now_ts)
                )

    def register_user(self, email: str, password: str, name: str, role: str = UserRole.SECURITY_ANALYST.value) -> Dict[str, Any]:
        email = email.strip().lower()
        if not email or "@" not in email:
            raise ValueError("Valid email is required")
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters")
        if role not in [r.value for r in UserRole]:
            role = UserRole.SECURITY_ANALYST.value

        p_hash, salt = hash_password(password)
        now_ts = datetime.now(timezone.utc).isoformat()
        user_id = f"user-{secrets.token_hex(8)}"

        with self.connect() as db:
            existing = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
            if existing:
                raise ValueError("User with this email already exists")
            db.execute(
                "INSERT INTO users VALUES (?,?,?,?,?,?,?)",
                (user_id, email, p_hash, salt, name.strip(), role, now_ts)
            )

        token = self._create_session(user_id)
        self.log_audit(user_id=user_id, action="USER_REGISTER", details=f"Registered {email} with role {role}")
        return {
            "user_id": user_id,
            "email": email,
            "name": name,
            "role": role,
            "token": token,
        }

    def authenticate_user(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        email = email.strip().lower()
        with self.connect() as db:
            user = db.execute("SELECT id, email, password_hash, salt, name, role FROM users WHERE email=?", (email,)).fetchone()
            if not user:
                return None
            if not verify_password(password, user["password_hash"], user["salt"]):
                return None

            token = self._create_session(user["id"])
            self.log_audit(user_id=user["id"], action="USER_LOGIN", details=f"Login from {email}")
            return {
                "user_id": user["id"],
                "email": user["email"],
                "name": user["name"],
                "role": user["role"],
                "token": token,
            }

    def _create_session(self, user_id: str) -> str:
        token = secrets.token_hex(32)
        now_ts = datetime.now(timezone.utc).isoformat()
        with self.connect() as db:
            db.execute("INSERT INTO user_sessions VALUES (?,?,?,?)", (token, user_id, now_ts, None))
        return token

    def validate_session(self, token: str) -> Optional[Dict[str, Any]]:
        if not token:
            return None
        with self.connect() as db:
            row = db.execute("""
                SELECT u.id, u.email, u.name, u.role
                FROM user_sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.token = ?
            """, (token,)).fetchone()
            if not row:
                return None
            return {
                "user_id": row["id"],
                "email": row["email"],
                "name": row["name"],
                "role": row["role"],
            }

    def invalidate_session(self, token: str):
        with self.connect() as db:
            db.execute("DELETE FROM user_sessions WHERE token=?", (token,))

    def log_audit(self, action: str, user_id: Optional[str] = None, project_id: Optional[str] = None, details: Optional[str] = None, ip_address: Optional[str] = None):
        log_id = f"audit-{secrets.token_hex(8)}"
        now_ts = datetime.now(timezone.utc).isoformat()
        with self.connect() as db:
            db.execute(
                "INSERT INTO audit_logs VALUES (?,?,?,?,?,?,?)",
                (log_id, user_id, project_id, action, details, ip_address, now_ts)
            )

    def get_audit_logs(self, project_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        with self.connect() as db:
            if project_id:
                rows = db.execute("SELECT * FROM audit_logs WHERE project_id=? ORDER BY created_at DESC LIMIT ?", (project_id, limit)).fetchall()
            else:
                rows = db.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]
