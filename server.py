
import os
import sqlite3
import secrets
import string
import calendar
import hashlib
import hmac
import time

from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel


# ============================================================
# CONFIG
# ============================================================

APP_NAME = "Resource Hub License Server"

DATABASE_PATH = Path(
    os.getenv("DATABASE_PATH", "licenses.db")
)

ADMIN_SECRET = os.getenv(
    "ADMIN_SECRET",
    ""
)

SESSION_DAYS = 30

app = FastAPI(
    title=APP_NAME,
    version="4.0.0"
)


# ============================================================
# DATABASE
# ============================================================

def get_connection():
    connection = sqlite3.connect(
        DATABASE_PATH
    )
    connection.row_factory = sqlite3.Row
    return connection


def setup_database():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            license_key TEXT PRIMARY KEY,
            duration_type TEXT NOT NULL,
            duration_amount INTEGER NOT NULL,
            activated INTEGER NOT NULL DEFAULT 0,
            bound_hwid TEXT,
            activated_at TEXT,
            expires_at TEXT,
            created_at TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            owner_username TEXT
        )
    """)

    connection.commit()
    connection.close()


@app.on_event("startup")
def startup():
    setup_database()


# ============================================================
# TIME
# ============================================================

def now_utc():
    return datetime.now(timezone.utc)


def iso(value):
    return value.isoformat()


def parse_datetime(value):
    if not value:
        return None
    return datetime.fromisoformat(value)


def seconds_remaining(expires_at):
    if not expires_at:
        return 0

    remaining = int(
        (
            expires_at - now_utc()
        ).total_seconds()
    )

    return max(0, remaining)


# ============================================================
# PASSWORD HASHING
# ============================================================

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16).hex()

    salt_bytes = bytes.fromhex(salt)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_bytes,
        200_000
    )

    return password_hash.hex(), salt


def verify_password(
    password,
    stored_hash,
    salt
):
    calculated_hash, _ = hash_password(
        password,
        salt
    )

    return hmac.compare_digest(
        calculated_hash,
        stored_hash
    )


# ============================================================
# SESSION TOKENS
# ============================================================

def create_session(username):
    raw_token = secrets.token_urlsafe(48)

    token_hash = hashlib.sha256(
        raw_token.encode("utf-8")
    ).hexdigest()

    created = now_utc()
    expires = created + timedelta(
        days=SESSION_DAYS
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO sessions (
            token_hash,
            username,
            created_at,
            expires_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            token_hash,
            username,
            iso(created),
            iso(expires)
        )
    )

    connection.commit()
    connection.close()

    return raw_token


def session_username(token):
    if not token:
        return None

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT username, expires_at
        FROM sessions
        WHERE token_hash = ?
        """,
        (token_hash,)
    )

    row = cursor.fetchone()

    if not row:
        connection.close()
        return None

    expires_at = parse_datetime(
        row["expires_at"]
    )

    if not expires_at or now_utc() >= expires_at:
        cursor.execute(
            """
            DELETE FROM sessions
            WHERE token_hash = ?
            """,
            (token_hash,)
        )
        connection.commit()
        connection.close()
        return None

    connection.close()
    return row["username"]


def delete_session(token):
    if not token:
        return

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        DELETE FROM sessions
        WHERE token_hash = ?
        """,
        (token_hash,)
    )

    connection.commit()
    connection.close()


def auth_username(
    authorization: str | None
):
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Login required."
        )

    token = authorization

    if token.startswith("Bearer "):
        token = token[7:].strip()

    username = session_username(token)

    if not username:
        raise HTTPException(
            status_code=401,
            detail="Session expired. Please sign in again."
        )

    return username


# ============================================================
# ADMIN AUTH
# ============================================================

def require_admin(
    x_admin_secret: str | None
):
    if not ADMIN_SECRET:
        raise HTTPException(
            status_code=500,
            detail="ADMIN_SECRET is not configured on the server."
        )

    if not x_admin_secret:
        raise HTTPException(
            status_code=401,
            detail="Admin authorization required."
        )

    if not hmac.compare_digest(
        x_admin_secret,
        ADMIN_SECRET
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid admin authorization."
        )


# ============================================================
# LICENSE HELPERS
# ============================================================

def generate_license_key():
    characters = (
        string.ascii_uppercase
        + string.digits
    )

    for char in "O01I":
        characters = characters.replace(
            char,
            ""
        )

    groups = []

    for _ in range(4):
        groups.append(
            "".join(
                secrets.choice(characters)
                for _ in range(5)
            )
        )

    return "-".join(groups)


def add_months(start, months):
    month_index = (
        start.month - 1 + months
    )

    year = (
        start.year
        + month_index // 12
    )

    month = (
        month_index % 12
        + 1
    )

    day = min(
        start.day,
        calendar.monthrange(
            year,
            month
        )[1]
    )

    return start.replace(
        year=year,
        month=month,
        day=day
    )


def calculate_expiration(
    duration_type,
    duration_amount
):
    start = now_utc()

    duration_type = (
        duration_type
        .strip()
        .lower()
    )

    if duration_type == "minutes":
        return start + timedelta(
            minutes=duration_amount
        )

    if duration_type == "hours":
        return start + timedelta(
            hours=duration_amount
        )

    if duration_type == "days":
        return start + timedelta(
            days=duration_amount
        )

    if duration_type == "months":
        return add_months(
            start,
            duration_amount
        )

    raise ValueError(
        "Invalid duration type."
    )


def license_status(row):
    if row["revoked"]:
        return "revoked"

    if not row["activated"]:
        return "not_activated"

    expires_at = parse_datetime(
        row["expires_at"]
    )

    if not expires_at or now_utc() >= expires_at:
        return "expired"

    return "active"


# ============================================================
# REQUEST MODELS
# ============================================================

class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class GenerateRequest(BaseModel):
    duration_type: str
    duration_amount: int


class LicenseRequest(BaseModel):
    license_key: str
    hwid: str


class AdminLicenseRequest(BaseModel):
    license_key: str


# ============================================================
# BASIC
# ============================================================

@app.get("/")
def root():
    return {
        "success": True,
        "message": "Resource Hub license server is online.",
        "version": "4.0.0",
        "server_time": iso(now_utc())
    }


@app.get("/health")
def health():
    return {
        "success": True,
        "status": "online",
        "server_time": iso(now_utc())
    }


# ============================================================
# AUTH
# ============================================================

@app.post("/api/auth/register")
def register(request: RegisterRequest):
    username = request.username.strip()
    password = request.password

    if len(username) < 3 or len(username) > 32:
        raise HTTPException(
            status_code=400,
            detail="Username must be 3-32 characters."
        )

    if not username.replace("_", "").isalnum():
        raise HTTPException(
            status_code=400,
            detail="Username may contain only letters, numbers, and underscores."
        )

    if len(password) < 6:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 6 characters."
        )

    password_hash, salt = hash_password(
        password
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id
        FROM users
        WHERE username = ?
        """,
        (username,)
    )

    if cursor.fetchone():
        connection.close()
        raise HTTPException(
            status_code=409,
            detail="Username already exists."
        )

    cursor.execute(
        """
        INSERT INTO users (
            username,
            password_hash,
            salt,
            created_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            username,
            password_hash,
            salt,
            iso(now_utc())
        )
    )

    connection.commit()
    connection.close()

    token = create_session(
        username
    )

    return {
        "success": True,
        "username": username,
        "token": token
    }


@app.post("/api/auth/login")
def login(request: LoginRequest):
    username = request.username.strip()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
        """,
        (username,)
    )

    user = cursor.fetchone()
    connection.close()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password."
        )

    if not verify_password(
        request.password,
        user["password_hash"],
        user["salt"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password."
        )

    token = create_session(
        username
    )

    return {
        "success": True,
        "username": username,
        "token": token
    }


@app.post("/api/auth/logout")
def logout(
    authorization: str | None = Header(default=None)
):
    if authorization:
        token = authorization
        if token.startswith("Bearer "):
            token = token[7:].strip()
        delete_session(token)

    return {
        "success": True
    }


@app.get("/api/auth/me")
def me(
    authorization: str | None = Header(default=None)
):
    username = auth_username(
        authorization
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT username, created_at
        FROM users
        WHERE username = ?
        """,
        (username,)
    )

    user = cursor.fetchone()

    cursor.execute(
        """
        SELECT *
        FROM licenses
        WHERE owner_username = ?
        ORDER BY activated_at DESC
        LIMIT 1
        """,
        (username,)
    )

    license_row = cursor.fetchone()

    connection.close()

    account = {
        "username": user["username"],
        "created_at": user["created_at"],
        "license": None
    }

    if license_row:
        expires_at = parse_datetime(
            license_row["expires_at"]
        )

        account["license"] = {
            "license_key": license_row["license_key"],
            "status": license_status(license_row),
            "expires_at": license_row["expires_at"],
            "seconds_remaining": seconds_remaining(
                expires_at
            )
        }

    return {
        "success": True,
        "account": account
    }


# ============================================================
# USER LICENSE ACTIVATION
# ============================================================

@app.post("/api/license/activate")
def activate(
    request: LicenseRequest,
    authorization: str | None = Header(default=None)
):
    username = auth_username(
        authorization
    )

    key = (
        request.license_key
        .strip()
        .upper()
    )

    hwid = request.hwid.strip()

    if not key:
        raise HTTPException(
            status_code=400,
            detail="License key is required."
        )

    if not hwid:
        raise HTTPException(
            status_code=400,
            detail="Device information is required."
        )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM licenses
        WHERE license_key = ?
        """,
        (key,)
    )

    row = cursor.fetchone()

    if not row:
        connection.close()
        raise HTTPException(
            status_code=404,
            detail="Invalid license key."
        )

    if row["revoked"]:
        connection.close()
        raise HTTPException(
            status_code=403,
            detail="This license has been revoked."
        )

    # First activation.
    if not row["activated"]:

        expiration = calculate_expiration(
            row["duration_type"],
            row["duration_amount"]
        )

        activated_at = now_utc()

        cursor.execute(
            """
            UPDATE licenses
            SET
                activated = 1,
                bound_hwid = ?,
                activated_at = ?,
                expires_at = ?,
                owner_username = ?
            WHERE license_key = ?
            """,
            (
                hwid,
                iso(activated_at),
                iso(expiration),
                username,
                key
            )
        )

        connection.commit()
        connection.close()

        return {
            "success": True,
            "message": "License activated successfully.",
            "seconds_remaining":
                seconds_remaining(expiration),
            "expires_at": iso(expiration)
        }

    # Already active: enforce the original account/device.
    if row["bound_hwid"] != hwid:
        connection.close()
        raise HTTPException(
            status_code=403,
            detail="HWID mismatch. This license is already bound to another device."
        )

    if (
        row["owner_username"]
        and row["owner_username"] != username
    ):
        connection.close()
        raise HTTPException(
            status_code=403,
            detail="This license belongs to another account."
        )

    expiration = parse_datetime(
        row["expires_at"]
    )

    if not expiration or now_utc() >= expiration:
        connection.close()
        raise HTTPException(
            status_code=403,
            detail="This license has expired."
        )

    connection.close()

    return {
        "success": True,
        "message": "License is valid.",
        "seconds_remaining":
            seconds_remaining(expiration),
        "expires_at": iso(expiration)
    }


@app.post("/api/license/validate")
def validate(
    request: LicenseRequest,
    authorization: str | None = Header(default=None)
):
    username = auth_username(
        authorization
    )

    key = (
        request.license_key
        .strip()
        .upper()
    )

    hwid = request.hwid.strip()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM licenses
        WHERE license_key = ?
        """,
        (key,)
    )

    row = cursor.fetchone()
    connection.close()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Invalid license key."
        )

    if row["revoked"]:
        raise HTTPException(
            status_code=403,
            detail="This license has been revoked."
        )

    if not row["activated"]:
        raise HTTPException(
            status_code=403,
            detail="This license has not been activated."
        )

    if row["bound_hwid"] != hwid:
        raise HTTPException(
            status_code=403,
            detail="HWID mismatch."
        )

    if (
        row["owner_username"]
        and row["owner_username"] != username
    ):
        raise HTTPException(
            status_code=403,
            detail="This license belongs to another account."
        )

    expiration = parse_datetime(
        row["expires_at"]
    )

    if not expiration or now_utc() >= expiration:
        raise HTTPException(
            status_code=403,
            detail="This license has expired."
        )

    return {
        "success": True,
        "valid": True,
        "seconds_remaining":
            seconds_remaining(expiration),
        "expires_at": iso(expiration),
        "username": username
    }


# ============================================================
# ADMIN: GENERATE
# ============================================================

@app.post("/api/admin/generate")
def admin_generate(
    request: GenerateRequest,
    x_admin_secret: str | None = Header(default=None)
):
    require_admin(
        x_admin_secret
    )

    duration_type = (
        request.duration_type
        .strip()
        .lower()
    )

    if duration_type not in {
        "minutes",
        "hours",
        "days",
        "months"
    }:
        raise HTTPException(
            status_code=400,
            detail="Invalid duration type."
        )

    if request.duration_amount < 1:
        raise HTTPException(
            status_code=400,
            detail="Amount must be at least 1."
        )

    connection = get_connection()
    cursor = connection.cursor()

    while True:
        key = generate_license_key()

        cursor.execute(
            """
            SELECT license_key
            FROM licenses
            WHERE license_key = ?
            """,
            (key,)
        )

        if not cursor.fetchone():
            break

    cursor.execute(
        """
        INSERT INTO licenses (
            license_key,
            duration_type,
            duration_amount,
            activated,
            created_at,
            revoked,
            owner_username
        )
        VALUES (?, ?, ?, 0, ?, 0, NULL)
        """,
        (
            key,
            duration_type,
            request.duration_amount,
            iso(now_utc())
        )
    )

    connection.commit()
    connection.close()

    return {
        "success": True,
        "license_key": key,
        "duration_type": duration_type,
        "duration_amount": request.duration_amount,
        "activated": False
    }


# ============================================================
# ADMIN: LIST
# ============================================================

@app.get("/api/admin/licenses")
def admin_list(
    x_admin_secret: str | None = Header(default=None)
):
    require_admin(
        x_admin_secret
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM licenses
        ORDER BY created_at DESC
        """
    )

    rows = cursor.fetchall()
    connection.close()

    licenses = []

    for row in rows:

        data = dict(row)

        status = license_status(
            row
        )

        expiration = parse_datetime(
            row["expires_at"]
        )

        data["status"] = status
        data["seconds_remaining"] = (
            seconds_remaining(expiration)
            if expiration
            else 0
        )

        data["activated"] = bool(
            row["activated"]
        )

        data["revoked"] = bool(
            row["revoked"]
        )

        licenses.append(
            data
        )

    return {
        "success": True,
        "count": len(licenses),
        "licenses": licenses
    }


@app.get("/api/admin/license/{license_key}")
def admin_one(
    license_key: str,
    x_admin_secret: str | None = Header(default=None)
):
    require_admin(
        x_admin_secret
    )

    key = (
        license_key
        .strip()
        .upper()
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM licenses
        WHERE license_key = ?
        """,
        (key,)
    )

    row = cursor.fetchone()
    connection.close()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="License not found."
        )

    data = dict(row)

    expiration = parse_datetime(
        row["expires_at"]
    )

    data["status"] = license_status(
        row
    )

    data["seconds_remaining"] = (
        seconds_remaining(expiration)
        if expiration
        else 0
    )

    data["activated"] = bool(
        row["activated"]
    )

    data["revoked"] = bool(
        row["revoked"]
    )

    return {
        "success": True,
        "license": data
    }


# ============================================================
# ADMIN: REVOKE / RESTORE / HWID RESET
# ============================================================

@app.post("/api/admin/revoke")
def admin_revoke(
    request: AdminLicenseRequest,
    x_admin_secret: str | None = Header(default=None)
):
    require_admin(
        x_admin_secret
    )

    key = (
        request.license_key
        .strip()
        .upper()
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE licenses
        SET revoked = 1
        WHERE license_key = ?
        """,
        (key,)
    )

    if cursor.rowcount == 0:
        connection.close()
        raise HTTPException(
            status_code=404,
            detail="License not found."
        )

    connection.commit()
    connection.close()

    return {
        "success": True,
        "message": "License revoked."
    }


@app.post("/api/admin/unrevoke")
def admin_restore(
    request: AdminLicenseRequest,
    x_admin_secret: str | None = Header(default=None)
):
    require_admin(
        x_admin_secret
    )

    key = (
        request.license_key
        .strip()
        .upper()
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE licenses
        SET revoked = 0
        WHERE license_key = ?
        """,
        (key,)
    )

    if cursor.rowcount == 0:
        connection.close()
        raise HTTPException(
            status_code=404,
            detail="License not found."
        )

    connection.commit()
    connection.close()

    return {
        "success": True,
        "message": "License restored."
    }


@app.post("/api/admin/reset-hwid")
def admin_reset_hwid(
    request: AdminLicenseRequest,
    x_admin_secret: str | None = Header(default=None)
):
    require_admin(
        x_admin_secret
    )

    key = (
        request.license_key
        .strip()
        .upper()
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE licenses
        SET
            activated = 0,
            bound_hwid = NULL,
            activated_at = NULL,
            expires_at = NULL,
            owner_username = NULL
        WHERE license_key = ?
        """,
        (key,)
    )

    if cursor.rowcount == 0:
        connection.close()
        raise HTTPException(
            status_code=404,
            detail="License not found."
        )

    connection.commit()
    connection.close()

    return {
        "success": True,
        "message": "HWID reset successfully."
    }


# ============================================================
# ADMIN: STATS
# ============================================================

@app.get("/api/admin/stats")
def admin_stats(
    x_admin_secret: str | None = Header(default=None)
):
    require_admin(
        x_admin_secret
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM licenses"
    )
    total = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM licenses
        WHERE activated = 1
        AND revoked = 0
        """
    )
    activated = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM licenses
        WHERE activated = 0
        """
    )
    unused = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM licenses
        WHERE revoked = 1
        """
    )
    revoked = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM users"
    )
    users = cursor.fetchone()[0]

    connection.close()

    return {
        "success": True,
        "total_keys": total,
        "activated_keys": activated,
        "unused_keys": unused,
        "revoked_keys": revoked,
        "users": users
    }
