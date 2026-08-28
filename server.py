
import os
import sqlite3
import secrets
import string
import calendar
import hashlib
import hmac

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
    version="5.0.0"
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


def ensure_column(
    cursor,
    table,
    column,
    definition
):
    columns = {
        row["name"]
        for row in cursor.execute(
            f"PRAGMA table_info({table})"
        ).fetchall()
    }

    if column not in columns:

        cursor.execute(
            f"""
            ALTER TABLE {table}
            ADD COLUMN {column} {definition}
            """
        )


def setup_database():

    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_login_at TEXT,
            last_seen_at TEXT
        )
        """
    )


    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            last_seen_at TEXT
        )
        """
    )


    cursor.execute(
        """
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
        """
    )


    # Migrate older database files safely.

    ensure_column(cursor, "users", "last_login_at", "TEXT")
    ensure_column(cursor, "users", "last_seen_at", "TEXT")
    ensure_column(cursor, "sessions", "last_seen_at", "TEXT")

    ensure_column(
        cursor,
        "licenses",
        "owner_username",
        "TEXT"
    )

    ensure_column(
        cursor,
        "licenses",
        "activated_at",
        "TEXT"
    )

    ensure_column(
        cursor,
        "licenses",
        "expires_at",
        "TEXT"
    )

    ensure_column(
        cursor,
        "licenses",
        "bound_hwid",
        "TEXT"
    )

    ensure_column(
        cursor,
        "licenses",
        "revoked",
        "INTEGER NOT NULL DEFAULT 0"
    )


    connection.commit()

    connection.close()


@app.on_event("startup")
def startup():

    setup_database()


# ============================================================
# TIME
# ============================================================

def now_utc():

    return datetime.now(
        timezone.utc
    )


def iso(value):

    return value.isoformat()


def parse_datetime(value):

    if not value:
        return None

    try:
        return datetime.fromisoformat(value)

    except Exception:
        return None


def remaining_seconds(value):

    if not value:
        return 0

    expires = parse_datetime(
        value
    )

    if not expires:
        return 0

    return max(
        0,
        int(
            (
                expires
                - now_utc()
            ).total_seconds()
        )
    )


# ============================================================
# PASSWORDS
# ============================================================

def hash_password(
    password,
    salt=None
):

    if salt is None:

        salt = secrets.token_bytes(
            16
        ).hex()


    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        200_000
    )


    return digest.hex(), salt


def verify_password(
    password,
    stored_hash,
    salt
):

    calculated, _ = hash_password(
        password,
        salt
    )

    return hmac.compare_digest(
        calculated,
        stored_hash
    )


# ============================================================
# SESSIONS
# ============================================================

def create_session(username):

    token = secrets.token_urlsafe(
        48
    )

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    created = now_utc()

    expires = (
        created
        + timedelta(
            days=SESSION_DAYS
        )
    )


    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute(
        """
        INSERT INTO sessions (
            token_hash,
            username,
            created_at,
            expires_at,
            last_seen_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            token_hash,
            username,
            iso(created),
            iso(expires),
            iso(created)
        )
    )


    connection.commit()

    connection.close()


    return token


def get_session_user(token, touch=True):

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

    connection.close()


    if not row:
        return None


    expires = parse_datetime(
        row["expires_at"]
    )


    if not expires or now_utc() >= expires:

        connection = get_connection()

        connection.execute(
            """
            DELETE FROM sessions
            WHERE token_hash = ?
            """,
            (token_hash,)
        )

        connection.commit()
        connection.close()

        return None


    return row["username"]


def delete_session(token):

    if not token:
        return


    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


    connection = get_connection()

    connection.execute(
        """
        DELETE FROM sessions
        WHERE token_hash = ?
        """,
        (token_hash,)
    )

    connection.commit()

    connection.close()


def require_user(
    authorization
):

    if not authorization:

        raise HTTPException(
            status_code=401,
            detail="Login required."
        )


    token = authorization

    if token.startswith("Bearer "):
        token = token[7:].strip()


    username = get_session_user(
        token
    )


    if not username:

        raise HTTPException(
            status_code=401,
            detail="Session expired. Please sign in again."
        )


    return username


# ============================================================
# ADMIN
# ============================================================

def require_admin(
    x_admin_secret
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

def generate_key():

    alphabet = (
        string.ascii_uppercase
        + string.digits
    )

    for bad in "O01I":
        alphabet = alphabet.replace(
            bad,
            ""
        )


    parts = []


    for _ in range(4):

        parts.append(
            "".join(
                secrets.choice(
                    alphabet
                )
                for _ in range(5)
            )
        )


    return "-".join(parts)


def add_months(
    start,
    count
):

    month_index = (
        start.month
        - 1
        + count
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


def expiration_from_duration(
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
        "Invalid duration."
    )


def status_for_row(row):

    if row["revoked"]:
        return "revoked"


    if not row["activated"]:
        return "not_activated"


    expires = parse_datetime(
        row["expires_at"]
    )


    if not expires:
        return "expired"


    if now_utc() >= expires:
        return "expired"


    return "active"


def license_dict(row):

    status = status_for_row(
        row
    )

    return {
        "license_key":
            row["license_key"],

        "duration_type":
            row["duration_type"],

        "duration_amount":
            row["duration_amount"],

        "activated":
            bool(row["activated"]),

        "bound_hwid":
            row["bound_hwid"],

        "activated_at":
            row["activated_at"],

        "expires_at":
            row["expires_at"],

        "created_at":
            row["created_at"],

        "revoked":
            bool(row["revoked"]),

        "owner_username":
            row["owner_username"],

        "status":
            status,

        "seconds_remaining":
            remaining_seconds(
                row["expires_at"]
            )
    }


# ============================================================
# MODELS
# ============================================================

class AuthRequest(BaseModel):
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
        "message":
            "Resource Hub license server is online.",
        "version":
            "5.0.0",
        "server_time":
            iso(now_utc())
    }


@app.get("/health")
def health():

    # Actually touch the database so the admin/client
    # can distinguish an online API from an unavailable DB.

    connection = get_connection()

    connection.execute(
        "SELECT 1"
    ).fetchone()

    connection.close()


    return {
        "success": True,
        "status": "online",
        "database": "ready",
        "server_time":
            iso(now_utc())
    }


# ============================================================
# AUTH
# ============================================================

@app.post("/api/auth/register")
def register(
    request: AuthRequest
):

    username = request.username.strip()

    password = request.password


    if len(username) < 3 or len(username) > 32:

        raise HTTPException(
            status_code=400,
            detail="Username must be 3-32 characters."
        )


    if not username.replace(
        "_",
        ""
    ).isalnum():

        raise HTTPException(
            status_code=400,
            detail=(
                "Username may only contain "
                "letters, numbers, and underscores."
            )
        )


    if len(password) < 6:

        raise HTTPException(
            status_code=400,
            detail="Password must be at least 6 characters."
        )


    password_hash, salt = (
        hash_password(password)
    )


    connection = get_connection()


    try:

        connection.execute(
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

    except sqlite3.IntegrityError:

        connection.close()

        raise HTTPException(
            status_code=409,
            detail="Username already exists."
        )


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
def login(
    request: AuthRequest
):

    username = request.username.strip()


    connection = get_connection()


    row = connection.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()


    connection.close()


    if not row:

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password."
        )


    if not verify_password(
        request.password,
        row["password_hash"],
        row["salt"]
    ):

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password."
        )


    seen = iso(now_utc())
    connection = get_connection()
    connection.execute(
        "UPDATE users SET last_login_at = ?, last_seen_at = ? WHERE username = ?",
        (seen, seen, username)
    )
    connection.commit()
    connection.close()

    return {
        "success": True,
        "username": username,
        "token":
            create_session(username)
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


@app.post("/api/auth/heartbeat")
def heartbeat(
    authorization: str | None = Header(default=None)
):
    username = require_user(authorization)
    return {"success": True, "username": username, "server_time": iso(now_utc())}


@app.get("/api/auth/me")
def me(
    authorization: str | None = Header(default=None)
):

    username = require_user(
        authorization
    )


    connection = get_connection()


    user = connection.execute(
        """
        SELECT username, created_at
        FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()


    license_row = connection.execute(
        """
        SELECT *
        FROM licenses
        WHERE owner_username = ?
        ORDER BY activated_at DESC, created_at DESC
        LIMIT 1
        """,
        (username,)
    ).fetchone()


    connection.close()


    account = {
        "username":
            user["username"] if user else username,

        "created_at":
            user["created_at"] if user else None,

        "license":
            license_dict(license_row)
            if license_row else None
    }


    return {
        "success": True,
        "account": account
    }


# ============================================================
# USER LICENSES
# ============================================================

@app.post("/api/license/activate")
def activate_license(
    request: LicenseRequest,
    authorization: str | None = Header(default=None)
):

    username = require_user(
        authorization
    )


    key = request.license_key.strip().upper()
    hwid = request.hwid.strip()


    if not key or not hwid:

        raise HTTPException(
            status_code=400,
            detail="License key and HWID are required."
        )


    connection = get_connection()


    row = connection.execute(
        """
        SELECT *
        FROM licenses
        WHERE license_key = ?
        """,
        (key,)
    ).fetchone()


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


    # First activation binds account + device.

    if not row["activated"]:

        expires = expiration_from_duration(
            row["duration_type"],
            row["duration_amount"]
        )


        activated_at = now_utc()


        connection.execute(
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
                iso(expires),
                username,
                key
            )
        )


        connection.commit()
        connection.close()


        return {
            "success": True,
            "message":
                "License activated successfully.",
            "seconds_remaining":
                remaining_seconds(
                    iso(expires)
                ),
            "expires_at":
                iso(expires)
        }


    # Existing license.

    if row["bound_hwid"] != hwid:

        connection.close()

        raise HTTPException(
            status_code=403,
            detail=(
                "HWID mismatch. "
                "This license is bound to another device."
            )
        )


    if (
        row["owner_username"]
        and
        row["owner_username"] != username
    ):

        connection.close()

        raise HTTPException(
            status_code=403,
            detail=(
                "This license belongs to another account."
            )
        )


    expires = parse_datetime(
        row["expires_at"]
    )


    if not expires or now_utc() >= expires:

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
            remaining_seconds(
                row["expires_at"]
            ),
        "expires_at":
            row["expires_at"]
    }


@app.post("/api/license/validate")
def validate_license(
    request: LicenseRequest,
    authorization: str | None = Header(default=None)
):

    username = require_user(
        authorization
    )


    key = request.license_key.strip().upper()
    hwid = request.hwid.strip()


    connection = get_connection()


    row = connection.execute(
        """
        SELECT *
        FROM licenses
        WHERE license_key = ?
        """,
        (key,)
    ).fetchone()


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
            detail="This license is not activated."
        )


    if row["bound_hwid"] != hwid:

        raise HTTPException(
            status_code=403,
            detail="HWID mismatch."
        )


    if (
        row["owner_username"]
        and
        row["owner_username"] != username
    ):

        raise HTTPException(
            status_code=403,
            detail="This license belongs to another account."
        )


    remaining = remaining_seconds(
        row["expires_at"]
    )


    if remaining <= 0:

        raise HTTPException(
            status_code=403,
            detail="This license has expired."
        )


    return {
        "success": True,
        "valid": True,
        "seconds_remaining":
            remaining,
        "expires_at":
            row["expires_at"]
    }


# ============================================================
# ADMIN GENERATE
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


    while True:

        key = generate_key()


        exists = connection.execute(
            """
            SELECT license_key
            FROM licenses
            WHERE license_key = ?
            """,
            (key,)
        ).fetchone()


        if not exists:
            break


    connection.execute(
        """
        INSERT INTO licenses (
            license_key,
            duration_type,
            duration_amount,
            activated,
            created_at,
            revoked
        )
        VALUES (?, ?, ?, 0, ?, 0)
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
        "duration_amount":
            request.duration_amount,
        "activated": False
    }


# ============================================================
# ADMIN LICENSE LIST
# ============================================================

@app.get("/api/admin/licenses")
def admin_licenses(
    x_admin_secret: str | None = Header(default=None)
):

    require_admin(
        x_admin_secret
    )


    connection = get_connection()


    rows = connection.execute(
        """
        SELECT *
        FROM licenses
        ORDER BY created_at DESC
        """
    ).fetchall()


    connection.close()


    licenses = [
        license_dict(row)
        for row in rows
    ]


    return {
        "success": True,
        "count": len(licenses),
        "licenses": licenses
    }


# ============================================================
# ADMIN USERS
# ============================================================

@app.get("/api/admin/users")
def admin_users(
    x_admin_secret: str | None = Header(default=None)
):

    require_admin(
        x_admin_secret
    )


    connection = get_connection()


    users = connection.execute(
        """
        SELECT
            id,
            username,
            created_at,
            last_login_at,
            last_seen_at
        FROM users
        ORDER BY created_at DESC
        """
    ).fetchall()


    result = []


    for user in users:

        licenses = connection.execute(
            """
            SELECT *
            FROM licenses
            WHERE owner_username = ?
            ORDER BY activated_at DESC, created_at DESC
            """,
            (user["username"],)
        ).fetchall()


        result.append(
            {
                "id":
                    user["id"],

                "username":
                    user["username"],

                "created_at":
                    user["created_at"],
                "last_login_at":
                    user["last_login_at"],
                "last_seen_at":
                    user["last_seen_at"],
                "online": bool(
                    user["last_seen_at"]
                    and
                    (now_utc() - parse_datetime(user["last_seen_at"])).total_seconds() <= 90
                ),

                "license_count":
                    len(licenses),

                "licenses":
                    [
                        license_dict(row)
                        for row in licenses
                    ]
            }
        )


    connection.close()


    return {
        "success": True,
        "count": len(result),
        "users": result
    }


# ============================================================
# ADMIN LICENSE DETAILS
# ============================================================

@app.get("/api/admin/license/{license_key}")
def admin_license(
    license_key: str,
    x_admin_secret: str | None = Header(default=None)
):

    require_admin(
        x_admin_secret
    )


    key = license_key.strip().upper()


    connection = get_connection()


    row = connection.execute(
        """
        SELECT *
        FROM licenses
        WHERE license_key = ?
        """,
        (key,)
    ).fetchone()


    connection.close()


    if not row:

        raise HTTPException(
            status_code=404,
            detail="License not found."
        )


    return {
        "success": True,
        "license":
            license_dict(row)
    }


# ============================================================
# ADMIN ACTIONS
# ============================================================

@app.post("/api/admin/revoke")
def admin_revoke(
    request: AdminLicenseRequest,
    x_admin_secret: str | None = Header(default=None)
):

    require_admin(
        x_admin_secret
    )


    key = request.license_key.strip().upper()


    connection = get_connection()


    cursor = connection.execute(
        """
        UPDATE licenses
        SET revoked = 1
        WHERE license_key = ?
        """,
        (key,)
    )


    connection.commit()


    if cursor.rowcount == 0:

        connection.close()

        raise HTTPException(
            status_code=404,
            detail="License not found."
        )


    connection.close()


    return {
        "success": True,
        "message":
            "License revoked."
    }


@app.post("/api/admin/unrevoke")
def admin_restore(
    request: AdminLicenseRequest,
    x_admin_secret: str | None = Header(default=None)
):

    require_admin(
        x_admin_secret
    )


    key = request.license_key.strip().upper()


    connection = get_connection()


    cursor = connection.execute(
        """
        UPDATE licenses
        SET revoked = 0
        WHERE license_key = ?
        """,
        (key,)
    )


    connection.commit()


    if cursor.rowcount == 0:

        connection.close()

        raise HTTPException(
            status_code=404,
            detail="License not found."
        )


    connection.close()


    return {
        "success": True,
        "message":
            "License restored."
    }


@app.post("/api/admin/reset-hwid")
def admin_reset_hwid(
    request: AdminLicenseRequest,
    x_admin_secret: str | None = Header(default=None)
):

    require_admin(
        x_admin_secret
    )


    key = request.license_key.strip().upper()


    connection = get_connection()


    cursor = connection.execute(
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


    connection.commit()


    if cursor.rowcount == 0:

        connection.close()

        raise HTTPException(
            status_code=404,
            detail="License not found."
        )


    connection.close()


    return {
        "success": True,
        "message":
            "HWID reset successfully."
    }


@app.get("/api/admin/activity")
def admin_activity(
    x_admin_secret: str | None = Header(default=None)
):
    require_admin(x_admin_secret)
    connection = get_connection()
    rows = connection.execute(
        """SELECT username, last_login_at, last_seen_at FROM users ORDER BY COALESCE(last_seen_at, last_login_at, created_at) DESC LIMIT 50"""
    ).fetchall()
    connection.close()
    result = []
    for row in rows:
        seen = parse_datetime(row["last_seen_at"]) if row["last_seen_at"] else None
        online = bool(seen and (now_utc() - seen).total_seconds() <= 90)
        result.append({
            "username": row["username"],
            "last_login_at": row["last_login_at"],
            "last_seen_at": row["last_seen_at"],
            "online": online
        })
    return {"success": True, "users": result}


# ============================================================
# ADMIN STATS
# ============================================================

@app.get("/api/admin/stats")
def admin_stats(
    x_admin_secret: str | None = Header(default=None)
):

    require_admin(
        x_admin_secret
    )


    connection = get_connection()


    total = connection.execute(
        "SELECT COUNT(*) FROM licenses"
    ).fetchone()[0]


    active = 0
    unused = 0
    revoked = 0
    expired = 0


    rows = connection.execute(
        "SELECT * FROM licenses"
    ).fetchall()


    for row in rows:

        status = status_for_row(
            row
        )


        if status == "active":
            active += 1

        elif status == "not_activated":
            unused += 1

        elif status == "revoked":
            revoked += 1

        elif status == "expired":
            expired += 1


    users = connection.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]


    connection.close()


    return {
        "success": True,
        "total_keys": total,
        "activated_keys": active,
        "unused_keys": unused,
        "revoked_keys": revoked,
        "expired_keys": expired,
        "users": users
    }
