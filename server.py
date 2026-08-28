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

APP_NAME = "SecureApp License Server"

ADMIN_SECRET = os.getenv(
    "ADMIN_SECRET",
    "CHANGE_THIS_ADMIN_SECRET"
)

DATABASE_PATH = Path("licenses.db")

SESSION_DAYS = 30

app = FastAPI(
    title=APP_NAME,
    version="3.0.0"
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

    # --------------------------------------------------------
    # LICENSES
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # USERS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # --------------------------------------------------------
    # SESSIONS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    """)

    # Migration for an older licenses.db
    columns = [
        row["name"]
        for row in cursor.execute(
            "PRAGMA table_info(licenses)"
        ).fetchall()
    ]

    if "owner_username" not in columns:

        cursor.execute(
            """
            ALTER TABLE licenses
            ADD COLUMN owner_username TEXT
            """
        )

    connection.commit()
    connection.close()


@app.on_event("startup")
def startup_event():

    setup_database()


# ============================================================
# TIME HELPERS
# ============================================================

def now_utc():

    return datetime.now(
        timezone.utc
    )


def datetime_to_string(value):

    return value.isoformat()


def string_to_datetime(value):

    if not value:
        return None

    return datetime.fromisoformat(
        value
    )


def get_time_remaining(expires_at):

    if not expires_at:
        return 0

    remaining = int(
        (
            expires_at -
            now_utc()
        ).total_seconds()
    )

    return max(
        0,
        remaining
    )


# ============================================================
# PASSWORD HASHING
# ============================================================

def hash_password(password, salt=None):

    if salt is None:

        salt_bytes = secrets.token_bytes(16)
        salt = salt_bytes.hex()

    else:

        salt_bytes = bytes.fromhex(
            salt
        )

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_bytes,
        200_000
    )

    return (
        password_hash.hex(),
        salt
    )


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
# SESSION HANDLING
# ============================================================

def create_session(username):

    raw_token = secrets.token_urlsafe(
        48
    )

    token_hash = hashlib.sha256(
        raw_token.encode("utf-8")
    ).hexdigest()

    created_at = now_utc()

    expires_at = (
        created_at +
        timedelta(days=SESSION_DAYS)
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
            datetime_to_string(
                created_at
            ),
            datetime_to_string(
                expires_at
            )
        )
    )

    connection.commit()
    connection.close()

    return raw_token


def get_username_from_token(token):

    if not token:
        return None

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM sessions
        WHERE token_hash = ?
        """,
        (token_hash,)
    )

    session = cursor.fetchone()

    if not session:

        connection.close()
        return None

    expires_at = string_to_datetime(
        session["expires_at"]
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

    return session["username"]


def get_user_from_token(token):

    username = get_username_from_token(
        token
    )

    if not username:
        return None

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

    return user


def remove_session(token):

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


def require_user(
    authorization: str = Header(default=None)
):

    if not authorization:

        raise HTTPException(
            status_code=401,
            detail="Login required."
        )

    if authorization.startswith(
        "Bearer "
    ):

        token = authorization[
            7:
        ].strip()

    else:

        token = authorization.strip()

    username = get_username_from_token(
        token
    )

    if not username:

        raise HTTPException(
            status_code=401,
            detail="Session expired. Please login again."
        )

    return username


# ============================================================
# ADMIN AUTH
# ============================================================

def check_admin_secret(
    x_admin_secret
):

    if not x_admin_secret:

        raise HTTPException(
            status_code=401,
            detail="Missing admin authorization."
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
# KEY GENERATION
# ============================================================

def generate_license_key():

    characters = (
        string.ascii_uppercase +
        string.digits
    )

    characters = characters.replace(
        "O",
        ""
    )

    characters = characters.replace(
        "I",
        ""
    )

    characters = characters.replace(
        "0",
        ""
    )

    characters = characters.replace(
        "1",
        ""
    )

    groups = []

    for _ in range(4):

        groups.append(
            "".join(
                secrets.choice(
                    characters
                )
                for _ in range(5)
            )
        )

    return "-".join(groups)


def add_months(
    start_date,
    months
):

    month = (
        start_date.month -
        1 +
        months
    )

    year = (
        start_date.year +
        month // 12
    )

    month = (
        month % 12 +
        1
    )

    day = min(
        start_date.day,
        calendar.monthrange(
            year,
            month
        )[1]
    )

    return start_date.replace(
        year=year,
        month=month,
        day=day
    )


def calculate_expiration(
    duration_type,
    duration_amount
):

    current_time = now_utc()

    duration_type = (
        duration_type
        .strip()
        .lower()
    )

    if duration_type == "minutes":

        return (
            current_time +
            timedelta(
                minutes=duration_amount
            )
        )

    if duration_type == "hours":

        return (
            current_time +
            timedelta(
                hours=duration_amount
            )
        )

    if duration_type == "days":

        return (
            current_time +
            timedelta(
                days=duration_amount
            )
        )

    if duration_type == "months":

        return add_months(
            current_time,
            duration_amount
        )

    raise ValueError(
        "Invalid duration type."
    )


# ============================================================
# REQUEST MODELS
# ============================================================

class RegisterRequest(BaseModel):

    username: str
    password: str


class LoginRequest(BaseModel):

    username: str
    password: str


class GenerateKeyRequest(BaseModel):

    duration_type: str
    duration_amount: int


class ActivateKeyRequest(BaseModel):

    license_key: str
    hwid: str


class ValidateKeyRequest(BaseModel):

    license_key: str
    hwid: str


class RevokeKeyRequest(BaseModel):

    license_key: str


class ResetHWIDRequest(BaseModel):

    license_key: str


class UnrevokeKeyRequest(BaseModel):

    license_key: str


# ============================================================
# SERVER TEST
# ============================================================

@app.get("/")
def root():

    return {
        "success": True,
        "message": (
            "SecureApp license server is online."
        ),
        "version": "3.0.0",
        "server_time":
            datetime_to_string(
                now_utc()
            )
    }


@app.get("/health")
def health():

    return {
        "success": True,
        "status": "online"
    }


# ============================================================
# REGISTER
# ============================================================

@app.post("/api/auth/register")
def register(
    request: RegisterRequest
):

    username = request.username.strip()

    password = request.password

    if len(username) < 3:

        raise HTTPException(
            status_code=400,
            detail=(
                "Username must be at least 3 characters."
            )
        )

    if len(username) > 32:

        raise HTTPException(
            status_code=400,
            detail=(
                "Username must be 32 characters or less."
            )
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
            detail=(
                "Password must be at least 6 characters."
            )
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
            datetime_to_string(
                now_utc()
            )
        )
    )

    connection.commit()
    connection.close()

    token = create_session(
        username
    )

    return {
        "success": True,
        "message": "Account created successfully.",
        "username": username,
        "token": token
    }


# ============================================================
# LOGIN
# ============================================================

@app.post("/api/auth/login")
def login(
    request: LoginRequest
):

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

    valid = verify_password(
        request.password,
        user["password_hash"],
        user["salt"]
    )

    if not valid:

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password."
        )

    token = create_session(
        username
    )

    return {
        "success": True,
        "message": "Login successful.",
        "username": username,
        "token": token
    }


# ============================================================
# LOGOUT
# ============================================================

@app.post("/api/auth/logout")
def logout(
    authorization: str = Header(default=None)
):

    if authorization:

        if authorization.startswith(
            "Bearer "
        ):
            token = authorization[7:].strip()

        else:
            token = authorization.strip()

        remove_session(token)

    return {
        "success": True,
        "message": "Logged out."
    }


# ============================================================
# CURRENT ACCOUNT
# ============================================================

@app.get("/api/auth/me")
def current_account(
    authorization: str = Header(default=None)
):

    username = require_user(
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

    license_data = cursor.fetchone()

    connection.close()

    result = {
        "username": user["username"],
        "created_at": user["created_at"],
        "license": None
    }

    if license_data:

        expires_at = string_to_datetime(
            license_data["expires_at"]
        )

        result["license"] = {
            "license_key":
                license_data["license_key"],
            "status":
                "revoked"
                if license_data["revoked"]
                else (
                    "expired"
                    if expires_at
                    and now_utc() >= expires_at
                    else "active"
                ),
            "expires_at":
                license_data["expires_at"],
            "seconds_remaining":
                get_time_remaining(
                    expires_at
                )
        }

    return {
        "success": True,
        "account": result
    }


# ============================================================
# ADMIN: GENERATE
# ============================================================

@app.post("/api/admin/generate")
def admin_generate(
    request: GenerateKeyRequest,
    x_admin_secret: str = Header(default=None)
):

    check_admin_secret(
        x_admin_secret
    )

    duration_type = (
        request.duration_type
        .strip()
        .lower()
    )

    if duration_type not in [
        "minutes",
        "hours",
        "days",
        "months"
    ]:

        raise HTTPException(
            status_code=400,
            detail=(
                "Duration type must be Minutes, "
                "Hours, Days, or Months."
            )
        )

    if request.duration_amount < 1:

        raise HTTPException(
            status_code=400,
            detail="Duration amount must be at least 1."
        )

    connection = get_connection()
    cursor = connection.cursor()

    while True:

        license_key = generate_license_key()

        cursor.execute(
            """
            SELECT license_key
            FROM licenses
            WHERE license_key = ?
            """,
            (license_key,)
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
            license_key,
            duration_type,
            request.duration_amount,
            datetime_to_string(
                now_utc()
            )
        )
    )

    connection.commit()
    connection.close()

    return {
        "success": True,
        "license_key": license_key,
        "duration_type": duration_type,
        "duration_amount":
            request.duration_amount,
        "activated": False
    }


# ============================================================
# USER: ACTIVATE LICENSE
# ============================================================

@app.post("/api/license/activate")
def activate_license(
    request: ActivateKeyRequest,
    authorization: str = Header(default=None)
):

    username = require_user(
        authorization
    )

    license_key = (
        request.license_key
        .strip()
        .upper()
    )

    hwid = request.hwid.strip()

    if not license_key:

        raise HTTPException(
            status_code=400,
            detail="License key is required."
        )

    if not hwid:

        raise HTTPException(
            status_code=400,
            detail="HWID is required."
        )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM licenses
        WHERE license_key = ?
        """,
        (license_key,)
    )

    license_data = cursor.fetchone()

    if not license_data:

        connection.close()

        raise HTTPException(
            status_code=404,
            detail="Invalid license key."
        )

    if license_data["revoked"]:

        connection.close()

        raise HTTPException(
            status_code=403,
            detail="This license has been revoked."
        )

    # --------------------------------------------------------
    # FIRST ACTIVATION
    # --------------------------------------------------------

    if not license_data["activated"]:

        try:

            expires_at = calculate_expiration(
                license_data["duration_type"],
                license_data["duration_amount"]
            )

        except ValueError:

            connection.close()

            raise HTTPException(
                status_code=500,
                detail="Invalid license duration."
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
                datetime_to_string(
                    activated_at
                ),
                datetime_to_string(
                    expires_at
                ),
                username,
                license_key
            )
        )

        connection.commit()
        connection.close()

        return {
            "success": True,
            "message": (
                "License activated successfully."
            ),
            "username": username,
            "first_activation": True,
            "expires_at":
                datetime_to_string(
                    expires_at
                ),
            "seconds_remaining":
                get_time_remaining(
                    expires_at
                )
        }

    # --------------------------------------------------------
    # ALREADY ACTIVATED
    # --------------------------------------------------------

    if license_data["bound_hwid"] != hwid:

        connection.close()

        raise HTTPException(
            status_code=403,
            detail=(
                "HWID mismatch. This license is "
                "already activated on another device."
            )
        )

    if (
        license_data["owner_username"]
        and
        license_data["owner_username"] != username
    ):

        connection.close()

        raise HTTPException(
            status_code=403,
            detail=(
                "This license belongs to another account."
            )
        )

    expires_at = string_to_datetime(
        license_data["expires_at"]
    )

    if not expires_at or now_utc() >= expires_at:

        connection.close()

        raise HTTPException(
            status_code=403,
            detail="This license has expired."
        )

    connection.close()

    return {
        "success": True,
        "message": "License is valid.",
        "username": username,
        "first_activation": False,
        "expires_at":
            datetime_to_string(
                expires_at
            ),
        "seconds_remaining":
            get_time_remaining(
                expires_at
            )
    }


# ============================================================
# USER: VALIDATE LICENSE
# ============================================================

@app.post("/api/license/validate")
def validate_license(
    request: ValidateKeyRequest,
    authorization: str = Header(default=None)
):

    username = require_user(
        authorization
    )

    license_key = (
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
        (license_key,)
    )

    license_data = cursor.fetchone()

    connection.close()

    if not license_data:

        raise HTTPException(
            status_code=404,
            detail="Invalid license key."
        )

    if license_data["revoked"]:

        raise HTTPException(
            status_code=403,
            detail="This license has been revoked."
        )

    if not license_data["activated"]:

        raise HTTPException(
            status_code=403,
            detail="This license has not been activated."
        )

    if license_data["bound_hwid"] != hwid:

        raise HTTPException(
            status_code=403,
            detail="HWID mismatch."
        )

    owner = license_data[
        "owner_username"
    ]

    if owner and owner != username:

        raise HTTPException(
            status_code=403,
            detail="This license belongs to another account."
        )

    expires_at = string_to_datetime(
        license_data["expires_at"]
    )

    if not expires_at or now_utc() >= expires_at:

        raise HTTPException(
            status_code=403,
            detail="This license has expired."
        )

    return {
        "success": True,
        "valid": True,
        "username": username,
        "expires_at":
            datetime_to_string(
                expires_at
            ),
        "seconds_remaining":
            get_time_remaining(
                expires_at
            )
    }


# ============================================================
# ADMIN: ALL LICENSES
# ============================================================

@app.get("/api/admin/licenses")
def admin_all_licenses(
    x_admin_secret: str = Header(default=None)
):

    check_admin_secret(
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

    results = []

    for row in rows:

        data = dict(row)

        expires_at = string_to_datetime(
            data.get("expires_at")
        )

        if data["revoked"]:

            status = "revoked"

        elif not data["activated"]:

            status = "not_activated"

        elif (
            expires_at
            and
            now_utc() >= expires_at
        ):

            status = "expired"

        else:

            status = "active"

        data["status"] = status

        data["seconds_remaining"] = (
            get_time_remaining(
                expires_at
            )
            if expires_at
            else 0
        )

        data["activated"] = bool(
            data["activated"]
        )

        data["revoked"] = bool(
            data["revoked"]
        )

        results.append(
            data
        )

    return {
        "success": True,
        "count": len(results),
        "licenses": results
    }


# ============================================================
# ADMIN: ONE LICENSE
# ============================================================

@app.get("/api/admin/license/{license_key}")
def admin_one_license(
    license_key: str,
    x_admin_secret: str = Header(default=None)
):

    check_admin_secret(
        x_admin_secret
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM licenses
        WHERE license_key = ?
        """,
        (
            license_key
            .strip()
            .upper(),
        )
    )

    row = cursor.fetchone()

    connection.close()

    if not row:

        raise HTTPException(
            status_code=404,
            detail="License key not found."
        )

    data = dict(row)

    expires_at = string_to_datetime(
        data.get("expires_at")
    )

    if data["revoked"]:

        status = "revoked"

    elif not data["activated"]:

        status = "not_activated"

    elif (
        expires_at
        and
        now_utc() >= expires_at
    ):

        status = "expired"

    else:

        status = "active"

    data["status"] = status

    data["seconds_remaining"] = (
        get_time_remaining(
            expires_at
        )
        if expires_at
        else 0
    )

    data["activated"] = bool(
        data["activated"]
    )

    data["revoked"] = bool(
        data["revoked"]
    )

    return {
        "success": True,
        "license": data
    }


# ============================================================
# ADMIN: REVOKE
# ============================================================

@app.post("/api/admin/revoke")
def admin_revoke(
    request: RevokeKeyRequest,
    x_admin_secret: str = Header(default=None)
):

    check_admin_secret(
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
            detail="License key not found."
        )

    connection.commit()
    connection.close()

    return {
        "success": True,
        "message": "License revoked."
    }


# ============================================================
# ADMIN: RESTORE
# ============================================================

@app.post("/api/admin/unrevoke")
def admin_unrevoke(
    request: UnrevokeKeyRequest,
    x_admin_secret: str = Header(default=None)
):

    check_admin_secret(
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
            detail="License key not found."
        )

    connection.commit()
    connection.close()

    return {
        "success": True,
        "message": "License restored."
    }


# ============================================================
# ADMIN: RESET HWID
# ============================================================

@app.post("/api/admin/reset-hwid")
def admin_reset_hwid(
    request: ResetHWIDRequest,
    x_admin_secret: str = Header(default=None)
):

    check_admin_secret(
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
        SELECT *
        FROM licenses
        WHERE license_key = ?
        """,
        (key,)
    )

    license_data = cursor.fetchone()

    if not license_data:

        connection.close()

        raise HTTPException(
            status_code=404,
            detail="License key not found."
        )

    cursor.execute(
        """
        UPDATE licenses
        SET
            bound_hwid = NULL,
            owner_username = NULL,
            activated = 0,
            activated_at = NULL,
            expires_at = NULL
        WHERE license_key = ?
        """,
        (key,)
    )

    connection.commit()
    connection.close()

    return {
        "success": True,
        "message": (
            "HWID reset. The license is ready "
            "for a new activation."
        )
    }


# ============================================================
# ADMIN: STATS
# ============================================================

@app.get("/api/admin/stats")
def admin_stats(
    x_admin_secret: str = Header(default=None)
):

    check_admin_secret(
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
