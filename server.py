import os
import sqlite3
import secrets
import string
import calendar

from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel


# ============================================================
# CONFIG
# ============================================================

APP_NAME = "SecureApp License Server"

# Change this on Render using an environment variable called ADMIN_SECRET.
# Do NOT leave the default value for a real deployment.
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "CHANGE_THIS_ADMIN_SECRET")

DATABASE_PATH = Path("licenses.db")

app = FastAPI(
    title=APP_NAME,
    version="1.0.0"
)


# ============================================================
# DATABASE
# ============================================================

def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def setup_database():

    connection = get_connection()
    cursor = connection.cursor()

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
            revoked INTEGER NOT NULL DEFAULT 0
        )
    """)

    connection.commit()
    connection.close()


@app.on_event("startup")
def startup_event():
    setup_database()


# ============================================================
# HELPERS
# ============================================================

def now_utc():
    return datetime.now(timezone.utc)


def datetime_to_string(value):
    return value.isoformat()


def string_to_datetime(value):
    return datetime.fromisoformat(value)


def generate_license_key():

    characters = (
        string.ascii_uppercase +
        string.digits
    )

    characters = characters.replace("O", "")
    characters = characters.replace("I", "")
    characters = characters.replace("0", "")
    characters = characters.replace("1", "")

    groups = []

    for _ in range(4):

        group = "".join(
            secrets.choice(characters)
            for _ in range(5)
        )

        groups.append(group)

    return "-".join(groups)


def add_months(start_date, months):

    month = start_date.month - 1 + months
    year = start_date.year + month // 12
    month = month % 12 + 1

    day = min(
        start_date.day,
        calendar.monthrange(year, month)[1]
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

    duration_type = duration_type.lower()

    if duration_type == "minutes":
        return current_time + timedelta(
            minutes=duration_amount
        )

    if duration_type == "hours":
        return current_time + timedelta(
            hours=duration_amount
        )

    if duration_type == "days":
        return current_time + timedelta(
            days=duration_amount
        )

    if duration_type == "months":
        return add_months(
            current_time,
            duration_amount
        )

    raise ValueError(
        "Invalid duration type."
    )


def get_time_remaining(expires_at):

    remaining = int(
        (expires_at - now_utc()).total_seconds()
    )

    return max(0, remaining)


def check_admin_secret(x_admin_secret):

    if not x_admin_secret:
        raise HTTPException(
            status_code=401,
            detail="Missing admin authorization."
        )

    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(
            status_code=403,
            detail="Invalid admin authorization."
        )


# ============================================================
# REQUEST MODELS
# ============================================================

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


# ============================================================
# ROOT / SERVER TEST
# ============================================================

@app.get("/")
def root():

    return {
        "success": True,
        "message": "SecureApp license server is online.",
        "server_time": datetime_to_string(now_utc())
    }


@app.get("/health")
def health():

    return {
        "success": True,
        "status": "online"
    }


# ============================================================
# ADMIN: GENERATE KEY
# ============================================================

@app.post("/api/admin/generate")
def generate_key(
    request: GenerateKeyRequest,
    x_admin_secret: str = Header(default=None)
):

    check_admin_secret(x_admin_secret)

    duration_type = (
        request.duration_type
        .strip()
        .lower()
    )

    allowed_types = [
        "minutes",
        "hours",
        "days",
        "months"
    ]

    if duration_type not in allowed_types:
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
            detail=(
                "Duration amount must be at least 1."
            )
        )

    connection = get_connection()
    cursor = connection.cursor()

    license_key = generate_license_key()

    # Make absolutely sure the key is unique
    while True:

        cursor.execute(
            """
            SELECT license_key
            FROM licenses
            WHERE license_key = ?
            """,
            (license_key,)
        )

        existing = cursor.fetchone()

        if not existing:
            break

        license_key = generate_license_key()

    created_at = datetime_to_string(
        now_utc()
    )

    cursor.execute(
        """
        INSERT INTO licenses (
            license_key,
            duration_type,
            duration_amount,
            activated,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            license_key,
            duration_type,
            request.duration_amount,
            0,
            created_at
        )
    )

    connection.commit()
    connection.close()

    return {
        "success": True,
        "license_key": license_key,
        "duration_type": duration_type,
        "duration_amount": request.duration_amount,
        "activated": False
    }


# ============================================================
# USER: ACTIVATE KEY
#
# First activation:
# - Saves that computer's HWID
# - Starts the expiration timer
#
# Later activations:
# - HWID must match
# ============================================================

@app.post("/api/license/activate")
def activate_license(
    request: ActivateKeyRequest
):

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

    # ========================================================
    # FIRST ACTIVATION
    # ========================================================

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
                expires_at = ?
            WHERE license_key = ?
            """,
            (
                hwid,
                datetime_to_string(activated_at),
                datetime_to_string(expires_at),
                license_key
            )
        )

        connection.commit()
        connection.close()

        return {
            "success": True,
            "message": "License activated successfully.",
            "first_activation": True,
            "expires_at": datetime_to_string(
                expires_at
            ),
            "seconds_remaining": get_time_remaining(
                expires_at
            )
        }

    # ========================================================
    # ALREADY ACTIVATED: CHECK HWID
    # ========================================================

    if license_data["bound_hwid"] != hwid:

        connection.close()

        raise HTTPException(
            status_code=403,
            detail=(
                "HWID mismatch. This license is "
                "already activated on another device."
            )
        )

    expires_at = string_to_datetime(
        license_data["expires_at"]
    )

    if now_utc() >= expires_at:

        connection.close()

        raise HTTPException(
            status_code=403,
            detail="This license has expired."
        )

    connection.close()

    return {
        "success": True,
        "message": "License is valid.",
        "first_activation": False,
        "expires_at": datetime_to_string(
            expires_at
        ),
        "seconds_remaining": get_time_remaining(
            expires_at
        )
    }


# ============================================================
# USER: VALIDATE LICENSE
#
# Your loader can call this periodically.
# If expired/revoked/wrong HWID, access is denied.
# ============================================================

@app.post("/api/license/validate")
def validate_license(
    request: ValidateKeyRequest
):

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

    expires_at = string_to_datetime(
        license_data["expires_at"]
    )

    if now_utc() >= expires_at:

        raise HTTPException(
            status_code=403,
            detail="This license has expired."
        )

    return {
        "success": True,
        "valid": True,
        "expires_at": datetime_to_string(
            expires_at
        ),
        "seconds_remaining": get_time_remaining(
            expires_at
        )
    }


# ============================================================
# ADMIN: REVOKE A KEY
# ============================================================

@app.post("/api/admin/revoke")
def revoke_key(
    request: RevokeKeyRequest,
    x_admin_secret: str = Header(default=None)
):

    check_admin_secret(x_admin_secret)

    license_key = (
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
        (license_key,)
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
# ADMIN: VIEW A KEY
# ============================================================

@app.get("/api/admin/license/{license_key}")
def get_license(
    license_key: str,
    x_admin_secret: str = Header(default=None)
):

    check_admin_secret(x_admin_secret)

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM licenses
        WHERE license_key = ?
        """,
        (license_key.strip().upper(),)
    )

    license_data = cursor.fetchone()

    connection.close()

    if not license_data:

        raise HTTPException(
            status_code=404,
            detail="License key not found."
        )

    return {
        "success": True,
        "license": dict(license_data)
    }
