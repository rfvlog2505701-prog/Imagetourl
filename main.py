from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import re
import secrets
import threading
import time
import warnings
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

import httpx
import uvicorn
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image, UnidentifiedImageError
from starlette.responses import Response, StreamingResponse
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)


# ============================================================
# HARD-CODED SETTINGS — edit these values before deployment.
# ============================================================

# Create a bot with @BotFather and paste its token here.
BOT_TOKEN = "9297998867:AAHofQxrhDYnySyPIy6vND0EF2u-Io7FYE4"

# Replace 123456789 with your own numeric Telegram user ID.
# Use /id in the bot to find your Telegram ID.
ADMIN_IDS = {8602082771}

# Render automatically supplies RENDER_EXTERNAL_URL at runtime.
# The fallback is only for local testing; on Render the automatic URL wins.
PUBLIC_BASE_URL_FALLBACK = "https://YOUR-SERVICE-NAME.onrender.com"

# Firebase Web Config used by the Firebase Auth REST endpoint and RTDB URL.
FIREBASE_WEB_CONFIG = {
    "apiKey": "AIzaSyDynK3F7VTFUGR8TCmqascD7yTdhn4ymWA",
    "authDomain": "imagetourl-fa59c.firebaseapp.com",
    "databaseURL": "https://imagetourl-fa59c-default-rtdb.firebaseio.com",
    "projectId": "imagetourl-fa59c",
    "storageBucket": "imagetourl-fa59c.firebasestorage.app",
    "messagingSenderId": "569478723033",
    "appId": "1:569478723033:web:36fe1b482400a3015415c8",
    "measurementId": "G-MDKL2C19P5",
}

# No Firebase Service Account is used.
# Enable Firebase Authentication > Email/Password, then create a dedicated
# backend-only account. Paste its credentials and UID below. This account is
# used only to obtain Firebase ID tokens for the Realtime Database REST API.
FIREBASE_AUTH_EMAIL = "ufbfahimyt250@gmail.com"
FIREBASE_AUTH_PASSWORD = "fahim@2507713"
FIREBASE_AUTH_UID = "lgjTAbm4l6MqWHxOpGWywyAAUK72"

# CloudNest / DropLink upstream API credentials supplied by you.
CLOUDNEST_UPLOAD_URL = "https://droplink-a7b1.onrender.com/api/upload/file"
CLOUDNEST_API_KEY = "dl_d74db55d88d9fa14c0b507b36edf1b3eceaeb40a"

# The app accepts raster images up to 50 MB.
MAX_IMAGE_BYTES = 50 * 1024 * 1024
FREE_DAILY_LIMIT = 200
PORT = int(os.environ.get("PORT", "10000"))
TIME_ZONE = ZoneInfo("Asia/Dhaka")

# SVG is deliberately not accepted: it is an active XML-based format, not a
# decoded raster image. The format is detected from image bytes, never filename.
IMAGE_FORMATS = {
    "PNG": (".png", "image/png"),
    "JPEG": (".jpg", "image/jpeg"),
    "GIF": (".gif", "image/gif"),
    "WEBP": (".webp", "image/webp"),
    "BMP": (".bmp", "image/bmp"),
    "TIFF": (".tiff", "image/tiff"),
    "ICO": (".ico", "image/vnd.microsoft.icon"),
}

Image.MAX_IMAGE_PIXELS = 40_000_000
warnings.simplefilter("error", Image.DecompressionBombWarning)

bot_application: Optional[Application] = None


# ============================================================
# FIREBASE REALTIME DATABASE
# ============================================================

def public_base_url() -> str:
    """Use Render's automatically supplied public URL when deployed."""
    value = os.environ.get("RENDER_EXTERNAL_URL", "").strip().rstrip("/")
    return value or PUBLIC_BASE_URL_FALLBACK.rstrip("/")


class FirebaseRESTError(RuntimeError):
    pass


class FirebaseRealtimeDatabase:
    """Realtime Database REST client authenticated as a dedicated Firebase user."""

    def __init__(self) -> None:
        self.base_url = FIREBASE_WEB_CONFIG["databaseURL"].rstrip("/")
        self.api_key = FIREBASE_WEB_CONFIG["apiKey"]
        self.email = FIREBASE_AUTH_EMAIL.strip()
        self.password = FIREBASE_AUTH_PASSWORD
        self.expected_uid = FIREBASE_AUTH_UID.strip()
        self._client = httpx.Client(timeout=httpx.Timeout(25.0, connect=15.0))
        self._lock = threading.RLock()
        self._id_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._token_expiry = 0.0

    def _check_config(self) -> None:
        placeholders = (
            not self.email or self.email.startswith("PASTE_"),
            not self.password or self.password.startswith("PASTE_"),
            not self.expected_uid or self.expected_uid.startswith("PASTE_"),
        )
        if any(placeholders):
            raise RuntimeError(
                "Firebase REST authentication is not configured. In main.py, set "
                "FIREBASE_AUTH_EMAIL, FIREBASE_AUTH_PASSWORD and FIREBASE_AUTH_UID "
                "for a dedicated Firebase Email/Password user. No Service Account is needed."
            )
        if not self.api_key or not self.base_url:
            raise RuntimeError("Firebase apiKey or Realtime Database URL is missing.")

    def _auth_error(self, response: httpx.Response) -> str:
        try:
            payload = response.json()
            return payload.get("error", {}).get("message", response.text)
        except Exception:
            return response.text

    def _sign_in(self) -> None:
        self._check_config()
        response = self._client.post(
            "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword",
            params={"key": self.api_key},
            json={"email": self.email, "password": self.password, "returnSecureToken": True},
        )
        if not response.is_success:
            raise FirebaseRESTError(
                "Firebase Email/Password sign-in failed: " + self._auth_error(response)
            )
        payload = response.json()
        actual_uid = payload.get("localId")
        if actual_uid != self.expected_uid:
            raise FirebaseRESTError(
                "Firebase Auth UID mismatch. Check FIREBASE_AUTH_UID in main.py."
            )
        self._id_token = payload["idToken"]
        self._refresh_token = payload["refreshToken"]
        self._token_expiry = time.monotonic() + max(60, int(payload.get("expiresIn", "3600")) - 120)

    def _refresh(self) -> None:
        if not self._refresh_token:
            self._sign_in()
            return
        response = self._client.post(
            "https://securetoken.googleapis.com/v1/token",
            params={"key": self.api_key},
            data={"grant_type": "refresh_token", "refresh_token": self._refresh_token},
        )
        if not response.is_success:
            # A revoked/expired refresh token can be recovered by a fresh sign-in.
            self._sign_in()
            return
        payload = response.json()
        self._id_token = payload["id_token"]
        self._refresh_token = payload.get("refresh_token", self._refresh_token)
        self._token_expiry = time.monotonic() + max(60, int(payload.get("expires_in", "3600")) - 120)

    def _token(self, force_refresh: bool = False) -> str:
        with self._lock:
            if force_refresh or not self._id_token or time.monotonic() >= self._token_expiry:
                if self._refresh_token and self._id_token:
                    self._refresh()
                else:
                    self._sign_in()
            assert self._id_token
            return self._id_token

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        clean_path = "/".join(part for part in path.strip("/").split("/") if part)
        url = f"{self.base_url}/{clean_path}.json" if clean_path else f"{self.base_url}/.json"
        for attempt in range(2):
            token = self._token(force_refresh=(attempt == 1))
            params = dict(kwargs.get("params", {}) or {})
            params["auth"] = token
            request_kwargs = {key: value for key, value in kwargs.items() if key != "_allow_statuses"}
            allowed_statuses = kwargs.get("_allow_statuses", set())
            response = self._client.request(method, url, params=params, **request_kwargs)
            if response.status_code == 401 and attempt == 0:
                continue
            if not response.is_success and response.status_code not in allowed_statuses:
                raise FirebaseRESTError(
                    f"Firebase Realtime Database {method} {clean_path or '/'} failed "
                    f"({response.status_code}): {self._auth_error(response)}"
                )
            return response
        raise FirebaseRESTError("Firebase authentication expired; please check backend auth account.")

    def get(self, path: str):
        return self._request("GET", path).json()

    def set(self, path: str, value):
        response = self._request("PUT", path, json=value)
        return response.json() if response.content else value

    def update(self, path: str, value: dict):
        response = self._request("PATCH", path, json=value)
        return response.json() if response.content else value

    def delete(self, path: str) -> None:
        self._request("DELETE", path)

    def transaction(self, path: str, updater, max_retries: int = 30):
        """ETag-based conditional PUT: an atomic RTDB transaction via REST."""
        for _ in range(max_retries):
            read_response = self._request(
                "GET", path, headers={"X-Firebase-ETag": "true"}
            )
            etag = read_response.headers.get("ETag")
            if not etag:
                raise FirebaseRESTError("Firebase did not return an ETag for a transaction.")
            current = read_response.json()
            updated = updater(current)
            write_response = self._request(
                "PUT", path, json=updated, headers={"if-match": etag},
                _allow_statuses={412},
            )
            if write_response.status_code == 412:
                continue
            # A successful conditional PUT is atomic relative to the ETag read.
            return write_response.json() if write_response.content else updated
        raise FirebaseRESTError("Firebase transaction exceeded its retry limit.")


firebase_db = FirebaseRealtimeDatabase()


def init_firebase() -> None:
    """Verify backend-only Firebase Authentication and Realtime Database access."""
    firebase_db._check_config()
    firebase_db._token()
    # A small read confirms that the authenticated user is allowed by DB rules.
    firebase_db.get("system/readiness_check")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_iso(value: Optional[datetime] = None) -> str:
    return (value or utc_now()).isoformat()


def today_in_dhaka() -> str:
    return datetime.now(TIME_ZONE).date().isoformat()


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def make_api_key() -> str:
    return "dlimg_" + secrets.token_urlsafe(36)


def user_ref(telegram_id: int) -> str:
    return f"users/{int(telegram_id)}"


def create_account(telegram_id: int) -> Optional[str]:
    """Create a user and its hashed API-key index; return key only on first creation."""
    api_key = make_api_key()
    key_hash = hash_api_key(api_key)
    record = {
        "telegram_id": int(telegram_id),
        "api_key_hash": key_hash,
        "created_at": utc_iso(),
        "premium_until": None,
    }
    result = firebase_db.transaction(
        user_ref(telegram_id), lambda current: record if current is None else current
    )
    if isinstance(result, dict) and result.get("api_key_hash") == key_hash:
        firebase_db.set(f"api_keys/{key_hash}", int(telegram_id))
        return api_key
    return None


def rotate_api_key(telegram_id: int) -> str:
    api_key = make_api_key()
    new_hash = hash_api_key(api_key)
    ref = user_ref(telegram_id)
    existing = firebase_db.get(ref)
    if not existing:
        create_account(telegram_id)
        existing = firebase_db.get(ref)
    if not existing:
        raise RuntimeError("Could not create the user account in Firebase.")
    old_hash = existing.get("api_key_hash")
    # Publish the new index first, then change the user's active hash.
    firebase_db.set(f"api_keys/{new_hash}", int(telegram_id))
    firebase_db.update(ref, {"api_key_hash": new_hash})
    if old_hash:
        firebase_db.delete(f"api_keys/{old_hash}")
    return api_key


def find_user_by_api_key(api_key: str) -> Optional[int]:
    key_hash = hash_api_key(api_key)
    telegram_id = firebase_db.get(f"api_keys/{key_hash}")
    if telegram_id is None:
        return None
    try:
        telegram_id = int(telegram_id)
    except (TypeError, ValueError):
        return None
    user = firebase_db.get(user_ref(telegram_id))
    if not isinstance(user, dict) or user.get("api_key_hash") != key_hash:
        return None
    return telegram_id


def premium_is_active(premium_until: Optional[str]) -> bool:
    if not premium_until:
        return False
    try:
        expiry = datetime.fromisoformat(premium_until)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return expiry > utc_now()
    except (TypeError, ValueError):
        return False


def quota_snapshot(telegram_id: int) -> dict:
    user = firebase_db.get(user_ref(telegram_id))
    used_value = firebase_db.get(
        f"daily_usage/{int(telegram_id)}/{today_in_dhaka()}"
    )
    used = int(used_value or 0)
    premium = bool(user and premium_is_active(user.get("premium_until")))
    return {
        "premium": premium,
        "used_today": used,
        "daily_limit": None if premium else FREE_DAILY_LIMIT,
        "remaining": None if premium else max(0, FREE_DAILY_LIMIT - used),
        "reset_timezone": "Asia/Dhaka",
    }


def reserve_quota(telegram_id: int) -> tuple[bool, dict, str]:
    """Atomically increment the user's daily counter using an RTDB transaction."""
    day = today_in_dhaka()
    user = firebase_db.get(user_ref(telegram_id))
    if not isinstance(user, dict):
        raise ValueError("Account not found. Open the Telegram bot and send /start first.")

    premium = premium_is_active(user.get("premium_until"))
    quota_ref = f"daily_usage/{int(telegram_id)}/{day}"
    transaction_state = {"reserved": False}

    def update_count(current):
        used = int(current or 0)
        allowed = premium or used < FREE_DAILY_LIMIT
        transaction_state["reserved"] = allowed
        return used + 1 if allowed else used

    new_used = int(firebase_db.transaction(quota_ref, update_count) or 0)
    if not transaction_state["reserved"]:
        return False, {
            "premium": False,
            "used_today": new_used,
            "daily_limit": FREE_DAILY_LIMIT,
            "remaining": 0,
            "reset_timezone": "Asia/Dhaka",
        }, day

    return True, {
        "premium": premium,
        "used_today": new_used,
        "daily_limit": None if premium else FREE_DAILY_LIMIT,
        "remaining": None if premium else max(0, FREE_DAILY_LIMIT - new_used),
        "reset_timezone": "Asia/Dhaka",
    }, day


def refund_quota(telegram_id: int, usage_day: str) -> None:
    quota_ref = f"daily_usage/{int(telegram_id)}/{usage_day}"
    firebase_db.transaction(quota_ref, lambda current: max(0, int(current or 0) - 1))


def save_image_record(
    direct_url: str,
    extension: str,
    content_type: str,
    file_size: int,
    telegram_id: int,
) -> str:
    """Save Catbox origin privately and expose only a random local filename."""
    for _ in range(10):
        filename = secrets.token_hex(16) + extension
        record = {
            "filename": filename,
            "direct_url": direct_url,
            "content_type": content_type,
            "file_size": int(file_size),
            "telegram_id": int(telegram_id),
            "created_at": utc_iso(),
        }
        state = {"created": False}

        def insert_if_missing(current):
            if current is None:
                state["created"] = True
                return record
            state["created"] = False
            return current

        firebase_db.transaction(f"images/{filename}", insert_if_missing)
        if state["created"]:
            return filename
    raise RuntimeError("Could not allocate a unique image filename.")


def get_image_record(filename: str) -> Optional[dict]:
    record = firebase_db.get(f"images/{filename}")
    return record if isinstance(record, dict) else None


def grant_premium(telegram_id: int, days: int) -> datetime:
    ref = user_ref(telegram_id)
    user = firebase_db.get(ref)
    if not isinstance(user, dict):
        create_account(telegram_id)
        user = firebase_db.get(ref)
    if not isinstance(user, dict):
        raise RuntimeError("Could not create target user in Firebase.")

    now = utc_now()
    old_expiry = user.get("premium_until")
    start = now
    if old_expiry:
        try:
            parsed = datetime.fromisoformat(old_expiry)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            if parsed > now:
                start = parsed
        except (TypeError, ValueError):
            pass
    expiry = start + timedelta(days=days)
    firebase_db.update(ref, {"premium_until": expiry.isoformat()})
    return expiry


def revoke_premium(telegram_id: int) -> bool:
    ref = user_ref(telegram_id)
    user = firebase_db.get(ref)
    if not isinstance(user, dict):
        return False
    firebase_db.update(ref, {"premium_until": None})
    return True


def database_stats() -> tuple[int, int]:
    users = firebase_db.get("users") or {}
    images = firebase_db.get("images") or {}
    return len(users) if isinstance(users, dict) else 0, len(images) if isinstance(images, dict) else 0


# ============================================================
# IMAGE VALIDATION AND UPSTREAM UPLOAD
# ============================================================

class InvalidImageError(Exception):
    pass


class UploadQuotaExceeded(Exception):
    def __init__(self, quota: dict):
        self.quota = quota
        super().__init__("Daily upload limit reached")


def inspect_image(data: bytes) -> tuple[str, str, str]:
    if not data:
        raise InvalidImageError("The uploaded file is empty.")
    if len(data) > MAX_IMAGE_BYTES:
        raise InvalidImageError("Image is larger than the 50 MB limit.")

    try:
        with Image.open(io.BytesIO(data)) as image_file:
            detected_format = (image_file.format or "").upper()
            width, height = image_file.size
            if detected_format not in IMAGE_FORMATS:
                raise InvalidImageError("This image format is not allowed.")
            if width < 1 or height < 1 or width * height > Image.MAX_IMAGE_PIXELS:
                raise InvalidImageError("Image dimensions are too large.")
            image_file.verify()

        # Force a real pixel decode as well. File extensions and MIME headers
        # supplied by clients are never used to decide whether a file is an image.
        with Image.open(io.BytesIO(data)) as image_file:
            image_file.load()

    except InvalidImageError:
        raise
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError,
            Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise InvalidImageError("The file is not a valid, decodable image.") from exc

    extension, content_type = IMAGE_FORMATS[detected_format]
    return detected_format, extension, content_type


async def upload_to_cloudnest(data: bytes, filename: str, content_type: str) -> str:
    timeout = httpx.Timeout(1200.0, connect=30.0)
    headers = {"X-API-Key": CLOUDNEST_API_KEY}
    files = {"file": (filename, data, content_type)}

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.post(
                CLOUDNEST_UPLOAD_URL,
                headers=headers,
                files=files,
                data={"shorten": "false"},
            )
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise RuntimeError("The image storage provider could not complete the upload.") from exc

    if not isinstance(payload, dict) or not payload.get("success"):
        message = payload.get("error", "Unknown upstream error") if isinstance(payload, dict) else "Invalid upstream response"
        raise RuntimeError(f"The image storage provider rejected the upload: {message}")

    # shorten=false is mandatory. Prefer direct_url and fall back to url only
    # because the upstream API documents url as its final link when shortening is off.
    direct_url = payload.get("direct_url") or payload.get("url")
    if not isinstance(direct_url, str):
        raise RuntimeError("The storage provider did not return a direct image URL.")

    parsed = urlparse(direct_url)
    if parsed.scheme != "https" or parsed.hostname != "files.catbox.moe":
        raise RuntimeError("The storage provider returned an unexpected file host.")
    return direct_url


async def process_image_upload(
    telegram_id: int,
    data: bytes,
    original_filename: str,
) -> tuple[str, int, dict]:
    _, extension, content_type = inspect_image(data)
    allowed, quota, usage_day = await asyncio.to_thread(reserve_quota, telegram_id)
    if not allowed:
        raise UploadQuotaExceeded(quota)

    # Use a server-controlled name and an extension matching the decoded format.
    upstream_filename = secrets.token_hex(12) + extension
    try:
        direct_url = await upload_to_cloudnest(data, upstream_filename, content_type)
        filename = await asyncio.to_thread(
            save_image_record,
            direct_url,
            extension,
            content_type,
            len(data),
            telegram_id,
        )
        current_quota = await asyncio.to_thread(quota_snapshot, telegram_id)
        return filename, len(data), current_quota
    except Exception:
        await asyncio.to_thread(refund_quota, telegram_id, usage_day)
        raise


def public_image_url(filename: str) -> str:
    return f"{public_base_url()}/{filename}"


# ============================================================
# TELEGRAM BOT
# ============================================================

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    message = update.effective_message
    if not user or not message:
        return

    new_key = await asyncio.to_thread(create_account, user.id)
    if new_key:
        key_text = f"\n\n<b>Your API key</b>\n<code>{new_key}</code>\nSave it now. Use /key to generate a new key if you lose it."
    else:
        key_text = "\n\nYour account already exists. Use /key to rotate your API key and receive a new one."

    await message.reply_text(
        "<b>Welcome to DropImage!</b>\n"
        "Your image-hosting account is ready.\n\n"
        f"Free plan: <b>{FREE_DAILY_LIMIT} images per day</b>.\n"
        "Premium accounts have unlimited uploads while their subscription is active.\n\n"
        "Send me an image or use the HTTP API.\n"
        f"API docs: {public_base_url()}/api/ai-docs\n"
        "/key — generate a new API key\n"
        "/quota — view today's quota\n"
        "/id — show your Telegram ID\n"
        "/help — commands"
        + key_text,
        parse_mode="HTML",
        disable_web_page_preview=True,
    )


async def key_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    message = update.effective_message
    if not user or not message:
        return
    api_key = await asyncio.to_thread(rotate_api_key, user.id)
    await message.reply_text(
        "<b>Your new API key</b>\n"
        f"<code>{api_key}</code>\n\n"
        "Your previous API key has been disabled. Keep this key private.",
        parse_mode="HTML",
    )


async def quota_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    message = update.effective_message
    if not user or not message:
        return
    await asyncio.to_thread(create_account, user.id)
    quota = await asyncio.to_thread(quota_snapshot, user.id)
    if quota["premium"]:
        text_value = (
            f"Premium: active\nUploads today: {quota['used_today']}\n"
            "Daily limit: Unlimited"
        )
    else:
        text_value = (
            f"Plan: Free\nUploads today: {quota['used_today']}/{FREE_DAILY_LIMIT}\n"
            f"Remaining today: {quota['remaining']}"
        )
    await message.reply_text(text_value + "\nDaily reset: 12:00 AM Asia/Dhaka.")


async def id_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    message = update.effective_message
    if user and message:
        await message.reply_text(f"Your Telegram user ID: <code>{user.id}</code>", parse_mode="HTML")


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    if not message:
        return
    await message.reply_text(
        "<b>DropImage commands</b>\n"
        "/start — create your account\n"
        "/key — rotate and show your API key\n"
        "/quota — show daily usage\n"
        "/id — show your Telegram ID\n"
        "/help — this message\n\n"
        "Send an image as a photo or document to upload it.\n\n"
        "Admin commands: /premium, /free, /stats",
        parse_mode="HTML",
    )


async def incoming_image(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    message = update.effective_message
    if not user or not message:
        return

    await asyncio.to_thread(create_account, user.id)
    telegram_file = None
    original_name = "telegram-image"

    try:
        if message.photo:
            telegram_file = await context.bot.get_file(message.photo[-1].file_id)
            original_name = "telegram-photo.jpg"
        elif message.document:
            telegram_file = await context.bot.get_file(message.document.file_id)
            original_name = message.document.file_name or "telegram-image"
            if message.document.file_size and message.document.file_size > MAX_IMAGE_BYTES:
                await message.reply_text("File is larger than the 50 MB limit.")
                return
        else:
            return

        raw_data = bytes(await telegram_file.download_as_bytearray())
        filename, size, quota = await process_image_upload(user.id, raw_data, original_name)
        link = public_image_url(filename)
        quota_line = (
            "Premium: unlimited uploads"
            if quota["premium"]
            else f"Today's usage: {quota['used_today']}/{FREE_DAILY_LIMIT}"
        )
        await message.reply_text(
            f"<b>Image uploaded successfully!</b>\n"
            f"<a href=\"{link}\">{link}</a>\n"
            f"Size: {size:,} bytes\n"
            f"{quota_line}",
            parse_mode="HTML",
            disable_web_page_preview=False,
        )
    except InvalidImageError as exc:
        await message.reply_text(f"Rejected: {exc}")
    except UploadQuotaExceeded:
        await message.reply_text(
            f"Daily free limit reached ({FREE_DAILY_LIMIT} images). "
            "Your quota resets at midnight Asia/Dhaka."
        )
    except ValueError as exc:
        await message.reply_text(str(exc))
    except Exception as exc:
        print(f"Telegram upload error for user {user.id}: {exc}")
        await message.reply_text("Upload failed. Please try again later.")


async def premium_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    actor = update.effective_user
    if not message or not actor:
        return
    if actor.id not in ADMIN_IDS:
        await message.reply_text("You are not authorized to use this command.")
        return
    if len(context.args) != 2:
        await message.reply_text("Usage: /premium TELEGRAM_USER_ID DAYS")
        return
    try:
        target_id = int(context.args[0])
        days = int(context.args[1])
        if target_id <= 0 or days < 1 or days > 3650:
            raise ValueError
    except ValueError:
        await message.reply_text("Enter a valid Telegram user ID and days (1–3650).")
        return

    expiry = await asyncio.to_thread(grant_premium, target_id, days)
    await message.reply_text(
        f"Premium granted to <code>{target_id}</code> until "
        f"<code>{expiry.strftime('%Y-%m-%d %H:%M UTC')}</code>.",
        parse_mode="HTML",
    )


async def free_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    actor = update.effective_user
    if not message or not actor:
        return
    if actor.id not in ADMIN_IDS:
        await message.reply_text("You are not authorized to use this command.")
        return
    if len(context.args) != 1:
        await message.reply_text("Usage: /free TELEGRAM_USER_ID")
        return
    try:
        target_id = int(context.args[0])
    except ValueError:
        await message.reply_text("Telegram user ID must be a number.")
        return
    changed = await asyncio.to_thread(revoke_premium, target_id)
    await message.reply_text("Premium removed." if changed else "User was not found.")


async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    actor = update.effective_user
    if not message or not actor:
        return
    if actor.id not in ADMIN_IDS:
        await message.reply_text("You are not authorized to use this command.")
        return
    users, images = await asyncio.to_thread(database_stats)
    await message.reply_text(f"Accounts: {users}\nHosted images: {images}")


# ============================================================
# FASTAPI SERVER
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    global bot_application
    init_firebase()

    if BOT_TOKEN and not BOT_TOKEN.startswith("PASTE_"):
        try:
            bot_application = Application.builder().token(BOT_TOKEN).build()
            bot_application.add_handler(CommandHandler("start", start_command))
            bot_application.add_handler(CommandHandler("key", key_command))
            bot_application.add_handler(CommandHandler("quota", quota_command))
            bot_application.add_handler(CommandHandler("id", id_command))
            bot_application.add_handler(CommandHandler("help", help_command))
            bot_application.add_handler(CommandHandler("premium", premium_command))
            bot_application.add_handler(CommandHandler("free", free_command))
            bot_application.add_handler(CommandHandler("stats", stats_command))
            bot_application.add_handler(
                MessageHandler(filters.PHOTO | filters.Document.ALL, incoming_image)
            )
            await bot_application.initialize()
            await bot_application.start()
            if bot_application.updater:
                await bot_application.updater.start_polling(drop_pending_updates=True)
            print("Telegram bot polling started.")
        except Exception as exc:
            print(f"Telegram bot failed to start; HTTP API remains available: {exc}")
    else:
        print("Telegram bot is disabled. Add your BotFather token to BOT_TOKEN in main.py.")

    yield

    if bot_application:
        try:
            if bot_application.updater and bot_application.updater.running:
                await bot_application.updater.stop()
            if bot_application.running:
                await bot_application.stop()
            await bot_application.shutdown()
        except Exception as exc:
            print(f"Telegram bot shutdown warning: {exc}")


app = FastAPI(
    title="DropImage API",
    description="Image-only hosting API with Firebase-backed Telegram accounts and daily quotas.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Public browser access: every origin is allowed. API keys are still required
# for uploads, so do not embed a private API key in a public frontend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Type", "Content-Length"],
    max_age=86400,
)


async def authenticate_api_key(request: Request) -> int:
    api_key = request.headers.get("X-API-Key", "").strip()
    if not api_key:
        authorization = request.headers.get("Authorization", "").strip()
        if authorization.lower().startswith("bearer "):
            api_key = authorization[7:].strip()

    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Use X-API-Key or Authorization: Bearer.",
        )

    user_id = await asyncio.to_thread(find_user_by_api_key, api_key)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid API key.")
    return user_id


@app.get("/health")
async def health_check():
    return {"success": True, "service": "DropImage", "status": "ok"}


@app.get("/api/me")
async def my_account(user_id: int = Depends(authenticate_api_key)):
    quota = await asyncio.to_thread(quota_snapshot, user_id)
    return {"success": True, "telegram_user_id": user_id, "quota": quota}


AI_DOCS = r"""# DropImage API — AI integration guide

Base URL: `https://YOUR-SERVICE-NAME.onrender.com`

## Authentication
Every API request must include one of these headers:

- `X-API-Key: YOUR_API_KEY`
- `Authorization: Bearer YOUR_API_KEY`

Do not put API keys in public source code. Create an account by opening the Telegram bot and sending `/start`. Use `/key` to generate/rotate your key.

## Upload an image
`POST /api/upload/file`

Content type: `multipart/form-data`

Required field:
- `file`: image file (maximum 50 MB)

Only decoded raster images are accepted: PNG, JPEG, GIF, WEBP, BMP, TIFF and ICO. The server checks the actual image bytes and decodes the image; changing an APK, ZIP, PDF or other file extension to `.png` does not make it an image. The server chooses the final extension from the detected image format.

Example JavaScript:

```javascript
const form = new FormData();
form.append("file", fileInput.files[0]);

const response = await fetch("https://YOUR-SERVICE-NAME.onrender.com/api/upload/file", {
  method: "POST",
  headers: { "X-API-Key": "YOUR_API_KEY" },
  body: form
});
const result = await response.json();
if (!response.ok) throw new Error(result.detail || "Upload failed");
console.log(result.url); // Your own Render URL; no browser redirect to Catbox.
```

Example cURL:

```bash
curl -X POST "https://YOUR-SERVICE-NAME.onrender.com/api/upload/file" \
  -H "X-API-Key: YOUR_API_KEY" \
  -F "file=@photo.png"
```

## Success response

```json
{
  "success": true,
  "filename": "random-server-generated-name.png",
  "size": 183422,
  "content_type": "image/png",
  "url": "https://YOUR-SERVICE-NAME.onrender.com/random-server-generated-name.png",
  "quota": {
    "premium": false,
    "used_today": 1,
    "daily_limit": 200,
    "remaining": 199,
    "reset_timezone": "Asia/Dhaka"
  }
}
```

The `url` is the final public image URL. Opening it displays the image through this server. The Catbox source URL is stored privately and is not returned by this API.

## Firebase persistence
User records, API-key hash indexes, daily counters, and private image-origin mappings are stored in Firebase Realtime Database through its REST API. This server does not use a Firebase Service Account. A dedicated Firebase Email/Password backend user supplies short-lived ID tokens; its UID must be the only UID allowed by your Realtime Database Security Rules. The Catbox `direct_url` is never included in upload responses.

## Other endpoints
- `GET /health` — health check; no authentication.
- `GET /api/me` — account and quota; requires API key.
- `GET /docs` — interactive OpenAPI documentation.
- `GET /api/ai-docs` — this AI-readable documentation.

## Limits and errors
- Free accounts: 200 successful image uploads per Bangladesh calendar day.
- Premium accounts: unlimited uploads until the premium expiry time.
- `401`: missing or invalid API key.
- `413`: request/file is too large.
- `415`: file is not a valid supported image.
- `429`: daily free quota exhausted.
- `502`: upstream image storage or retrieval failed.

CORS is enabled for all origins. CORS does not hide API keys: a key embedded in public browser JavaScript can be copied by visitors. For public websites, upload through your own backend or use a user-specific key with appropriate controls.
"""


@app.get("/api/ai-docs", response_class=Response)
async def ai_docs():
    rendered_docs = AI_DOCS.replace(
        "https://YOUR-SERVICE-NAME.onrender.com",
        public_base_url(),
    )
    return Response(content=rendered_docs, media_type="text/markdown; charset=utf-8")


@app.post("/api/upload/file")
@app.post("/api/upload", include_in_schema=False)
async def upload_image_api(
    request: Request,
    file: UploadFile = File(...),
    user_id: int = Depends(authenticate_api_key),
):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_IMAGE_BYTES + (2 * 1024 * 1024):
                raise HTTPException(status_code=413, detail="Upload is larger than the 50 MB limit.")
        except ValueError:
            pass

    data = await file.read(MAX_IMAGE_BYTES + 1)
    if len(data) > MAX_IMAGE_BYTES:
        raise HTTPException(status_code=413, detail="Image is larger than the 50 MB limit.")

    try:
        filename, size, quota = await process_image_upload(
            user_id,
            data,
            file.filename or "upload-image",
        )
    except InvalidImageError as exc:
        raise HTTPException(status_code=415, detail=str(exc)) from exc
    except UploadQuotaExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail={
                "message": "Daily free upload limit reached.",
                "quota": exc.quota,
            },
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except Exception as exc:
        print(f"API upload error for user {user_id}: {exc}")
        raise HTTPException(status_code=502, detail="Image storage provider upload failed.") from exc

    return {
        "success": True,
        "filename": filename,
        "size": size,
        "content_type": inspect_image(data)[2],
        "url": public_image_url(filename),
        "quota": quota,
    }


@app.get("/{filename}")
async def serve_image(filename: str):
    # Only server-generated filenames are served by this route.
    if not re.fullmatch(r"[a-f0-9]{32}\.(png|jpg|gif|webp|bmp|tiff|ico)", filename):
        raise HTTPException(status_code=404, detail="Image not found.")

    record = await asyncio.to_thread(get_image_record, filename)
    if not record:
        raise HTTPException(status_code=404, detail="Image not found.")

    direct_url = record["direct_url"]
    parsed = urlparse(direct_url)
    if parsed.scheme != "https" or parsed.hostname != "files.catbox.moe":
        raise HTTPException(status_code=502, detail="Stored image source is invalid.")

    client = httpx.AsyncClient(
        timeout=httpx.Timeout(90.0, connect=20.0),
        follow_redirects=False,
    )
    try:
        upstream_request = client.build_request("GET", direct_url)
        upstream_response = await client.send(upstream_request, stream=True)
        if not upstream_response.is_success:
            await upstream_response.aclose()
            await client.aclose()
            raise HTTPException(status_code=502, detail="Image source is temporarily unavailable.")
    except HTTPException:
        raise
    except httpx.HTTPError as exc:
        await client.aclose()
        raise HTTPException(status_code=502, detail="Could not retrieve the image.") from exc

    async def stream_image():
        try:
            async for chunk in upstream_response.aiter_bytes():
                yield chunk
        finally:
            await upstream_response.aclose()
            await client.aclose()

    headers = {
        "Cache-Control": "public, max-age=86400",
        "X-Content-Type-Options": "nosniff",
        "Content-Disposition": "inline",
    }
    return StreamingResponse(
        stream_image(),
        media_type=record["content_type"],
        headers=headers,
    )


if __name__ == "__main__":
    init_firebase()
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PORT,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
