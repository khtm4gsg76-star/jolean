import os
import json
import subprocess
import re
from urllib.parse import quote, unquote
import sys
import hashlib
import secrets
import time
import threading
import requests
import shutil
import zipfile
import tarfile
import signal
import psutil
import socket
import tempfile
import ast
import unicodedata
import stat
import platform
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask import Flask, send_from_directory, send_file, request, jsonify, session, redirect, make_response, Response, stream_with_context

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# التخزين الدائم: نستخدم مسار Railway Volume إذا كان موجوداً.
# مهم: لا نستخدم db.json الموجود داخل المشروع كمصدر لبيانات المستخدمين.
DATA_DIR = (os.environ.get("MAZAGI_DATA_DIR") or
            os.environ.get("RAILWAY_VOLUME_MOUNT_PATH") or
            "/data")
try:
    os.makedirs(DATA_DIR, exist_ok=True)
except Exception:
    DATA_DIR = BASE_DIR
USERS_DIR = os.path.join(DATA_DIR, "USERS")
os.makedirs(USERS_DIR, exist_ok=True)

# مجلد PHP
PHP_DIR = os.path.join(DATA_DIR, "php_files")
os.makedirs(PHP_DIR, exist_ok=True)

def _load_session_secret():
    """Use a configured secret or create a persistent random key under DATA_DIR."""
    configured = os.environ.get("SECRET_KEY", "").strip()
    if configured:
        return configured
    secret_file = os.path.join(DATA_DIR, ".flask_secret_key")
    try:
        if os.path.isfile(secret_file):
            value = open(secret_file, "r", encoding="utf-8").read().strip()
            if len(value) >= 32:
                return value
        value = secrets.token_urlsafe(48)
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(secret_file, "w", encoding="utf-8") as handle:
            handle.write(value)
        try:
            os.chmod(secret_file, 0o600)
        except OSError:
            pass
        return value
    except Exception:
        # The process remains usable in read-only development environments,
        # but deployments should always use a persistent DATA_DIR or SECRET_KEY.
        return secrets.token_urlsafe(48)

app = Flask(__name__, static_folder=None)
app.secret_key = _load_session_secret()
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_UPLOAD_BYTES', 500 * 1024 * 1024))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('COOKIE_SECURE', 'true' if os.environ.get('RAILWAY_ENVIRONMENT') or os.environ.get('RENDER') else 'false').lower() == 'true'

# ============== بيانات المسؤول ==============
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "zzmmkj").strip() or "zzmmkj"
ADMIN_PASSWORD_RAW = os.environ.get("ADMIN_PASSWORD", "").strip()

# ============== إعدادات البوت والإشعارات ==============
BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
BOT_USERNAME = os.environ.get("BOT_USERNAME", "@sjsjjskbbot")
try:
    ADMIN_TELEGRAM_ID = int(os.environ.get("ADMIN_TELEGRAM_ID", "8394089237") or "0")
except (TypeError, ValueError):
    ADMIN_TELEGRAM_ID = 0
ADMIN_TELEGRAM_USERNAME = "@zzmmkj"

# ============== دوال الإشعارات ==============
def notify_admin(message: str):
    if not BOT_TOKEN or not ADMIN_TELEGRAM_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            json={"chat_id": ADMIN_TELEGRAM_ID, "text": message, "parse_mode": "Markdown"},
            timeout=10
        )
    except Exception:
        pass

def notify_user(telegram_id: str, message: str):
    if not BOT_TOKEN or not telegram_id:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            json={"chat_id": telegram_id, "text": message, "parse_mode": "Markdown"},
            timeout=10
        )
    except Exception:
        pass

def get_user_telegram_id(username: str):
    user = db["users"].get(username)
    if user:
        return user.get("telegram_id")
    return None

def get_pending_users_list():
    pending = []
    for username, data in db["users"].items():
        if data.get("status") == "pending" and username != ADMIN_USERNAME:
            pending.append({
                "username": username,
                "created_at": data.get("created_at"),
                "telegram_id": data.get("telegram_id")
            })
    return pending

# ============== قاعدة البيانات ==============
def _new_admin_record():
    """Create a first admin without shipping a reusable default password."""
    password = ADMIN_PASSWORD_RAW or secrets.token_urlsafe(18)
    if not ADMIN_PASSWORD_RAW:
        print("⚠️ تم إنشاء كلمة مرور مسؤول أولية عشوائية. احفظها من سجل الإقلاع ثم اضبط ADMIN_PASSWORD/غيّرها.")
        print(f"MAZAGI_INITIAL_ADMIN_PASSWORD={password}")
    return {
        "password": generate_password_hash(password),
        "is_admin": True,
        "created_at": str(datetime.now()),
        "max_servers": 999999,
        "expiry_days": 3650,
        "last_login": None,
        "telegram_id": None,
        "api_key": None,
        "storage_limit": 10240,
        "plan": "admin",
        "status": "approved"
    }


def _password_matches(stored, candidate):
    """Read old SHA-256 records once, then migrate them to Werkzeug's password hash."""
    if not stored or not candidate:
        return False
    try:
        if isinstance(stored, str) and (stored.startswith("pbkdf2:") or stored.startswith("scrypt:")):
            return check_password_hash(stored, candidate)
        legacy = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
        return secrets.compare_digest(str(stored), legacy)
    except Exception:
        return False


def _upgrade_password_hash(user, candidate):
    stored = user.get("password", "")
    if isinstance(stored, str) and (stored.startswith("pbkdf2:") or stored.startswith("scrypt:")):
        return False
    user["password"] = generate_password_hash(candidate)
    return True

DB_FILE = os.path.join(DATA_DIR, "db.json")
BUNDLED_DB_FILE = os.path.join(BASE_DIR, "db.json")
_DB_LOCK = threading.RLock()

def load_db():
    # القاعدة الدائمة هي الأساس. إذا لم توجد، نستخدم فقط لقطة portable_data/db.json إن وُجدت.
    # وجود DB_FILE يعني أن بيانات Railway الحالية لها الأولوية ولا يتم استبدالها.
    if not os.path.exists(DB_FILE):
        portable_db = os.path.join(BASE_DIR, "portable_data", "db.json")
        if os.path.exists(portable_db):
            try:
                os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
                shutil.copy2(portable_db, DB_FILE)
            except Exception:
                pass
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # ضمان وجود بنية قاعدة البيانات والخطط الافتراضية حتى لو كانت db.json جديدة أو فارغة.
                default_plans = {
                    "free": {"name": "🎁 مجاني", "storage": 512000, "ram": 256, "cpu": 0.5, "max_servers": 2, "price": 0},
                    "4gb": {"name": "💎 4 جيجا", "storage": 4096000, "ram": 1024, "cpu": 1, "max_servers": 5, "price": 5},
                    "10gb": {"name": "💎 10 جيجا", "storage": 10240000, "ram": 2048, "cpu": 2, "max_servers": 10, "price": 10},
                    "40gb": {"name": "💎 40 جيجا", "storage": 40960000, "ram": 4096, "cpu": 4, "max_servers": 20, "price": 25}
                }
                data.setdefault("users", {})
                data.setdefault("servers", {})
                data.setdefault("logs", [])
                data.setdefault("plans", {})
                for plan_id, plan_data in default_plans.items():
                    data["plans"].setdefault(plan_id, plan_data)

                # إصلاح حساب الأدمن تلقائياً إذا كانت قاعدة البيانات القديمة لا تحتويه.
                # عند ضبط ADMIN_PASSWORD صراحةً في متغيرات Railway، تتم مزامنة
                # كلمة مرور حساب الأدمن الموجود أيضاً، دون المساس بأي مستخدم أو ملف آخر.
                needs_save = False
                if ADMIN_USERNAME not in data.get("users", {}):
                    data.setdefault("users", {})[ADMIN_USERNAME] = _new_admin_record()
                    needs_save = True
                else:
                    admin_record = data["users"][ADMIN_USERNAME]
                    if not isinstance(admin_record, dict):
                        raise RuntimeError("سجل حساب المسؤول غير صالح داخل قاعدة البيانات")

                    # ضمان صلاحيات المسؤول وإكمال حالة الحساب عند غيابها.
                    if not admin_record.get("is_admin"):
                        admin_record["is_admin"] = True
                        needs_save = True
                    if "status" not in admin_record:
                        admin_record["status"] = "approved"
                        needs_save = True

                    # ADMIN_PASSWORD يعمل الآن كإعادة تعيين صريحة وآمنة عند بدء التطبيق.
                    # لا تُطبع كلمة المرور في السجلات، وتُحفظ ببصمة Werkzeug الحديثة.
                    if ADMIN_PASSWORD_RAW and not _password_matches(
                        admin_record.get("password"), ADMIN_PASSWORD_RAW
                    ):
                        admin_record["password"] = generate_password_hash(ADMIN_PASSWORD_RAW)
                        needs_save = True
                        print(
                            f"✅ تمت مزامنة كلمة مرور المسؤول '{ADMIN_USERNAME}' "
                            "من متغير ADMIN_PASSWORD وحفظها في قاعدة البيانات الدائمة.",
                            flush=True,
                        )

                if needs_save and not save_db(data):
                    raise RuntimeError(
                        "تعذر حفظ تحديث حساب المسؤول في قاعدة البيانات الدائمة. "
                        "تحقق من صلاحيات الكتابة على مجلد /data."
                    )
                return data
        except Exception as exc:
            raise RuntimeError(
                f"تعذر قراءة قاعدة البيانات الدائمة {DB_FILE}: {exc}. "
                "تم إيقاف التشغيل لحماية بيانات المستخدمين؛ أصلح أو استعد نسخة db.json قبل إعادة التشغيل."
            ) from exc
    default_db = {
        "users": {
            ADMIN_USERNAME: _new_admin_record()
        },
        "servers": {},
        "logs": [],
        "plans": {
            "free": {"name": "🎁 مجاني", "storage": 512000, "ram": 256, "cpu": 0.5, "max_servers": 2, "price": 0},
            "4gb": {"name": "💎 4 جيجا", "storage": 4096000, "ram": 1024, "cpu": 1, "max_servers": 5, "price": 5},
            "10gb": {"name": "💎 10 جيجا", "storage": 10240000, "ram": 2048, "cpu": 2, "max_servers": 10, "price": 10},
            "40gb": {"name": "💎 40 جيجا", "storage": 40960000, "ram": 4096, "cpu": 4, "max_servers": 20, "price": 25}
        }
    }
    save_db(default_db)
    return default_db

def save_db(db_data):
    """Persist the live database atomically; serialize concurrent writers."""
    try:
        with _DB_LOCK:
            os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
            tmp_file = DB_FILE + '.tmp'
            with open(tmp_file, 'w', encoding='utf-8') as f:
                json.dump(db_data, f, indent=4, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_file, DB_FILE)
            try:
                os.chmod(DB_FILE, 0o600)
            except OSError:
                pass
        return True
    except Exception as e:
        print(f"❌ خطأ في حفظ DB: {e}")
        return False

def safe_user_filename(filename):
    """يحافظ على الأسماء العربية/Unicode ويمنع مسارات الهروب."""
    if not filename:
        return ''
    name = unicodedata.normalize('NFC', str(filename)).replace('\\', '/').split('/')[-1]
    name = ''.join(ch for ch in name if ch >= ' ' and ch not in '\x7f')
    if name in ('', '.', '..') or '..' in name:
        return ''
    return name[:255]

def safe_child_path(base, name):
    """Resolve a single safe child path, including symlink resolution."""
    clean = safe_user_filename(name)
    if not clean:
        return None
    base_real = os.path.realpath(os.path.abspath(base))
    path_real = os.path.realpath(os.path.join(base_real, clean))
    try:
        if os.path.commonpath([base_real, path_real]) != base_real:
            return None
    except ValueError:
        return None
    return path_real

def safe_relative_path(base, name):
    """Safe path within a server directory; rejects traversal and symlink escape."""
    if not name:
        return None
    raw = unicodedata.normalize('NFC', str(name)).replace('\\', '/')
    parts = []
    for part in raw.split('/'):
        part = ''.join(ch for ch in part if ch >= ' ' and ch not in '\x7f')
        if part in ('', '.'):
            continue
        if part == '..' or ':' in part or '\x00' in part:
            return None
        parts.append(part)
    if not parts:
        return None
    base_real = os.path.realpath(os.path.abspath(base))
    path_real = os.path.realpath(os.path.join(base_real, *parts))
    try:
        if os.path.commonpath([base_real, path_real]) != base_real:
            return None
    except ValueError:
        return None
    return path_real


def _tree_size_bytes(path):
    total = 0
    if not os.path.isdir(path):
        return os.path.getsize(path) if os.path.isfile(path) else 0
    for root_dir, dirs, files in os.walk(path, followlinks=False):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root_dir, d))]
        for name in files:
            item = os.path.join(root_dir, name)
            try:
                if not os.path.islink(item):
                    total += os.path.getsize(item)
            except OSError:
                pass
    return total


def _user_storage_usage_bytes(username):
    total = 0
    for srv in db.get("servers", {}).values():
        if srv.get("owner") == username:
            total += _tree_size_bytes(srv.get("path", ""))
    return total


def _storage_limit_bytes(user):
    # Admin accounts are not restricted by the legacy 10 MiB value in the bundled DB.
    if user.get("is_admin"):
        return 10 * 1024 * 1024 * 1024 * 1024  # 10 TiB application-level ceiling
    # Existing plan values are stored in KiB (e.g. 4,096,000 KiB ≈ 4 GiB).
    try:
        return max(0, int(user.get("storage_limit", 512000))) * 1024
    except (TypeError, ValueError):
        return 512000 * 1024


def _check_storage_quota(username, additional_bytes=0, replacing_path=None, replacing_paths=None):
    user = db.get("users", {}).get(username, {})
    used = _user_storage_usage_bytes(username)
    candidates = []
    if replacing_path:
        candidates.append(replacing_path)
    if replacing_paths:
        candidates.extend(replacing_paths)
    # Subtract each existing target only once when an upload replaces it.
    for path in set(os.path.abspath(x) for x in candidates if x):
        if os.path.isfile(path) and not os.path.islink(path):
            try:
                used -= os.path.getsize(path)
            except OSError:
                pass
    limit = _storage_limit_bytes(user)
    if used + max(0, int(additional_bytes)) > limit:
        remaining = max(0, limit - used)
        return False, remaining
    return True, max(0, limit - used)


def safe_extract_zip(zip_path, destination, *, max_files=10000, max_uncompressed=500 * 1024 * 1024, flatten_single_root=True):
    """Extract ZIP safely: blocks traversal, symlinks and oversized archives."""
    base = os.path.realpath(os.path.abspath(destination))
    os.makedirs(base, exist_ok=True)
    temp_dir = tempfile.mkdtemp(prefix=".mazagi-extract-", dir=base)
    try:
        with zipfile.ZipFile(zip_path, "r") as archive:
            infos = [i for i in archive.infolist() if i.filename and i.filename not in (".", "./")]
            if len(infos) > max_files:
                raise ValueError("ملف ZIP يحتوي عدداً كبيراً جداً من الملفات")
            total_size = sum(max(0, i.file_size) for i in infos)
            if total_size > max_uncompressed:
                raise ValueError("حجم الملفات بعد فك الضغط يتجاوز الحد المسموح")
            bad = archive.testzip()
            if bad:
                raise ValueError(f"ملف ZIP تالف: {bad}")

            clean_items = []
            first_parts = set()
            has_top_level_file = False
            for info in infos:
                raw = info.filename.replace('\\', '/')
                if raw.startswith('/') or re.match(r'^[A-Za-z]:', raw) or '\x00' in raw:
                    raise ValueError("ZIP يحتوي مساراً غير آمن")
                parts = [x for x in raw.split('/') if x not in ('', '.')]
                if not parts or any(x == '..' for x in parts):
                    raise ValueError("ZIP يحتوي مساراً غير آمن")
                mode = (info.external_attr >> 16) & 0o170000
                if mode == stat.S_IFLNK:
                    raise ValueError("ZIP يحتوي رابطاً رمزياً غير مسموح")
                if len(parts) == 1 and not info.is_dir():
                    has_top_level_file = True
                first_parts.add(parts[0])
                clean_items.append((info, parts))

            strip_root = flatten_single_root and len(first_parts) == 1 and not has_top_level_file
            written = 0
            for info, parts in clean_items:
                if strip_root:
                    parts = parts[1:]
                if not parts:
                    continue
                target = os.path.realpath(os.path.join(temp_dir, *parts))
                if os.path.commonpath([temp_dir, target]) != temp_dir:
                    raise ValueError("ZIP يحتوي مساراً خارج مجلد المشروع")
                if info.is_dir() or info.filename.endswith('/'):
                    os.makedirs(target, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with archive.open(info, 'r') as source, open(target, 'wb') as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                written += 1

        # Merge only after a fully successful extraction. Validate every existing
        # destination component again: an old symlink inside the project must not
        # redirect a ZIP write outside the project during the merge phase.
        def checked_destination(parts):
            current = base
            for component in parts:
                if component in ("", ".", "..") or ":" in component or "\x00" in component:
                    raise ValueError("مسار دمج ZIP غير آمن")
                current = os.path.join(current, component)
                if os.path.islink(current):
                    raise ValueError("لا يمكن فك ZIP فوق مسار يحتوي رابطاً رمزياً موجوداً")
                resolved = os.path.realpath(current)
                try:
                    if os.path.commonpath([base, resolved]) != base:
                        raise ValueError("مسار ZIP يحاول الخروج من مجلد المشروع")
                except ValueError as exc:
                    if "مسار ZIP" in str(exc):
                        raise
                    raise ValueError("مسار ZIP غير آمن") from exc
            return current

        for root_dir, dirs, files in os.walk(temp_dir):
            rel = os.path.relpath(root_dir, temp_dir)
            rel_parts = [] if rel == "." else rel.split(os.sep)
            out_dir = checked_destination(rel_parts) if rel_parts else base
            os.makedirs(out_dir, exist_ok=True)
            for dirname in dirs:
                checked_destination(rel_parts + [dirname])
            for filename in files:
                src = os.path.join(root_dir, filename)
                dst = checked_destination(rel_parts + [filename])
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                os.replace(src, dst)
        return written
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


ARCHIVE_EXTENSIONS = (
    ".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz"
)


def is_supported_archive(filename):
    name = str(filename or "").lower()
    return any(name.endswith(ext) for ext in ARCHIVE_EXTENSIONS)


def archive_uncompressed_size(archive_path, *, max_files=10000, max_uncompressed=500 * 1024 * 1024):
    """Return declared extracted size after validating supported archive metadata."""
    name = str(archive_path).lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as archive:
            infos = [item for item in archive.infolist() if item.filename and item.filename not in (".", "./")]
            if len(infos) > max_files:
                raise ValueError("الأرشيف يحتوي عدداً كبيراً جداً من الملفات")
            total = sum(max(0, int(item.file_size)) for item in infos)
            if total > max_uncompressed:
                raise ValueError("حجم الملفات بعد فك الضغط يتجاوز الحد المسموح")
            bad = archive.testzip()
            if bad:
                raise ValueError(f"ملف ZIP تالف: {bad}")
            return total
    try:
        with tarfile.open(archive_path, mode="r:*") as archive:
            members = archive.getmembers()
            if len(members) > max_files:
                raise ValueError("الأرشيف يحتوي عدداً كبيراً جداً من الملفات")
            total = 0
            for member in members:
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ValueError("الأرشيف يحتوي روابط أو ملفات خاصة غير مسموح بها")
                total += max(0, int(member.size))
                if total > max_uncompressed:
                    raise ValueError("حجم الملفات بعد فك الضغط يتجاوز الحد المسموح")
            return total
    except (tarfile.TarError, OSError) as exc:
        raise ValueError("صيغة الأرشيف غير مدعومة أو أن الملف تالف؛ استخدم ZIP أو TAR.GZ") from exc


def safe_extract_tar(archive_path, destination, *, max_files=10000,
                     max_uncompressed=500 * 1024 * 1024, flatten_single_root=True):
    """Safely extract TAR/TAR.GZ/TAR.BZ2/TAR.XZ without extractall or links."""
    base = os.path.realpath(os.path.abspath(destination))
    os.makedirs(base, exist_ok=True)
    temp_dir = tempfile.mkdtemp(prefix=".mazagi-extract-", dir=base)
    try:
        with tarfile.open(archive_path, mode="r:*") as archive:
            members = [m for m in archive.getmembers() if m.name and m.name not in (".", "./")]
            if len(members) > max_files:
                raise ValueError("الأرشيف يحتوي عدداً كبيراً جداً من الملفات")
            total_declared = 0
            first_parts = set()
            has_top_level_file = False
            clean_members = []
            for member in members:
                raw = member.name.replace("\\", "/")
                if raw.startswith("/") or re.match(r"^[A-Za-z]:", raw) or "\x00" in raw:
                    raise ValueError("الأرشيف يحتوي مساراً غير آمن")
                parts = [part for part in raw.split("/") if part not in ("", ".")]
                if not parts or any(part == ".." or ":" in part for part in parts):
                    raise ValueError("الأرشيف يحتوي مساراً غير آمن")
                if not (member.isdir() or member.isfile()):
                    raise ValueError("الأرشيف يحتوي رابطاً أو ملفاً خاصاً غير مسموح")
                if member.isfile():
                    total_declared += max(0, int(member.size))
                    if total_declared > max_uncompressed:
                        raise ValueError("حجم الملفات بعد فك الضغط يتجاوز الحد المسموح")
                    if len(parts) == 1:
                        has_top_level_file = True
                first_parts.add(parts[0])
                clean_members.append((member, parts))
            strip_root = flatten_single_root and len(first_parts) == 1 and not has_top_level_file
            actual_total = 0
            written = 0
            for member, original_parts in clean_members:
                parts = original_parts[1:] if strip_root else original_parts
                if not parts:
                    continue
                target = os.path.realpath(os.path.join(temp_dir, *parts))
                if os.path.commonpath([temp_dir, target]) != temp_dir:
                    raise ValueError("الأرشيف يحتوي مساراً خارج مجلد المشروع")
                if member.isdir():
                    os.makedirs(target, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError("تعذرت قراءة أحد ملفات الأرشيف")
                with source, open(target, "wb") as output:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        actual_total += len(chunk)
                        if actual_total > max_uncompressed:
                            raise ValueError("تجاوز الأرشيف الحجم الفعلي المسموح بعد فك الضغط")
                        output.write(chunk)
                written += 1

        # Merge through checked paths only; a pre-existing symlink may not redirect writes.
        def checked_destination(parts):
            current = base
            for component in parts:
                if component in ("", ".", "..") or ":" in component or "\x00" in component:
                    raise ValueError("مسار دمج الأرشيف غير آمن")
                current = os.path.join(current, component)
                if os.path.islink(current):
                    raise ValueError("لا يمكن فك الأرشيف فوق مسار يحتوي رابطاً رمزياً")
                resolved = os.path.realpath(current)
                if os.path.commonpath([base, resolved]) != base:
                    raise ValueError("مسار الأرشيف يحاول الخروج من مجلد المشروع")
            return current

        for root_dir, dirs, files in os.walk(temp_dir):
            rel = os.path.relpath(root_dir, temp_dir)
            rel_parts = [] if rel == "." else rel.split(os.sep)
            out_dir = checked_destination(rel_parts) if rel_parts else base
            os.makedirs(out_dir, exist_ok=True)
            for dirname in dirs:
                checked_destination(rel_parts + [dirname])
            for filename in files:
                src = os.path.join(root_dir, filename)
                dst = checked_destination(rel_parts + [filename])
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                os.replace(src, dst)
        return written
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def safe_extract_archive(archive_path, destination, **kwargs):
    """Single safe extraction entrypoint for supported ZIP and TAR formats."""
    if str(archive_path).lower().endswith(".zip"):
        return safe_extract_zip(archive_path, destination, **kwargs)
    return safe_extract_tar(archive_path, destination, **kwargs)

db = load_db()
DEFAULT_SETTINGS = {
    "global_max_servers": 2,
    "max_file_size_mb": 100,
    "registration_status": "open",
}

def _backup_current_db_once():
    """ينشئ نسخة احتياطية غير مدمرة من قاعدة البيانات الحالية قبل أي إصلاح."""
    try:
        if not os.path.exists(DB_FILE):
            return
        backup_dir = os.path.join(DATA_DIR, "backups")
        os.makedirs(backup_dir, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = os.path.join(backup_dir, f"db_before_update_{stamp}.json")
        if not os.path.exists(target):
            shutil.copy2(DB_FILE, target)
    except Exception as exc:
        print(f"⚠️ تعذر إنشاء نسخة DB احتياطية: {exc}")

def _safe_server_dir(owner, folder):
    owner = safe_user_filename(owner)
    folder = safe_user_filename(folder)
    if not owner or not folder:
        return None
    return os.path.join(USERS_DIR, owner, "SERVERS", folder)

def _copy_tree_if_needed(src, dst):
    try:
        if not src or not os.path.exists(src) or os.path.exists(dst):
            return False
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.isdir(src):
            shutil.copytree(src, dst, dirs_exist_ok=True)
        else:
            shutil.copy2(src, dst)
        return True
    except Exception as exc:
        print(f"⚠️ تعذر استرجاع الملفات من {src}: {exc}")
        return False

def migrate_server_storage():
    """يربط السيرفرات القديمة بمسار /data بدون حذف أي ملف.
    إذا كانت الملفات ما زالت في المسار القديم، يتم نسخها إلى التخزين الدائم.
    """
    changed = False
    for folder, srv in db.get("servers", {}).items():
        owner = srv.get("owner")
        persistent = _safe_server_dir(owner, folder)
        if not persistent:
            continue
        os.makedirs(os.path.dirname(persistent), exist_ok=True)
        current = srv.get("path") or ""
        if os.path.abspath(current) != os.path.abspath(persistent):
            candidates = [current,
                          os.path.join(BASE_DIR, "USERS", str(owner), "SERVERS", str(folder)),
                          os.path.join("/app", "USERS", str(owner), "SERVERS", str(folder))]
            for candidate in candidates:
                if candidate and os.path.exists(candidate):
                    _copy_tree_if_needed(candidate, persistent)
                    break
            srv["path"] = persistent
            changed = True
        else:
            os.makedirs(persistent, exist_ok=True)
    if changed:
        save_db(db)

_backup_current_db_once()
settings_changed = False
db.setdefault("settings", {})
for _setting_key, _setting_value in DEFAULT_SETTINGS.items():
    if _setting_key not in db["settings"]:
        db["settings"][_setting_key] = _setting_value
        settings_changed = True
try:
    app.config["MAX_CONTENT_LENGTH"] = int(db["settings"].get("max_file_size_mb", 100)) * 1024 * 1024
except (TypeError, ValueError):
    app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024
if settings_changed:
    save_db(db)
migrate_server_storage()

# ============== كشف تلقائي لنوع السيرفر ==============
def _project_files(srv_path, suffixes):
    found = []
    for root_dir, dirs, files in os.walk(srv_path):
        dirs[:] = [d for d in dirs if d not in {".venv", "venv", "__pycache__", ".git", "node_modules", "vendor"}]
        for name in files:
            if name.lower().endswith(suffixes):
                found.append(os.path.relpath(os.path.join(root_dir, name), srv_path).replace(os.sep, '/'))
    return sorted(found, key=lambda x: (x.count('/'), x.lower()))


def _node_project_manifest(srv_path):
    """Return (project_dir, package_data, relative_manifest) for the shallowest package.json."""
    manifests = _project_files(srv_path, ("package.json",))
    for relative in manifests:
        manifest_path = os.path.join(srv_path, relative)
        try:
            with open(manifest_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            return os.path.dirname(manifest_path) or srv_path, data, relative
        except (OSError, ValueError, TypeError):
            continue
    return None, {}, ""


def _static_site_entry(srv_path):
    """Find an HTML entrypoint, preferring index.html and the shallowest site root."""
    index_files = _project_files(srv_path, ("index.html", "index.htm"))
    if index_files:
        return index_files[0]
    html_files = _project_files(srv_path, (".html", ".htm"))
    return html_files[0] if html_files else ""


def _static_site_root(srv_path, entrypoint=None):
    # Ignore stale Python/Node startup selections after changing a project into a website.
    if not entrypoint or not str(entrypoint).lower().endswith((".html", ".htm")):
        entrypoint = _static_site_entry(srv_path)
    entry_path = safe_relative_path(srv_path, entrypoint) if entrypoint else None
    if entry_path and os.path.isfile(entry_path):
        return os.path.dirname(entry_path) or srv_path
    return srv_path


def _node_build_output_dir(srv_path):
    """Find common static outputs, including nested Angular browser and framework exports."""
    project_dir, package_data, _relative = _node_project_manifest(srv_path)
    if not project_dir:
        return ""
    output_names = ("dist", "build", "out", "public", "www")
    # Prefer conventional output roots, but allow frameworks such as Angular to
    # produce dist/<application>/browser/index.html.
    for name in output_names:
        candidate = os.path.join(project_dir, name)
        if os.path.isdir(candidate):
            for index_name in ("index.html", "index.htm"):
                if os.path.isfile(os.path.join(candidate, index_name)):
                    return candidate
            for root_dir, dirs, files in os.walk(candidate):
                rel_depth = os.path.relpath(root_dir, candidate).count(os.sep)
                dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", ".next", ".nuxt"}]
                if rel_depth > 4:
                    dirs[:] = []
                    continue
                if "index.html" in files or "index.htm" in files:
                    return root_dir
    # Framework-specific output roots (only when the generated entry exists).
    framework_candidates = (
        os.path.join(project_dir, ".output", "public"),
        os.path.join(project_dir, ".next", "server", "app"),
        os.path.join(project_dir, "wwwroot"),
    )
    for candidate in framework_candidates:
        if os.path.isfile(os.path.join(candidate, "index.html")):
            return candidate
    return ""


def _node_built_script(srv_path):
    """Find common compiled Node entrypoints for TypeScript/backend build-only projects."""
    project_dir, package_data, _relative = _node_project_manifest(srv_path)
    if not project_dir:
        return ""
    candidates = []
    main = package_data.get("main") if package_data else None
    if main:
        candidates.append(os.path.normpath(os.path.join(project_dir, str(main))))
    for folder in ("dist", "build", "lib", os.path.join(".output", "server"), os.path.join(".next", "standalone"), "server"):
        for name in ("index.js", "main.js", "server.js", "bot.js", "app.js", "index.mjs", "index.cjs"):
            candidates.append(os.path.join(project_dir, folder, name))
    for candidate in candidates:
        full = os.path.abspath(candidate)
        if os.path.isfile(full) and os.path.commonpath([os.path.realpath(project_dir), os.path.realpath(full)]) == os.path.realpath(project_dir):
            return full
    return ""


def auto_detect_server_type(srv_path: str, srv: dict):
    """Detect bots, backend apps, PHP sites, Node sites and static HTML websites."""
    if not os.path.isdir(srv_path):
        return False
    try:
        package_dir, package_data, package_rel = _node_project_manifest(srv_path)
        scripts = (package_data.get("scripts") or {}) if package_data else {}
        has_node_runtime = bool(
            package_dir and (
                scripts.get("start") or scripts.get("build") or scripts.get("dev")
                or package_data.get("main")
            )
        )
        php_files = _project_files(srv_path, (".php",))
        php_index = _project_files(srv_path, ("index.php",))
        py_files = _project_files(srv_path, (".py",))
        html_entry = _static_site_entry(srv_path)
        js_files = _project_files(srv_path, (".js", ".mjs", ".cjs", ".ts", ".tsx"))

        preferred_python = ("manage.py", "main.py", "bot.py", "app.py", "server.py", "run.py", "start.py", "wsgi.py", "asgi.py")
        has_python_entry = any(os.path.basename(name).lower() in preferred_python for name in py_files)
        root_node_entry = any(
            os.path.isfile(os.path.join(srv_path, name))
            for name in ("server.js", "bot.js", "app.js", "main.js", "index.js", "server.mjs", "index.mjs")
        )

        # Explicit backend manifests/entrypoints take precedence over frontend assets.
        if has_node_runtime or (not html_entry and root_node_entry):
            detected = "Node.js"
        elif php_index or (html_entry and php_files):
            detected = "PHP"
        elif has_python_entry:
            detected = "Python"
        elif html_entry:
            detected = "Static Website"
        elif package_dir or js_files:
            detected = "Node.js"
        elif php_files:
            detected = "PHP"
        elif py_files:
            detected = "Python"
        else:
            return False

        type_changed = srv.get("type") != detected
        changed = type_changed
        srv["type"] = detected
        startup = srv.get("startup_file") or ""
        startup_path = safe_relative_path(srv_path, startup) if startup else None
        if type_changed or not startup_path or not os.path.isfile(startup_path):
            srv["startup_file"] = detect_main_file(srv_path, detected)
            changed = True
        if changed:
            save_db(db)
        return changed
    except Exception as exc:
        print(f"⚠️ خطأ في الكشف التلقائي: {exc}")
        return False


def fix_server_types():
    updated = False
    for folder, srv in db.get("servers", {}).items():
        old_type, old_start = srv.get("type"), srv.get("startup_file")
        auto_detect_server_type(srv.get("path", ""), srv)
        if old_type != srv.get("type") or old_start != srv.get("startup_file"):
            updated = True
    if updated:
        save_db(db)

fix_server_types()

# ============== المنافذ ==============
PORT_RANGE_START = 8100
PORT_RANGE_END = 9100
_PORT_RESERVATION_LOCK = threading.RLock()
_RESERVED_PORTS = set()

def get_assigned_port():
    """Reserve a free internal port atomically across concurrent upload requests."""
    with _PORT_RESERVATION_LOCK:
        used = set(_RESERVED_PORTS)
        for srv in db.get("servers", {}).values():
            try:
                if srv.get("port"):
                    used.add(int(srv["port"]))
            except (TypeError, ValueError):
                continue
        for port in range(PORT_RANGE_START, PORT_RANGE_END):
            if port in used:
                continue
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
                sock.settimeout(0.1)
                if sock.connect_ex(('127.0.0.1', port)) == 0:
                    continue
                _RESERVED_PORTS.add(port)
                return port
            finally:
                sock.close()
        raise RuntimeError("لا توجد منافذ داخلية متاحة حالياً؛ احذف سيرفراً متوقفاً أو وسّع نطاق المنافذ")


def _release_port_reservation(port):
    try:
        with _PORT_RESERVATION_LOCK:
            _RESERVED_PORTS.discard(int(port))
    except (TypeError, ValueError):
        pass

# ============== كشف الملف الرئيسي ==============
def detect_main_file(srv_path: str, server_type: str) -> str:
    """Find a sensible runtime/site entrypoint, including nested ZIP projects."""
    if server_type == "Static Website":
        return _static_site_entry(srv_path)
    if server_type == "Node.js":
        project_dir, data, rel_pkg = _node_project_manifest(srv_path)
        if project_dir:
            project_rel = os.path.dirname(rel_pkg)
            main = data.get("main") or ""
            if main:
                candidate = os.path.normpath(os.path.join(project_rel, main)).replace(os.sep, '/')
                if os.path.isfile(os.path.join(srv_path, candidate)):
                    return candidate
            scripts = data.get("scripts") or {}
            if scripts.get("start") or scripts.get("build") or scripts.get("dev"):
                return rel_pkg
        files = _project_files(srv_path, (".js", ".mjs", ".cjs", ".ts", ".tsx"))
        preferred = ("server.js", "bot.js", "app.js", "main.js", "index.js", "index.mjs", "main.cjs")
        for name in preferred:
            for rel in files:
                if os.path.basename(rel).lower() == name:
                    return rel
        return files[0] if files else ""
    if server_type == "PHP":
        files = _project_files(srv_path, (".php",))
        preferred = ("index.php", "main.php", "bot.php", "app.php", "start.php", "run.php")
        for name in preferred:
            for rel in files:
                if os.path.basename(rel).lower() == name:
                    return rel
        return files[0] if files else ""
    if server_type == "Python":
        files = _project_files(srv_path, (".py",))
        preferred = ("manage.py", "main.py", "bot.py", "app.py", "server.py", "index.py", "run.py", "start.py")
        for name in preferred:
            for rel in files:
                if os.path.basename(rel).lower() == name:
                    return rel
        return files[0] if files else ""
    return ""

# ============== تثبيت تلقائي للمكتبات ==============
# أسماء الاستيراد الشائعة التي تختلف عن اسم الحزمة في PyPI.
PYTHON_PACKAGE_MAP = {
    "telebot": "pyTelegramBotAPI",
    "telegram": "python-telegram-bot",
    "bs4": "beautifulsoup4",
    "Crypto": "pycryptodome",
    "PIL": "Pillow",
    "cv2": "opencv-python",
    "dotenv": "python-dotenv",
    "yaml": "PyYAML",
    "dns": "dnspython",
    "jwt": "PyJWT",
    "google": "google-api-python-client",
    "googleapiclient": "google-api-python-client",
    "selenium": "selenium",
    "discord": "discord.py",
    "discord_webhook": "discord-webhook",
    "flask": "Flask",
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "aiohttp": "aiohttp",
    "httpx": "httpx",
    "bs4": "beautifulsoup4",
    "lxml": "lxml",
    "pandas": "pandas",
    "numpy": "numpy",
    "openpyxl": "openpyxl",
    "qrcode": "qrcode",
    "rich": "rich",
    "colorama": "colorama",
    "fake_useragent": "fake-useragent",
    "user_agent": "user-agent",
    "jwt": "PyJWT",
    "cryptography": "cryptography",
    "dateutil": "python-dateutil",
    "pytz": "pytz",
    "requests_html": "requests-html",
    "schedule": "schedule",
    "apscheduler": "APScheduler",
    "pydantic": "pydantic",
    "peewee": "peewee",
    "sqlalchemy": "SQLAlchemy",
    "aiogram": "aiogram",
    "pyrogram": "pyrogram",
    "telethon": "Telethon",
    "instaloader": "instaloader",
    "yt_dlp": "yt-dlp",
    "cv": "opencv-python",
    "telegramify_markdown": "telegramify-markdown",
}

PYTHON_STDLIB = set(getattr(sys, "stdlib_module_names", set())) | {
    "__future__", "typing_extensions"
}


def _python_imports_from_file(py_file):
    """استخراج أسماء المكتبات الخارجية من ملف Python بدون تشغيله."""
    modules = set()
    try:
        with open(py_file, "r", encoding="utf-8", errors="ignore") as f:
            tree = ast.parse(f.read(), filename=py_file)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    modules.add(alias.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module.split('.')[0])
    except Exception:
        # إذا كان الملف فيه خطأ صياغة، التشغيل نفسه سيعرض الخطأ للمستخدم.
        return set()
    return modules


def detect_python_packages(srv_path):
    """Detect third-party imports across the whole project, not just root files."""
    imports = set()
    local_modules = set()
    for root_dir, dirs, files in os.walk(srv_path):
        dirs[:] = [d for d in dirs if d not in {".venv", "venv", "__pycache__", ".git", "node_modules", "vendor"}]
        for name in files:
            if name.endswith('.py'):
                full = os.path.join(root_dir, name)
                imports.update(_python_imports_from_file(full))
                local_modules.add(name[:-3])
        for dirname in dirs:
            if os.path.isfile(os.path.join(root_dir, dirname, "__init__.py")):
                local_modules.add(dirname)

    packages = []
    for module in sorted(imports):
        if module in PYTHON_STDLIB or module in local_modules or module.startswith('_'):
            continue
        package = PYTHON_PACKAGE_MAP.get(module, module)
        packages.append(package)
    return list(dict.fromkeys(packages))


def _requirements_package_key(line):
    clean = line.strip()
    if not clean or clean.startswith('#') or clean.startswith(('-', 'git+', 'http:', 'https:', '.')):
        return None
    match = re.match(r'([A-Za-z0-9_.-]+)', clean)
    return match.group(1).lower().replace('_', '-') if match else None


def _prepare_python_requirements(srv_path, log_file=None):
    # ZIP archives may contain a project under a nested folder. Prefer the
    # shallowest existing requirements.txt so pinned dependencies are honored.
    requirement_files = _project_files(srv_path, ("requirements.txt",))
    req_file = os.path.join(srv_path, requirement_files[0]) if requirement_files else os.path.join(srv_path, "requirements.txt")
    existing = []
    if os.path.isfile(req_file):
        with open(req_file, "r", encoding="utf-8", errors="ignore") as f:
            existing = [line.rstrip() for line in f if line.strip()]
    existing_keys = {_requirements_package_key(x) for x in existing}
    existing_keys.discard(None)
    inferred = detect_python_packages(srv_path)
    if any(name.lower().replace("_", "-") == "fastapi" for name in inferred):
        inferred.append("uvicorn")
    missing = []
    for package in inferred:
        key = package.lower().replace('_', '-')
        if key not in existing_keys:
            missing.append(package)
            existing_keys.add(key)
    if missing:
        with open(req_file, "a", encoding="utf-8") as f:
            if existing and not existing[-1].endswith('\n'):
                f.write("\n")
            f.write("\n".join(missing) + "\n")
        if log_file:
            log_file.write("\n🔎 تم اكتشاف مكتبات ناقصة وإضافتها تلقائياً: " + ", ".join(missing) + "\n")
            log_file.flush()
    elif not os.path.exists(req_file):
        with open(req_file, "w", encoding="utf-8") as f:
            f.write("")
    return req_file


_PROJECT_ENV_LOCK = threading.RLock()
_PROJECT_ENV_RESERVED = {
    "PATH", "HOME", "USERPROFILE", "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD",
    "LD_LIBRARY_PATH", "PORT", "SERVER_PORT", "HOST", "HOSTNAME", "NUXT_HOST",
    "NUXT_PORT", "MAZAGI_SERVER_FOLDER", "MAZAGI_SERVER_OWNER", "MAZAGI_DATA_DIR",
    "SECRET_KEY", "ADMIN_PASSWORD", "ADMIN_USERNAME", "ADMIN_TELEGRAM_ID",
    "TELEGRAM_WEBHOOK_SECRET", "COOKIE_SECURE", "RAILWAY_ENVIRONMENT", "RENDER",
}


def _load_user_dotenv(project_dir):
    """Read simple KEY=VALUE pairs from a project's own .env; never read host secrets."""
    env_path = safe_relative_path(project_dir, ".env")
    if not env_path or not os.path.isfile(env_path):
        # ZIPs may contain a project folder inside the archive. If there is no
        # root .env, load the shallowest project-local .env without traversing
        # dependency, cache or VCS directories.
        candidates = _project_files(project_dir, (".env",))
        env_path = safe_relative_path(project_dir, candidates[0]) if candidates else None
    if not env_path or not os.path.isfile(env_path) or os.path.islink(env_path):
        return {}
    try:
        if os.path.getsize(env_path) > 128 * 1024:
            return {}
        values = {}
        with open(env_path, "r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[7:].lstrip()
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", key):
                    continue
                if key.upper() in _PROJECT_ENV_RESERVED or key.upper().startswith(("MAZAGI_", "RAILWAY_", "RENDER_")):
                    continue
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                    value = value[1:-1]
                elif " #" in value:
                    value = value.split(" #", 1)[0].rstrip()
                if "\x00" in value:
                    continue
                values[key] = value
        return values
    except OSError:
        return {}


def _build_project_environment(project_dir, *, folder=None, owner=None, port=None):
    """Build an allow-listed environment for uploaded code and package installers.

    The host process environment is deliberately NOT inherited, so project code
    cannot accidentally receive the platform's Flask, admin, or Telegram secrets.
    Project-specific values may be supplied by that project's own .env file.
    """
    allowed_host_keys = (
        "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "SYSTEMROOT",
        "WINDIR", "COMSPEC", "PATHEXT",
    )
    env = {key: os.environ[key] for key in allowed_host_keys if os.environ.get(key)}
    project_home = os.path.join(project_dir, ".mazagi-home")
    project_tmp = os.path.join(project_dir, ".mazagi-tmp")
    try:
        os.makedirs(project_home, exist_ok=True)
        os.makedirs(project_tmp, exist_ok=True)
    except OSError:
        pass
    env.update({
        "HOME": project_home,
        "USERPROFILE": project_home,
        "TMPDIR": project_tmp,
        "TEMP": project_tmp,
        "TMP": project_tmp,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_CACHE_DIR": os.path.join(project_home, ".cache", "pip"),
        "npm_config_cache": os.path.join(project_home, ".cache", "npm"),
        "PYTHONUNBUFFERED": "1",
    })
    env.update(_load_user_dotenv(project_dir))
    if port is not None:
        env.update({
            "PORT": str(int(port)), "SERVER_PORT": str(int(port)),
            "HOST": "0.0.0.0", "HOSTNAME": "0.0.0.0",
            "NUXT_HOST": "0.0.0.0", "NUXT_PORT": str(int(port)),
            "GRADIO_SERVER_NAME": "0.0.0.0", "GRADIO_SERVER_PORT": str(int(port)),
            "STREAMLIT_SERVER_ADDRESS": "0.0.0.0", "STREAMLIT_SERVER_PORT": str(int(port)),
        })
    if folder:
        env["MAZAGI_SERVER_FOLDER"] = str(folder)
    if owner:
        env["MAZAGI_SERVER_OWNER"] = str(owner)
    return env


def _file_digest(paths):
    digest = hashlib.sha256()
    for path in paths:
        digest.update(os.path.basename(path).encode("utf-8", errors="ignore"))
        try:
            with open(path, "rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
        except OSError:
            digest.update(b"<missing>")
    return digest.hexdigest()


def _run_install_command(cmd, cwd, log_file, timeout=600, label="تثبيت المكتبات", env=None):
    if log_file:
        log_file.write(f"\n📦 {label}...\n")
        log_file.flush()
    try:
        with open(os.devnull, 'wb') as null_out:
            output = log_file if log_file else null_out
            result = subprocess.run(
                cmd, cwd=cwd, stdout=output, stderr=subprocess.STDOUT,
                timeout=timeout, check=False, text=False,
                env=env or _build_project_environment(cwd)
            )
        if result.returncode != 0:
            raise RuntimeError(f"فشل {label} (رمز الخروج {result.returncode})؛ راجع سجل الأخطاء")
        if log_file:
            log_file.write(f"✅ اكتمل {label} بنجاح\n")
            log_file.flush()
        return True
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"انتهت مهلة {label}. تحقق من اتصال الاستضافة أو حجم المتطلبات")
    except FileNotFoundError as exc:
        raise RuntimeError(f"أداة مطلوبة غير مثبتة: {exc.filename}")


def ensure_python_environment(srv_path, log_file=None):
    """Create an isolated venv per project and install declared + inferred packages."""
    venv_dir = os.path.join(srv_path, ".venv")
    venv_python = os.path.join(venv_dir, "Scripts", "python.exe") if os.name == "nt" else os.path.join(venv_dir, "bin", "python")
    if not os.path.isfile(venv_python):
        if log_file:
            log_file.write("\n🧰 إنشاء بيئة Python مستقلة لهذا السيرفر...\n")
            log_file.flush()
        result = subprocess.run([sys.executable, "-m", "venv", venv_dir], cwd=srv_path,
                                capture_output=True, text=True, timeout=180)
        if result.returncode != 0 or not os.path.isfile(venv_python):
            detail = (result.stderr or result.stdout or "تعذر إنشاء البيئة الافتراضية")[-1500:]
            raise RuntimeError(detail)

    req_file = _prepare_python_requirements(srv_path, log_file)
    req_content = open(req_file, "rb").read()
    digest = hashlib.sha256(req_content).hexdigest()
    marker = os.path.join(venv_dir, ".mazagi_requirements_sha256")
    previous = ""
    try:
        previous = open(marker, "r", encoding="ascii").read().strip()
    except OSError:
        pass

    needs_install = bool(req_content.strip() and previous != digest)
    project_env = _build_project_environment(srv_path)
    if req_content.strip() and not needs_install:
        integrity = subprocess.run(
            [venv_python, "-m", "pip", "check"], cwd=srv_path,
            capture_output=True, text=True, timeout=120, env=project_env
        )
        if integrity.returncode != 0:
            needs_install = True
            if log_file:
                log_file.write("⚠️ اكتشف الفحص خللاً في بيئة Python؛ ستتم محاولة إصلاح المكتبات تلقائياً.\n")
                log_file.write((integrity.stdout or integrity.stderr or "")[-4000:] + "\n")
                log_file.flush()
    if needs_install:
        _run_install_command(
            [venv_python, "-m", "pip", "install", "--disable-pip-version-check", "-r", req_file],
            os.path.dirname(req_file), log_file, timeout=900, label="تثبيت/إصلاح مكتبات Python", env=project_env
        )
        _run_install_command([venv_python, "-m", "pip", "check"], srv_path, log_file,
                             timeout=120, label="فحص توافق مكتبات Python", env=project_env)
        with open(marker, "w", encoding="ascii") as f:
            f.write(digest)
    elif log_file:
        log_file.write("✅ فحص مكتبات Python ناجح؛ لم تتغير المتطلبات وتم تخطي إعادة التثبيت\n")
        log_file.flush()
    return venv_python


def _node_project_dir(srv_path):
    project_dir, _data, _relative = _node_project_manifest(srv_path)
    return project_dir or srv_path


def _node_build_source_digest(project_dir):
    """Hash Node project inputs while excluding dependencies and generated output."""
    digest = hashlib.sha256()
    ignored_dirs = {
        ".git", ".venv", "venv", "node_modules", "vendor", "__pycache__",
        ".next", ".nuxt", ".output", ".svelte-kit", ".angular", ".turbo",
        ".astro", ".vercel", ".netlify", ".mazagi-home", ".mazagi-tmp",
        "dist", "build", "out", "coverage", ".cache",
    }
    ignored_files = {
        ".mazagi_node_build_sha256", ".mazagi_node_deps_sha256",
        "out.log", "errors.log", "server.log",
    }
    project_real = os.path.realpath(project_dir)
    for root_dir, dirs, files in os.walk(project_real):
        dirs[:] = sorted(d for d in dirs if d not in ignored_dirs and not os.path.islink(os.path.join(root_dir, d)))
        for name in sorted(files):
            if name in ignored_files or name.endswith((".pyc", ".log", ".tmp", ".upload_tmp")):
                continue
            full = os.path.join(root_dir, name)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            relative = os.path.relpath(full, project_real).replace(os.sep, "/")
            digest.update(relative.encode("utf-8", errors="replace"))
            digest.update(b"\0")
            try:
                with open(full, "rb") as handle:
                    while True:
                        chunk = handle.read(1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
            except OSError:
                digest.update(b"<unreadable>")
            digest.update(b"\0")
    return digest.hexdigest()


def _runtime_working_dir(srv):
    srv_path = srv.get("path", "")
    server_type = srv.get("type")
    if server_type == "Static Website":
        return _static_site_root(srv_path, srv.get("startup_file"))
    if server_type == "Node.js":
        project_dir, data, _relative = _node_project_manifest(srv_path)
        if project_dir and not (data.get("scripts") or {}).get("start"):
            build_root = _node_build_output_dir(srv_path)
            if build_root:
                return build_root
        return _node_project_dir(srv_path)
    startup_file = srv.get("startup_file") or detect_main_file(srv_path, server_type or "Python")
    startup_path = safe_relative_path(srv_path, startup_file) if startup_file else None
    if startup_path and os.path.isfile(startup_path):
        # Run from the entry-point folder so sibling imports and relative files
        # behave like a normal local project, even when the ZIP has a wrapper dir.
        return os.path.dirname(startup_path) or srv_path
    return srv_path


def _node_package_manager(project_dir, package_data=None):
    """Choose the package manager declared by the project, then its lock file."""
    package_data = package_data or {}
    declared = str(package_data.get("packageManager", "")).lower()
    if declared.startswith("pnpm@") or os.path.isfile(os.path.join(project_dir, "pnpm-lock.yaml")):
        return ["corepack", "pnpm"]
    if declared.startswith("yarn@") or os.path.isfile(os.path.join(project_dir, "yarn.lock")):
        return ["corepack", "yarn"]
    if os.path.isfile(os.path.join(project_dir, "bun.lock")) or os.path.isfile(os.path.join(project_dir, "bun.lockb")):
        raise RuntimeError("المشروع يستخدم Bun، وهو غير مثبت في صورة الاستضافة الحالية. استخدم npm أو pnpm أو Yarn حالياً.")
    return ["npm"]


def _node_script_command(project_dir, package_data, script_name, *extra_args):
    return _node_package_manager(project_dir, package_data) + ["run", script_name] + list(extra_args)


def auto_install_deps(srv_path: str, server_type: str, log_file):
    """Install dependencies for a project's runtime. Errors prevent unsafe start attempts."""
    try:
        if server_type == "Static Website":
            # HTML/CSS/JS static sites use Python's built-in HTTP server; no packages required.
            if log_file:
                log_file.write("✅ موقع ثابت: لا يحتاج تثبيت مكتبات؛ سيتم تقديم ملفات HTML/CSS/JS مباشرة\n")
                log_file.flush()
        elif server_type == "Node.js":
            if not shutil.which("node"):
                raise RuntimeError("Node.js غير مثبت في بيئة الاستضافة")
            project_dir = _node_project_dir(srv_path)
            package_file = os.path.join(project_dir, "package.json")
            if os.path.isfile(package_file):
                if not shutil.which("npm"):
                    raise RuntimeError("npm غير مثبت في بيئة الاستضافة")
                try:
                    with open(package_file, "r", encoding="utf-8") as handle:
                        package_data = json.load(handle)
                except (OSError, ValueError, TypeError) as exc:
                    raise RuntimeError(f"ملف package.json غير صالح أو تعذرت قراءته: {exc}") from exc
                declared_dependencies = any(
                    bool(package_data.get(key))
                    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
                )
                lock = os.path.join(project_dir, "package-lock.json")
                yarn_lock = os.path.join(project_dir, "yarn.lock")
                pnpm_lock = os.path.join(project_dir, "pnpm-lock.yaml")
                marker = os.path.join(project_dir, ".mazagi_node_deps_sha256")
                dependency_files = [package_file] + [x for x in (lock, yarn_lock, pnpm_lock) if os.path.isfile(x)]
                digest = _file_digest(dependency_files)
                previous = ""
                try:
                    previous = open(marker, "r", encoding="ascii").read().strip()
                except OSError:
                    pass
                node_modules = os.path.join(project_dir, "node_modules")
                dependencies_valid = previous == digest and (os.path.isdir(node_modules) or not declared_dependencies)
                if dependencies_valid and declared_dependencies and os.path.isdir(node_modules) and not (os.path.isfile(pnpm_lock) or os.path.isfile(yarn_lock)):
                    # Detect an incomplete node_modules directory instead of trusting
                    # a stale cache marker after a user deletes individual packages.
                    integrity = subprocess.run(
                        ["npm", "ls", "--depth=0", "--json", "--omit=optional"],
                        cwd=project_dir, capture_output=True, text=True, timeout=90,
                        env=_build_project_environment(srv_path)
                    )
                    dependencies_valid = integrity.returncode == 0
                    if not dependencies_valid and log_file:
                        log_file.write("⚠️ اكتشف الفحص نقصاً في حزم Node.js؛ ستتم إعادة تثبيتها\n")
                        log_file.write((integrity.stderr or integrity.stdout or "")[-2500:] + "\n")
                        log_file.flush()
                if not dependencies_valid:
                    declared_pm = str(package_data.get("packageManager", "")).lower()
                    if os.path.isfile(pnpm_lock) or declared_pm.startswith("pnpm@"):
                        if not shutil.which("corepack"):
                            raise RuntimeError("المشروع يستخدم pnpm لكن corepack غير متاح في بيئة الاستضافة")
                        cmd = ["corepack", "pnpm", "install", "--frozen-lockfile"]
                    elif os.path.isfile(yarn_lock) or declared_pm.startswith("yarn@"):
                        if not shutil.which("corepack"):
                            raise RuntimeError("المشروع يستخدم Yarn لكن corepack غير متاح في بيئة الاستضافة")
                        yarn_v1 = False
                        try:
                            yarn_v1 = "yarn lockfile v1" in open(yarn_lock, "r", encoding="utf-8", errors="ignore").read(300).lower()
                        except OSError:
                            pass
                        cmd = ["corepack", "yarn", "install", "--frozen-lockfile" if yarn_v1 else "--immutable"]
                    else:
                        cmd = ["npm", "ci", "--no-audit", "--no-fund"] if os.path.isfile(lock) else ["npm", "install", "--no-audit", "--no-fund"]
                    _run_install_command(cmd, project_dir, log_file, timeout=900, label="تثبيت مكتبات Node.js",
                                         env=_build_project_environment(srv_path))
                    # npm install may generate package-lock.json when the uploader
                    # did not include one; cache the post-install fingerprint to
                    # avoid an unnecessary reinstall on the next restart.
                    refreshed_dependency_files = [package_file] + [
                        candidate for candidate in (lock, yarn_lock, pnpm_lock)
                        if os.path.isfile(candidate)
                    ]
                    digest = _file_digest(refreshed_dependency_files)
                    with open(marker, "w", encoding="ascii") as handle:
                        handle.write(digest)
                elif log_file:
                    log_file.write("✅ مكتبات Node.js مثبتة ومطابقة لملفات القفل؛ تم تخطي إعادة التثبيت\n")
                    log_file.flush()
                if (package_data.get("scripts") or {}).get("build"):
                    build_marker = os.path.join(project_dir, ".mazagi_node_build_sha256")
                    source_digest = _node_build_source_digest(project_dir)
                    previous_build = ""
                    try:
                        previous_build = open(build_marker, "r", encoding="ascii").read().strip()
                    except OSError:
                        pass
                    needs_build = previous_build != source_digest
                    if needs_build:
                        _run_install_command(_node_script_command(project_dir, package_data, "build"), project_dir, log_file,
                                             timeout=1200, label="بناء ملفات الموقع (npm run build)",
                                             env=_build_project_environment(srv_path))
                        if not (package_data.get("scripts") or {}).get("start") and not (
                            _node_build_output_dir(srv_path) or _node_built_script(srv_path)
                        ):
                            raise RuntimeError("اكتمل أمر build لكن لم أجد ناتج موقع (index.html داخل dist/build/out/public) أو ملف تشغيل Node داخل dist/build/lib")
                        with open(build_marker, "w", encoding="ascii") as handle:
                            handle.write(source_digest)
                    elif log_file:
                        log_file.write("✅ ملفات البناء لم تتغير؛ تم تخطي إعادة البناء\n")
                        log_file.flush()
        elif server_type == "PHP":
            if not shutil.which("php"):
                raise RuntimeError("PHP غير مثبت في بيئة الاستضافة")
            composer_manifests = _project_files(srv_path, ("composer.json",))
            composer_dir = os.path.dirname(os.path.join(srv_path, composer_manifests[0])) if composer_manifests else srv_path
            composer_file = os.path.join(composer_dir, "composer.json")
            if os.path.isfile(composer_file):
                if not shutil.which("composer"):
                    raise RuntimeError("Composer غير مثبت في بيئة الاستضافة")
                composer_lock = os.path.join(composer_dir, "composer.lock")
                marker = os.path.join(composer_dir, ".mazagi_composer_deps_sha256")
                digest = _file_digest([composer_file] + ([composer_lock] if os.path.isfile(composer_lock) else []))
                previous = ""
                try:
                    previous = open(marker, "r", encoding="ascii").read().strip()
                except OSError:
                    pass
                if previous != digest or not os.path.isfile(os.path.join(composer_dir, "vendor", "autoload.php")):
                    _run_install_command(["composer", "install", "--no-interaction", "--no-dev", "--prefer-dist"],
                                         composer_dir, log_file, timeout=900, label="تثبيت مكتبات PHP",
                                         env=_build_project_environment(srv_path))
                    with open(marker, "w", encoding="ascii") as handle:
                        handle.write(digest)
                elif log_file:
                    log_file.write("✅ مكتبات Composer مثبتة ومطابقة للملفات؛ تم تخطي إعادة التثبيت\n")
                    log_file.flush()
        else:
            ensure_python_environment(srv_path, log_file)
        return True
    except Exception as exc:
        if log_file:
            log_file.write(f"\n❌ تعذر تجهيز بيئة التشغيل: {exc}\n")
            log_file.flush()
        return False

# ============== تشغيل السيرفر ==============
_PROCESS_LOCKS = {}
_PROCESS_LOCKS_GUARD = threading.Lock()


def _server_lock(folder):
    with _PROCESS_LOCKS_GUARD:
        return _PROCESS_LOCKS.setdefault(folder, threading.RLock())


def _process_is_alive(srv):
    pid = srv.get("pid")
    if not pid:
        return False
    try:
        proc = psutil.Process(int(pid))
        if not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE:
            return False
        created = srv.get("process_create_time")
        if created is not None:
            return abs(proc.create_time() - float(created)) < 2.0
        # Legacy rows have no creation time: only trust the PID if its working directory
        # is still within this server's directory. This avoids treating a reused PID as ours.
        expected = os.path.realpath(srv.get("path", ""))
        actual = os.path.realpath(proc.cwd())
        return bool(expected and os.path.commonpath([expected, actual]) == expected)
    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, TypeError, OSError):
        return False


def _server_requires_http_ready_check(srv):
    """Require a listening port for projects identified as websites/web apps."""
    try:
        return _server_is_website(srv)
    except Exception:
        return srv.get("type") == "Static Website"


def _wait_for_listening_port(port, process, timeout=8.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", int(port)), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _python_web_app_target(srv_path, main_file, framework):
    """Return a Flask/FastAPI module target discovered from AST, not an assumed `app` name."""
    main_path = safe_relative_path(srv_path, main_file) if main_file else None
    if not main_path or not os.path.isfile(main_path):
        return None
    try:
        source = open(main_path, "r", encoding="utf-8", errors="replace").read(2 * 1024 * 1024)
        tree = ast.parse(source, filename=main_path)
    except (OSError, SyntaxError, ValueError):
        return None

    wanted = "Flask" if framework == "flask" else "FastAPI"
    main_imports = _python_imports_from_file(main_path)
    imported_names = {wanted}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == framework:
            for item in node.names:
                if item.name == wanted:
                    imported_names.add(item.asname or item.name)
        elif isinstance(node, ast.Import):
            for item in node.names:
                if item.name == framework:
                    imported_names.add(framework)

    assignments = []
    factory_names = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if isinstance(value, ast.Call):
                func = value.func
                call_name = func.id if isinstance(func, ast.Name) else (func.attr if isinstance(func, ast.Attribute) else "")
                is_framework_call = call_name in imported_names or (isinstance(func, ast.Attribute) and func.attr == wanted)
                if is_framework_call:
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target, ast.Name):
                            assignments.append(target.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in {"create_app", "make_app", "create_application"}:
                if any(
                    isinstance(child, ast.Call) and (
                        (isinstance(child.func, ast.Name) and child.func.id in imported_names) or
                        (isinstance(child.func, ast.Attribute) and child.func.attr == wanted)
                    )
                    for child in ast.walk(node)
                ):
                    factory_names.append(node.name)

    variable = next((name for name in assignments if name in {"app", "application", "api"}), None)
    if not variable and assignments:
        variable = assignments[0]
    if not variable and factory_names:
        variable = factory_names[0] + "()"
    if not variable and framework not in main_imports:
        return None
    if not variable:
        variable = "app"

    relative = os.path.relpath(main_path, srv_path).replace(os.sep, "/")
    parts = relative.split("/")
    stem = os.path.splitext(parts[-1])[0]
    if stem == "__init__":
        parts = parts[:-1]
    else:
        parts[-1] = stem
    if not parts or any(not part.isidentifier() for part in parts):
        return None
    return ".".join(parts) + ":" + variable


def _build_server_command(srv, port, python_bin=None):
    srv_path = srv["path"]
    server_type = srv.get("type", "Python")
    main_file = srv.get("startup_file") or detect_main_file(srv_path, server_type)

    if server_type == "Static Website":
        site_entry = _static_site_entry(srv_path)
        site_root = _static_site_root(srv_path, site_entry)
        if not os.path.isdir(site_root) or not site_entry:
            raise RuntimeError("لم أجد صفحة HTML لبدء الموقع؛ ارفع index.html أو ملف ZIP للموقع")
        default_page = os.path.basename(site_entry)
        static_server = os.path.join(BASE_DIR, "mazaji_static_site_server.py")
        return [sys.executable, "-u", static_server, str(int(port)), site_root, default_page]

    main_path = safe_relative_path(srv_path, main_file) if main_file else None
    if not main_file or not main_path or not os.path.isfile(main_path):
        raise RuntimeError("لم يتم العثور على ملف تشغيل صالح داخل المشروع")

    if server_type == "Node.js":
        project_dir, package_data, _relative = _node_project_manifest(srv_path)
        scripts = (package_data.get("scripts") or {}) if package_data else {}
        if not scripts.get("start") and _node_build_output_dir(srv_path):
            output_dir = _node_build_output_dir(srv_path)
            static_server = os.path.join(BASE_DIR, "mazaji_static_site_server.py")
            index_page = "index.html" if os.path.isfile(os.path.join(output_dir, "index.html")) else "index.htm"
            return [sys.executable, "-u", static_server, str(int(port)), output_dir, index_page]
        if scripts.get("start"):
            start_script = str(scripts.get("start") or "").lower()
            # Vite/Angular/Vue/Astro development servers do not consistently read PORT by themselves.
            if any(marker in start_script for marker in (
                "vite", "ng serve", "vue-cli-service serve", "webpack-dev-server", "astro dev", "astro preview",
                "vite preview", "svelte-kit dev", "nuxt dev", "nuxt start", "remix dev", "react-router dev", "solid-start dev",
            )):
                flag = "--hostname" if any(x in start_script for x in ("next", "nuxt")) else "--host"
                return _node_script_command(project_dir, package_data, "start", "--", flag, "0.0.0.0", "--port", str(int(port)))
            return _node_script_command(project_dir, package_data, "start")
        if scripts.get("build"):
            output_dir = _node_build_output_dir(srv_path)
            if output_dir:
                static_server = os.path.join(BASE_DIR, "mazaji_static_site_server.py")
                index_page = "index.html" if os.path.isfile(os.path.join(output_dir, "index.html")) else "index.htm"
                return [sys.executable, "-u", static_server, str(int(port)), output_dir, index_page]
            built_script = _node_built_script(srv_path)
            if built_script:
                return ["node", built_script]
            if main_path and os.path.isfile(main_path) and os.path.splitext(main_path)[1].lower() in (".js", ".mjs", ".cjs"):
                return ["node", main_path]
            raise RuntimeError("لم أجد ناتج بناء الموقع أو ملف تشغيل Node داخل dist/build/lib")
        if scripts.get("dev"):
            dev_script = str(scripts.get("dev") or "").lower()
            if any(x in dev_script for x in ("next", "nuxt")):
                return _node_script_command(project_dir, package_data, "dev", "--", "--hostname", "0.0.0.0", "--port", str(int(port)))
            return _node_script_command(project_dir, package_data, "dev", "--", "--host", "0.0.0.0", "--port", str(int(port)))
        return ["node", main_path]
    if server_type == "PHP":
        if _server_is_website(srv):
            html_entry = _static_site_entry(srv_path)
            if html_entry:
                php_docroot = _static_site_root(srv_path, html_entry)
            else:
                php_docroot = os.path.dirname(main_path) or srv_path
            router = os.path.join(BASE_DIR, "mazaji_php_site_router.php")
            return ["php", "-S", f"0.0.0.0:{port}", "-t", php_docroot, router]
        return ["php", main_path]
    # Common Python web frameworks need an explicit public host/port command.
    if server_type == "Python":
        py_bin = python_bin or sys.executable
        modules = _python_project_imports(srv_path)
        if os.path.basename(main_file).lower() == "manage.py" and "django" in modules:
            return [py_bin, main_path, "runserver", f"0.0.0.0:{int(port)}", "--noreload"]
        entry_modules = _python_imports_from_file(main_path)
        # Frameworks whose CLI owns the web listener.
        if "streamlit" in modules:
            return [py_bin, "-m", "streamlit", "run", main_path, "--server.address", "0.0.0.0", "--server.port", str(int(port)), "--server.headless", "true"]
        if "gradio" in modules:
            return [py_bin, "-u", main_path]
        framework_order = []
        for framework in ("fastapi", "flask"):
            if framework in entry_modules:
                framework_order.append(framework)
        for framework in ("fastapi", "flask"):
            if framework in modules and framework not in framework_order:
                framework_order.append(framework)
        for framework in framework_order:
            target = _python_web_app_target(srv_path, main_file, framework)
            if not target:
                continue
            if framework == "fastapi":
                return [py_bin, "-m", "uvicorn", target, "--host", "0.0.0.0", "--port", str(int(port))]
            return [py_bin, "-m", "flask", "--app", target, "run", "--host", "0.0.0.0", "--port", str(int(port))]
    # Use the resolved absolute path: Python projects uploaded in a nested ZIP
    # may run with the entry-point directory as cwd, not the archive root.
    return [python_bin or sys.executable, "-u", main_path]


def start_server_process(folder):
    with _server_lock(folder):
        srv = db.get("servers", {}).get(folder)
        if not srv:
            return False, "السيرفر غير موجود"
        srv_path = os.path.abspath(srv.get("path", ""))
        if not os.path.isdir(srv_path):
            return False, "مجلد ملفات السيرفر غير موجود"
        if srv.get("status") == "Running" and _process_is_alive(srv):
            return True, "السيرفر يعمل بالفعل"

        auto_detect_server_type(srv_path, srv)
        server_type = srv.get("type", "Python")
        main_file = srv.get("startup_file") or detect_main_file(srv_path, server_type)
        if not main_file:
            return False, "لم أجد نقطة تشغيل. للبوتات ارفع main.py أو bot.js أو index.php، وللمواقع ارفع index.html أو مشروع ZIP كامل"
        srv["startup_file"] = main_file
        reserved_here = not bool(srv.get("port"))
        port = srv.get("port") or get_assigned_port()
        srv["port"] = int(port)
        if reserved_here:
            # The DB record now owns this port; remove the temporary reservation.
            save_db(db)
            _release_port_reservation(port)

        log_path = os.path.join(srv_path, "out.log")
        error_path = os.path.join(srv_path, "errors.log")
        os.makedirs(srv_path, exist_ok=True)
        try:
            with open(log_path, "a", encoding="utf-8") as log_file:
                log_file.write(f"\n{'='*60}\n🚀 تجهيز التشغيل: {datetime.now()}\n📁 {main_file}\n🔌 {port}\n🏷 {server_type}\n{'='*60}\n")
                log_file.flush()
                if not auto_install_deps(srv_path, server_type, log_file):
                    message = "فشل تثبيت المكتبات أو تجهيز بيئة التشغيل. راجع out.log لمعرفة اسم الحزمة أو سبب الفشل"
                    srv["status"] = "Error"
                    srv["pid"] = None
                    srv["process_create_time"] = None
                    srv["last_error"] = message
                    try:
                        with open(error_path, "a", encoding="utf-8") as err:
                            err.write("\n❌ " + message + "\n")
                    except OSError:
                        pass
                    save_db(db)
                    return False, message
                owner_name = srv.get("owner")
                if owner_name:
                    quota_ok, quota_remaining = _check_storage_quota(owner_name, 0)
                    if not quota_ok:
                        message = (
                            "تجاوزت ملفات المشروع أو مكتباته المثبتة حد التخزين؛ "
                            f"المساحة المتبقية قبل التجهيز كانت {quota_remaining / (1024*1024):.2f} MB. "
                            "احذف ملفات غير ضرورية أو اطلب زيادة الحصة."
                        )
                        srv["status"] = "Error"
                        srv["pid"] = None
                        srv["process_create_time"] = None
                        srv["last_error"] = message
                        save_db(db)
                        return False, message
                if srv.get("start_cancelled"):
                    srv["status"] = "Stopped"
                    srv["pid"] = None
                    srv["process_create_time"] = None
                    srv["start_cancelled"] = False
                    save_db(db)
                    return False, "تم إلغاء التشغيل أثناء تجهيز المكتبات"
                python_bin = None
                if server_type == "Python":
                    venv_dir = os.path.join(srv_path, ".venv")
                    python_bin = os.path.join(venv_dir, "Scripts", "python.exe") if os.name == "nt" else os.path.join(venv_dir, "bin", "python")
                cmd = _build_server_command(srv, port, python_bin)
                env = _build_project_environment(
                    srv_path, folder=folder, owner=srv.get("owner", ""), port=port
                )
                env["PYTHONPATH"] = srv_path
                if server_type == "PHP" and _server_is_website(srv):
                    html_entry = _static_site_entry(srv_path)
                    if html_entry:
                        env["MAZAGI_SITE_ROOT"] = _static_site_root(srv_path, html_entry)
                    else:
                        env["MAZAGI_SITE_ROOT"] = os.path.dirname(safe_relative_path(srv_path, main_file) or srv_path)
                with open(error_path, "a", encoding="utf-8") as err_file:
                    proc = subprocess.Popen(
                        cmd, cwd=_runtime_working_dir(srv), stdout=log_file, stderr=err_file, env=env,
                        start_new_session=(os.name != "nt"), close_fds=True
                    )
            time.sleep(0.35)
            poll = proc.poll()
            if poll is not None:
                srv["status"] = "Error"
                srv["pid"] = None
                srv["process_create_time"] = None
                srv["last_exit_code"] = poll
                save_db(db)
                return False, f"توقف البرنامج مباشرة بعد التشغيل (رمز الخروج {poll}). راجع errors.log و out.log"
            if _server_requires_http_ready_check(srv) and not _wait_for_listening_port(port, proc, timeout=8.0):
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                srv["status"] = "Error"
                srv["pid"] = None
                srv["process_create_time"] = None
                srv["last_error"] = "لم يبدأ خادم الموقع بالاستماع على المنفذ المحدد خلال المهلة"
                save_db(db)
                return False, "لم يستجب الموقع على المنفذ المحدد خلال 8 ثوانٍ. تحقق من ملف البداية والسجلات."
            srv["status"] = "Running"
            srv["pid"] = proc.pid
            srv["process_create_time"] = psutil.Process(proc.pid).create_time()
            srv["start_time"] = time.time()
            srv["last_error"] = None
            save_db(db)
            return True, "✅ تم تثبيت المتطلبات وتشغيل السيرفر بنجاح"
        except FileNotFoundError as exc:
            message = f"أداة التشغيل غير موجودة: {exc.filename}"
        except Exception as exc:
            message = str(exc)
        srv["status"] = "Error"
        srv["pid"] = None
        srv["process_create_time"] = None
        srv["last_error"] = message
        save_db(db)
        try:
            with open(error_path, "a", encoding="utf-8") as ef:
                ef.write(f"\n❌ {message}\n")
        except Exception:
            pass
        return False, message


def stop_server_process(folder, *, cancel_start=True):
    current = db.get("servers", {}).get(folder)
    if current and cancel_start and current.get("status") == "Installing" and not current.get("pid"):
        current["start_cancelled"] = True
        current["status"] = "Stopped"
        save_db(db)
        return True
    if current and cancel_start:
        current["start_cancelled"] = True
    with _server_lock(folder):
        srv = db.get("servers", {}).get(folder)
        if not srv:
            return False
        pid = srv.get("pid")
        if pid:
            try:
                proc = psutil.Process(int(pid))
                expected_created = srv.get("process_create_time")
                if expected_created is not None and abs(proc.create_time() - float(expected_created)) >= 2.0:
                    proc = None
                if proc is not None and expected_created is None:
                    expected_dir = os.path.realpath(srv.get("path", ""))
                    actual_dir = os.path.realpath(proc.cwd())
                    if not expected_dir or os.path.commonpath([expected_dir, actual_dir]) != expected_dir:
                        proc = None
                if proc is None:
                    raise psutil.NoSuchProcess(int(pid))
                descendants = proc.children(recursive=True)
                for child in reversed(descendants):
                    try:
                        child.terminate()
                    except Exception:
                        pass
                try:
                    proc.terminate()
                except Exception:
                    pass
                _, alive = psutil.wait_procs([proc] + descendants, timeout=5)
                for item in alive:
                    try:
                        item.kill()
                    except Exception:
                        pass
            except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, TypeError):
                pass
        srv["status"] = "Stopped"
        srv["pid"] = None
        srv["process_create_time"] = None
        srv["start_time"] = None
        save_db(db)
        return True


def restart_server(folder):
    srv = db.get("servers", {}).get(folder)
    if srv:
        srv["restart_attempts"] = 0
        srv["last_restart_attempt"] = 0
        save_db(db)
    stop_server_process(folder, cancel_start=False)
    time.sleep(0.4)
    if srv:
        srv["start_cancelled"] = False
        srv["status"] = "Installing"
        save_db(db)
    return start_server_process(folder)


def _server_start_worker(folder, restart=False):
    srv = db.get("servers", {}).get(folder)
    if not srv:
        return
    if restart:
        stop_server_process(folder, cancel_start=False)
        time.sleep(0.25)
    srv = db.get("servers", {}).get(folder)
    if not srv:
        return
    srv["status"] = "Installing"
    srv["start_cancelled"] = False
    save_db(db)
    ok, message = start_server_process(folder)
    srv = db.get("servers", {}).get(folder)
    if srv and not ok and not message.startswith("تم إلغاء التشغيل"):
        srv["status"] = "Error"
        srv["last_error"] = message
        save_db(db)
    try:
        with open(os.path.join(srv.get("path", ""), "out.log"), "a", encoding="utf-8") as handle:
            handle.write(f"\n🧵 نتيجة مهمة التشغيل بالخلفية: {message}\n")
    except Exception:
        pass


def queue_server_start(folder, restart=False):
    """Queue potentially slow dependency installation outside the HTTP request."""
    srv = db.get("servers", {}).get(folder)
    if not srv:
        return False, "السيرفر غير موجود"
    if srv.get("status") == "Installing":
        return False, "جاري تجهيز السيرفر بالفعل"
    if not restart and srv.get("status") == "Running" and _process_is_alive(srv):
        return False, "السيرفر يعمل بالفعل"
    if restart:
        srv["restart_attempts"] = 0
        srv["last_restart_attempt"] = 0
    srv["status"] = "Restarting" if restart else "Installing"
    srv["start_cancelled"] = False
    srv["last_error"] = None
    save_db(db)
    threading.Thread(target=_server_start_worker, args=(folder, restart), daemon=True).start()
    return True, "بدأ تجهيز البيئة وتثبيت المكتبات وتشغيل السيرفر في الخلفية؛ راقب الحالة والسجلات"

# ============== مراقبة العمليات ==============
def process_monitor():
    """Recover crashed projects with a bounded retry policy (avoid endless crash loops)."""
    while True:
        try:
            for folder, srv in list(db.get("servers", {}).items()):
                if srv.get("status") != "Running" or not srv.get("pid"):
                    continue
                if _process_is_alive(srv):
                    continue
                attempts = int(srv.get("restart_attempts", 0) or 0)
                last = float(srv.get("last_restart_attempt", 0) or 0)
                now = time.time()
                if now - last > 600:
                    attempts = 0
                if attempts >= 3:
                    srv["status"] = "Error"
                    srv["pid"] = None
                    srv["process_create_time"] = None
                    srv["last_error"] = "توقف البرنامج عدة مرات؛ أوقفنا إعادة التشغيل المتكرر. راجع سجل الأخطاء"
                    save_db(db)
                    continue
                srv["restart_attempts"] = attempts + 1
                srv["last_restart_attempt"] = now
                srv["status"] = "Stopped"
                srv["pid"] = None
                srv["process_create_time"] = None
                save_db(db)
                ok, msg = start_server_process(folder)
                try:
                    with open(os.path.join(srv.get("path", ""), "out.log"), "a", encoding="utf-8") as lf:
                        lf.write(f"\n🔁 محاولة استعادة تلقائية {attempts + 1}/3: {msg}\n")
                except Exception:
                    pass
                if not ok:
                    srv["status"] = "Error"
                    srv["last_error"] = msg
                    save_db(db)
        except Exception as exc:
            print(f"⚠️ process monitor: {exc}")
        time.sleep(15)


threading.Thread(target=process_monitor, daemon=True, name="mazagi-process-monitor").start()

# ============== دوال مساعدة ==============
def get_current_user():
    if "username" in session:
        return db["users"].get(session["username"])
    return None

def effective_max_servers(user):
    """Return the effective per-account server limit, honoring the global cap."""
    try:
        personal = max(1, int(user.get("max_servers", 2)))
    except (TypeError, ValueError):
        personal = 2
    if user.get("is_admin"):
        return personal
    try:
        global_cap = int(db.get("settings", {}).get("global_max_servers", 0))
    except (TypeError, ValueError):
        global_cap = 0
    return min(personal, global_cap) if global_cap > 0 else personal


def get_user_servers_dir(username):
    username = safe_user_filename(username)
    if not username:
        raise ValueError("اسم مستخدم غير صالح")
    path = os.path.join(USERS_DIR, username, "SERVERS")
    os.makedirs(path, exist_ok=True)
    return path

def is_admin(username):
    if username == ADMIN_USERNAME:
        return True
    u = db["users"].get(username)
    return u.get("is_admin", False) if u else False

def get_public_ip():
    try:
        return requests.get('https://api.ipify.org', timeout=3).text
    except Exception:
        return "127.0.0.1"

def generate_api_key():
    return secrets.token_urlsafe(32)

def get_user_by_api_key(api_key):
    for username, udata in db["users"].items():
        if udata.get("api_key") == api_key:
            return username, udata
    return None, None

def uptime_str(start_time):
    if not start_time:
        return "0 ثانية"
    diff = time.time() - start_time
    days = int(diff // 86400)
    hours = int((diff % 86400) // 3600)
    mins = int((diff % 3600) // 60)
    parts = []
    if days > 0: parts.append(f"{days} يوم")
    if hours > 0: parts.append(f"{hours} ساعة")
    if mins > 0: parts.append(f"{mins} دقيقة")
    return " و ".join(parts) if parts else "أقل من دقيقة"

def _check_admin_access():
    if "username" in session and is_admin(session["username"]):
        return True
    api_key = None
    if request.is_json:
        try:
            api_key = (request.get_json(silent=True) or {}).get("api_key")
        except Exception:
            pass
    if not api_key:
        api_key = request.headers.get("X-API-Key")
    if api_key:
        username, user = get_user_by_api_key(api_key)
        if username and is_admin(username):
            return True
    return False

@app.route('/healthz', methods=['GET'])
def health_check():
    """Lightweight platform health probe; does not expose credentials or private paths."""
    try:
        if not isinstance(db, dict) or not isinstance(db.get("users"), dict) or not isinstance(db.get("servers"), dict):
            return jsonify({"ok": False, "status": "database_invalid"}), 503
        if not os.path.isdir(DATA_DIR) or not os.access(DATA_DIR, os.W_OK):
            return jsonify({"ok": False, "status": "storage_not_writable"}), 503
        return jsonify({"ok": True, "status": "healthy", "runtimes": {
            "python": sys.version.split()[0],
            "node": bool(shutil.which("node")),
            "npm": bool(shutil.which("npm")),
            "php": bool(shutil.which("php")),
            "composer": bool(shutil.which("composer")),
            "websocket_proxy": True,
            "public_site_domain_configured": bool(os.environ.get("PUBLIC_SITE_DOMAIN", "").strip()),
        }}), 200
    except Exception:
        return jsonify({"ok": False, "status": "unhealthy"}), 503


@app.errorhandler(413)
def request_entity_too_large(_error):
    return jsonify({"success": False, "message": "حجم الملف أكبر من الحد المسموح للرفع في إعدادات الاستضافة."}), 413


# ============== الصفحات ==============
@app.route('/')
def home():
    if 'username' not in session:
        return redirect('/login')
    return redirect('/dashboard')

@app.route('/login')
def login_page():
    if 'username' in session:
        return redirect('/')
    return send_from_directory(BASE_DIR, 'login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')
    return send_from_directory(BASE_DIR, 'index.html')

@app.route('/admin')
def admin_panel():
    if 'username' not in session or not is_admin(session['username']):
        return redirect('/login')
    return send_from_directory(BASE_DIR, 'admin_panel.html')

# ============== API المصادقة ==============
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json(silent=True) or {}
    if db.get("settings", {}).get("registration_status", "open") != "open":
        return jsonify({"success": False, "message": "التسجيل مغلق حالياً من الإدارة."}), 403
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()
    telegram_id = str(data.get("telegram_id", "")).strip()

    if not username or not password:
        return jsonify({"success": False, "message": "جميع الحقول مطلوبة"})
    if not re.fullmatch(r"[\w.-]{3,32}", username, flags=re.UNICODE) or username in (".", "..") or ".." in username:
        return jsonify({"success": False, "message": "اسم المستخدم يجب أن يكون 3-32 حرفاً أو رقماً أو _ أو - أو ."})
    if len(password) < 8:
        return jsonify({"success": False, "message": "كلمة المرور يجب أن تكون 8 أحرف على الأقل"})
    if username in db["users"]:
        return jsonify({"success": False, "message": "اسم المستخدم موجود بالفعل"})
    if username == ADMIN_USERNAME:
        return jsonify({"success": False, "message": "لا يمكن استخدام هذا الاسم"})

    db["users"][username] = {
        "password": generate_password_hash(password),
        "is_admin": False,
        "created_at": str(datetime.now()),
        "max_servers": max(1, int(db.get("settings", {}).get("global_max_servers", db["plans"]["free"]["max_servers"]))),
        "expiry_days": 365,
        "last_login": None,
        "telegram_id": telegram_id if telegram_id else None,
        "api_key": None,
        "storage_limit": db["plans"]["free"]["storage"],
        "plan": "free",
        "status": "pending"
    }
    save_db(db)

    user_dir = os.path.join(USERS_DIR, safe_user_filename(username))
    os.makedirs(user_dir, exist_ok=True)
    os.makedirs(os.path.join(user_dir, "SERVERS"), exist_ok=True)

    admin_msg = (
        f"🔔 *طلب تسجيل جديد في مزاجي!*\n"
        f"👤 المستخدم: `{username}`\n"
        f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
        f"📱 تليجرام: {telegram_id or 'غير مرتبط'}\n\n"
        f"للقبول: `/approve_{username}`\n"
        f"للرفض: `/reject_{username}`"
    )
    threading.Thread(
        target=notify_admin,
        args=(admin_msg,),
        daemon=True
    ).start()

    return jsonify({
        "success": True,
        "message": "✅ تم إرسال طلب التسجيل للمطور. سيتم إعلامك عند الموافقة."
    })

# مسار دخول الأدمن بكلمة مرور فقط. يعتمد التحقق على بصمة الحساب المخزنة
# في قاعدة التشغيل، مع اعتماد بصمة النسخة المرفقة مرة واحدة للاستعادة فقط.
_ADMIN_PASSWORD_LOGIN_LOCK = threading.Lock()
_ADMIN_PASSWORD_LOGIN_FAILURES = {}
_ADMIN_PASSWORD_LOGIN_WINDOW = 15 * 60
_ADMIN_PASSWORD_LOGIN_MAX_FAILURES = 8


def _bundled_admin_password_hash():
    """Return the bundled admin hash only until the first successful recovery."""
    try:
        if db.get("settings", {}).get("admin_password_recovery_used") is True:
            return None
        bundled_file = os.path.join(BASE_DIR, "portable_data", "db.json")
        with open(bundled_file, "r", encoding="utf-8") as handle:
            bundled = json.load(handle)
        record = bundled.get("users", {}).get(ADMIN_USERNAME, {})
        if isinstance(record, dict) and record.get("password"):
            return record.get("password")
    except Exception as exc:
        print(f"⚠️ تعذر قراءة بصمة الاستعادة المرفقة: {exc}", flush=True)
    return None


def _admin_password_rate_limited(client_ip):
    now = time.time()
    with _ADMIN_PASSWORD_LOGIN_LOCK:
        attempts = [t for t in _ADMIN_PASSWORD_LOGIN_FAILURES.get(client_ip, [])
                    if now - t < _ADMIN_PASSWORD_LOGIN_WINDOW]
        _ADMIN_PASSWORD_LOGIN_FAILURES[client_ip] = attempts
        if len(attempts) >= _ADMIN_PASSWORD_LOGIN_MAX_FAILURES:
            return True, max(1, int(_ADMIN_PASSWORD_LOGIN_WINDOW - (now - attempts[0])))
    return False, 0


def _record_admin_password_failure(client_ip):
    now = time.time()
    with _ADMIN_PASSWORD_LOGIN_LOCK:
        attempts = [t for t in _ADMIN_PASSWORD_LOGIN_FAILURES.get(client_ip, [])
                    if now - t < _ADMIN_PASSWORD_LOGIN_WINDOW]
        attempts.append(now)
        _ADMIN_PASSWORD_LOGIN_FAILURES[client_ip] = attempts


def _clear_admin_password_failures(client_ip):
    with _ADMIN_PASSWORD_LOGIN_LOCK:
        _ADMIN_PASSWORD_LOGIN_FAILURES.pop(client_ip, None)


@app.route('/api/admin/password-login', methods=['POST'])
def admin_password_login():
    data = request.get_json(silent=True) or {}
    # لا نستخدم strip لكلمة المرور؛ المسافات أو الرموز جزء من كلمة المرور إن وجدت.
    password = data.get("password", "")
    if not isinstance(password, str) or not password:
        return jsonify({"success": False, "message": "أدخل كلمة مرور الأدمن."}), 400

    client_ip = request.remote_addr or "unknown"
    limited, retry_after = _admin_password_rate_limited(client_ip)
    if limited:
        response = jsonify({"success": False, "message": "محاولات كثيرة. حاول لاحقاً."})
        response.status_code = 429
        response.headers["Retry-After"] = str(retry_after)
        return response

    admin_record = db.get("users", {}).get(ADMIN_USERNAME)
    if not isinstance(admin_record, dict):
        return jsonify({"success": False, "message": "حساب الأدمن غير مهيأ. راجع إعدادات الحساب."}), 503

    stored_hash = admin_record.get("password", "")
    valid_live_password = _password_matches(stored_hash, password)
    valid_configured_password = bool(
        ADMIN_PASSWORD_RAW and secrets.compare_digest(ADMIN_PASSWORD_RAW, password)
    )
    bundled_hash = _bundled_admin_password_hash()
    valid_one_time_recovery = bool(bundled_hash and _password_matches(bundled_hash, password))

    if not (valid_live_password or valid_configured_password or valid_one_time_recovery):
        _record_admin_password_failure(client_ip)
        return jsonify({"success": False, "message": "كلمة مرور الأدمن غير صحيحة."}), 401

    # ثبّت صلاحية الأدمن وكلمة المرور الصحيحة على السجل الحي دون المساس ببقية البيانات.
    admin_record["is_admin"] = True
    admin_record["status"] = "approved"
    if not valid_live_password:
        admin_record["password"] = generate_password_hash(password)
    admin_record["last_login"] = str(datetime.now())
    # خزّن انتهاء الاستعادة الاحتياطية بنفس الحفظ الذري لكلمة المرور.
    if valid_one_time_recovery and not valid_live_password:
        db.setdefault("settings", {})["admin_password_recovery_used"] = True
    if not save_db(db):
        return jsonify({"success": False, "message": "تعذر حفظ جلسة الأدمن. تحقق من التخزين الدائم."}), 503

    _clear_admin_password_failures(client_ip)
    session.clear()
    session["username"] = ADMIN_USERNAME
    session.permanent = True
    response = jsonify({"success": True, "redirect": "/admin", "is_admin": True})
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    user = db["users"].get(username)
    if not user:
        return jsonify({"success": False, "message": "المستخدم غير موجود"})
    
    if user.get("status") == "pending":
        return jsonify({"success": False, "message": "⏳ حسابك في انتظار موافقة المطور"})
    if user.get("status") == "rejected":
        return jsonify({"success": False, "message": "❌ تم رفض حسابك من قبل المطور"})
    
    if _password_matches(user.get("password"), password):
        _upgrade_password_hash(user, password)
        session.clear()
        session['username'] = username
        session.permanent = True
        user["last_login"] = str(datetime.now())
        save_db(db)
        return jsonify({"success": True, "redirect": "/dashboard", "is_admin": bool(user.get("is_admin") or username == ADMIN_USERNAME)})

    return jsonify({"success": False, "message": "بيانات غير صحيحة"})

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    response = make_response(jsonify({"success": True}))
    response.set_cookie('session', '', expires=0)
    return response

@app.route('/api/current_user')
def api_current_user():
    if "username" in session:
        u = db["users"].get(session["username"])
        if u:
            return jsonify({
                "success": True,
                "username": session["username"],
                "is_admin": u.get("is_admin", False) or session["username"] == ADMIN_USERNAME,
                "plan": u.get("plan", "free"),
                "status": u.get("status", "approved")
            })
    return jsonify({"success": False})

# ============== دوال قبول ورفض المستخدمين ==============
@app.route('/api/admin/approve-user', methods=['POST'])
def approve_user():
    if 'username' not in session or not is_admin(session['username']):
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    
    if not username:
        return jsonify({"success": False, "message": "اسم المستخدم مطلوب"})
    
    if username not in db["users"]:
        return jsonify({"success": False, "message": "المستخدم غير موجود"})
    
    user = db["users"][username]
    user["status"] = "approved"
    save_db(db)
    
    tg_id = user.get("telegram_id")
    if tg_id:
        msg = (
            f"🎉 *تم قبول حسابك في مزاجي!*\n"
            f"👤 المستخدم: `{username}`\n"
            f"✅ يمكنك الآن تسجيل الدخول واستخدام خدماتنا.\n\n"
            f"🔗 {ADMIN_TELEGRAM_USERNAME}"
        )
        threading.Thread(target=notify_user, args=(tg_id, msg), daemon=True).start()
    
    notify_admin(f"✅ تم قبول المستخدم `{username}`")
    
    return jsonify({"success": True, "message": f"✅ تم قبول المستخدم {username}"})

@app.route('/api/admin/reject-user', methods=['POST'])
def reject_user():
    if 'username' not in session or not is_admin(session['username']):
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    
    if not username:
        return jsonify({"success": False, "message": "اسم المستخدم مطلوب"})
    
    if username not in db["users"]:
        return jsonify({"success": False, "message": "المستخدم غير موجود"})
    
    user = db["users"][username]
    user["status"] = "rejected"
    save_db(db)
    
    tg_id = user.get("telegram_id")
    if tg_id:
        msg = (
            f"❌ *تم رفض حسابك في مزاجي*\n"
            f"👤 المستخدم: `{username}`\n"
            f"للتواصل مع الدعم: {ADMIN_TELEGRAM_USERNAME}"
        )
        threading.Thread(target=notify_user, args=(tg_id, msg), daemon=True).start()
    
    notify_admin(f"❌ تم رفض المستخدم `{username}`")
    
    return jsonify({"success": True, "message": f"❌ تم رفض المستخدم {username}"})

@app.route('/api/admin/pending-users', methods=['GET'])
def get_pending_users():
    if 'username' not in session or not is_admin(session['username']):
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    
    pending = []
    for username, data in db["users"].items():
        if data.get("status") == "pending" and username != ADMIN_USERNAME:
            pending.append({
                "username": username,
                "created_at": data.get("created_at"),
                "telegram_id": data.get("telegram_id"),
                "plan": data.get("plan", "free")
            })
    
    return jsonify({"success": True, "users": pending})

# ============== أوامر البوت للقبول والرفض ==============
@app.route('/webhook', methods=['POST'])
def telegram_webhook():
    expected_secret = os.environ.get("TELEGRAM_WEBHOOK_SECRET", "").strip()
    if not expected_secret:
        return jsonify({"status": "webhook_secret_not_configured"}), 503
    if not secrets.compare_digest(request.headers.get("X-Telegram-Bot-Api-Secret-Token", ""), expected_secret):
        return jsonify({"status": "forbidden"}), 403
    data = request.get_json(silent=True) or {}
    
    if 'message' not in data:
        return jsonify({"status": "ok"})
    
    msg = data['message']
    chat_id = msg.get('chat', {}).get('id')
    text = msg.get('text', '').strip()
    
    if str(chat_id) != str(ADMIN_TELEGRAM_ID):
        return jsonify({"status": "ok"})
    
    if text.startswith('/approve_'):
        username = text.replace('/approve_', '').strip()
        if username in db["users"] and db["users"][username].get("status") == "pending":
            db["users"][username]["status"] = "approved"
            save_db(db)
            
            tg_id = db["users"][username].get("telegram_id")
            if tg_id:
                msg = (
                    f"🎉 *تم قبول حسابك في مزاجي!*\n"
                    f"👤 المستخدم: `{username}`\n"
                    f"✅ يمكنك الآن تسجيل الدخول."
                )
                threading.Thread(target=notify_user, args=(tg_id, msg), daemon=True).start()
            
            requests.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                json={"chat_id": chat_id, "text": f"✅ تم قبول المستخدم `{username}`"},
                timeout=10
            )
        else:
            requests.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                json={"chat_id": chat_id, "text": f"❌ المستخدم `{username}` غير موجود أو غير معلق"},
                timeout=10
            )
    
    elif text.startswith('/reject_'):
        username = text.replace('/reject_', '').strip()
        if username in db["users"] and db["users"][username].get("status") == "pending":
            db["users"][username]["status"] = "rejected"
            save_db(db)
            
            tg_id = db["users"][username].get("telegram_id")
            if tg_id:
                msg = (
                    f"❌ *تم رفض حسابك في مزاجي*\n"
                    f"👤 المستخدم: `{username}`\n"
                    f"للتواصل مع الدعم: {ADMIN_TELEGRAM_USERNAME}"
                )
                threading.Thread(target=notify_user, args=(tg_id, msg), daemon=True).start()
            
            requests.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                json={"chat_id": chat_id, "text": f"❌ تم رفض المستخدم `{username}`"},
                timeout=10
            )
        else:
            requests.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                json={"chat_id": chat_id, "text": f"❌ المستخدم `{username}` غير موجود أو غير معلق"},
                timeout=10
            )
    
    return jsonify({"status": "ok"})

@app.route('/api/bot/set_webhook', methods=['POST'])
def set_webhook():
    if "username" not in session or not is_admin(session["username"]):
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    if not BOT_TOKEN:
        return jsonify({"success": False, "message": "BOT_TOKEN غير مضبوط في متغيرات الاستضافة"}), 503
    if not os.environ.get("TELEGRAM_WEBHOOK_SECRET", "").strip():
        return jsonify({"success": False, "message": "اضبط TELEGRAM_WEBHOOK_SECRET أولاً لحماية Webhook"}), 400
    base_url = request.host_url.rstrip('/')
    webhook_url = f"{base_url}/webhook"
    payload = {"url": webhook_url}
    webhook_secret = os.environ.get("TELEGRAM_WEBHOOK_SECRET", "").strip()
    if webhook_secret:
        payload["secret_token"] = webhook_secret
    try:
        response = requests.post(f"https://api.telegram.org/bot{BOT_TOKEN}/setWebhook", json=payload, timeout=15)
        return jsonify(response.json()), response.status_code
    except requests.RequestException as exc:
        return jsonify({"success": False, "message": str(exc)}), 502

# ============== API Key ==============
@app.route('/api/api_key', methods=['GET'])
def get_api_key():
    if 'username' not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    return jsonify({"success": True, "api_key": db["users"][session['username']].get("api_key")})


@app.route('/api/revoke_api_key', methods=['POST'])
def revoke_api_key():
    if 'username' not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    db["users"][session['username']]["api_key"] = None
    if not save_db(db):
        return jsonify({"success": False, "message": "تعذر إبطال المفتاح"}), 500
    return jsonify({"success": True, "message": "تم إبطال مفتاح API"})


@app.route('/api/create_api_key', methods=['POST'])
def create_api_key():
    if 'username' not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    username = session['username']
    new_key = generate_api_key()
    db["users"][username]["api_key"] = new_key
    if not save_db(db):
        db["users"][username]["api_key"] = None
        return jsonify({"success": False, "message": "تعذر حفظ مفتاح API"}), 500
    return jsonify({"success": True, "api_key": new_key, "message": "تم إنشاء مفتاح API"})

@app.route('/api/link_telegram', methods=['POST'])
def link_telegram():
    if 'username' not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    data = request.get_json(silent=True) or {}
    tg_id = str(data.get('telegram_id', ''))
    if not tg_id:
        return jsonify({"success": False, "message": "معرف تليجرام مطلوب"})
    db["users"][session['username']]["telegram_id"] = tg_id
    save_db(db)
    return jsonify({"success": True, "message": "تم ربط حساب التليجرام"})

@app.route('/api/admin/settings', methods=['GET', 'POST'])
def admin_settings():
    if not _check_admin_access():
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    if request.method == 'GET':
        return jsonify({"success": True, "settings": db.get("settings", DEFAULT_SETTINGS)})
    data = request.get_json(silent=True) or {}
    try:
        max_servers = int(data.get("global_max_servers", db["settings"].get("global_max_servers", 2)))
        max_file_size_mb = int(data.get("max_file_size_mb", db["settings"].get("max_file_size_mb", 100)))
        registration_status = str(data.get("registration_status", db["settings"].get("registration_status", "open"))).lower()
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "قيم الإعدادات غير صحيحة"}), 400
    if not 1 <= max_servers <= 100 or not 10 <= max_file_size_mb <= 500 or registration_status not in ("open", "closed"):
        return jsonify({"success": False, "message": "الحد الأقصى للسيرفرات 1-100، وحجم الملف 10-500 MB"}), 400
    db.setdefault("settings", {}).update({
        "global_max_servers": max_servers,
        "max_file_size_mb": max_file_size_mb,
        "registration_status": registration_status,
    })
    app.config["MAX_CONTENT_LENGTH"] = max_file_size_mb * 1024 * 1024
    if not save_db(db):
        return jsonify({"success": False, "message": "تعذر حفظ الإعدادات في التخزين الدائم"}), 500
    return jsonify({"success": True, "message": "تم حفظ الإعدادات بنجاح", "settings": db["settings"]})


@app.route('/api/admin/change-password', methods=['POST'])
def admin_change_password():
    if "username" not in session or not is_admin(session["username"]):
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    data = request.get_json(silent=True) or {}
    new_password = str(data.get("password", ""))
    if len(new_password) < 8:
        return jsonify({"success": False, "message": "كلمة المرور يجب أن تكون 8 أحرف على الأقل"}), 400
    db["users"][session["username"]]["password"] = generate_password_hash(new_password)
    if not save_db(db):
        return jsonify({"success": False, "message": "تعذر حفظ كلمة المرور"}), 500
    return jsonify({"success": True, "message": "تم تحديث كلمة المرور بنجاح"})


def _parse_created_at(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).replace(tzinfo=None)
    except (TypeError, ValueError):
        return None


@app.route('/api/admin/analytics')
def admin_analytics():
    if not _check_admin_access():
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    now = datetime.now()
    month_keys = []
    for offset in range(5, -1, -1):
        year = now.year
        month = now.month - offset
        while month <= 0:
            month += 12
            year -= 1
        month_keys.append(f"{year:04d}-{month:02d}")
    user_counts = {key: 0 for key in month_keys}
    server_counts = {key: 0 for key in month_keys}
    for username, user in db.get("users", {}).items():
        if username == ADMIN_USERNAME:
            continue
        created = _parse_created_at(user.get("created_at"))
        if created:
            key = created.strftime("%Y-%m")
            if key in user_counts:
                user_counts[key] += 1
    for server in db.get("servers", {}).values():
        created = _parse_created_at(server.get("created_at"))
        if created:
            key = created.strftime("%Y-%m")
            if key in server_counts:
                server_counts[key] += 1
    return jsonify({
        "success": True,
        "labels": month_keys,
        "users": [user_counts[key] for key in month_keys],
        "servers": [server_counts[key] for key in month_keys],
        "totals": {
            "users": max(0, len(db.get("users", {})) - (1 if ADMIN_USERNAME in db.get("users", {}) else 0)),
            "servers": len(db.get("servers", {})),
        },
    })


# ============== API الخطط ==============
@app.route('/api/plans')
def get_plans():
    return jsonify({"success": True, "plans": db.get("plans", {})})

@app.route('/api/user/upgrade', methods=['POST'])
def upgrade_plan():
    if 'username' not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    data = request.get_json(silent=True) or {}
    plan_id = data.get("plan_id")
    if not plan_id or plan_id not in db.get("plans", {}):
        return jsonify({"success": False, "message": "خطة غير موجودة"}), 404
    if plan_id != "free":
        return jsonify({
            "success": False,
            "message": "الخطط المدفوعة لا تُفعّل من طلب مباشر؛ أرسل طلبك للدعم وبعد تأكيد الدفع يتم تفعيلها من الإدارة."
        }), 403

    plan = db["plans"][plan_id]
    username = session['username']
    user = db["users"][username]
    previous = {key: user.get(key) for key in ("plan", "max_servers", "storage_limit")}
    user["plan"] = plan_id
    user["max_servers"] = plan["max_servers"]
    user["storage_limit"] = plan["storage"]
    if not save_db(db):
        for key, value in previous.items():
            if value is None:
                user.pop(key, None)
            else:
                user[key] = value
        return jsonify({"success": False, "message": "تعذر حفظ تغيير الخطة؛ لم يتم تطبيق التغيير"}), 500
    
    threading.Thread(
        target=notify_admin,
        args=(
            f"💎 *ترقية خطة جديدة!*\n"
            f"👤 المستخدم: `{username}`\n"
            f"📦 الخطة: {plan['name']}\n"
            f"💰 السعر: {plan['price']}$",
        ),
        daemon=True
    ).start()
    
    return jsonify({"success": True, "message": f"✅ تم ترقية حسابك إلى {plan['name']}"})

# ============== API الإدارة - المستخدمون ==============
@app.route('/api/admin/users')
def admin_users():
    if not _check_admin_access():
        return jsonify({"success": False}), 403
    users_list = []
    for uname, udata in db["users"].items():
        users_list.append({
            "username": uname,
            "is_admin": udata.get("is_admin", False),
            "created_at": udata.get("created_at"),
            "last_login": udata.get("last_login"),
            "max_servers": udata.get("max_servers", 1),
            "expiry_days": udata.get("expiry_days", 365),
            "telegram_id": udata.get("telegram_id"),
            "plan": udata.get("plan", "free"),
            "status": udata.get("status", "approved")
        })
    return jsonify({"success": True, "users": users_list})

@app.route('/api/admin/user-servers/<username>')
def admin_user_servers(username):
    if not _check_admin_access():
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    if username not in db.get("users", {}):
        return jsonify({"success": False, "message": "المستخدم غير موجود"}), 404
    servers = []
    for folder, srv in db.get("servers", {}).items():
        if srv.get("owner") == username:
            servers.append({
                "folder": folder, "title": srv.get("name", folder),
                "type": srv.get("type", "Python"), "status": srv.get("status", "Stopped"),
                "port": srv.get("port"), "startup_file": srv.get("startup_file", ""),
                "created_at": srv.get("created_at", ""),
                "disk_used": round(_tree_size_bytes(srv.get("path", "")) / (1024 * 1024), 2)
            })
    return jsonify({"success": True, "servers": servers})


@app.route('/api/admin/approve', methods=['POST'])
def admin_approve_alias():
    if not _check_admin_access():
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    user = db.get("users", {}).get(username)
    if not user:
        return jsonify({"success": False, "message": "المستخدم غير موجود"}), 404
    user["status"] = "approved"
    save_db(db)
    return jsonify({"success": True, "message": f"تم قبول {username}"})


@app.route('/api/admin/reject', methods=['POST'])
def admin_reject_alias():
    if not _check_admin_access():
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    user = db.get("users", {}).get(username)
    if not user or username == ADMIN_USERNAME:
        return jsonify({"success": False, "message": "المستخدم غير موجود أو لا يمكن رفضه"}), 404
    user["status"] = "rejected"
    save_db(db)
    return jsonify({"success": True, "message": f"تم رفض {username}"})


@app.route('/api/admin/pending')
def admin_pending_alias():
    if not _check_admin_access():
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    pending = get_pending_users_list()
    return jsonify({"success": True, "requests": pending, "users": pending})


@app.route('/api/admin/add-plan', methods=['POST'])
def admin_add_plan():
    if not _check_admin_access():
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    data = request.get_json(silent=True) or {}
    plan_id = re.sub(r'[^a-zA-Z0-9_-]', '', str(data.get("id", "")).strip())
    name = str(data.get("name", "")).strip()
    if not plan_id and name:
        plan_id = "plan_" + re.sub(r'[^a-zA-Z0-9_-]', '', name.lower())[:24] + "_" + secrets.token_hex(3)
    try:
        storage = int(data.get("storage", 0))
        ram = int(data.get("ram", 0))
        max_servers = int(data.get("max_servers", 1))
        cpu = float(data.get("cpu", 0.5))
        price = float(data.get("price", 0))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "قيم الخطة غير صحيحة"}), 400
    if not plan_id or not name or min(storage, ram, max_servers) <= 0 or cpu <= 0 or price < 0:
        return jsonify({"success": False, "message": "أكمل بيانات الخطة بقيم صحيحة"}), 400
    db.setdefault("plans", {})[plan_id] = {
        "name": name, "storage": storage, "ram": ram,
        "cpu": cpu, "max_servers": max_servers, "price": price
    }
    save_db(db)
    return jsonify({"success": True, "message": "تمت إضافة الخطة بنجاح"})


@app.route('/api/admin/update-plan', methods=['POST'])
def admin_update_plan():
    if not _check_admin_access():
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    data = request.get_json(silent=True) or {}
    plan_id = str(data.get("id", "")).strip()
    if not plan_id or plan_id == "free" or plan_id not in db.get("plans", {}):
        return jsonify({"success": False, "message": "الخطة غير موجودة أو لا يمكن تعديل الخطة المجانية"}), 404
    name = str(data.get("name", "")).strip()
    try:
        storage = int(data.get("storage", 0))
        ram = int(data.get("ram", 0))
        max_servers = int(data.get("max_servers", 1))
        cpu = float(data.get("cpu", 0.5))
        price = float(data.get("price", 0))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "قيم الخطة غير صحيحة"}), 400
    if not name or min(storage, ram, max_servers) <= 0 or cpu <= 0 or price < 0:
        return jsonify({"success": False, "message": "أكمل بيانات الخطة بقيم صحيحة"}), 400
    db["plans"][plan_id] = {
        "name": name, "storage": storage, "ram": ram,
        "cpu": cpu, "max_servers": max_servers, "price": price
    }
    if not save_db(db):
        return jsonify({"success": False, "message": "تعذر حفظ الخطة"}), 500
    return jsonify({"success": True, "message": "تم تحديث الخطة بنجاح"})


@app.route('/api/admin/create-user', methods=['POST'])
def admin_create_user():
    if not _check_admin_access():
        return jsonify({"success": False}), 403
    data = request.get_json(silent=True) or {}
    username = safe_user_filename(str(data.get("username", "")).strip())
    password = str(data.get("password", "")).strip()
    try:
        max_servers = int(data.get("max_servers", 2))
        expiry_days = int(data.get("expiry_days", 365))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "قيم الحساب غير صحيحة"}), 400
    if (not username or not re.fullmatch(r"[\w.-]{3,32}", username, flags=re.UNICODE)
            or ".." in username or len(password) < 8 or max_servers < 1 or expiry_days < 1):
        return jsonify({"success": False, "message": "جميع الحقول مطلوبة"})
    if username in db["users"]:
        return jsonify({"success": False, "message": "المستخدم موجود"})
    db["users"][username] = {
        "password": generate_password_hash(password),
        "is_admin": False,
        "created_at": str(datetime.now()),
        "max_servers": max_servers,
        "expiry_days": expiry_days,
        "last_login": None,
        "telegram_id": None,
        "api_key": None,
        "storage_limit": 512000,
        "plan": "free",
        "status": "approved"
    }
    save_db(db)
    user_dir = os.path.join(USERS_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    os.makedirs(os.path.join(user_dir, "SERVERS"), exist_ok=True)
    return jsonify({"success": True, "message": "✅ تم إنشاء الحساب"})

@app.route('/api/admin/delete-user', methods=['POST'])
def admin_delete_user():
    if not _check_admin_access():
        return jsonify({"success": False}), 403
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    if not username or username == ADMIN_USERNAME:
        return jsonify({"success": False, "message": "لا يمكن حذف هذا المستخدم"})
    if username in db["users"]:
        for fid in [fid for fid, srv in db["servers"].items() if srv.get("owner") == username]:
            stop_server_process(fid)
            if os.path.exists(db["servers"][fid]["path"]):
                shutil.rmtree(db["servers"][fid]["path"], ignore_errors=True)
            del db["servers"][fid]
        user_dir = os.path.join(USERS_DIR, username)
        if os.path.exists(user_dir):
            shutil.rmtree(user_dir, ignore_errors=True)
        del db["users"][username]
        save_db(db)
        return jsonify({"success": True, "message": f"🗑 تم حذف المستخدم {username}"})
    return jsonify({"success": False, "message": "المستخدم غير موجود"})

@app.route('/api/admin/update-user', methods=['POST'])
def admin_update_user():
    if not _check_admin_access():
        return jsonify({"success": False}), 403
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    if username not in db["users"]:
        return jsonify({"success": False, "message": "المستخدم غير موجود"})
    u = db["users"][username]
    if "max_servers" in data:
        u["max_servers"] = int(data["max_servers"])
    if "expiry_days" in data:
        u["expiry_days"] = int(data["expiry_days"])
    if "is_admin" in data:
        u["is_admin"] = bool(data["is_admin"])
    if "storage_limit" in data:
        u["storage_limit"] = int(data["storage_limit"])
    save_db(db)
    return jsonify({"success": True, "message": f"✅ تم تحديث {username}"})

# ============== API النظام ==============
@app.route('/api/system/metrics')
def get_metrics():
    if not _check_admin_access():
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    return jsonify({
        "cpu": psutil.cpu_percent(),
        "memory": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage('/').percent
    })

@app.route('/api/ping', methods=['GET', 'POST'])
def ping():
    return jsonify({"status": "pong", "timestamp": str(datetime.now())})

# ============== السيرفرات ==============


def _python_project_imports(srv_path):
    modules = set()
    for rel in _project_files(srv_path, (".py",)):
        path = safe_relative_path(srv_path, rel)
        if path:
            modules.update(_python_imports_from_file(path))
    return modules


def _server_is_website(srv):
    """Best-effort distinction between web apps and background bots."""
    server_type = srv.get("type", "")
    srv_path = srv.get("path", "")
    if server_type == "Static Website":
        return bool(_static_site_entry(srv_path))
    if server_type == "PHP":
        php_files = _project_files(srv_path, (".php",))
        has_php_index = any(os.path.basename(x).lower() == "index.php" for x in php_files)
        return bool(has_php_index or (_static_site_entry(srv_path) and php_files))
    if server_type == "Node.js":
        if _node_build_output_dir(srv_path):
            return True
        _root, package_data, _rel = _node_project_manifest(srv_path)
        dependencies = {}
        if package_data:
            dependencies.update(package_data.get("dependencies") or {})
            dependencies.update(package_data.get("devDependencies") or {})
        web_packages = {
            "express", "fastify", "koa", "@hapi/hapi", "@nestjs/core", "next", "nuxt",
            "vite", "astro", "react-scripts", "@angular/cli", "@angular-devkit/build-angular",
            "vue", "@vue/cli-service", "svelte", "svelte-kit", "@sveltejs/kit",
            "@remix-run/dev", "@remix-run/serve", "@react-router/serve", "gatsby",
            "@solidjs/start", "solid-start", "@builder.io/qwik", "@qwik.dev/router",
            "hono", "elysia", "h3", "http-server", "serve", "live-server",
        }
        if any(name in dependencies for name in web_packages):
            return True
        scripts = (package_data.get("scripts") or {}) if package_data else {}
        start_text = " ".join(str(scripts.get(k, "")) for k in ("start", "dev", "preview")).lower()
        return any(name in start_text for name in ("next", "nuxt", "vite", "astro", "serve", "http-server", "express", "fastify"))
    if server_type == "Python":
        web_modules = {
            "flask", "django", "fastapi", "starlette", "sanic", "tornado", "bottle",
            "quart", "falcon", "uvicorn", "streamlit", "gradio", "dash", "panel",
            "bokeh", "nicegui", "reflex", "shiny", "voila",
        }
        modules = _python_project_imports(srv_path)
        if modules & web_modules:
            return True
        for rel in _project_files(srv_path, ("requirements.txt", "pyproject.toml", "Pipfile")):
            path = safe_relative_path(srv_path, rel)
            if not path:
                continue
            try:
                content = open(path, "r", encoding="utf-8", errors="ignore").read(512 * 1024).lower()
                if re.search(r"(?m)^\s*(flask|django|fastapi|starlette|sanic|tornado|bottle|quart|falcon|uvicorn|streamlit|gradio|dash|panel|bokeh|nicegui|reflex|shiny|voila)(?:[<=>~!;\s\[]|$)", content):
                    return True
            except OSError:
                pass
    return False


# ============== زر فتح السيرفر: بوت تليجرام أو موقع ==============
def find_telegram_bot_token(srv_path: str):
    """يبحث عن توكن بوت تليجرام داخل ملفات السيرفر بدون تغيير الملفات."""
    token_re = re.compile(r'(?<![A-Za-z0-9:_-])\d{6,12}:[A-Za-z0-9_-]{30,50}(?![A-Za-z0-9_-])')
    skip_ext = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.zip', '.pyc', '.db', '.sqlite', '.sqlite3'}
    try:
        for root, dirs, files in os.walk(srv_path):
            dirs[:] = [d for d in dirs if d not in {'.venv', 'venv', 'node_modules', '__pycache__', '.git', 'vendor', '.mazagi-home', '.mazagi-tmp'}]
            for filename in files:
                if os.path.splitext(filename)[1].lower() in skip_ext:
                    continue
                path = os.path.join(root, filename)
                try:
                    if os.path.getsize(path) > 2 * 1024 * 1024:
                        continue
                    with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                        text = fh.read()
                    match = token_re.search(text)
                    if match:
                        return match.group(0)
                except Exception:
                    continue
    except Exception:
        pass
    return None

def get_server_open_url(folder: str, srv: dict):
    """إرجاع رابط الموقع للمشاريع المعروفة كمواقع، ورابط Telegram للبوتات."""
    server_type = srv.get("type", "")
    startup_name = os.path.basename(str(srv.get("startup_file") or "")).lower()
    is_website = _server_is_website(srv)
    token = None if is_website else find_telegram_bot_token(srv.get("path", ""))
    if token:
        try:
            tg = requests.get(
                f"https://api.telegram.org/bot{token}/getMe",
                timeout=8
            ).json()
            username = (tg.get("result") or {}).get("username")
            if username:
                return {
                    "kind": "telegram",
                    "url": f"https://t.me/{username}",
                    "label": "فتح"
                }
        except Exception:
            pass

    # موقع الويب يحتاج رابطاً عاماً لأن الزائر لا يملك جلسة دخول لوحة مزاجي.
    # الرمز عشوائي بطول كافٍ، ولا نستخدم اسم مجلد السيرفر ككلمة مرور.
    if is_website and srv.get("port"):
        if not srv.get("public_token"):
            srv["public_token"] = secrets.token_urlsafe(32)
        site_domain = os.environ.get("PUBLIC_SITE_DOMAIN", "").strip().strip(".").lower()
        if site_domain:
            if not srv.get("public_host"):
                srv["public_host"] = secrets.token_hex(12)
            save_db(db)
            scheme = os.environ.get("PUBLIC_SITE_SCHEME", "https").strip().lower()
            if scheme not in ("http", "https"):
                scheme = "https"
            site_url = f"{scheme}://{srv['public_host']}.{site_domain}/"
        else:
            save_db(db)
            configured_base = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
            base = configured_base or request.host_url.rstrip("/")
            site_url = f"{base}/public-site/{quote(srv['public_token'], safe='')}/"
        return {"kind": "website", "url": site_url, "label": "فتح"}
    return None

@app.route('/api/server/open/<folder>')
def server_open(folder):
    if "username" not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    srv = db["servers"].get(folder)
    if not srv or srv.get("owner") != session["username"]:
        return jsonify({"success": False, "message": "غير مصرح"}), 403

    result = get_server_open_url(folder, srv)
    if not result:
        if _server_is_website(srv):
            message = "الموقع معروف، لكن لم يُسجّل له منفذ تشغيل. شغّله أولاً وراجع السجلات إذا فشل."
        else:
            message = "هذا بوت وليس موقعاً، ولم يُعثر على توكن Telegram صالح لفتح رابط البوت."
        return jsonify({"success": False, "message": message}), 404

    return jsonify({"success": True, **result})

@app.route('/site/<folder>/', defaults={'subpath': ''})
@app.route('/site/<folder>/<path:subpath>')
def proxy_user_site(folder, subpath):
    """وكيل بسيط لعرض مواقع السيرفرات من خلال رابط فتح واحد."""
    srv = db["servers"].get(unquote(folder))
    if not srv or not srv.get("port") or not _server_is_website(srv):
        return "الموقع غير متاح", 404

    # لا نسمح بالوصول إلى سيرفرات الآخرين عبر هذا المسار.
    if srv.get("owner") != session.get("username"):
        return "غير مصرح", 403

    return _proxy_user_site_response(srv, subpath)

def _website_path_is_public(subpath, srv=None):
    """Block common source, credential and repository paths from every public website."""
    decoded = str(subpath or "")
    for _ in range(3):
        newer = unquote(decoded)
        if newer == decoded:
            break
        decoded = newer
    decoded = decoded.replace("\\", "/")
    raw_parts = [part.casefold() for part in decoded.split("/") if part]
    if any(part == ".." for part in raw_parts):
        return False
    parts = [part for part in raw_parts if part != "."]
    blocked_dirs = {".git", ".svn", ".hg", ".venv", "venv", "node_modules", "__pycache__", ".idea", ".vscode", "portable_data", ".mazagi-home", ".mazagi-tmp"}
    if any(part in blocked_dirs or (part.startswith(".") and part != ".well-known") or part.startswith(".env") for part in parts):
        return False
    blocked_names = {
        "db.json", "credentials.json", "service-account.json", ".htpasswd", "id_rsa", "id_ed25519",
        "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "composer.json", "composer.lock",
        "requirements.txt", "pyproject.toml", "pipfile", "out.log", "errors.log", "server.log",
    }
    if any(part in blocked_names for part in parts):
        return False
    blocked_suffixes = (".py", ".pyc", ".pyo", ".log", ".sqlite", ".sqlite3", ".db", ".pem", ".key", ".p12", ".pfx", ".bak", ".swp", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".ps1", ".bat")
    # PHP sites must be allowed to execute .php routes through the PHP router;
    # other website runtimes must never expose PHP source as a static file.
    if not srv or srv.get("type") != "PHP":
        blocked_suffixes += (".php", ".phtml", ".phar", ".inc")
    elif parts and parts[-1].endswith((".phtml", ".phar", ".inc")):
        return False
    if parts and parts[-1].endswith(blocked_suffixes):
        return False
    return True


def _proxy_user_site_response(srv, subpath):
    if not _server_is_website(srv):
        return "هذا السيرفر ليس موقع ويب عاماً", 404
    if not _website_path_is_public(subpath, srv):
        return "الملف غير متاح", 404
    if srv.get("status") != "Running" or not _process_is_alive(srv):
        return "الموقع غير متاح حالياً. شغّل السيرفر ثم حاول مرة أخرى.", 503
    target_path = "/" + quote(unquote(subpath or ""), safe="/@:+")
    if request.query_string:
        target_path += "?" + request.query_string.decode("utf-8", errors="ignore")
    upstream = None
    try:
        headers = {}
        for key, value in request.headers.items():
            lower = key.lower()
            if lower in {"host", "content-length", "connection", "transfer-encoding", "cookie", "upgrade"}:
                continue
            headers[key] = value
        public_domain = os.environ.get("PUBLIC_SITE_DOMAIN", "").strip().strip(".").lower()
        host_name = request.host.split(":", 1)[0].lower()
        public_prefix = "" if public_domain and host_name.endswith("." + public_domain) else f"/public-site/{srv.get('public_token', '')}"
        headers["X-Forwarded-Prefix"] = public_prefix
        headers["X-Forwarded-Host"] = request.host
        headers["X-Forwarded-Proto"] = request.headers.get("X-Forwarded-Proto", request.scheme)
        headers["X-Forwarded-For"] = request.remote_addr or ""
        # Never forward the dashboard's session cookie to user code.
        forwarded_cookies = {k: v for k, v in request.cookies.items() if k != "session"}
        upstream = requests.request(
            method=request.method,
            url=f"http://127.0.0.1:{int(srv['port'])}{target_path}",
            headers=headers,
            data=request.get_data(),
            cookies=forwarded_cookies,
            allow_redirects=False,
            timeout=(5, 45),
            stream=True
        )
        excluded = {"content-encoding", "content-length", "transfer-encoding", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "upgrade"}
        response_headers = []
        public_domain = os.environ.get("PUBLIC_SITE_DOMAIN", "").strip().strip(".").lower()
        host_name = request.host.split(":", 1)[0].lower()
        if public_domain and host_name.endswith("." + public_domain):
            public_base = request.url_root.rstrip("/")
        else:
            public_base = (os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/") or request.host_url.rstrip("/")) + f"/public-site/{srv.get('public_token', '')}"
        for key, value in upstream.headers.items():
            if key.lower() in excluded:
                continue
            if key.lower() == "location":
                value = value.replace(f"http://127.0.0.1:{int(srv['port'])}", public_base)
                if value.startswith("/") and not value.startswith(public_base):
                    value = public_base + value
            response_headers.append((key, value))
        def generate_body():
            try:
                for chunk in upstream.iter_content(chunk_size=8192):
                    if chunk:
                        yield chunk
            finally:
                upstream.close()
        return Response(stream_with_context(generate_body()), status=upstream.status_code, headers=response_headers)
    except Exception:
        if upstream is not None:
            try:
                upstream.close()
            except Exception:
                pass
        return "تعذر الاتصال بموقع السيرفر حالياً", 502


@app.route('/public-site/<token>/', defaults={'subpath': ''}, methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'])
@app.route('/public-site/<token>/<path:subpath>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'])
def public_user_site(token, subpath):
    """Public website endpoint authenticated by a high-entropy per-server token."""
    srv = next((item for item in db.get("servers", {}).values()
                if item.get("public_token") and secrets.compare_digest(str(item.get("public_token")), str(token))), None)
    if not srv or not srv.get("port") or not _server_is_website(srv):
        return "الموقع غير موجود", 404
    return _proxy_user_site_response(srv, subpath)


@app.before_request
def _dispatch_public_site_subdomain():
    """Route wildcard website hostnames directly to the matching uploaded site."""
    domain = os.environ.get("PUBLIC_SITE_DOMAIN", "").strip().strip(".").lower()
    if not domain:
        return None
    host = request.host.split(":", 1)[0].lower()
    suffix = "." + domain
    if not host.endswith(suffix):
        return None
    label = host[:-len(suffix)]
    if not label or "." in label or not re.fullmatch(r"[a-f0-9]{24}", label):
        return "الموقع غير موجود", 404
    srv = next((item for item in db.get("servers", {}).values()
                if item.get("public_host") and secrets.compare_digest(str(item.get("public_host")).lower(), label)), None)
    if not srv or not _server_is_website(srv):
        return "الموقع غير موجود", 404
    return _proxy_user_site_response(srv, request.path.lstrip("/"))


@app.route('/api/servers')
def list_servers():
    requested_user = request.args.get("user", "").strip()
    if requested_user:
        if not _check_admin_access():
            return jsonify({"success": False, "message": "غير مصرح"}), 403
        target_username = requested_user
    else:
        if "username" not in session:
            return jsonify({"success": False}), 401
        target_username = session["username"]
    user_servers = []
    total_disk_used_mb = 0.0
    for folder, srv in db["servers"].items():
        if srv.get("owner") == target_username:
            disk_used = _tree_size_bytes(srv.get("path", ""))
            disk_used_mb = round(disk_used / (1024 * 1024), 2)
            total_disk_used_mb += disk_used_mb
            is_website = _server_is_website(srv)
            has_telegram_token = bool(find_telegram_bot_token(srv.get("path", "")))
            user_servers.append({
                "folder": folder,
                "title": srv["name"],
                "subtitle": f"سيرفر {srv.get('type', 'Python')}",
                "type": srv.get("type", "Python"),
                "startup_file": srv.get("startup_file", ""),
                "status": srv.get("status", "Stopped"),
                "uptime": uptime_str(srv.get("start_time")) if srv.get("status") == "Running" else "0 ثانية",
                "port": srv.get("port", "N/A"),
                "plan": srv.get("plan", "free"),
                "storage_limit": srv.get("storage_limit", 100),
                "ram_limit": srv.get("ram_limit", 256),
                "cpu_limit": srv.get("cpu_limit", 0.5),
                "disk_used": disk_used_mb,
                "can_open": bool(srv.get("port") and (is_website or has_telegram_token)),
                "open_kind": "website" if is_website else ("telegram" if has_telegram_token else "none")
            })
    user = db["users"].get(target_username, {})
    return jsonify({
        "success": True,
        "servers": user_servers,
        "stats": {
            "used": len(user_servers),
            "total": effective_max_servers(user),
            "expiry": user.get("expiry_days", 365),
            "disk_used": round(total_disk_used_mb, 2),
            "disk_total": round((psutil.disk_usage(DATA_DIR).total / (1024 * 1024)) if user.get("is_admin") else (_storage_limit_bytes(user) / (1024 * 1024)), 2),
        }
    })

@app.route('/api/server/add', methods=['POST'])
def add_server():
    if "username" not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    user = db["users"].get(session["username"])
    if not user:
        return jsonify({"success": False, "message": "مستخدم غير موجود"})
    
    user_srv_count = len([s for s in db["servers"].values() if s["owner"] == session["username"]])
    max_allowed = effective_max_servers(user)
    if user_srv_count >= max_allowed:
        return jsonify({"success": False, "message": f"وصلت للحد الأقصى ({max_allowed}) سيرفر."}), 403
    
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"success": False, "message": "الرجاء إدخال اسم للسيرفر"})
    
    server_type = data.get("server_type", "Python")
    if server_type not in ("Python", "Node.js", "PHP", "Static Website"):
        server_type = "Python"
    
    plan_id = user.get("plan", "free")
    plan = db["plans"].get(plan_id, db["plans"]["free"])
    
    folder = f"{safe_user_filename(session['username'])}_{re.sub(r'[^a-zA-Z0-9_-]', '', name)[:32]}_{int(time.time() * 1000)}_{secrets.token_hex(2)}"
    path = os.path.join(get_user_servers_dir(session["username"]), folder)
    os.makedirs(path, exist_ok=True)
    assigned_port = get_assigned_port()
    
    db["servers"][folder] = {
        "name": name,
        "owner": session["username"],
        "path": path,
        "type": server_type,
        "status": "Stopped",
        "created_at": str(datetime.now()),
        "startup_file": "",
        "pid": None,
        "port": assigned_port,
        "public_token": secrets.token_urlsafe(32),
        "public_host": secrets.token_hex(12),
        "plan": plan_id,
        "storage_limit": plan["storage"],
        "ram_limit": plan["ram"],
        "cpu_limit": plan["cpu"]
    }
    save_db(db)
    _release_port_reservation(assigned_port)
    return jsonify({"success": True, "message": f"✅ تم إنشاء الخادم {name}"})

@app.route('/api/server/action/<folder>/<action>', methods=['POST'])
def server_action(folder, action):
    if "username" not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session["username"]:
        return jsonify({"success": False, "message": "غير مصرح"})
    if action == "start":
        ok, msg = queue_server_start(folder, restart=False)
        return jsonify({"success": ok, "message": msg}), (202 if ok else 409)
    elif action == "stop":
        stop_server_process(folder)
        return jsonify({"success": True, "message": "🛑 تم الإيقاف"})
    elif action == "restart":
        ok, msg = queue_server_start(folder, restart=True)
        return jsonify({"success": ok, "message": msg}), (202 if ok else 409)
    elif action == "delete":
        stop_server_process(folder)
        if os.path.exists(srv["path"]):
            shutil.rmtree(srv["path"], ignore_errors=True)
        del db["servers"][folder]
        save_db(db)
        return jsonify({"success": True, "message": "🗑 تم الحذف"})
    return jsonify({"success": False})

@app.route('/api/server/stats/<folder>')
def get_server_stats(folder):
    if "username" not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session["username"]:
        return jsonify({"success": False})
    status = srv.get("status", "Stopped")
    if status == "Running" and not _process_is_alive(srv):
        status = "Error"
        srv["status"] = "Error"
        srv["pid"] = None
        srv["process_create_time"] = None
        srv["last_error"] = "توقفت العملية؛ راجع سجل الأخطاء ثم أعد التشغيل"
        save_db(db)
    logs = "لا توجد مخرجات بعد"
    log_path = os.path.join(srv["path"], "out.log")
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.read().split('\n')
                logs = '\n'.join(lines[-500:])
        except Exception:
            pass
    errors = ""
    error_path = os.path.join(srv["path"], "errors.log")
    if os.path.exists(error_path):
        try:
            with open(error_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().strip()
                if content:
                    errors = '\n'.join(content.split('\n')[-50:])
        except Exception:
            pass
    mem_info = "0 MB"
    if srv.get("pid") and status == "Running":
        try:
            process = psutil.Process(int(srv["pid"]))
            family = [process] + process.children(recursive=True)
            total_rss = sum(item.memory_info().rss for item in family if item.is_running())
            mem_info = f"{total_rss / (1024*1024):.1f} MB"
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, TypeError):
            pass
    return jsonify({
        "success": True,
        "status": status,
        "logs": logs,
        "errors": errors,
        "mem": mem_info,
        "uptime": uptime_str(srv.get("start_time")) if status == "Running" else "0 ثانية",
        "port": srv.get("port", "--"),
        "ip": get_public_ip(),
        "type": srv.get("type", "Python")
    })

# ============== الملفات ==============
@app.route('/api/files/list/<folder>')
def list_server_files(folder):
    if "username" not in session:
        return jsonify([]), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session["username"]:
        return jsonify([]), 403
    base = os.path.abspath(srv["path"])
    files = []
    try:
        for root, dirs, names in os.walk(base):
            dirs[:] = [d for d in dirs if d not in ['__pycache__', '.git', '.venv', 'venv', 'node_modules', 'vendor']]
            rel_root = os.path.relpath(root, base)
            rel_root = '' if rel_root == '.' else rel_root.replace(os.sep, '/')
            for name in dirs + names:
                if name in ['out.log', 'server.log', 'meta.json', 'errors.log']:
                    continue
                full = os.path.join(root, name)
                if os.path.islink(full):
                    continue
                rel = os.path.join(rel_root, name).replace(os.sep, '/') if rel_root else name
                try:
                    stat = os.stat(full)
                    size_bytes = stat.st_size if os.path.isfile(full) else 0
                    if size_bytes < 1024:
                        size_str = f"{size_bytes} B"
                    elif size_bytes < 1024 * 1024:
                        size_str = f"{size_bytes/1024:.1f} KB"
                    else:
                        size_str = f"{size_bytes/(1024*1024):.1f} MB"
                    files.append({
                        "name": rel,
                        "size": size_str,
                        "is_dir": os.path.isdir(full),
                        "modified": datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M'),
                        "is_zip": is_supported_archive(rel),
                        "is_archive": is_supported_archive(rel)
                    })
                except OSError:
                    continue
    except Exception as exc:
        return jsonify({"success": False, "message": str(exc)}), 500
    return jsonify(sorted(files, key=lambda x: (x['name'].count('/'), not x['is_dir'], x['name'].lower())))

@app.route('/api/files/download/<folder>/<path:filename>')
def download_user_file(folder, filename):
    if "username" not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    srv = db["servers"].get(folder)
    if not srv or srv.get("owner") != session["username"]:
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    fpath = safe_relative_path(srv["path"], filename)
    if not fpath or not os.path.isfile(fpath):
        return jsonify({"success": False, "message": "الملف غير موجود"}), 404
    return send_file(fpath, as_attachment=True, download_name=os.path.basename(fpath))

@app.route('/api/files/content/<folder>/<path:filename>')
def get_file_content(folder, filename):
    if "username" not in session:
        return jsonify({"content": ""}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session["username"]:
        return jsonify({"content": ""}), 403
    fpath = safe_relative_path(srv["path"], filename)
    if not fpath or not os.path.isfile(fpath):
        return jsonify({"content": "", "message": "الملف غير موجود"}), 404
    try:
        with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
            return jsonify({"content": f.read()})
    except Exception:
        return jsonify({"content": "[ملف ثنائي]"})

@app.route('/api/files/save/<folder>/<path:filename>', methods=['POST'])
def save_file_content(folder, filename):
    if "username" not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session["username"]:
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    fpath = safe_relative_path(srv["path"], filename)
    if not fpath or not os.path.isfile(fpath):
        return jsonify({"success": False, "message": "الملف غير موجود"}), 404
    data = request.get_json(silent=True) or {}
    try:
        with open(fpath, 'w', encoding='utf-8') as f:
            f.write(data.get("content", ""))
        return jsonify({"success": True, "message": "✅ تم الحفظ"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/files/upload/<folder>', methods=['POST'])
def upload_files(folder):
    if "username" not in session:
        return jsonify({"success": False, "message": "سجّل الدخول أولاً"}), 401
    srv = db.get("servers", {}).get(folder)
    if not srv or srv.get("owner") != session["username"]:
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    os.makedirs(srv["path"], exist_ok=True)
    files = request.files.getlist('files[]') or request.files.getlist('files')
    files = [f for f in files if f and f.filename]
    if not files:
        return jsonify({"success": False, "message": "لم يتم استلام أي ملف"}), 400

    # Check quota before writing anything, accounting for files that will be replaced.
    incoming = 0
    replacement_targets = []
    for item in files:
        try:
            item.stream.seek(0, os.SEEK_END)
            incoming += item.stream.tell()
            item.stream.seek(0)
        except Exception:
            pass
        safe_name = unicodedata.normalize('NFC', str(item.filename or '')).replace('\\', '/')
        target = safe_relative_path(srv["path"], safe_name)
        if not target:
            return jsonify({"success": False, "message": f"اسم أو مسار ملف غير صالح: {item.filename}"}), 400
        replacement_targets.append(target)
    allowed, remaining = _check_storage_quota(
        session["username"], incoming, replacing_paths=replacement_targets
    )
    if not allowed:
        return jsonify({"success": False, "message": f"تجاوزت مساحة التخزين. المتبقي {remaining / (1024*1024):.2f} MB"}), 413

    uploaded = 0
    errors_list = []
    for item in files:
        filename = unicodedata.normalize('NFC', str(item.filename or '')).replace('\\', '/')
        save_path = safe_relative_path(srv["path"], filename)
        if not save_path:
            errors_list.append(f"اسم أو مسار ملف غير صالح: {item.filename}")
            continue
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        if os.path.isdir(save_path):
            errors_list.append(f"يوجد مجلد بالاسم نفسه: {filename}")
            continue
        try:
            temp_path = save_path + ".upload_tmp"
            item.save(temp_path)
            os.replace(temp_path, save_path)
            uploaded += 1
        except Exception as exc:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass
            errors_list.append(f"{filename}: {exc}")

    if not uploaded:
        return jsonify({"success": False, "message": "فشل رفع الملفات", "errors": errors_list}), 400

    auto_detect_server_type(srv["path"], srv)
    if not srv.get("startup_file"):
        srv["startup_file"] = detect_main_file(srv["path"], srv.get("type", "Python"))
    save_db(db)
    threading.Thread(target=_install_and_start_after_upload, args=(folder,), daemon=True).start()
    msg = f"✅ تم رفع {uploaded} ملف. يجري الآن فحص المشروع وتثبيت المكتبات وتشغيله تلقائياً."
    if errors_list:
        msg += f" تعذّر رفع {len(errors_list)} ملف."
    return jsonify({"success": True, "message": msg, "warnings": errors_list, "folder": folder})


def _install_and_start_after_upload(folder, *, restart_if_running=True):
    """After a completed upload: prepare dependencies once, then launch/restart."""
    srv = db.get("servers", {}).get(folder)
    if not srv:
        return
    was_running = srv.get("status") == "Running" and _process_is_alive(srv)
    if was_running and restart_if_running:
        srv["status"] = "Restarting"
        stop_server_process(folder, cancel_start=False)
    srv = db.get("servers", {}).get(folder)
    if not srv:
        return
    srv["status"] = "Installing"
    srv["start_cancelled"] = False
    save_db(db)
    ok, message = start_server_process(folder)
    try:
        with open(os.path.join(srv.get("path", ""), "out.log"), "a", encoding="utf-8") as lf:
            lf.write(f"\n🤖 نتيجة التشغيل بعد الرفع: {message}\n")
    except Exception:
        pass
    if not ok and not message.startswith("تم إلغاء التشغيل"):
        srv["status"] = "Error"
        srv["last_error"] = message
        save_db(db)


def _auto_install_after_upload(srv_path: str, server_type: str, log_path: str):
    """Compatibility wrapper: ensure dependencies and report an accurate result."""
    try:
        with open(log_path, "a", encoding="utf-8") as lf:
            auto_install_deps(srv_path, server_type, lf)
    except Exception as exc:
        with open(log_path, "a", encoding="utf-8") as lf:
            lf.write(f"\n❌ التثبيت التلقائي: {exc}\n")


@app.route('/api/server/auto-upload', methods=['POST'])
def auto_create_server_from_upload():
    """Upload one source file or a project ZIP, then auto-install and launch it."""
    if "username" not in session:
        return jsonify({"success": False, "message": "سجّل الدخول أولاً"}), 401
    username = session["username"]
    user = db.get("users", {}).get(username)
    if not user:
        return jsonify({"success": False, "message": "مستخدم غير موجود"}), 404
    user_srv_count = sum(1 for srv in db.get("servers", {}).values() if srv.get("owner") == username)
    max_allowed = effective_max_servers(user)
    if user_srv_count >= max_allowed:
        return jsonify({"success": False, "message": f"وصلت للحد الأقصى ({max_allowed}) سيرفر."}), 403

    upload = request.files.get('file')
    if not upload or not upload.filename:
        return jsonify({"success": False, "message": "اختر ملفاً أولاً"}), 400
    filename = safe_user_filename(upload.filename)
    if not filename:
        return jsonify({"success": False, "message": "اسم الملف غير صالح"}), 400
    ext = os.path.splitext(filename)[1].lower()
    is_archive = is_supported_archive(filename)
    supported_single_files = {
        '.py', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.php', '.html', '.htm',
    }
    if not is_archive and ext not in supported_single_files:
        return jsonify({"success": False, "message": "ارفع ملف مشروع مضغوط ZIP/TAR.GZ أو ملف بداية مدعوماً. بقية ملفات المشروع ارفعها داخل الأرشيف."}), 400

    try:
        upload.stream.seek(0, os.SEEK_END)
        upload_size = upload.stream.tell()
        upload.stream.seek(0)
    except Exception:
        upload_size = 0
    allowed, remaining = _check_storage_quota(username, upload_size)
    if not allowed and not is_archive:
        return jsonify({"success": False, "message": f"مساحة التخزين غير كافية. المتبقي {remaining / (1024*1024):.2f} MB"}), 413

    base_name = os.path.splitext(filename)[0]
    safe_name = re.sub(r'[^a-zA-Z0-9_-]+', '', base_name) or "my-server"
    server_name = base_name[:40] or "سيرفري الجديد"
    folder = f"{safe_user_filename(username)}_{safe_name}_{int(time.time() * 1000)}"
    path = os.path.join(get_user_servers_dir(username), folder)
    os.makedirs(path, exist_ok=False)
    plan_id = user.get("plan", "free")
    plan = db.get("plans", {}).get(plan_id, db["plans"]["free"])
    assigned_port = get_assigned_port()

    try:
        upload_path = safe_child_path(path, filename)
        upload.save(upload_path)
        if is_archive:
            expanded_size = archive_uncompressed_size(upload_path)
            allowed_after_extract, _remaining_after_extract = _check_storage_quota(
                username, expanded_size, replacing_path=upload_path
            )
            if not allowed_after_extract:
                raise ValueError("المساحة المتاحة لا تكفي لفك المشروع المضغوط")
            safe_extract_archive(upload_path, path)
            if not any(_project_files(path, suffixes) for suffixes in (
                (".py",), (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"),
                (".php",), (".html", ".htm"),
            )):
                raise ValueError("لم أجد ملف مشروع أو صفحة موقع معروفة داخل الأرشيف")
            # Keep only the extracted project; do not leave the source archive
            # inside a public document root or count archive + extracted copy.
            try:
                os.remove(upload_path)
            except OSError:
                pass
            final_usage_ok, final_remaining = _check_storage_quota(username, 0)
            if not final_usage_ok:
                raise ValueError(f"الملفات بعد فك الضغط تجاوزت حصة التخزين. المتبقي {final_remaining / (1024*1024):.2f} MB")
        srv = {
            "name": server_name,
            "owner": username,
            "path": path,
            "type": "Python",
            "status": "Stopped",
            "created_at": str(datetime.now()),
            "startup_file": "",
            "pid": None,
            "port": assigned_port,
            "public_token": secrets.token_urlsafe(32),
            "public_host": secrets.token_hex(12),
            "plan": plan_id,
            "storage_limit": plan["storage"],
            "ram_limit": plan["ram"],
            "cpu_limit": plan["cpu"]
        }
        db["servers"][folder] = srv
        auto_detect_server_type(path, srv)
        srv["startup_file"] = srv.get("startup_file") or detect_main_file(path, srv.get("type", "Python"))
        save_db(db)
        _release_port_reservation(assigned_port)
        threading.Thread(target=_install_and_start_after_upload, args=(folder,), daemon=True).start()
        return jsonify({
            "success": True,
            "message": "✅ تم رفع المشروع. يجري فحصه وتثبيت مكتباته وتشغيله تلقائياً؛ ستجد النتيجة في سجل السيرفر.",
            "folder": folder,
            "server_type": srv.get("type"),
            "startup_file": srv.get("startup_file"),
        })
    except Exception as exc:
        db.get("servers", {}).pop(folder, None)
        save_db(db)
        _release_port_reservation(assigned_port)
        shutil.rmtree(path, ignore_errors=True)
        return jsonify({"success": False, "message": f"فشل تجهيز المشروع: {exc}"}), 400

@app.route('/api/files/replace/<folder>/<path:filename>', methods=['POST'])
def replace_file(folder, filename):
    """استبدال ملف موجود مباشرة بدون حذفه أولاً."""
    if "username" not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session["username"]:
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    if not filename or filename.startswith('/'):
        return jsonify({"success": False, "message": "اسم ملف غير صالح"}), 400
    target = safe_relative_path(srv["path"], filename)
    if not target:
        return jsonify({"success": False, "message": "اسم ملف غير صالح"}), 400
    if os.path.isdir(target):
        return jsonify({"success": False, "message": "لا يمكن استبدال مجلد"}), 400
    if not os.path.exists(target):
        return jsonify({"success": False, "message": "الملف الأصلي غير موجود"}), 404
    new_file = request.files.get('file')
    if not new_file or not new_file.filename:
        return jsonify({"success": False, "message": "اختر الملف الجديد أولاً"}), 400
    try:
        try:
            new_file.stream.seek(0, os.SEEK_END)
            incoming_size = new_file.stream.tell()
            new_file.stream.seek(0)
        except Exception:
            incoming_size = 0
        allowed, remaining = _check_storage_quota(session["username"], incoming_size, replacing_path=target)
        if not allowed:
            return jsonify({"success": False, "message": f"مساحة التخزين غير كافية. المتبقي {remaining / (1024*1024):.2f} MB"}), 413
        # Write to a temporary file, then atomically replace the target.
        temp_path = target + '.replace_tmp'
        new_file.save(temp_path)
        os.replace(temp_path, target)

        auto_detect_server_type(srv["path"], srv)
        if srv.get("startup_file") == filename and not os.path.isfile(os.path.join(srv["path"], filename)):
            srv["startup_file"] = ""
        save_db(db)
        threading.Thread(target=_install_and_start_after_upload, args=(folder,), daemon=True).start()

        return jsonify({
            "success": True,
            "message": f"✅ تم استبدال {filename} بنجاح"
        })
    except Exception as e:
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass
        return jsonify({"success": False, "message": f"فشل الاستبدال: {e}"}), 500


@app.route('/api/files/rename/<folder>', methods=['POST'])
def rename_file(folder):
    if "username" not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session["username"]:
        return jsonify({"success": False})
    data = request.get_json(silent=True) or {}
    old_name = str(data.get("old_name", "")).strip()
    new_name = safe_user_filename(str(data.get("new_name", "")).strip())
    if not old_name or not new_name:
        return jsonify({"success": False, "message": "اسم غير صالح"})
    old_path = safe_relative_path(srv["path"], old_name)
    new_path = safe_relative_path(os.path.dirname(old_path) if old_path else srv["path"], new_name) if old_path else None
    if not old_path or not new_path:
        return jsonify({"success": False, "message": "اسم غير صالح"})
    if not os.path.exists(old_path):
        return jsonify({"success": False, "message": "الملف غير موجود"})
    if os.path.exists(new_path):
        return jsonify({"success": False, "message": "يوجد ملف بهذا الاسم"})
    try:
        os.rename(old_path, new_path)
        startup_changed = srv.get("startup_file") == old_name
        if startup_changed:
            srv["startup_file"] = os.path.relpath(new_path, srv["path"]).replace(os.sep, "/")
        save_db(db)
        if startup_changed:
            ok, message = queue_server_start(folder, restart=True)
            if not ok:
                return jsonify({"success": True, "message": f"تمت إعادة التسمية، لكن تعذر بدء إعادة التشغيل: {message}"})
        return jsonify({"success": True, "message": f"✅ تمت إعادة التسمية إلى {new_name}"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/api/files/unzip/<folder>/<path:filename>', methods=['POST'])
def unzip_file(folder, filename):
    if "username" not in session:
        return jsonify({"success": False, "message": "سجّل الدخول أولاً"}), 401
    srv = db.get("servers", {}).get(folder)
    if not srv or srv.get("owner") != session["username"]:
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    if not is_supported_archive(filename):
        return jsonify({"success": False, "message": "الصيغة غير مدعومة. الصيغ المدعومة: ZIP وTAR وTAR.GZ وTAR.BZ2 وTAR.XZ"}), 400
    zip_path = safe_relative_path(srv["path"], filename)
    if not zip_path or not os.path.isfile(zip_path):
        return jsonify({"success": False, "message": "ملف الأرشيف غير موجود"}), 404
    try:
        expected = archive_uncompressed_size(zip_path)
        allowed, remaining = _check_storage_quota(session["username"], expected)
        if not allowed:
            return jsonify({"success": False, "message": f"لا توجد مساحة كافية لفك الضغط. المتبقي {remaining / (1024*1024):.2f} MB"}), 413
        count = safe_extract_archive(zip_path, srv["path"])
        auto_detect_server_type(srv["path"], srv)
        if not srv.get("startup_file"):
            srv["startup_file"] = detect_main_file(srv["path"], srv.get("type", "Python"))
        save_db(db)
        threading.Thread(target=_install_and_start_after_upload, args=(folder,), daemon=True).start()
        return jsonify({"success": True, "message": f"✅ تم فك الأرشيف ({count} ملف). يجري اكتشاف نوع المشروع وتجهيزه وتشغيله تلقائياً."})
    except (zipfile.BadZipFile, tarfile.TarError):
        return jsonify({"success": False, "message": "الأرشيف غير صالح أو تالف"}), 400
    except Exception as exc:
        return jsonify({"success": False, "message": str(exc)}), 400

@app.route('/api/files/delete/<folder>', methods=['POST'])
def delete_files(folder):
    if "username" not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session["username"]:
        return jsonify({"success": False})
    data = request.get_json(silent=True) or {}
    names = data.get("names", data.get("name", []))
    if isinstance(names, str):
        names = [names]
    deleted = 0
    for name in names:
        if not name or '..' in name:
            continue
        fpath = safe_relative_path(srv["path"], name)
        if not fpath:
            continue
        try:
            if os.path.isdir(fpath):
                shutil.rmtree(fpath)
            elif os.path.exists(fpath):
                os.remove(fpath)
            deleted += 1
        except Exception:
            pass
    if deleted > 0:
        # Re-select a valid entrypoint if the previous one was deleted.
        previous_startup = srv.get("startup_file", "")
        previous_path = safe_relative_path(srv["path"], previous_startup) if previous_startup else None
        if previous_path and not os.path.isfile(previous_path):
            srv["startup_file"] = ""
        auto_detect_server_type(srv["path"], srv)
        if srv.get("startup_file") and srv.get("startup_file") != previous_startup:
            stop_server_process(folder)
            save_db(db)
            threading.Thread(target=_install_and_start_after_upload, args=(folder,), daemon=True).start()
        elif previous_startup and not srv.get("startup_file"):
            stop_server_process(folder)
            save_db(db)
        else:
            save_db(db)
        return jsonify({"success": True, "message": f"🗑 تم حذف {deleted} ملف"})
    return jsonify({"success": False, "message": "فشل الحذف"})

@app.route('/api/files/create/<folder>', methods=['POST'])
def create_file_api(folder):
    if "username" not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session["username"]:
        return jsonify({"success": False})
    data = request.get_json(silent=True) or {}
    filename = str(data.get("filename", "")).strip()
    fpath = safe_relative_path(srv["path"], filename)
    if not fpath:
        return jsonify({"success": False, "message": "اسم أو مسار غير صالح"})
    if os.path.exists(fpath):
        return jsonify({"success": False, "message": "يوجد ملف بهذا الاسم"}), 409
    allowed, remaining = _check_storage_quota(session["username"], len(str(data.get("content", "")).encode("utf-8")))
    if not allowed:
        return jsonify({"success": False, "message": f"مساحة التخزين غير كافية. المتبقي {remaining / (1024*1024):.2f} MB"}), 413
    try:
        os.makedirs(os.path.dirname(fpath), exist_ok=True)
        with open(fpath, 'x', encoding='utf-8') as f:
            f.write(data.get("content", ""))
        # كشف تلقائي بعد الإنشاء + حفظ
        auto_detect_server_type(srv["path"], srv)
        save_db(db)
        return jsonify({"success": True, "message": f"✅ تم إنشاء {filename}"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/api/server/set-startup/<folder>', methods=['POST'])
def set_startup_file(folder):
    if "username" not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session["username"]:
        return jsonify({"success": False})
    data = request.get_json(silent=True) or {}
    filename = str(data.get("filename", "")).strip()
    candidate = safe_relative_path(srv["path"], filename)
    if not candidate:
        return jsonify({"success": False, "message": "اسم غير صالح"})
    if not os.path.isfile(candidate):
        return jsonify({"success": False, "message": "الملف غير موجود"})
    srv["startup_file"] = filename
    save_db(db)
    return jsonify({"success": True, "message": f"✅ تم تعيين {filename} كملف التشغيل"})

@app.route('/api/admin/server-files/<folder>')
def admin_server_files(folder):
    if not _check_admin_access():
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    srv = db["servers"].get(folder)
    if not srv:
        return jsonify({"success": False, "message": "السيرفر غير موجود"}), 404
    files = []
    base = srv.get("path", "")
    if not os.path.isdir(base):
        return jsonify({"success": True, "files": []})
    for root_dir, dirs, names in os.walk(base):
        dirs[:] = [d for d in dirs if d not in {'.venv', 'venv', '__pycache__', '.git', 'node_modules', 'vendor'}]
        for name in names:
            if name in {'out.log','errors.log','server.log','meta.json'}:
                continue
            full = os.path.join(root_dir, name)
            rel = os.path.relpath(full, base).replace(os.sep, '/')
            try:
                size = os.path.getsize(full)
            except Exception:
                size = 0
            files.append({"name": rel, "size": size})
    return jsonify({"success": True, "owner": srv.get("owner"), "server": srv.get("name"), "files": sorted(files, key=lambda x: x["name"].lower())})

@app.route('/api/admin/file/download/<folder>/<path:filename>')
def admin_download_file(folder, filename):
    if not _check_admin_access():
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    srv = db["servers"].get(folder)
    if not srv:
        return jsonify({"success": False, "message": "السيرفر غير موجود"}), 404
    fpath = safe_relative_path(srv["path"], filename)
    if not fpath or not os.path.isfile(fpath):
        return jsonify({"success": False, "message": "مسار غير صالح أو الملف غير موجود"}), 404
    return send_file(fpath, as_attachment=True, download_name=os.path.basename(fpath))

@app.route('/api/admin/file/delete/<folder>', methods=['POST'])
def admin_delete_file(folder):
    if not _check_admin_access():
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    srv = db["servers"].get(folder)
    if not srv:
        return jsonify({"success": False, "message": "السيرفر غير موجود"}), 404
    data = request.get_json(silent=True) or {}
    name = data.get("name", "")
    if not name:
        return jsonify({"success": False, "message": "اسم الملف مطلوب"}), 400
    fpath = safe_relative_path(srv["path"], name)
    if not fpath or not os.path.exists(fpath):
        return jsonify({"success": False, "message": "الملف غير موجود"}), 404
    try:
        if os.path.isdir(fpath):
            shutil.rmtree(fpath)
        else:
            os.remove(fpath)
        save_db(db)
        return jsonify({"success": True, "message": "🗑 تم حذف الملف من السيرفر"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/admin/server/download-all/<folder>')
def admin_download_server(folder):
    if not _check_admin_access():
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    srv = db["servers"].get(folder)
    if not srv or not os.path.isdir(srv.get("path", "")):
        return jsonify({"success": False, "message": "السيرفر غير موجود"}), 404
    temp_base = os.path.join(tempfile.gettempdir(), f"mazagi_admin_{secrets.token_hex(8)}")
    os.makedirs(temp_base, exist_ok=True)
    archive_base = os.path.join(temp_base, f"{safe_user_filename(srv.get('name','server')) or 'server'}")
    try:
        shutil.make_archive(archive_base, 'zip', srv["path"])
        return send_file(archive_base + '.zip', as_attachment=True, download_name=(safe_user_filename(srv.get('name','server')) or 'server') + '.zip')
    except Exception as e:
        shutil.rmtree(temp_base, ignore_errors=True)
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/server/install/<folder>', methods=['POST'])
def install_requirements(folder):
    if "username" not in session:
        return jsonify({"success": False, "message": "سجّل الدخول أولاً"}), 401
    srv = db.get("servers", {}).get(folder)
    if not srv or srv.get("owner") != session["username"]:
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    log_path = os.path.join(srv["path"], "out.log")
    def worker():
        try:
            with open(log_path, "a", encoding="utf-8") as lf:
                ok = auto_install_deps(srv["path"], srv.get("type", "Python"), lf)
                lf.write("\n✅ انتهى تجهيز المكتبات\n" if ok else "\n❌ تعذر تجهيز المكتبات\n")
        except Exception as exc:
            with open(log_path, "a", encoding="utf-8") as lf:
                lf.write(f"\n❌ {exc}\n")
    threading.Thread(target=worker, daemon=True).start()
    return jsonify({"success": True, "message": "بدأ فحص وتثبيت مكتبات هذا السيرفر. تابع سجل التشغيل للتفاصيل."})

# ============== API البوت ==============
@app.route('/api/bot/verify', methods=['POST'])
def bot_verify():
    data = request.get_json(silent=True) or {}
    api_key = data.get('api_key', '').strip()
    if not api_key:
        return jsonify({"success": False, "message": "API Key مطلوب"})
    username, user = get_user_by_api_key(api_key)
    if not username:
        return jsonify({"success": False, "message": "API Key غير صالح"})
    return jsonify({
        "success": True,
        "username": username,
        "is_admin": is_admin(username),
        "max_servers": user.get("max_servers", 2),
        "expiry_days": user.get("expiry_days", 365)
    })

@app.route('/api/bot/servers', methods=['GET'])
def bot_list_servers():
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        return jsonify({"success": False, "message": "API Key مطلوب"}), 401
    username, _ = get_user_by_api_key(api_key)
    if not username:
        return jsonify({"success": False, "message": "API Key غير صالح"}), 401
    user_servers = []
    for folder, srv in db["servers"].items():
        if srv["owner"] == username:
            user_servers.append({
                "folder": folder,
                "title": srv["name"],
                "status": srv.get("status", "Stopped"),
                "uptime": uptime_str(srv.get("start_time")) if srv.get("status") == "Running" else "0 ثانية",
                "port": srv.get("port", "N/A"),
                "plan": srv.get("plan", "free"),
                "type": srv.get("type", "Python"),
                "storage_limit": srv.get("storage_limit", 100),
                "ram_limit": srv.get("ram_limit", 256),
                "cpu_limit": srv.get("cpu_limit", 0.5)
            })
    return jsonify({"success": True, "servers": user_servers})

@app.route('/api/bot/server/action', methods=['POST'])
def bot_server_action():
    data = request.get_json(silent=True) or {}
    api_key = data.get('api_key')
    folder = data.get('folder')
    action = data.get('action')
    if not all([api_key, folder, action]):
        return jsonify({"success": False, "message": "بيانات ناقصة"}), 400
    username, _ = get_user_by_api_key(api_key)
    if not username:
        return jsonify({"success": False, "message": "API Key غير صالح"}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != username:
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    if action == "start":
        ok, msg = queue_server_start(folder, restart=False)
        return jsonify({"success": ok, "message": msg}), (202 if ok else 409)
    elif action == "stop":
        stop_server_process(folder)
        return jsonify({"success": True, "message": "🛑 تم الإيقاف"})
    elif action == "restart":
        ok, msg = queue_server_start(folder, restart=True)
        return jsonify({"success": ok, "message": msg}), (202 if ok else 409)
    elif action == "delete":
        stop_server_process(folder)
        if os.path.exists(srv["path"]):
            shutil.rmtree(srv["path"], ignore_errors=True)
        del db["servers"][folder]
        save_db(db)
        return jsonify({"success": True, "message": "🗑 تم الحذف"})
    return jsonify({"success": False, "message": "إجراء غير معروف"})

@app.route('/api/bot/console', methods=['GET'])
def bot_console():
    api_key = request.headers.get('X-API-Key')
    folder = request.args.get('folder')
    if not api_key or not folder:
        return jsonify({"success": False, "message": "بيانات ناقصة"}), 400
    username, _ = get_user_by_api_key(api_key)
    if not username:
        return jsonify({"success": False, "message": "API Key غير صالح"}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != username:
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    log_path = os.path.join(srv["path"], "out.log")
    logs = "لا توجد مخرجات بعد"
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.read().split('\n')
                logs = '\n'.join(lines[-500:])
        except Exception:
            pass
    return jsonify({"success": True, "logs": logs})

@app.route('/api/bot/errors', methods=['GET'])
def bot_errors():
    api_key = request.headers.get('X-API-Key')
    folder = request.args.get('folder')
    if not api_key or not folder:
        return jsonify({"success": False, "message": "بيانات ناقصة"}), 400
    username, _ = get_user_by_api_key(api_key)
    if not username:
        return jsonify({"success": False, "message": "API Key غير صالح"}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != username:
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    errors = "✅ لا توجد أخطاء مسجلة"
    error_path = os.path.join(srv["path"], "errors.log")
    if os.path.exists(error_path):
        try:
            with open(error_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().strip()
                if content:
                    errors = '\n'.join(content.split('\n')[-300:])
        except Exception:
            pass
    return jsonify({"success": True, "errors": errors})

@app.route('/api/bot/install', methods=['POST'])
def bot_install():
    data = request.get_json(silent=True) or {}
    api_key = data.get('api_key')
    folder = data.get('folder')
    if not api_key or not folder:
        return jsonify({"success": False, "message": "بيانات ناقصة"}), 400
    username, _ = get_user_by_api_key(api_key)
    if not username:
        return jsonify({"success": False, "message": "API Key غير صالح"}), 401
    srv = db.get("servers", {}).get(folder)
    if not srv or srv.get("owner") != username:
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    log_path = os.path.join(srv["path"], "out.log")
    def worker():
        with open(log_path, "a", encoding="utf-8") as lf:
            ok = auto_install_deps(srv["path"], srv.get("type", "Python"), lf)
            lf.write("\n✅ اكتمل تثبيت المتطلبات\n" if ok else "\n❌ فشل تثبيت المتطلبات؛ راجع السجل\n")
    threading.Thread(target=worker, daemon=True).start()
    return jsonify({"success": True, "message": "بدأ فحص وتثبيت المكتبات داخل بيئة السيرفر الخاصة."})

@app.route('/api/bot/create_server', methods=['POST'])
def bot_create_server():
    data = request.get_json(silent=True) or {}
    api_key = data.get('api_key')
    name = data.get('name', '').strip()
    server_type = data.get('server_type', 'Python')
    if not api_key:
        return jsonify({"success": False, "message": "API Key مطلوب"}), 400
    if not name:
        return jsonify({"success": False, "message": "الرجاء إدخال اسم للسيرفر"}), 400
    username, user = get_user_by_api_key(api_key)
    if not username:
        return jsonify({"success": False, "message": "API Key غير صالح"}), 401
    user_srv_count = len([s for s in db["servers"].values() if s.get("owner") == username])
    max_allowed = effective_max_servers(user)
    if user_srv_count >= max_allowed:
        return jsonify({"success": False, "message": f"وصلت للحد الأقصى ({max_allowed}) سيرفر"}), 403
    if server_type not in ("Python", "Node.js", "PHP", "Static Website"):
        server_type = "Python"
    
    plan_id = user.get("plan", "free")
    plan = db["plans"].get(plan_id, db["plans"]["free"])
    
    folder = f"{safe_user_filename(username)}_{re.sub(r'[^a-zA-Z0-9_-]', '', name)[:32]}_{int(time.time() * 1000)}_{secrets.token_hex(2)}"
    path = os.path.join(get_user_servers_dir(username), folder)
    os.makedirs(path, exist_ok=True)
    assigned_port = get_assigned_port()
    db["servers"][folder] = {
        "name": name,
        "owner": username,
        "path": path,
        "type": server_type,
        "status": "Stopped",
        "created_at": str(datetime.now()),
        "startup_file": "",
        "pid": None,
        "port": assigned_port,
        "public_token": secrets.token_urlsafe(32),
        "public_host": secrets.token_hex(12),
        "plan": plan_id,
        "storage_limit": plan["storage"],
        "ram_limit": plan["ram"],
        "cpu_limit": plan["cpu"]
    }
    save_db(db)
    _release_port_reservation(assigned_port)
    return jsonify({"success": True, "message": f"✅ تم إنشاء السيرفر {name}", "folder": folder, "port": assigned_port})

@app.route('/api/bot/set_startup', methods=['POST'])
def bot_set_startup():
    data = request.get_json(silent=True) or {}
    api_key = data.get('api_key')
    folder = data.get('folder')
    filename = data.get('filename')
    if not all([api_key, folder, filename]):
        return jsonify({"success": False, "message": "بيانات ناقصة"}), 400
    username, _ = get_user_by_api_key(api_key)
    if not username:
        return jsonify({"success": False, "message": "API Key غير صالح"}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != username:
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    file_path = safe_relative_path(srv["path"], filename)
    if not file_path or not os.path.isfile(file_path):
        return jsonify({"success": False, "message": "الملف غير موجود أو المسار غير صالح"}), 404
    srv["startup_file"] = filename
    save_db(db)
    return jsonify({"success": True, "message": f"✅ تم تعيين {filename} كملف التشغيل"})

# ============== دعم PHP ==============
def _api_or_session_username():
    if "username" in session and session.get("username") in db.get("users", {}):
        return session["username"]
    data = request.get_json(silent=True) or {}
    api_key = data.get("api_key") or request.headers.get("X-API-Key")
    username, _user = get_user_by_api_key(api_key) if api_key else (None, None)
    return username


def _user_php_dir(username):
    safe_user = safe_user_filename(username)
    if not safe_user:
        return None
    folder = os.path.join(PHP_DIR, safe_user)
    os.makedirs(folder, exist_ok=True)
    return folder


def _run_php_file_for_user(username, file_path, timeout=15):
    if not shutil.which("php"):
        return {"success": False, "message": "PHP غير مثبت في بيئة الاستضافة"}, 503
    try:
        result = subprocess.run(["php", file_path], cwd=os.path.dirname(file_path),
                                capture_output=True, text=True, timeout=timeout)
        return {"success": True, "output": result.stdout, "error": result.stderr, "code": result.returncode}, 200
    except subprocess.TimeoutExpired:
        return {"success": False, "message": f"انتهت مهلة التنفيذ ({timeout} ثانية)"}, 408
    except Exception as exc:
        return {"success": False, "message": str(exc)}, 500


@app.route('/api/php/run', methods=['POST'])
def run_php_code():
    username = _api_or_session_username()
    if not username:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    data = request.get_json(silent=True) or {}
    code = str(data.get('code', '')).strip()
    if not code:
        return jsonify({"success": False, "message": "الكود مطلوب"}), 400
    user_dir = _user_php_dir(username)
    fd, temp_path = tempfile.mkstemp(prefix="run_", suffix=".php", dir=user_dir, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            if not code.startswith("<?php"):
                handle.write("<?php\n")
            handle.write(code)
            if not code.endswith("?>"):
                handle.write("\n?>")
        payload, status = _run_php_file_for_user(username, temp_path)
        return jsonify(payload), status
    finally:
        try:
            os.remove(temp_path)
        except OSError:
            pass


@app.route('/api/php/upload', methods=['POST'])
def upload_php_file():
    username = _api_or_session_username()
    if not username:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    data = request.get_json(silent=True) or {}
    filename = safe_user_filename(data.get('filename', '').strip())
    content = str(data.get('content', ''))
    if not filename or not filename.lower().endswith('.php'):
        return jsonify({"success": False, "message": "اسم الملف يجب أن ينتهي بـ .php"}), 400
    if len(content.encode("utf-8")) > 5 * 1024 * 1024:
        return jsonify({"success": False, "message": "حجم ملف PHP يتجاوز 5 MB"}), 413
    folder = _user_php_dir(username)
    file_path = safe_child_path(folder, filename)
    if not file_path:
        return jsonify({"success": False, "message": "اسم ملف غير صالح"}), 400
    try:
        with open(file_path, 'w', encoding='utf-8') as handle:
            if not content.strip().startswith('<?php'):
                handle.write('<?php\n')
            handle.write(content)
            if not content.strip().endswith('?>'):
                handle.write('\n?>')
        return jsonify({"success": True, "message": f"✅ تم حفظ {filename}"})
    except Exception as exc:
        return jsonify({"success": False, "message": str(exc)}), 500


@app.route('/api/php/list', methods=['GET'])
def list_php_files():
    username = _api_or_session_username()
    if not username:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    folder = _user_php_dir(username)
    files = []
    try:
        for name in os.listdir(folder):
            file_path = os.path.join(folder, name)
            if name.lower().endswith('.php') and os.path.isfile(file_path) and not os.path.islink(file_path):
                stat_info = os.stat(file_path)
                files.append({"name": name, "size": stat_info.st_size,
                              "modified": datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M')})
    except OSError as exc:
        return jsonify({"success": False, "message": str(exc)}), 500
    return jsonify({"success": True, "files": sorted(files, key=lambda item: item["name"].lower())})


@app.route('/api/php/run-file', methods=['POST'])
def run_php_file():
    username = _api_or_session_username()
    if not username:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    data = request.get_json(silent=True) or {}
    filename = safe_user_filename(data.get('filename', '').strip())
    if not filename or not filename.lower().endswith('.php'):
        return jsonify({"success": False, "message": "اسم ملف غير صالح"}), 400
    folder = _user_php_dir(username)
    file_path = safe_child_path(folder, filename)
    if not file_path or not os.path.isfile(file_path):
        return jsonify({"success": False, "message": "الملف غير موجود"}), 404
    payload, status = _run_php_file_for_user(username, file_path)
    return jsonify(payload), status


@app.route('/api/php/delete', methods=['POST'])
def delete_php_file():
    username = _api_or_session_username()
    if not username:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    data = request.get_json(silent=True) or {}
    filename = safe_user_filename(data.get('filename', '').strip())
    if not filename or not filename.lower().endswith('.php'):
        return jsonify({"success": False, "message": "اسم ملف غير صالح"}), 400
    folder = _user_php_dir(username)
    file_path = safe_child_path(folder, filename)
    if not file_path or not os.path.isfile(file_path):
        return jsonify({"success": False, "message": "الملف غير موجود"}), 404
    try:
        os.remove(file_path)
        return jsonify({"success": True, "message": f"✅ تم حذف {filename}"})
    except OSError as exc:
        return jsonify({"success": False, "message": str(exc)}), 500


@app.route('/api/php/get-content', methods=['POST'])
def get_php_content():
    username = _api_or_session_username()
    if not username:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    data = request.get_json(silent=True) or {}
    filename = safe_user_filename(data.get('filename', '').strip())
    if not filename or not filename.lower().endswith('.php'):
        return jsonify({"success": False, "message": "اسم ملف غير صالح"}), 400
    folder = _user_php_dir(username)
    file_path = safe_child_path(folder, filename)
    if not file_path or not os.path.isfile(file_path):
        return jsonify({"success": False, "message": "الملف غير موجود"}), 404
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as handle:
            return jsonify({"success": True, "content": handle.read()})
    except OSError as exc:
        return jsonify({"success": False, "message": str(exc)}), 500


@app.route('/api/php/update', methods=['POST'])
def update_php_file():
    username = _api_or_session_username()
    if not username:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    data = request.get_json(silent=True) or {}
    filename = safe_user_filename(data.get('filename', '').strip())
    content = str(data.get('content', ''))
    if not filename or not filename.lower().endswith('.php'):
        return jsonify({"success": False, "message": "اسم ملف غير صالح"}), 400
    if len(content.encode("utf-8")) > 5 * 1024 * 1024:
        return jsonify({"success": False, "message": "حجم الملف يتجاوز 5 MB"}), 413
    folder = _user_php_dir(username)
    file_path = safe_child_path(folder, filename)
    if not file_path or not os.path.isfile(file_path):
        return jsonify({"success": False, "message": "الملف غير موجود"}), 404
    temp_path = file_path + ".tmp"
    try:
        with open(temp_path, 'w', encoding='utf-8') as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, file_path)
        return jsonify({"success": True, "message": f"✅ تم تحديث {filename}"})
    except OSError as exc:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        return jsonify({"success": False, "message": str(exc)}), 500


# ============== التشغيل ==============
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)