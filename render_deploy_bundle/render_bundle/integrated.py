import os
import time
import threading
import json
import hmac
import hashlib
import subprocess
import hmac
import secrets
import sqlite3
import requests

from datetime import datetime, timedelta
from urllib.parse import urlencode
from functools import wraps
from flask import Flask, request, redirect, session, render_template_string
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

# Render persistent disk: seed SQLite files from package on first boot only.
if os.getenv("RENDER", "").lower() == "true":
    from pathlib import Path as _SeedPath
    import shutil as _seed_shutil
    _seed_dir = _SeedPath("/var/data")
    _seed_dir.mkdir(parents=True, exist_ok=True)
    for _seed_name in ("security.db", "security_events.db"):
        _seed_target = _seed_dir / _seed_name
        _seed_source = _SeedPath(__file__).resolve().parent / _seed_name
        if not _seed_target.exists() and _seed_source.exists():
            _seed_shutil.copy2(_seed_source, _seed_target)
    os.environ.setdefault("SECURITY_DB_PATH", str(_seed_dir / "security.db"))
    os.environ.setdefault("SECURITY_EVENT_DB", str(_seed_dir / "security_events.db"))


app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_PATH="/",
    PERMANENT_SESSION_LIFETIME=600
)

# ngrok is the single trusted reverse proxy in front of this local Flask app.
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1
)


# 상세 세션/쿠키 진단 로그는 운영 환경에서 비활성화합니다.

CLIENT_ID = os.environ["DISCORD_CLIENT_ID"]
CLIENT_SECRET = os.environ["DISCORD_CLIENT_SECRET"]
REDIRECT_URI = os.environ["DISCORD_REDIRECT_URI"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "").strip()
ALERT_CHANNEL_ID = os.getenv("ALERT_CHANNEL_ID", "").strip()

API = "https://discord.com/api/v10"
DB = os.getenv("SECURITY_DB_PATH", "security.db").strip() or "security.db"
VERIFY_GUILD_ID = os.getenv("VERIFY_GUILD_ID", "").strip()
VERIFY_ROLE_ID = os.getenv("VERIFY_ROLE_ID", "").strip()

IP_RETENTION_DAYS = 30

def init_db():
    with sqlite3.connect(DB) as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            username TEXT,
            consent INTEGER,
            created_at TEXT
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            user_id TEXT PRIMARY KEY,
            reason TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )
        """)

        con.execute("""CREATE TABLE IF NOT EXISTS ip_blacklist (
            ip_address TEXT PRIMARY KEY, source_user_id TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
        )""")
        con.execute("""
        CREATE TABLE IF NOT EXISTS guild_blacklist (
            guild_id TEXT PRIMARY KEY,
            guild_name TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS alert_settings (
            setting_key TEXT PRIMARY KEY,
            channel_id TEXT NOT NULL DEFAULT ''
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS user_guilds (
            user_id TEXT NOT NULL,
            guild_id TEXT NOT NULL,
            guild_name TEXT NOT NULL DEFAULT '',
            guild_icon TEXT,
            is_owner INTEGER NOT NULL DEFAULT 0,
            permissions TEXT NOT NULL DEFAULT '0',
            updated_at TEXT NOT NULL,
            PRIMARY KEY (user_id, guild_id)
        )
        """)
        con.execute(
            "CREATE INDEX IF NOT EXISTS idx_user_guilds_user_id ON user_guilds(user_id)"
        )
        con.execute("""
        CREATE TABLE IF NOT EXISTS verification_grants (
            user_id TEXT PRIMARY KEY,
            guild_id TEXT NOT NULL,
            role_id TEXT NOT NULL,
            granted_at TEXT NOT NULL
        )
        """)

        # 기존 security.db를 유지하면서 필요한 열만 추가
        columns = {
            row[1] for row in con.execute("PRAGMA table_info(records)").fetchall()
        }
        if "ip_address" not in columns:
            con.execute("ALTER TABLE records ADD COLUMN ip_address TEXT")
        if "ip_consent" not in columns:
            con.execute("ALTER TABLE records ADD COLUMN ip_consent INTEGER DEFAULT 0")
        if "ip_recorded_at" not in columns:
            con.execute("ALTER TABLE records ADD COLUMN ip_recorded_at TEXT")

        # ID 로고 30일 후 비우고, 기존 Discord 인증 기록은 보존
        cutoff = (datetime.now() - timedelta(days=IP_RETENTION_DAYS)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        con.execute(
            "UPDATE records SET ip_address=NULL "
            "WHERE ip_recorded_at IS NOT NULL AND ip_recorded_at < ?",
            (cutoff,)
        )

init_db()


def grant_verification_role(user_id):
    """
    지정된 인증 서버의 멤버인지 Discord API로 확인한 뒤 역할을 지급합니다.
    PUT 역할 엔드포인트는 동일 역할에 대해 반복 호출해도 안전합니다.
    """
    if not DISCORD_BOT_TOKEN:
        return False, "봇 토큰(DISCORD_BOT_TOKEN)이 설정되지 않았습니다."
    if not VERIFY_GUILD_ID.isdigit() or not VERIFY_ROLE_ID.isdigit():
        return False, "VERIFY_GUILD_ID 또는 VERIFY_ROLE_ID 설정이 올바르지 않습니다."

    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
    member_url = f"{API}/guilds/{VERIFY_GUILD_ID}/members/{user_id}"

    try:
        member_response = requests.get(member_url, headers=headers, timeout=15)
        if member_response.status_code == 404:
            return False, "인증 대상 Discord 서버에 먼저 입장해야 합니다."
        if not member_response.ok:
            print("[VERIFY] 멤버 확인 실패:", member_response.status_code,
                  member_response.text[:300])
            return False, "Discord 서버 멤버 확인에 실패했습니다. 봇 권한과 설정을 확인해 주세요."

        member_data = member_response.json()
        current_roles = {str(role_id) for role_id in member_data.get("roles", [])}
        already_had_role = VERIFY_ROLE_ID in current_roles

        if not already_had_role:
            role_response = requests.put(
                f"{member_url}/roles/{VERIFY_ROLE_ID}",
                headers=headers,
                timeout=15
            )
            if role_response.status_code not in (200, 204):
                print("[VERIFY] 역할 지급 실패:", role_response.status_code,
                      role_response.text[:300])
                return False, (
                    "역할 지급에 실패했습니다. 봇의 역할 관리 권한과 "
                    "봇 역할이 인증 역할보다 위에 있는지 확인해 주세요."
                )

        granted_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with sqlite3.connect(DB) as con:
            con.execute(
                """
                INSERT INTO verification_grants (user_id, guild_id, role_id, granted_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    guild_id=excluded.guild_id,
                    role_id=excluded.role_id,
                    granted_at=excluded.granted_at
                """,
                (str(user_id), VERIFY_GUILD_ID, VERIFY_ROLE_ID, granted_at)
            )

        return True, "이미 역할이 있었습니다." if already_had_role else "인증 역할을 지급했습니다."

    except requests.RequestException as exc:
        print("[VERIFY] Discord API 통신 오류:", type(exc).__name__)
        return False, "Discord 서버와 통신할 수 없습니다. 잠시 후 다시 시도해 주세요."


def fetch_and_save_user_guilds(user_id, access_token):
    """인증 사용자의 Discord 서버 목록을 가져와 DB에 최신 상태로 저장합니다."""
    headers = {"Authorization": "Bearer " + access_token}
    guilds = []
    before = None

    # Discord API 페이지당 최대 200개. 과도한 반복을 막기 위해 최대 10페이지까지 조회합니다.
    for _ in range(10):
        params = {"limit": 200}
        if before:
            params["before"] = before

        response = requests.get(
            API + "/users/@me/guilds",
            headers=headers,
            params=params,
            timeout=15
        )
        response.raise_for_status()
        batch = response.json()

        if not isinstance(batch, list) or not batch:
            break

        guilds.extend(batch)
        if len(batch) < 200:
            break

        next_before = batch[-1].get("id")
        if not next_before or next_before == before:
            break
        before = next_before

    updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Keep old server associations; insert/update by the unique (user_id, guild_id) key.
    unique_guilds = {str(g.get("id")): g for g in guilds if g.get("id")}
    with sqlite3.connect(DB) as con:
        con.executemany(
            """
            INSERT INTO user_guilds
                (user_id, guild_id, guild_name, guild_icon, is_owner, permissions, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, guild_id) DO UPDATE SET
                guild_name=excluded.guild_name, guild_icon=excluded.guild_icon,
                is_owner=excluded.is_owner, permissions=excluded.permissions,
                updated_at=excluded.updated_at
            """,
            [
                (str(user_id), gid, str(g.get("name", "")), g.get("icon"),
                 1 if g.get("owner") else 0, str(g.get("permissions", "0")), updated_at)
                for gid, g in unique_guilds.items()
            ]
        )
    return list(unique_guilds.values())


def get_alert_channel(channel_type="general"):
    """DB의 관리자 설정을 우선 사용하고, 없으면 .env 값을 사용합니다."""
    env_defaults = {
        "blacklist": os.getenv("ALERT_BLACKLIST_CHANNEL_ID", "").strip() or ALERT_CHANNEL_ID,
        "ip": os.getenv("ALERT_IP_CHANNEL_ID", "").strip() or ALERT_CHANNEL_ID,
        "general": ALERT_CHANNEL_ID
    }
    with sqlite3.connect(DB) as con:
        row = con.execute(
            "SELECT channel_id FROM alert_settings WHERE setting_key = ?",
            (channel_type,)
        ).fetchone()
    return (row[0].strip() if row and row[0].strip() else env_defaults.get(channel_type, ALERT_CHANNEL_ID))


def send_discord_alert(title, description, color=0x5865F2, channel_id=None):
    """설정된 Discord 채널로 알림을 보냅니다."""
    target_channel = (channel_id or get_alert_channel("general")).strip()
    if not DISCORD_BOT_TOKEN or not target_channel:
        print("[ALERT] 봇 토큰 또는 알림 채널 ID가 없어 알림을 건너뜁니다.")
        return False
    try:
        response = requests.post(
            f"{API}/channels/{target_channel}/messages",
            headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
            json={"embeds": [{
                "title": str(title)[:256],
                "description": str(description)[:4000],
                "color": color,
                "timestamp": datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
            }]},
            timeout=10
        )
        if not response.ok:
            print("[ALERT] Discord 전송 실패:", response.status_code, response.text[:300])
            return False
        return True
    except requests.RequestException as exc:
        print("[ALERT] Discord 통신 오류:", type(exc).__name__)
        return False


# 별도 보안 이벤트 DB를 사용하므로 기존 security.db의 인증 기록은 변경하지 않습니다.
import os
import re
import json
import hmac
import hashlib
import sqlite3
import time
import threading
from datetime import datetime, timezone
from pathlib import Path

import requests
from flask import request

BASE_DIR = Path(__file__).resolve().parent
EVENT_DB = Path(os.getenv("SECURITY_EVENT_DB", str(BASE_DIR / "security_events.db")))
ALERT_URL = os.getenv("SECURITY_DISCORD_WEBHOOK_URL", "").strip()
LOG_KEY = os.getenv("SECURITY_LOG_KEY", "").encode("utf-8")
ALERT_COOLDOWN = int(os.getenv("SECURITY_ALERT_COOLDOWN", "300"))
RATE_WINDOW = 300
RATE_THRESHOLD = 8

# These are indicators, not proof of malicious intent.
SENSITIVE_PATHS = (
    "/.env", "/.git", "/config", "/backup", "/backups",
    "/database", "/security.db", "/dump", "/phpmyadmin",
    "/wp-admin", "/wp-login.php", "/vendor/phpunit",
    "/actuator", "/server-status", "/.aws"
)
PATTERNS = (
    r"(?i)(union\s+select|select\s+.+\s+from|or\s+1\s*=\s*1)",
    r"(?i)(<script\b|javascript:|onerror\s*=|onload\s*=)",
    r"(?i)(\.\./|%2e%2e%2f|%252e%252e)",
    r"(?i)(/etc/passwd|win\.ini|boot\.ini)",
    r"(?i)(\b sleep\s*\(|benchmark\s*\()",
)
COMPILED = [re.compile(p) for p in PATTERNS]
_lock = threading.Lock()
_last_alert = {}

def _connect():
    con = sqlite3.connect(str(EVENT_DB), timeout=5)
    con.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            severity TEXT NOT NULL,
            event_type TEXT NOT NULL,
            ip_fingerprint TEXT,
            method TEXT,
            path TEXT,
            status INTEGER,
            user_agent TEXT,
            detail TEXT,
            prev_hash TEXT,
            event_hash TEXT NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS alert_state (
            alert_key TEXT PRIMARY KEY,
            sent_at REAL NOT NULL
        )
    """)
    # Keep security-event data for 30 days. If old rows expire, rebuild the
    # retained chain so verification remains valid for the retained window.
    cutoff = datetime.fromtimestamp(time.time() - 30 * 86400, timezone.utc).isoformat(timespec="seconds")
    deleted = con.execute("DELETE FROM events WHERE created_at < ?", (cutoff,))
    if deleted.rowcount:
        rows = con.execute("""
            SELECT id,created_at,severity,event_type,ip_fingerprint,method,path,status,user_agent,detail
            FROM events ORDER BY id
        """).fetchall()
        previous = ""
        for row in rows:
            event_id,created_at,severity,event_type,fp,method,path,status,ua,detail = row
            payload = {
                "created_at":created_at, "severity":severity, "event_type":event_type,
                "ip_fingerprint":fp, "method":method, "path":path, "status":status,
                "user_agent":ua, "detail":detail
            }
            digest = _chain_hash(payload, previous)
            con.execute("UPDATE events SET prev_hash=?, event_hash=? WHERE id=?",
                        (previous,digest,event_id))
            previous = digest
    return con

def _fingerprint(ip):
    # Do not store raw visitor IPs in this security event database.
    if not ip or not LOG_KEY:
        return None
    return hmac.new(LOG_KEY, ip.encode("utf-8", "ignore"), hashlib.sha256).hexdigest()[:20]

def _chain_hash(payload, prev_hash):
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    key = LOG_KEY or b"missing-security-log-key"
    return hmac.new(key, (prev_hash + raw).encode("utf-8"), hashlib.sha256).hexdigest()

def _send_alert(key, message):
    if not ALERT_URL:
        return
    now = time.time()
    with _lock:
        if now - _last_alert.get(key, 0) < ALERT_COOLDOWN:
            return
        _last_alert[key] = now
    try:
        requests.post(ALERT_URL, json={"content": message[:1900]}, timeout=3)
    except requests.RequestException:
        # Monitoring must never break the authentication site.
        pass

def record_event(event_type, severity="warning", detail="", status=None):
    try:
        ip = request.remote_addr if request else None
        path = request.path[:300] if request else ""
        method = request.method[:12] if request else ""
        ua = request.headers.get("User-Agent", "")[:240] if request else ""
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        fp = _fingerprint(ip)

        with _connect() as con:
            row = con.execute("SELECT event_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
            prev = row[0] if row else ""
            payload = {
                "created_at": now, "severity": severity, "event_type": event_type,
                "ip_fingerprint": fp, "method": method, "path": path,
                "status": status, "user_agent": ua, "detail": str(detail)[:500]
            }
            digest = _chain_hash(payload, prev)
            con.execute("""
                INSERT INTO events
                (created_at,severity,event_type,ip_fingerprint,method,path,status,
                 user_agent,detail,prev_hash,event_hash)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (now,severity,event_type,fp,method,path,status,ua,
                  str(detail)[:500],prev,digest))
        return True
    except Exception:
        return False

def _count_recent(fp):
    if not fp:
        return 0
    cutoff = datetime.fromtimestamp(time.time() - RATE_WINDOW, timezone.utc).isoformat(timespec="seconds")
    with _connect() as con:
        return con.execute(
            "SELECT COUNT(*) FROM events WHERE ip_fingerprint=? AND created_at>=? AND severity IN ('warning','high','critical')",
            (fp, cutoff)
        ).fetchone()[0]

def inspect_request():
    try:
        path = request.path.lower()
        target = (request.path + "?" + request.query_string.decode("utf-8", "ignore"))[:4000]
        detected = []
        if any(path == p or path.startswith(p + "/") for p in SENSITIVE_PATHS):
            detected.append(("sensitive_path_probe", "warning", "민감 경로 탐색 요청"))
        for pattern in COMPILED:
            if pattern.search(target):
                detected.append(("attack_pattern_probe", "high", "요청 경로/쿼리에서 공격 패턴 의심"))
                break

        ua = request.headers.get("User-Agent", "").lower()
        if any(x in ua for x in ("sqlmap", "nikto", "nmap", "masscan", "zgrab", "gobuster", "dirbuster")):
            detected.append(("scanner_user_agent", "warning", "스캐너로 알려진 User-Agent"))

        for event_type, severity, detail in detected:
            record_event(event_type, severity, detail)
            if severity in ("high", "critical"):
                _send_alert(event_type, f"🛡️ **보안 감지: {severity.upper()}**\n유형: {event_type}\n경로: `{request.path}`\n메서드: `{request.method}`\n세부: {detail}\nIP 식별값: `{_fingerprint(request.remote_addr) or '미설정'}`")

        if detected:
            fp = _fingerprint(request.remote_addr)
            if _count_recent(fp) >= RATE_THRESHOLD:
                record_event("repeated_probe_threshold", "critical", "5분 내 의심 요청 기준 초과")
                _send_alert("repeated_probe_threshold",
                    f"🚨 **반복 탐색 감지**\n5분 내 의심 요청이 {RATE_THRESHOLD}회 이상 관찰됐어.\n경로: `{request.path}`\nIP 식별값: `{fp or '미설정'}`")
    except Exception:
        # Fail open: security logging errors must not take down OAuth.
        pass
    return None

def inspect_response(response):
    try:
        if response.status_code >= 500:
            record_event("server_error", "high", "서버 내부 오류 응답", response.status_code)
            _send_alert("server_error", f"⚠️ **서버 오류 감지**\n경로: `{request.path}`\nHTTP: `{response.status_code}`")
        elif response.status_code == 401:
            record_event("unauthorized_response", "warning", "인증 실패 응답", response.status_code)
        elif response.status_code == 403:
            record_event("forbidden_response", "warning", "접근 거부 응답", response.status_code)
    except Exception:
        pass
    return response

def verify_event_chain():
    try:
        with _connect() as con:
            rows = con.execute("""
                SELECT created_at,severity,event_type,ip_fingerprint,method,path,status,
                       user_agent,detail,prev_hash,event_hash
                FROM events ORDER BY id
            """).fetchall()
        previous = ""
        for row in rows:
            created_at,severity,event_type,fp,method,path,status,ua,detail,prev,digest = row
            if prev != previous:
                return False, "이전 해시 연결 불일치"
            payload = {
                "created_at":created_at, "severity":severity, "event_type":event_type,
                "ip_fingerprint":fp, "method":method, "path":path, "status":status,
                "user_agent":ua, "detail":detail
            }
            if not hmac.compare_digest(_chain_hash(payload, previous), digest):
                return False, "로그 해시 불일치"
            previous = digest
        return True, "정상"
    except Exception as exc:
        return False, type(exc).__name__


@app.before_request
def _security_request_monitor():
    return inspect_request()

@app.after_request
def _security_response_monitor(response):
    return inspect_response(response)

STYLE = """
<style>
body {
    background:#17191f;color:white;
    font-family:Arial,sans-serif;
    padding:40px 15px;text-align:center
}
.card {
    background:#252831;padding:30px;
    border-radius:16px;max-width:480px;
    margin:30px auto
}
button {
    background:#5865F2;color:white;
    border:0;border-radius:9px;
    padding:14px 25px;cursor:pointer
}
input {
    padding:12px;border-radius:8px;
    border:0;margin:8px
}
a {color:#9daaff}
</style>
"""

@app.route("/")
def home():
    # 사이트에 접속하면 별도 시작 페이지 없이 Discord OAuth로 이동합니다.
    return redirect("/login")

@app.route("/consent", methods=["GET", "POST"])
def consent():
    if request.method == "POST":
        if request.form.get("agree") != "yes":
            return "필수 인증 안내에 동의해야 진행할 수 있습니다."

        session.permanent = True
        session["consent"] = True
        # ID 수집은 별도 선택 동의이며, 동의하지 않으면 ID를 저장하지 않음
        session["ip_consent"] = request.form.get("ip_agree") == "yes"
        session.modified = True
        return redirect("/login")

    return render_template_string("""
    <html lang="ko"><meta charset="UTF-8">
    """ + STYLE + """
    <div class="card">
    <h2>개인정보 처리 안내</h2>
    <p>Discord 사용자명과 사용자 ID를 인증 기록으로 저장합니다.</p>
    <p><b>디스코드 공식사이트에서 인증받습니다</b></p>
    <p>수집 항목: 디스코드 ID및 사용자 닉네임</p>
    <p>수집 목적: 인증 기록 확인 및 보안 관리</p>
    <p>보관 기간: 수집 시점부터 30일</p>
    <p>ID 수집 동의는 선택 사항이며, 동의하지 않아도 Discord 계정 인증을 진행할 수 있습니다.</p>
    <p><b>별도 보안 기록 안내</b></p>
    <p>사이트 보호를 위해 접속 시각, 요청 경로·방식, 브라우저 정보 및 가명 식별값을 별도 보안 로그에 기록하며 30일간 보관합니다. 이 기록은 비정상 접근 탐지와 보안 사고 확인 목적으로만 사용합니다.</p>
    <form method="POST">
    <label>
    <input type="checkbox" name="agree" value="yes" required>
    Discord 사용자명 및 사용자 ID 저장 안내를 확인했습니다.
    </label><br><br>
    <label>
    <input type="checkbox" name="ip_agree" value="yes">
    IP 주소 수집 및 30일 보관에 별도로 동의합니다.
    </label><br><br>
    <button>동의하고 진행</button>
    </form>
    </div></html>
    """)

@app.route("/login")
def login():
    # 별도 사전 동의 페이지 없이 Discord OAuth 인증을 시작합니다.
    # ngrok의 X-Forwarded-Proto / Host를 ProxyFix가 반영한
    # 현재 공개 주소를 사용해 Discord 인증 URL과 토큰 교환 URI를 일치시킵니다.
    callback_uri = request.url_root.rstrip("/") + "/callback"

    state = secrets.token_urlsafe(32)
    session.permanent = True
    session["oauth_state"] = state
    session["oauth_redirect_uri"] = callback_uri
    session.modified = True

    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": callback_uri,
        "response_type": "code",
        "scope": "identify guilds",
        "state": state
    }

    print("[OAUTH] Redirect URI:", callback_uri)
    return redirect(
        "https://discord.com/oauth2/authorize?"
        + urlencode(params)
    )

@app.route("/callback")
def callback():
    if request.args.get("error"):
        return "인증이 취소되었습니다."

    code = request.args.get("code")
    state = request.args.get("state")
    saved = session.get("oauth_state")
    callback_uri = session.get("oauth_redirect_uri")

    print(
        "[SESSION DEBUG] callback:",
        "secure=", request.is_secure,
        "cookie_present=", bool(request.cookies.get("session")),
        "consent=", bool(session.get("consent")),
        "oauth_state_present=", bool(saved),
        "query_keys=", sorted(request.args.keys())
    )

    if not code or not state or not saved:
        # /callback을 직접 열거나 인증이 중간에 끊긴 경우,
        # 기존 동의는 유지하고 로그인부터 다시 시작하도록 안내합니다.
        return render_template_string("""
        <html lang="ko"><meta charset="UTF-8">
        """ + STYLE + """
        <div class="card">
          <h2>인증 절차가 완료되지 않았습니다.</h2>
          <p>Discord에서 인증을 승인한 뒤 돌아와야 합니다.</p>
          <a href="/login"><button>Discord 인증 다시 시작</button></a>
          <p><a href="/">처음으로</a></p>
        </div></html>
        """), 400

    if not callback_uri:
        return "인증 세션이 만료되었습니다. 처음부터 다시 인증해 주세요.", 400

    if not hmac.compare_digest(state, saved):
        return "보안 검증 실패", 400

    if request.args.get("iss") != "https://discord.com":
        return "인증 발급자를 확인할 수 없습니다.", 400

    current_ip = request.remote_addr or ""
    if current_ip:
        with sqlite3.connect(DB) as con:
            ip_block = con.execute(
                "SELECT source_user_id, reason FROM ip_blacklist WHERE ip_address = ?",
                (current_ip,)
            ).fetchone()
        if ip_block:
            send_discord_alert(
                "🚫 차단된 IP의 접속 시도",
                f"IP: `{current_ip}`\n기준 계정 ID: `{ip_block[0]}`\n사유: {ip_block[1] or '사유 미입력'}",
                0xED4245,
                channel_id=get_alert_channel("ip")
            )
            return "접속이 차단되었습니다. 관리자에게 문의해 주세요.", 403

    try:
        r = requests.post(
            API + "/oauth2/token",
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": callback_uri
            },
            timeout=15
        )
        if not r.ok:
            print("[OAUTH] Discord token exchange failed:", r.status_code)
            return (
                "???? ??? ??????.<br>"
                f"HTTP ?? ??: {r.status_code}<br>"
                "????? ?? ??? ??? ???."
            ), 400

        token_data = r.json()
        if "access_token" not in token_data:
            print("[OAUTH] Token response missing access_token.")
            return "?????? ?? ??? ?? ?????.", 400

        print("?? ??: Discord ?? ??")
        token = token_data["access_token"]

        headers = {"Authorization": "Bearer " + token}

        u = requests.get(
            API + "/users/@me",
            headers=headers,
            timeout=15
        )
        u.raise_for_status()
        user = u.json()

        # 블랙리스트 계정은 인증 기록에 저장하지 않고 차단합니다.
        with sqlite3.connect(DB) as con:
            blocked = con.execute(
                "SELECT reason FROM blacklist WHERE user_id = ?", (str(user["id"]),)
            ).fetchone()
        if blocked:
            send_discord_alert(
                "🚨 블랙리스트 계정 인증 시도",
                f"사용자명: {user.get('username', '알 수 없음')}\\n"
                f"사용자 ID: `{user['id']}`\\n"
                f"차단 사유: {blocked[0] or '사유 미입력'}\\n결과: 인증 차단",
                0xED4245,
                channel_id=get_alert_channel("blacklist")
            )
            return render_template_string("""
            <html lang="ko"><meta charset="UTF-8">
            """ + STYLE + """
            <div class="card">
              <h1>⛔ 인증이 차단되었습니다</h1>
              <p>해당 Discord 계정은 블랙리스트에 등록되어 있습니다.</p>
              <p>관리자에게 문의해 주세요.</p>
            </div></html>
            """), 403

        # Discord 서버 목록을 확인하고, 블랙리스트 서버의 구성원이면 인증을 차단합니다.
        try:
            user_guilds = fetch_and_save_user_guilds(user["id"], token)
            print(f"[GUILDS] Saved {len(user_guilds)} guilds for user {user['id']}.")
        except (requests.RequestException, ValueError, KeyError) as exc:
            print("[GUILDS] Server list fetch failed:", type(exc).__name__)
            user_guilds = []

        blocked_guild = None
        for guild in user_guilds:
            guild_id = str(guild.get("id", ""))
            if not guild_id:
                continue
            with sqlite3.connect(DB) as con:
                blocked_guild = con.execute(
                    "SELECT guild_name, reason FROM guild_blacklist WHERE guild_id = ?",
                    (guild_id,)
                ).fetchone()
            if blocked_guild:
                guild_name = blocked_guild[0] or guild.get("name", "이름 없는 서버")
                send_discord_alert(
                    "🚨 블랙리스트 서버 구성원 인증 시도",
                    f"사용자명: {user.get('username', '알 수 없음')}\\n"
                    f"사용자 ID: `{user['id']}`\\n"
                    f"서버명: {guild_name}\\n"
                    f"서버 ID: `{guild_id}`\\n"
                    f"차단 사유: {blocked_guild[1] or '사유 미입력'}\\n결과: 인증 차단",
                    0xED4245,
                    channel_id=get_alert_channel("blacklist")
                )
                return render_template_string("""
                <html lang="ko"><meta charset="UTF-8">
                """ + STYLE + """
                <div class="card">
                  <h1>⛔ 인증이 차단되었습니다</h1>
                  <p>블랙리스트에 등록된 Discord 서버의 구성원으로 확인되었습니다.</p>
                  <p>관리자에게 문의해 주세요.</p>
                </div></html>
                """), 403

        # 블랙리스트 검사를 모두 통과한 실제 Discord 사용자 ID에만 인증 역할을 지급합니다.
        role_ok, role_message = grant_verification_role(str(user["id"]))
        if not role_ok:
            return render_template_string("""
            <html lang="ko"><meta charset="UTF-8">
            """ + STYLE + """
            <div class="card">
              <h1>인증 역할 지급을 완료하지 못했습니다.</h1>
              <p>{{ message }}</p>
              <p>문제가 해결된 뒤 다시 인증해 주세요.</p>
            </div></html>
            """, message=role_message), 403

        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 접속 전 IP 수집 안내가 별도로 제공된다는 전제하에,
        # OAuth 콜백 요청의 접속 IP를 보안 기록으로 저장합니다.
        # ProxyFix가 신뢰하도록 설정된 프록시(ngrok)의 전달 정보만 반영합니다.
        # IP를 저장했다는 사실만으로 별도 동의가 있었다고 기록하지 않습니다.
        ip_address = request.remote_addr or None
        ip_recorded_at = created_at if ip_address else None
        ip_consent = bool(session.get("ip_consent"))

        with sqlite3.connect(DB) as con:
            con.execute(
                """
                INSERT INTO records
                    (user_id, username, consent, created_at,
                     ip_address, ip_consent, ip_recorded_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user["id"],
                    user["username"],
                    0,  # 별도 개인정보 동의 절차를 거치지 않았으므로 동의 플래그는 0으로 기록
                    created_at,
                    ip_address,
                    1 if ip_consent else 0,
                    ip_recorded_at
                )
            )

        send_discord_alert(
            "✅ Discord 계정 인증 완료",
            f"사용자명: {user.get('username', '알 수 없음')}\\n"
            f"사용자 ID: `{user['id']}`\\n인증 시간: {created_at}",
            0x57F287
        )

        session.pop("consent", None)
        session.pop("ip_consent", None)
        session.pop("oauth_state", None)

        return render_template_string("""
        <html lang="ko"><meta charset="UTF-8">
        """ + STYLE + """
        <div class="card">
        <h1>✅ 인증 완료</h1>
        <p>사용자명: {{ username }}</p>
        <p>사용자 ID: {{ uid }}</p>
        <p>인증이 정상적으로 완료되었으며, 인증 역할 지급을 확인했습니다.</p>
        </div></html>
        """, username=user["username"], uid=user["id"])

    except requests.RequestException:
        return "Discord 인증 서버와 통신할 수 없습니다.", 502

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect("/admin")
        return func(*args, **kwargs)
    return wrapper

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        password = request.form.get("password", "")
        if hmac.compare_digest(password, ADMIN_PASSWORD):
            session["admin"] = True
            return redirect("/admin/panel")
        return "비밀번호가 올바르지 않습니다.", 401

    return render_template_string("""
    <html lang="ko"><meta charset="UTF-8">
    """ + STYLE + """
    <div class="card">
    <h2>관리자 로그인</h2>
    <form method="POST">
    <input type="password" name="password"
    placeholder="관리자 비밀번호" required>
    <button>로그인</button>
    </form></div></html>
    """)

@app.route("/admin/panel", methods=["GET", "POST"])
@admin_required
def panel():
    if request.method == "POST" and request.form.get("action") == "delete_record":
        record_id = request.form.get("record_id", "").strip()
        if record_id.isdigit():
            with sqlite3.connect(DB) as con:
                con.execute("DELETE FROM records WHERE id = ?", (int(record_id),))
        return redirect("/admin/panel")

    with sqlite3.connect(DB) as con:
        # 관리자 페이지를 열 때도 30일이 지난 IP만 만료 처리
        cutoff = (datetime.now() - timedelta(days=IP_RETENTION_DAYS)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        con.execute(
            "UPDATE records SET ip_address=NULL "
            "WHERE ip_recorded_at IS NOT NULL AND ip_recorded_at < ?",
            (cutoff,)
        )
        rows = con.execute(
            "SELECT id, user_id, username, consent, created_at, ip_address, ip_consent "
            "FROM records ORDER BY id DESC"
        ).fetchall()

    return render_template_string("""
    <html lang="ko"><meta charset="UTF-8">
    """ + STYLE + """
    <div class="card" style="max-width:900px;text-align:left">
      <h1>통합 사이트 관리자</h1>
      <p>사이트 인증 기록, Discord 서버, 블랙리스트를 한 곳에서 관리합니다.</p>
      <p><a href="/admin/servers">Discord 서버 관리</a> ·
         <a href="/admin/blacklist">블랙리스트 관리</a> · <a href="/admin/settings">알림 채널 설정</a> ·
         <a href="/admin/logout">로그아웃</a></p>
      <hr><h2>인증 기록 ({{ rows|length }}건)</h2>
      {% for r in rows %}
        <div style="padding:12px 0;border-bottom:1px solid #444">
          <p><b>{{ r[2] or '알 수 없음' }}</b></p>
          <p>사용자 ID: <code>{{ r[1] }}</code></p>
          <p>인증 시간: {{ r[4] }}</p>
          <p>IP 별도 동의 여부: {{ '동의' if r[6] else '별도 동의 기록 없음' }}</p>
          <p>접속 IP: {{ r[5] if r[5] else '저장 안 함 / 보관 기간 만료' }}</p>
          <form method="POST" onsubmit="return confirm('이 인증 기록을 삭제할까요?');">
            <input type="hidden" name="action" value="delete_record">
            <input type="hidden" name="record_id" value="{{ r[0] }}">
            <button type="submit">이 기록 삭제</button>
          </form>
        </div>
      {% else %}<p>인증 기록이 없습니다.</p>{% endfor %}
    </div></html>
    """, rows=rows)

@app.route("/admin/servers", methods=["GET", "POST"])
@admin_required
def admin_servers():
    if request.method == "POST" and request.form.get("action") == "delete_guild":
        guild_id = request.form.get("guild_id", "").strip()
        user_id = request.form.get("user_id", "").strip()
        if guild_id:
            with sqlite3.connect(DB) as con:
                # 선택한 서버의 저장 기록을 전체 사용자 기준으로 삭제
                con.execute("DELETE FROM user_guilds WHERE guild_id = ?", (guild_id,))
        return redirect("/admin/servers?user_id=" + user_id if user_id else "/admin/servers")

    keyword = request.args.get("q", "").strip().casefold()
    selected_user_id = request.args.get("user_id", "").strip()

    with sqlite3.connect(DB) as con:
        rows = con.execute("""
            SELECT g.guild_id, g.guild_name, g.guild_icon, g.user_id,
                   g.is_owner, g.permissions, g.updated_at,
                   COALESCE(r.username, '알 수 없음')
            FROM user_guilds AS g
            LEFT JOIN (
                SELECT user_id, username FROM records
                WHERE id IN (SELECT MAX(id) FROM records GROUP BY user_id)
            ) AS r ON r.user_id = g.user_id
            ORDER BY g.guild_name COLLATE NOCASE
        """).fetchall()

    # 먼저 사용자별 서버 목록을 구성합니다.
    users = {}
    for row in rows:
        gid, name, icon, uid, owner, perms, updated, username = row
        uid = str(uid)
        user = users.setdefault(uid, {
            "id": uid, "username": username or "알 수 없음",
            "servers": [], "updated_at": updated
        })
        try:
            permission_value = int(perms or "0")
        except (TypeError, ValueError):
            permission_value = 0
        user["servers"].append({
            "id": str(gid), "name": name or "이름 없는 서버",
            "icon_url": f"https://cdn.discordapp.com/icons/{gid}/{icon}.png?size=64" if icon else None,
            "owner": bool(owner), "admin": bool(permission_value & 0x8),
            "manage_guild": bool(permission_value & 0x20),
            "updated_at": updated
        })
        if updated and (not user["updated_at"] or updated > user["updated_at"]):
            user["updated_at"] = updated

    selected_user = users.get(selected_user_id)
    if selected_user:
        servers_list = [server for server in selected_user["servers"]
                        if not keyword or keyword in (server["name"] + " " + server["id"]).casefold()]
        user_list = []
    else:
        selected_user_id = ""
        selected_user = None
        user_list = [user for user in users.values()
                     if not keyword or keyword in (user["username"] + " " + user["id"]).casefold()]
        user_list.sort(key=lambda user: user["username"].casefold())
        servers_list = []

    return render_template_string("""
    <html lang="ko"><meta charset="UTF-8">
    """ + STYLE + """
    <style>
      .server,.user{background:#252831;border-radius:12px;margin:12px 0;padding:14px}
      .head{display:flex;align-items:center;gap:12px}
      .head img,.placeholder{width:48px;height:48px;border-radius:50%;object-fit:cover}
      .placeholder{display:flex;align-items:center;justify-content:center;background:#5865F2}
      .member{padding:10px;margin:8px 0;background:#17191f;border-radius:8px}
      .search{display:flex;gap:8px;flex-wrap:wrap}
      .search input{flex:1;min-width:190px}
      .user-link{display:block;color:white;text-decoration:none}
      .user-link:hover{opacity:.82}
    </style>
    <div class="card" style="max-width:1000px;text-align:left">
      <h1>Discord 서버 관리</h1>
      <p><a href="/admin/panel">통합 관리자</a> · <a href="/admin/blacklist">블랙리스트</a> · <a href="/admin/settings">알림 채널 설정</a> · <a href="/admin/logout">로그아웃</a></p>

      {% if selected_user %}
        <p><a href="/admin/servers">← 전체 사용자 목록</a></p>
        <h2>{{ selected_user.username }}</h2>
        <p>사용자 ID: <code>{{ selected_user.id }}</code></p>
        <p>가입/인증 기록이 확인된 서버 {{ selected_user.servers|length }}개</p>
        <form method="GET" class="search">
          <input type="hidden" name="user_id" value="{{ selected_user.id }}">
          <input name="q" value="{{ keyword }}" placeholder="서버명 / 서버 ID 검색">
          <button>검색</button><a href="/admin/servers?user_id={{ selected_user.id|urlencode }}"><button type="button">초기화</button></a>
        </form>
        {% for server in servers %}
          <div class="server"><div class="head">
            {% if server.icon_url %}<img src="{{ server.icon_url }}" alt="">
            {% else %}<div class="placeholder">D</div>{% endif %}
            <div style="flex:1"><b>{{ server.name }}</b><br>
              <small>서버 ID: {{ server.id }}</small><br>
              <small>{% if server.owner %}서버 소유자{% elif server.admin %}관리자 권한{% elif server.manage_guild %}서버 관리 권한{% else %}일반 멤버 또는 제한 권한{% endif %}</small><br>
              <small>마지막 갱신: {{ server.updated_at or '기록 없음' }}</small></div>
          </div>
          <form method="POST" onsubmit="return confirm('이 서버의 저장 기록을 모든 사용자에게서 삭제할까요?');">
            <input type="hidden" name="action" value="delete_guild">
            <input type="hidden" name="guild_id" value="{{ server.id }}">
            <input type="hidden" name="user_id" value="{{ selected_user.id }}">
            <button>이 서버 기록 전체 삭제</button>
          </form></div>
        {% else %}<p>검색 결과가 없습니다.</p>{% endfor %}
      {% else %}
        <p>사용자를 클릭하면 해당 사용자가 인증 과정에서 확인된 Discord 서버 목록을 볼 수 있습니다.</p>
        <form method="GET" class="search">
          <input name="q" value="{{ keyword }}" placeholder="사용자명 / 사용자 ID 검색">
          <button>검색</button><a href="/admin/servers"><button type="button">초기화</button></a>
        </form>
        <p>검색 결과: <b>{{ users|length }}</b>명</p>
        {% for user in users %}
          <div class="user">
            <a class="user-link" href="/admin/servers?user_id={{ user.id|urlencode }}">
              <div class="head">
                <div class="placeholder">U</div>
                <div style="flex:1"><b>{{ user.username }}</b><br>
                  <small>사용자 ID: {{ user.id }}</small><br>
                  <small>확인된 서버 {{ user.servers|length }}개 · 마지막 갱신: {{ user.updated_at or '기록 없음' }}</small></div>
                <span>서버 보기 →</span>
              </div>
            </a>
          </div>
        {% else %}<p>검색 결과가 없습니다.</p>{% endfor %}
      {% endif %}
    </div></html>
    """, users=user_list, servers=servers_list, keyword=keyword,
       selected_user=selected_user)



@app.route("/admin/blacklist", methods=["GET", "POST"])
@admin_required
def blacklist_admin():
    if request.method == "POST":
        action = request.form.get("action", "")
        reason = request.form.get("reason", "").strip()[:500]
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if action == "add":
            user_id = request.form.get("user_id", "").strip()
            if not user_id.isdigit() or not (15 <= len(user_id) <= 22):
                return "올바른 Discord 사용자 ID를 입력해 주세요.", 400
            with sqlite3.connect(DB) as con:
                cur = con.execute(
                    "INSERT OR IGNORE INTO blacklist (user_id, reason, created_at) VALUES (?, ?, ?)",
                    (user_id, reason, created_at)
                )
                if cur.rowcount != 1:
                    return redirect("/admin/blacklist?duplicate=1")
                cutoff = (datetime.now() - timedelta(days=IP_RETENTION_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
                ip_row = con.execute(
                    "SELECT ip_address FROM records WHERE user_id=? "
                    "AND ip_address IS NOT NULL AND ip_recorded_at>=? "
                    "ORDER BY ip_recorded_at DESC LIMIT 1", (user_id, cutoff)
                ).fetchone()
                blocked_ip = ip_row[0] if ip_row else None
                if blocked_ip:
                    con.execute(
                        "INSERT INTO ip_blacklist (ip_address, source_user_id, reason, created_at) "
                        "VALUES (?, ?, ?, ?) ON CONFLICT(ip_address) DO UPDATE SET "
                        "source_user_id=excluded.source_user_id, reason=excluded.reason, created_at=excluded.created_at",
                        (blocked_ip, user_id, reason, created_at)
                    )
            send_discord_alert(
                "⛔ 블랙리스트 계정 등록",
                f"사용자 ID: `{user_id}`\\n사유: {reason or '사유 미입력'}\\n등록 시간: {created_at}"
                + (f"\\n저장된 IP도 별도 차단: `{blocked_ip}`" if blocked_ip else ""),
                0xED4245, channel_id=get_alert_channel("blacklist")
            )
            return redirect("/admin/blacklist")

        if action == "add_guild":
            guild_id = request.form.get("guild_id", "").strip()
            guild_name = request.form.get("guild_name", "").strip()[:100]
            if not guild_id.isdigit() or not (15 <= len(guild_id) <= 22):
                return "올바른 Discord 서버 ID를 입력해 주세요.", 400
            with sqlite3.connect(DB) as con:
                cur = con.execute(
                    "INSERT OR IGNORE INTO guild_blacklist (guild_id, guild_name, reason, created_at) VALUES (?, ?, ?, ?)",
                    (guild_id, guild_name, reason, created_at)
                )
            if cur.rowcount != 1:
                return redirect("/admin/blacklist?duplicate_guild=1")
            send_discord_alert(
                "⛔ 블랙리스트 서버 등록",
                f"서버명: {guild_name or '이름 미입력'}\\n서버 ID: `{guild_id}`\\n사유: {reason or '사유 미입력'}",
                0xED4245, channel_id=get_alert_channel("blacklist")
            )
            return redirect("/admin/blacklist")

        if action == "remove_guild":
            guild_id = request.form.get("guild_id", "").strip()
            with sqlite3.connect(DB) as con:
                cur = con.execute("DELETE FROM guild_blacklist WHERE guild_id = ?", (guild_id,))
            if cur.rowcount:
                send_discord_alert("♻️ 서버 블랙리스트 해제", f"서버 ID: `{guild_id}`",
                                   0x57F287, channel_id=get_alert_channel("blacklist"))
            return redirect("/admin/blacklist")

        if action == "remove_ip":
            ip_address = request.form.get("ip_address", "").strip()
            with sqlite3.connect(DB) as con:
                cur = con.execute("DELETE FROM ip_blacklist WHERE ip_address=?", (ip_address,))
            if cur.rowcount:
                send_discord_alert("♻️ IP 차단 해제", f"IP: `{ip_address}`",
                                   0x57F287, channel_id=get_alert_channel("ip"))
            return redirect("/admin/blacklist")

        if action == "remove":
            user_id = request.form.get("user_id", "").strip()
            with sqlite3.connect(DB) as con:
                cur = con.execute("DELETE FROM blacklist WHERE user_id = ?", (user_id,))
                removed = cur.rowcount > 0
            if removed:
                send_discord_alert("♻️ 블랙리스트 계정 해제", f"사용자 ID: `{user_id}`\\n해제 시간: {created_at}",
                                   0x57F287, channel_id=get_alert_channel("blacklist"))
            return redirect("/admin/blacklist")

        return "잘못된 요청입니다.", 400

    with sqlite3.connect(DB) as con:
        rows = con.execute("SELECT user_id, reason, created_at FROM blacklist ORDER BY created_at DESC").fetchall()
        ip_rows = con.execute("SELECT ip_address, source_user_id, reason, created_at FROM ip_blacklist ORDER BY created_at DESC").fetchall()
        guild_rows = con.execute("SELECT guild_id, guild_name, reason, created_at FROM guild_blacklist ORDER BY created_at DESC").fetchall()

    return render_template_string("""
    <html lang="ko"><meta charset="UTF-8">
    """ + STYLE + """
    <div class="card" style="max-width:900px;text-align:left">
      <h1>⛔ 블랙리스트 관리</h1>
      {% if request.args.get('duplicate') %}<p style="color:#ffcc66">이미 등록된 계정입니다.</p>{% endif %}
      {% if request.args.get('duplicate_guild') %}<p style="color:#ffcc66">이미 등록된 서버입니다.</p>{% endif %}
      <p><a href="/admin/panel">통합 관리자</a> · <a href="/admin/servers">서버 관리</a> · <a href="/admin/settings">알림 채널 설정</a></p>
      <h2>계정 블랙리스트</h2>
      <form method="POST">
        <input type="hidden" name="action" value="add">
        <input name="user_id" placeholder="Discord 사용자 ID" required inputmode="numeric">
        <input name="reason" placeholder="차단 사유 (선택)">
        <button>계정 블랙 등록</button>
      </form>
      {% for r in rows %}
        <hr><p>사용자 ID: <code>{{ r[0] }}</code></p><p>사유: {{ r[1] or '사유 미입력' }} · 등록: {{ r[2] }}</p>
        <form method="POST"><input type="hidden" name="action" value="remove"><input type="hidden" name="user_id" value="{{ r[0] }}"><button>계정 블랙 해제</button></form>
      {% else %}<p>등록된 계정 블랙리스트가 없습니다.</p>{% endfor %}

      <hr><h2>서버 ID 블랙리스트</h2>
      <p>등록된 서버에 속한 사용자는 사이트 인증이 차단되고 블랙 감지 채널로 알림이 전송됩니다.</p>
      <form method="POST">
        <input type="hidden" name="action" value="add_guild">
        <input name="guild_id" placeholder="Discord 서버 ID" required inputmode="numeric">
        <input name="guild_name" placeholder="서버 이름 (선택)">
        <input name="reason" placeholder="차단 사유 (선택)">
        <button>서버 블랙 등록</button>
      </form>
      {% for g in guild_rows %}
        <hr><p><b>{{ g[1] or '이름 미입력' }}</b></p><p>서버 ID: <code>{{ g[0] }}</code></p><p>사유: {{ g[2] or '사유 미입력' }} · 등록: {{ g[3] }}</p>
        <form method="POST"><input type="hidden" name="action" value="remove_guild"><input type="hidden" name="guild_id" value="{{ g[0] }}"><button>서버 블랙 해제</button></form>
      {% else %}<p>등록된 서버 블랙리스트가 없습니다.</p>{% endfor %}

      <hr><h2>IP 차단 목록</h2>
      {% for ip in ip_rows %}
        <p>IP: <code>{{ ip[0] }}</code> / 기준 계정: {{ ip[1] }}</p><p>사유: {{ ip[2] or '사유 미입력' }} / 등록: {{ ip[3] }}</p>
        <form method="POST"><input type="hidden" name="action" value="remove_ip"><input type="hidden" name="ip_address" value="{{ ip[0] }}"><button>IP 차단 해제</button></form>
      {% else %}<p>등록된 IP 차단이 없습니다.</p>{% endfor %}
    </div></html>
    """, rows=rows, ip_rows=ip_rows, guild_rows=guild_rows)


@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def alert_settings_admin():
    if request.method == "POST":
        blacklist_channel = request.form.get("blacklist_channel_id", "").strip()
        ip_channel = request.form.get("ip_channel_id", "").strip()
        for label, channel in (("블랙 감지 채널", blacklist_channel), ("IP 감지 채널", ip_channel)):
            if channel and (not channel.isdigit() or not (15 <= len(channel) <= 22)):
                return f"{label}의 Discord 채널 ID가 올바르지 않습니다.", 400
        with sqlite3.connect(DB) as con:
            con.executemany(
                "INSERT INTO alert_settings (setting_key, channel_id) VALUES (?, ?) "
                "ON CONFLICT(setting_key) DO UPDATE SET channel_id=excluded.channel_id",
                [("blacklist", blacklist_channel), ("ip", ip_channel)]
            )
        return redirect("/admin/settings?saved=1")

    with sqlite3.connect(DB) as con:
        values = dict(con.execute("SELECT setting_key, channel_id FROM alert_settings").fetchall())
    blacklist_default = os.getenv("ALERT_BLACKLIST_CHANNEL_ID", "").strip() or ALERT_CHANNEL_ID
    ip_default = os.getenv("ALERT_IP_CHANNEL_ID", "").strip() or ALERT_CHANNEL_ID
    blacklist_value = values.get("blacklist", "") or blacklist_default
    ip_value = values.get("ip", "") or ip_default

    return render_template_string("""
    <html lang="ko"><meta charset="UTF-8">
    """ + STYLE + """
    <div class="card" style="max-width:700px;text-align:left">
      <h1>Discord 감지 알림 채널 설정</h1>
      <p><a href="/admin/panel">통합 관리자</a> · <a href="/admin/blacklist">블랙리스트</a> · <a href="/admin/servers">서버 관리</a></p>
      {% if request.args.get('saved') %}<p style="color:#8be28b">알림 채널 설정을 저장했습니다.</p>{% endif %}
      <form method="POST">
        <label>블랙 감지 채널 ID (계정 블랙 + 서버 블랙)</label><br>
        <input name="blacklist_channel_id" value="{{ blacklist_value }}" placeholder="Discord 채널 ID" style="width:90%"><br>
        <small>디스코드 서버에서 멤버 입장 감지(봇이 들어가 있는 서버), 계정 ID 블랙 및 서버 ID 블랙 감지 알림을 보냅니다.</small><br><br>
        <label>IP 감지 채널 ID</label><br>
        <input name="ip_channel_id" value="{{ ip_value }}" placeholder="Discord 채널 ID" style="width:90%"><br>
        <small>웹사이트에 차단된 IP로 접속해 인증을 시도할 때만 이 채널로 알림을 보냅니다. Discord는 멤버의 IP를 봇에 제공하지 않습니다.</small><br><br>
        <button>설정 저장</button>
      </form>
    </div></html>
    """, blacklist_value=blacklist_value, ip_value=ip_value)
@app.route("/admin/logout")
def logout():
    session.pop("admin", None)
    return redirect("/admin")



# ===== Embedded Discord bot =====
import os
import sqlite3

import discord
from discord import app_commands
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("DISCORD_BOT_TOKEN", "").strip()
DB = os.getenv("SECURITY_DB_PATH", "security.db").strip() or "security.db"
VERIFY_URL = os.getenv("VERIFY_URL", "").strip()
LEGACY_CHANNEL_ID = os.getenv("ALERT_CHANNEL_ID", "").strip()
BLACKLIST_CHANNEL_ENV = (
    os.getenv("ALERT_BLACKLIST_CHANNEL_ID", "").strip() or LEGACY_CHANNEL_ID
)

if not TOKEN:
    raise SystemExit(".env 파일에 DISCORD_BOT_TOKEN이 없습니다.")


def get_blacklist_channel_id():
    """Flask 관리자 설정에 저장된 블랙 감지 채널을 우선 사용합니다."""
    try:
        with sqlite3.connect(DB) as con:
            row = con.execute(
                "SELECT channel_id FROM alert_settings WHERE setting_key = 'blacklist'"
            ).fetchone()
        return row[0].strip() if row and row[0] else BLACKLIST_CHANNEL_ENV
    except sqlite3.Error as exc:
        print("[DB] 알림 채널 조회 실패:", type(exc).__name__)
        return BLACKLIST_CHANNEL_ENV


def get_join_detection(member_id, guild_id):
    """가입한 계정 ID와 현재 입장한 서버 ID가 블랙리스트인지 확인합니다."""
    try:
        with sqlite3.connect(DB) as con:
            account = con.execute(
                "SELECT reason FROM blacklist WHERE user_id = ?",
                (str(member_id),)
            ).fetchone()
            blocked_guild = con.execute(
                "SELECT guild_name, reason FROM guild_blacklist WHERE guild_id = ?",
                (str(guild_id),)
            ).fetchone()
        return account, blocked_guild
    except sqlite3.Error as exc:
        print("[DB] 블랙리스트 조회 실패:", type(exc).__name__)
        return None, None


intents = discord.Intents.default()
intents.members = True  # Developer Portal에서도 Server Members Intent 활성화 필요


class SecurityBot(discord.Client):
    def __init__(self):
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        # 전역 슬래시 명령어 동기화. Discord 반영까지 시간이 걸릴 수 있습니다.
        synced = await self.tree.sync()
        print(f"[COMMAND] 슬래시 명령어 {len(synced)}개 동기화 완료")


client = SecurityBot()


@client.tree.command(
    name="인증메시지",
    description="현재 채널에 Discord 입장 인증 안내 메시지를 게시합니다."
)
async def verification_message(interaction: discord.Interaction):
    if interaction.guild is None or interaction.channel is None:
        await interaction.response.send_message(
            "서버 채널에서만 사용할 수 있는 명령어입니다.",
            ephemeral=True
        )
        return

    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message(
            "서버 관리 권한이 있는 관리자만 사용할 수 있습니다.",
            ephemeral=True
        )
        return

    if not VERIFY_URL.startswith("https://"):
        await interaction.response.send_message(
            "봇 환경변수 VERIFY_URL에 HTTPS 인증 주소를 설정해 주세요.",
            ephemeral=True
        )
        return

    embed = discord.Embed(
        title="보안봇 | 입장 인증",
        description="입장 인증을 누른 뒤, 열리는 디스코드 화면에서 인증을 완료해 주세요.",
        color=discord.Color.from_rgb(88, 101, 242)
    )
    view = discord.ui.View()
    view.add_item(
        discord.ui.Button(
            label="입장 인증",
            style=discord.ButtonStyle.link,
            url=VERIFY_URL
        )
    )

    await interaction.channel.send(embed=embed, view=view)
    await interaction.response.send_message(
        "인증 안내 메시지를 게시했습니다.",
        ephemeral=True
    )


@client.event
async def on_ready():
    print(f"봇 온라인: {client.user}")
    print("실시간 입장 감지 및 /인증메시지 명령어 활성화")


@client.event
async def on_member_join(member: discord.Member):
    """새 멤버 입장 시 계정/서버 블랙리스트를 확인합니다."""
    account, blocked_guild = get_join_detection(member.id, member.guild.id)

    if not account and not blocked_guild:
        return

    channel_id = get_blacklist_channel_id()
    if not channel_id or not channel_id.isdigit():
        print("[ALERT] 블랙 감지 채널 ID가 설정되지 않았습니다.")
        return

    channel = client.get_channel(int(channel_id))
    if channel is None:
        try:
            channel = await client.fetch_channel(int(channel_id))
        except (discord.NotFound, discord.Forbidden, discord.HTTPException) as exc:
            print("[ALERT] 알림 채널을 찾거나 접근할 수 없습니다:", type(exc).__name__)
            return

    reasons = []
    if account:
        reasons.append(f"계정 블랙 사유: {account[0] or '사유 미입력'}")
    if blocked_guild:
        reasons.append(f"서버 블랙 사유: {blocked_guild[1] or '사유 미입력'}")

    embed = discord.Embed(
        title="🚨 Discord 블랙리스트 입장 감지",
        description=(
            f"**사용자:** {member} (`{member.id}`)\n"
            f"**입장한 서버:** {member.guild.name} (`{member.guild.id}`)\n"
            f"**계정 생성일:** {member.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
            + "\n".join(reasons)
        ),
        color=discord.Color.red()
    )
    embed.set_footer(
        text="IP 정보는 Discord에서 제공되지 않아 ID 감지에만 표시됩니다."
    )

    try:
        await channel.send(embed=embed)
        print(
            f"[DETECT] 블랙리스트 입장 감지: user={member.id}, "
            f"guild={member.guild.id}, channel={channel_id}"
        )
    except discord.HTTPException as exc:
        print("[ALERT] Discord 알림 전송 실패:", type(exc).__name__)



def run_bot_thread():
    client.run(TOKEN)




# ===== Embedded watchdog (background thread) =====
import subprocess, sys
ROOT = BASE_DIR
KEY = os.getenv("SECURITY_LOG_KEY", "").encode("utf-8")
WEBHOOK = os.getenv("SECURITY_DISCORD_WEBHOOK_URL", "").strip()
def sha(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()
def sign(data):
    return hmac.new(KEY or b"missing-security-log-key",json.dumps(data,sort_keys=True).encode(),hashlib.sha256).hexdigest()
WATCHDOG_FILES = ["integrated.py"]
WATCHDOG_INTERVAL = int(os.getenv("SECURITY_WATCH_INTERVAL", "30"))
WATCHDOG_DATA_DIR = Path(os.getenv("SECURITY_BASELINE_DIR", str(BASE_DIR)))
WATCHDOG_DATA_DIR.mkdir(parents=True, exist_ok=True)
WATCHDOG_BASELINE = WATCHDOG_DATA_DIR / "security_baseline.json"
WATCHDOG_SIGNATURE = WATCHDOG_DATA_DIR / "security_baseline.sig"
watchdog_last_alert = {}

def watchdog_snapshot():
    out={}
    for nm in WATCHDOG_FILES:
        p=BASE_DIR/nm
        out[nm]=sha(p) if p.is_file() else None
    return out

def watchdog_alert(title, detail):
    now=time.time()
    if now-watchdog_last_alert.get(title,0)<300: return
    watchdog_last_alert[title]=now
    print(f"[WATCHDOG] {title}: {detail}")
    if WEBHOOK:
        try: requests.post(WEBHOOK,json={"content":f"🚨 **{title}**\n{detail}"[:1900]},timeout=3)
        except requests.RequestException: pass

def watchdog_main():
    if not KEY:
        print("[WATCHDOG] SECURITY_LOG_KEY가 없어 watchdog 실행 중단")
        return
    current=watchdog_snapshot()
    if not WATCHDOG_BASELINE.exists() or not WATCHDOG_SIGNATURE.exists():
        WATCHDOG_BASELINE.write_text(json.dumps(current,indent=2),encoding="utf-8")
        WATCHDOG_SIGNATURE.write_text(sign(current),encoding="utf-8")
        print("[WATCHDOG] 초기 기준선 생성")
    else:
        try:
            baseline=json.loads(WATCHDOG_BASELINE.read_text(encoding="utf-8"))
            sig=WATCHDOG_SIGNATURE.read_text(encoding="utf-8").strip()
            if not hmac.compare_digest(sign(baseline),sig):
                watchdog_alert("기준선 서명 검증 실패","기준선 또는 서명이 변경되었습니다.")
                return
        except Exception as exc:
            watchdog_alert("기준선 읽기 실패",type(exc).__name__); return
    baseline=json.loads(WATCHDOG_BASELINE.read_text(encoding="utf-8"))
    last_seen=dict(baseline)
    print("[WATCHDOG] 보안 감시 시작")
    while True:
        try:
            current=watchdog_snapshot()
            for name,digest in current.items():
                if digest!=baseline.get(name) and digest!=last_seen.get(name):
                    watchdog_alert("중요 파일 변경 감지",f"{name} 파일 해시가 기준선과 달라졌습니다.")
                    last_seen[name]=digest
            try:
                if os.name == "nt":
                    cmd=["netstat","-ano"]
                    marker="LISTENING"
                else:
                    cmd=["ss","-ltnp"]
                    marker="LISTEN"
                output=subprocess.run(cmd,capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=8).stdout
                for line in output.splitlines():
                    parts=line.split()
                    if marker in line.upper():
                        local=parts[1] if os.name == "nt" and len(parts)>1 else (parts[3] if len(parts)>3 else "")
                        if local.startswith("0.0.0.0:") or local.startswith("[::]:") or local.startswith("*:"):
                            port=local.rsplit(":",1)[-1]
                            if port not in ("5000", os.getenv("PORT", "5000")):
                                watchdog_alert("외부 인터페이스 수신 포트 확인 필요",f"{local} listening")
            except Exception: pass
            time.sleep(WATCHDOG_INTERVAL)
        except Exception as exc:
            print("[WATCHDOG] loop error:",type(exc).__name__); time.sleep(WATCHDOG_INTERVAL)

def start_ngrok():
    if os.getenv("RENDER", "").lower() == "true" or os.getenv("NGROK_ENABLED", "1").strip().lower() in ("0", "false", "no", "off"):
        print("[NGROK] Render 환경 또는 비활성 설정으로 ngrok 실행 건너뜀")
        return
    # Uses the reserved ngrok domain specified in VERIFY_URL.
    if os.getenv("NGROK_ENABLED", "1").strip().lower() not in ("1", "true", "yes", "on"):
        print("[NGROK] 자동 실행 비활성화")
        return
    domain = os.getenv("NGROK_DOMAIN", "").strip()
    if not domain:
        from urllib.parse import urlparse
        domain = urlparse(os.getenv("VERIFY_URL", "")).hostname or ""
    if not domain:
        print("[NGROK] 도메인 설정 없음. ngrok 실행을 건너뜁니다.")
        return
    try:
        proc = subprocess.Popen(["ngrok", "http", f"--domain={domain}", "5000"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        if proc.poll() is None:
            print(f"[NGROK] 터널 실행 요청 완료: https://{domain} -> http://localhost:5000")
        else:
            print("[NGROK] 실행 실패. ngrok 설치/PATH 및 계정 인증을 확인하세요.")
    except FileNotFoundError:
        print("[NGROK] ngrok 실행파일을 찾지 못했습니다. 설치 후 PATH에 등록하세요.")
    except Exception as exc:
        print("[NGROK] 실행 오류:", type(exc).__name__)

def start_services():
    threading.Thread(target=watchdog_main,daemon=True,name="security-watchdog").start()
    threading.Thread(target=run_bot_thread,daemon=True,name="discord-bot").start()
    if os.getenv("RENDER", "").lower() != "true":
        threading.Thread(target=start_ngrok,daemon=True,name="ngrok-tunnel").start()
    print("[START] 웹사이트, Discord 봇, watchdog 시작")

if __name__ == "__main__":
    start_services()
    print("[OAUTH] Client ID loaded:", bool(CLIENT_ID))
    print("[OAUTH] Redirect URI is generated from the current ngrok request.")
    print("[ALERT] Discord bot token configured:", bool(DISCORD_BOT_TOKEN))
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False, threaded=True)
