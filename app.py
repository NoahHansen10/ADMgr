import os
import subprocess
import tempfile
import json
import base64
import sqlite3
import threading
import time
import ipaddress
from time import monotonic
from functools import wraps
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from authlib.integrations.base_client.errors import MismatchingStateError, OAuthError
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, session, url_for, flash
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-me")
FLASK_DEBUG = os.environ.get("FLASK_DEBUG", "").strip().lower() in ("1", "true", "yes", "on")
if not FLASK_DEBUG and app.secret_key == "dev-only-change-me":
    raise RuntimeError("FLASK_SECRET_KEY is required when FLASK_DEBUG is false")

DNS_ZONE = os.environ.get("DNS_ZONE", "local.ndhansen.com")
DNS_SERVER = os.environ.get("DNS_SERVER", "dc01.local.ndhansen.com")
ALLOWED_ADMIN_GROUP = os.environ.get("ALLOWED_ADMIN_GROUP", "DNS-Admins")
POWERSHELL_EXE = os.environ.get("POWERSHELL_EXE", "pwsh")
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))
OIDC_TOKEN_ENDPOINT_AUTH_METHOD = os.environ.get("OIDC_TOKEN_ENDPOINT_AUTH_METHOD", "").strip()
OAUTH_STATE_DIR = Path(os.environ.get("OAUTH_STATE_DIR", Path(tempfile.gettempdir()) / "ad-dns-web-oauth-state"))
OIDC_REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI", "").strip()
TRUST_PROXY = int(os.environ.get("TRUST_PROXY", "0"))
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "").strip().lower() in ("1", "true", "yes")
SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
DNS_EXECUTION_MODE = os.environ.get("DNS_EXECUTION_MODE", "local").strip().lower()
WINRM_AUTH = os.environ.get("WINRM_AUTH", "Kerberos").strip()
WINRM_USE_SSL = os.environ.get("WINRM_USE_SSL", "").strip().lower() in ("1", "true", "yes")
WINRM_USERNAME = os.environ.get("WINRM_USERNAME", "").strip()
WINRM_PASSWORD = os.environ.get("WINRM_PASSWORD", "")
WINRM_PASSWORD_FILE = os.environ.get("WINRM_PASSWORD_FILE", "").strip()
WINRM_DOMAIN = os.environ.get("WINRM_DOMAIN", "").strip()
PWSH_REMOTE_TRANSPORT = os.environ.get("PWSH_REMOTE_TRANSPORT", "wsman").strip().lower()
PWSH_SSH_PORT = int(os.environ.get("PWSH_SSH_PORT", "22"))
PWSH_SSH_KEY_FILE = os.environ.get("PWSH_SSH_KEY_FILE", "").strip()
SSH_EXE = os.environ.get("SSH_EXE", "ssh").strip()
DNS_CACHE_DB_PATH = Path(os.environ.get("DNS_CACHE_DB_PATH", str(Path(tempfile.gettempdir()) / "ad-dns-web-dns-cache.sqlite3")))
DNS_CACHE_REFRESH_SECONDS = int(os.environ.get("DNS_CACHE_REFRESH_SECONDS", str(15 * 60)))
DNS_CACHE = {"tree": {"expires": 0.0, "value": None}, "records": {}, "delegations": {}, "forwarders": {"expires": 0.0, "value": None}}
DNS_CACHE_SCHEMA_READY = False
DNS_CACHE_SCHEMA_LOCK = threading.Lock()
DNS_CACHE_REFRESH_LOCK = threading.Lock()
DNS_CACHE_REFRESH_THREAD_STARTED = False
DNS_CACHE_BOOTSTRAPPED = False
DNS_TREE_CACHE_TTL = int(os.environ.get("DNS_TREE_CACHE_TTL", "20"))
DNS_TREE_CACHE = {"expires": 0.0, "value": None}
RECORDS_CACHE_TTL = int(os.environ.get("RECORDS_CACHE_TTL", "10"))
RECORDS_CACHE = {"expires": 0.0, "value": {}}
DNS_TREE_CACHE_VERSION = 2

if DNS_EXECUTION_MODE not in {"local", "winrm"}:
    raise RuntimeError("DNS_EXECUTION_MODE must be 'local' or 'winrm'")
if PWSH_REMOTE_TRANSPORT not in {"wsman", "ssh", "ssh_exec"}:
    raise RuntimeError("PWSH_REMOTE_TRANSPORT must be 'wsman', 'ssh', or 'ssh_exec'")
if DNS_EXECUTION_MODE == "local" and (WINRM_USERNAME or WINRM_PASSWORD or WINRM_PASSWORD_FILE or WINRM_DOMAIN):
    raise RuntimeError("WINRM_USERNAME, WINRM_PASSWORD, WINRM_PASSWORD_FILE, and WINRM_DOMAIN require DNS_EXECUTION_MODE='winrm'")
if WINRM_PASSWORD and WINRM_PASSWORD_FILE:
    raise RuntimeError("Set only one of WINRM_PASSWORD or WINRM_PASSWORD_FILE")
if WINRM_USERNAME and PWSH_REMOTE_TRANSPORT == "wsman" and not (WINRM_PASSWORD or WINRM_PASSWORD_FILE):
    raise RuntimeError("WINRM_PASSWORD or WINRM_PASSWORD_FILE is required when WINRM_USERNAME is set")
if DNS_EXECUTION_MODE == "winrm" and PWSH_REMOTE_TRANSPORT == "ssh" and not WINRM_USERNAME:
    raise RuntimeError("WINRM_USERNAME is required when PWSH_REMOTE_TRANSPORT='ssh'")
if DNS_EXECUTION_MODE == "winrm" and PWSH_REMOTE_TRANSPORT == "ssh_exec" and not WINRM_USERNAME:
    raise RuntimeError("WINRM_USERNAME is required when PWSH_REMOTE_TRANSPORT='ssh_exec'")
if WINRM_PASSWORD_FILE:
    password_path = Path(WINRM_PASSWORD_FILE)
    if not password_path.exists():
        raise RuntimeError(f"WINRM_PASSWORD_FILE does not exist: {password_path}")
if PWSH_SSH_KEY_FILE:
    key_path = Path(PWSH_SSH_KEY_FILE)
    if not key_path.exists():
        raise RuntimeError(f"PWSH_SSH_KEY_FILE does not exist: {key_path}")

app.config["OIDC_CLIENT_ID"] = os.environ["OIDC_CLIENT_ID"]
app.config["OIDC_CLIENT_SECRET"] = os.environ["OIDC_CLIENT_SECRET"]
app.config["OIDC_DISCOVERY_URL"] = os.environ["OIDC_DISCOVERY_URL"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE,
    SESSION_COOKIE_SAMESITE=SESSION_COOKIE_SAMESITE,
)

if TRUST_PROXY > 0:
    # Respect X-Forwarded-* headers when running behind nginx/traefik.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUST_PROXY, x_proto=TRUST_PROXY, x_host=TRUST_PROXY, x_port=TRUST_PROXY, x_prefix=TRUST_PROXY)

OIDC_CLIENT_ID = app.config["OIDC_CLIENT_ID"]
OIDC_CLIENT_SECRET = app.config["OIDC_CLIENT_SECRET"]
OIDC_DISCOVERY_URL = app.config["OIDC_DISCOVERY_URL"]
# OIDC_ISSUER = os.environ["OIDC_ISSUER"]

oauth = OAuth(app)
oauth.register(
    name="idp",
    client_id=OIDC_CLIENT_ID,
    client_secret=OIDC_CLIENT_SECRET,
    server_metadata_url=OIDC_DISCOVERY_URL,
    client_kwargs={
        "scope": "openid profile email",
        "token_endpoint_auth_method": OIDC_TOKEN_ENDPOINT_AUTH_METHOD or "client_secret_post",
    },
)



def run_ps(script: str) -> str:
    completed = subprocess.run(
        [POWERSHELL_EXE, "-NoProfile", "-NonInteractive", "-Command", script],
        text=True,
        capture_output=True,
        timeout=30,
    )
    if completed.returncode != 0:
        error = completed.stderr.strip() or completed.stdout.strip()
        if "no supported wsman client library was found" in error.lower():
            raise RuntimeError(
                "PowerShell remoting failed: WSMan client libraries are missing on this Linux host. "
                "Either install PSWSMan/WSMan dependencies or set PWSH_REMOTE_TRANSPORT=ssh and configure PowerShell SSH remoting on the Windows server."
            )
        raise RuntimeError(error)
    return completed.stdout.strip()


def ps_quote(value: str) -> str:
    # Single-quote safe PowerShell string.
    return "'" + value.replace("'", "''") + "'"


def load_winrm_password() -> str:
    if WINRM_PASSWORD_FILE:
        return Path(WINRM_PASSWORD_FILE).read_text(encoding="utf-8").strip()
    return WINRM_PASSWORD


def run_ps_ssh_exec(script_body: str) -> str:
    # Executes PowerShell over a plain SSH command channel; no PSRP subsystem required.
    remote_script = f"Import-Module DnsServer\n{script_body}"
    encoded = base64.b64encode(remote_script.encode("utf-16-le")).decode("ascii")
    remote_command = f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {encoded}"

    cmd = [SSH_EXE, "-p", str(PWSH_SSH_PORT)]
    if PWSH_SSH_KEY_FILE:
        cmd.extend(["-i", PWSH_SSH_KEY_FILE])
    cmd.extend(["-l", WINRM_USERNAME, DNS_SERVER, remote_command])

    completed = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        timeout=45,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
    return completed.stdout.strip()


def dns_server_arg() -> str:
    if DNS_EXECUTION_MODE == "winrm":
        return ""
    return f"-ComputerName {ps_quote(DNS_SERVER)}"


def build_dns_script(script_body: str) -> str:
    if DNS_EXECUTION_MODE == "winrm":
        if PWSH_REMOTE_TRANSPORT == "ssh":
            ssh_args = [
                f"-HostName {ps_quote(DNS_SERVER)}",
                f"-UserName {ps_quote(WINRM_USERNAME)}",
                f"-Port {PWSH_SSH_PORT}",
            ]
            if PWSH_SSH_KEY_FILE:
                ssh_args.append(f"-KeyFilePath {ps_quote(PWSH_SSH_KEY_FILE)}")
            return f"""
$script = {{
Import-Module DnsServer
{script_body}
}}
Invoke-Command {' '.join(ssh_args)} -ScriptBlock $script
"""

        use_ssl_flag = "-UseSSL" if WINRM_USE_SSL else ""
        credential_block = ""
        credential_arg = ""
        if WINRM_USERNAME:
            winrm_username = WINRM_USERNAME
            if "\\" not in winrm_username and "@" not in winrm_username and WINRM_DOMAIN:
                winrm_username = f"{WINRM_DOMAIN}\\{winrm_username}"
            credential_block = f"""
$securePassword = ConvertTo-SecureString {ps_quote(load_winrm_password())} -AsPlainText -Force
$credential = [PSCredential]::new({ps_quote(winrm_username)}, $securePassword)
"""
            credential_arg = "-Credential $credential"
        return f"""
$script = {{
Import-Module DnsServer
{script_body}
}}
{credential_block}Invoke-Command -ComputerName {ps_quote(DNS_SERVER)} -Authentication {ps_quote(WINRM_AUTH)} {use_ssl_flag} {credential_arg} -ScriptBlock $script
"""

    return f"""
Import-Module DnsServer
{script_body}
"""


def run_dns_ps(script_body: str) -> str:
    if DNS_EXECUTION_MODE == "winrm" and PWSH_REMOTE_TRANSPORT == "ssh_exec":
        return run_ps_ssh_exec(script_body)
    return run_ps(build_dns_script(script_body))


def _dns_cache_connection() -> sqlite3.Connection:
    DNS_CACHE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DNS_CACHE_DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def ensure_dns_cache_schema() -> None:
    global DNS_CACHE_SCHEMA_READY
    if DNS_CACHE_SCHEMA_READY:
        return
    with DNS_CACHE_SCHEMA_LOCK:
        if DNS_CACHE_SCHEMA_READY:
            return
        with _dns_cache_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS dns_cache_entries (
                    kind TEXT NOT NULL,
                    cache_key TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (kind, cache_key)
                )
                """
            )
        DNS_CACHE_SCHEMA_READY = True


def cache_dns_payload(kind: str, cache_key: str, payload) -> None:
    ensure_dns_cache_schema()
    serialized = json.dumps(payload)
    with _dns_cache_connection() as conn:
        conn.execute(
            """
            INSERT INTO dns_cache_entries (kind, cache_key, payload, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(kind, cache_key) DO UPDATE SET
                payload=excluded.payload,
                updated_at=excluded.updated_at
            """,
            (kind, cache_key, serialized, time.time()),
        )


def load_dns_payload(kind: str, cache_key: str, max_age_seconds: int | None = None):
    ensure_dns_cache_schema()
    with _dns_cache_connection() as conn:
        row = conn.execute(
            "SELECT payload, updated_at FROM dns_cache_entries WHERE kind = ? AND cache_key = ?",
            (kind, cache_key),
        ).fetchone()
    if not row:
        return None
    if max_age_seconds is not None and (time.time() - float(row["updated_at"])) > max_age_seconds:
        return None
    try:
        return json.loads(row["payload"])
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def delete_dns_cache(kind: str | None = None) -> None:
    ensure_dns_cache_schema()
    with _dns_cache_connection() as conn:
        if kind is None:
            conn.execute("DELETE FROM dns_cache_entries")
        else:
            conn.execute("DELETE FROM dns_cache_entries WHERE kind = ?", (kind,))


def delete_dns_cache_entry(kind: str, cache_key: str) -> None:
    ensure_dns_cache_schema()
    with _dns_cache_connection() as conn:
        conn.execute("DELETE FROM dns_cache_entries WHERE kind = ? AND cache_key = ?", (kind, cache_key))


def list_dns_cache_entries() -> list[dict]:
    ensure_dns_cache_schema()
    with _dns_cache_connection() as conn:
        rows = conn.execute(
            "SELECT kind, cache_key, updated_at FROM dns_cache_entries ORDER BY kind, cache_key"
        ).fetchall()
    return [dict(row) for row in rows]


def cached_record_key(zone_name: str, name: str, record_type: str, recursive: bool) -> str:
    return json.dumps(
        {
            "zone": zone_name.strip().rstrip("."),
            "name": name.strip(),
            "type": record_type.strip().upper(),
            "recursive": bool(recursive),
        },
        sort_keys=True,
    )


def cached_delegation_key(zone_name: str) -> str:
    return zone_name.strip().rstrip(".")


def load_cached_tree() -> dict | None:
    cached = load_dns_payload("tree", f"main:v{DNS_TREE_CACHE_VERSION}", DNS_CACHE_REFRESH_SECONDS)
    if isinstance(cached, dict):
        return cached
    cached = load_dns_payload("tree", "main", DNS_CACHE_REFRESH_SECONDS)
    if isinstance(cached, dict):
        return cached
    return None


def load_cached_records(zone_name: str, name: str, record_type: str, recursive: bool) -> list[dict] | None:
    cached = load_dns_payload("records", cached_record_key(zone_name, name, record_type, recursive), DNS_CACHE_REFRESH_SECONDS)
    if isinstance(cached, list):
        return cached
    return None


def load_cached_delegations(zone_name: str) -> list[dict] | None:
    cached = load_dns_payload("delegations", cached_delegation_key(zone_name), DNS_CACHE_REFRESH_SECONDS)
    if isinstance(cached, list):
        return cached
    return None


def refresh_dns_cache_once() -> dict:
    with DNS_CACHE_REFRESH_LOCK:
        tree = normalize_dns_tree(build_dns_tree())
        cache_dns_payload("tree", f"main:v{DNS_TREE_CACHE_VERSION}", tree)
        cache_dns_payload("forwarders", "main", tree.get("forwarders", []))
        now = monotonic()
        DNS_TREE_CACHE["value"] = tree
        DNS_TREE_CACHE["expires"] = now + DNS_CACHE_REFRESH_SECONDS
        DNS_CACHE["forwarders"]["value"] = tree.get("forwarders", [])
        DNS_CACHE["forwarders"]["expires"] = now + DNS_CACHE_REFRESH_SECONDS

        zones = [item.get("name", "").strip().rstrip(".") for item in tree.get("forward", []) + tree.get("reverse", []) + tree.get("other", [])]
        zones = [zone for zone in zones if zone]
        active_zone_set = set(zones)

        for entry in list_dns_cache_entries():
            if entry["kind"] not in {"records", "delegations"}:
                continue
            if entry["kind"] == "records":
                try:
                    params = json.loads(entry["cache_key"])
                except (TypeError, ValueError, json.JSONDecodeError):
                    delete_dns_cache_entry("records", entry["cache_key"])
                    continue
                zone_name = str(params.get("zone", "")).strip().rstrip(".")
                if params.get("recursive"):
                    try:
                        rows = get_records_from_dns(zone_name or DNS_ZONE, str(params.get("name", "")), str(params.get("type", "ALL")), True)
                        cache_dns_payload("records", entry["cache_key"], rows)
                        DNS_CACHE["records"][entry["cache_key"]] = {"expires": now + DNS_CACHE_REFRESH_SECONDS, "value": rows}
                    except Exception:
                        delete_dns_cache_entry("records", entry["cache_key"])
                else:
                    if zone_name and zone_name not in active_zone_set:
                        delete_dns_cache_entry("records", entry["cache_key"])
                        continue
                    try:
                        rows = get_records_from_dns(zone_name or DNS_ZONE, str(params.get("name", "")), str(params.get("type", "ALL")), False)
                        cache_dns_payload("records", entry["cache_key"], rows)
                        DNS_CACHE["records"][entry["cache_key"]] = {"expires": now + DNS_CACHE_REFRESH_SECONDS, "value": rows}
                    except Exception:
                        delete_dns_cache_entry("records", entry["cache_key"])
            elif entry["kind"] == "delegations":
                zone_name = str(entry["cache_key"]).strip().rstrip(".")
                if zone_name and zone_name not in active_zone_set and zone_name != DNS_ZONE:
                    delete_dns_cache_entry("delegations", entry["cache_key"])
                    continue
                try:
                    rows = get_delegation_rows_from_dns(zone_name or DNS_ZONE)
                    cache_dns_payload("delegations", entry["cache_key"], rows)
                    DNS_CACHE["delegations"][entry["cache_key"]] = {"expires": now + DNS_CACHE_REFRESH_SECONDS, "value": rows}
                except Exception:
                    delete_dns_cache_entry("delegations", entry["cache_key"])
        return tree


def ensure_dns_cache_warm(force: bool = False) -> dict | None:
    cached = load_cached_tree()
    if cached is not None and not force:
        return normalize_dns_tree(cached)
    try:
        return refresh_dns_cache_once()
    except Exception:
        return normalize_dns_tree(cached)


def start_dns_cache_refresher() -> None:
    global DNS_CACHE_REFRESH_THREAD_STARTED
    if DNS_CACHE_REFRESH_THREAD_STARTED:
        return
    if app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return

    DNS_CACHE_REFRESH_THREAD_STARTED = True

    def _loop() -> None:
        while True:
            try:
                refresh_dns_cache_once()
            except Exception:
                pass
            time.sleep(DNS_CACHE_REFRESH_SECONDS)

    thread = threading.Thread(target=_loop, name="dns-cache-refresher", daemon=True)
    thread.start()


def dns_record_value_expression() -> str:
    return """
@{Name='Target';Expression={
    $data = $_.RecordData
    switch ($_.RecordType) {
        'A' { "$($data.IPv4Address)" }
        'AAAA' { "$($data.IPv6Address)" }
        'CNAME' { "$($data.HostNameAlias)" }
        'NS' { "$($data.NameServer)" }
        'PTR' { "$($data.PtrDomainName)" }
        'MX' { "$($data.MailExchange)" }
        'SRV' { "$($data.DomainName)" }
        'SOA' { "$($data.PrimaryServer)" }
        'TXT' { ($data.DescriptiveText -join ' ') }
        default { ($data | Out-String).Trim() }
    }
}}, @{Name='Ttl';Expression={$_.TimeToLive.ToString()}}, @{Name='TtlSeconds';Expression={[int]$_.TimeToLive.TotalSeconds}}
""".strip()


def normalize_record_rows(output: str) -> list[dict]:
    if not output:
        return []
    try:
        parsed = json.loads(output)
    except (TypeError, ValueError):
        return []
    if isinstance(parsed, dict):
        parsed = [parsed]
    rows: list[dict] = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "zone": item.get("ZoneName", ""),
                "name": item.get("HostName", ""),
                "type": item.get("RecordType", ""),
                "ttl": format_ttl_value(item.get("Ttl", item.get("TimeToLive", ""))),
                "ttl_seconds": parse_ttl_seconds(item.get("TtlSeconds", item.get("TimeToLive", item.get("Ttl", "")))),
                "target": item.get("Target", item.get("Value", "")),
            }
        )
    return rows


def format_ttl_value(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return ""
        if "." in text and ":" in text:
            day_part, time_part = text.split(".", 1)
            if day_part.isdigit():
                time_bits = time_part.split(":")
                if len(time_bits) == 3 and all(part.isdigit() for part in time_bits):
                    days = int(day_part)
                    hours, minutes, seconds = (int(part) for part in time_bits)
                    parts = []
                    if days:
                        parts.append(f"{days}d")
                    if hours:
                        parts.append(f"{hours}h")
                    if minutes:
                        parts.append(f"{minutes}m")
                    if seconds or not parts:
                        parts.append(f"{seconds}s")
                    return " ".join(parts)
        if ":" in text:
            parts = text.split(":")
            if len(parts) == 3 and all(part.isdigit() for part in parts):
                hours, minutes, seconds = (int(part) for part in parts)
                if hours and minutes == 0 and seconds == 0:
                    return f"{hours}h"
                if hours or minutes:
                    return f"{hours}h {minutes}m {seconds}s".strip()
        return text
    if isinstance(value, (int, float)):
        seconds = int(value)
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours:
            return f"{hours}h {minutes}m {seconds}s"
        if minutes:
            return f"{minutes}m {seconds}s"
        return f"{seconds}s"
    if isinstance(value, dict):
        days = int(value.get("Days", 0) or 0)
        hours = int(value.get("Hours", 0) or 0)
        minutes = int(value.get("Minutes", 0) or 0)
        seconds = int(value.get("Seconds", 0) or 0)
        parts = []
        if days:
            parts.append(f"{days}d")
        if hours:
            parts.append(f"{hours}h")
        if minutes:
            parts.append(f"{minutes}m")
        if seconds or not parts:
            parts.append(f"{seconds}s")
        return " ".join(parts)
    return str(value)


def parse_ttl_seconds(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        return str(int(value))
    if isinstance(value, dict):
        days = int(value.get("Days", 0) or 0)
        hours = int(value.get("Hours", 0) or 0)
        minutes = int(value.get("Minutes", 0) or 0)
        seconds = int(value.get("Seconds", 0) or 0)
        return str((((days * 24) + hours) * 60 + minutes) * 60 + seconds)
    text = str(value).strip()
    if not text:
        return ""
    if text.isdigit():
        return text
    if "." in text and ":" in text:
        day_part, time_part = text.split(".", 1)
        if day_part.isdigit():
            time_bits = time_part.split(":")
            if len(time_bits) == 3 and all(part.isdigit() for part in time_bits):
                days = int(day_part)
                hours, minutes, seconds = (int(part) for part in time_bits)
                return str((((days * 24) + hours) * 60 + minutes) * 60 + seconds)
    if ":" in text:
        parts = text.split(":")
        if len(parts) == 3 and all(part.isdigit() for part in parts):
            hours, minutes, seconds = (int(part) for part in parts)
            return str((hours * 3600) + (minutes * 60) + seconds)
    return text


def parse_json_rows(output: str) -> list[dict]:
    if not output:
        return []
    try:
        parsed = json.loads(output)
    except (TypeError, ValueError):
        return []
    if isinstance(parsed, dict):
        parsed = [parsed]
    return [item for item in parsed if isinstance(item, dict)]


def csv_items(raw: str) -> list[str]:
    if not raw:
        return []
    items = []
    for chunk in raw.replace("\n", ",").split(","):
        item = chunk.strip()
        if item:
            items.append(item)
    return items


def ps_array_literal(items: list[str]) -> str:
    if not items:
        return "@()"
    return "@(" + ", ".join(ps_quote(item) for item in items) + ")"


def normalize_zone_rows(output: str) -> list[dict]:
    rows = []
    for item in parse_json_rows(output):
        rows.append(
            {
                "name": item.get("ZoneName", ""),
                "type": item.get("ZoneType", ""),
                "ds": item.get("IsDsIntegrated", ""),
                "reverse": item.get("IsReverseLookupZone", ""),
                "auto": item.get("IsAutoCreated", ""),
                "signed": item.get("IsSigned", ""),
                "dynamic_update": item.get("DynamicUpdate", ""),
                "replication_scope": item.get("ReplicationScope", ""),
                "aging": item.get("Aging", ""),
                "directory_partition": item.get("DirectoryPartitionName", ""),
            }
        )
    return rows


def normalize_forwarder_rows(output: str) -> list[dict]:
    def extract_forwarder_address(value) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, int):
            try:
                return str(ipaddress.IPv4Address(value))
            except ipaddress.AddressValueError:
                return str(value)
        if isinstance(value, list):
            parts = [extract_forwarder_address(item) for item in value]
            return ", ".join(part for part in parts if part)
        if isinstance(value, dict):
            if "value" in value:
                return extract_forwarder_address(value.get("value"))
            if "Address" in value:
                address_value = value.get("Address")
                if isinstance(address_value, int):
                    try:
                        return str(ipaddress.IPv4Address(address_value))
                    except ipaddress.AddressValueError:
                        return str(address_value)
                if isinstance(address_value, list):
                    return extract_forwarder_address(address_value)
                return extract_forwarder_address(address_value)
            if "IPAddress" in value:
                return extract_forwarder_address(value.get("IPAddress"))
            if "IPAddressToString" in value:
                return extract_forwarder_address(value.get("IPAddressToString"))
            if "count" in value and len(value) == 1:
                return ""
            parts = [extract_forwarder_address(item) for item in value.values()]
            return ", ".join(part for part in parts if part)
        if hasattr(value, "IPAddressToString"):
            return str(getattr(value, "IPAddressToString"))
        if hasattr(value, "Address"):
            try:
                return str(ipaddress.IPv4Address(int(getattr(value, "Address"))))
            except Exception:
                return str(getattr(value, "Address"))
        return str(value)

    rows = []
    for item in parse_json_rows(output):
        rows.append(
            {
                "address": extract_forwarder_address(item.get("IPAddress", item.get("IPAddresss", item.get("Server", item.get("address", ""))))),
                "use_recursion": item.get("UseRecursion", ""),
                "timeout": item.get("Timeout", item.get("ForwarderTimeout", "")),
                "scope": item.get("ZoneScope", ""),
            }
        )
    return rows


def normalize_delegation_rows(output: str) -> list[dict]:
    rows = []
    for item in parse_json_rows(output):
        rows.append(
            {
                "zone": item.get("Name", ""),
                "child": item.get("ChildZoneName", ""),
                "ns": item.get("NameServer", ""),
                "ip": item.get("IPAddress", ""),
            }
        )
    return rows


def normalize_user_rows(output: str) -> list[dict]:
    rows = []
    for item in parse_json_rows(output):
        rows.append(
            {
                "name": item.get("Name", ""),
                "sam_account_name": item.get("SamAccountName", ""),
                "enabled": item.get("Enabled", ""),
                "email": item.get("EmailAddress", ""),
                "department": item.get("Department", ""),
                "title": item.get("Title", ""),
                "dn": item.get("DistinguishedName", ""),
            }
        )
    return rows


def normalize_group_rows(output: str) -> list[dict]:
    rows = []
    for item in parse_json_rows(output):
        rows.append(
            {
                "name": item.get("Name", ""),
                "sam_account_name": item.get("SamAccountName", ""),
                "scope": item.get("GroupScope", ""),
                "category": item.get("GroupCategory", ""),
                "description": item.get("Description", ""),
                "dn": item.get("DistinguishedName", ""),
            }
        )
    return rows


AD_OBJECT_DENYLIST = {
    "distinguishedname",
    "objectclass",
    "objectguid",
    "objectsid",
    "canonicalname",
    "whencreated",
    "whenchanged",
    "lastknownparent",
    "uSNCreated".lower(),
    "uSNChanged".lower(),
    "msds-user-account-control-computed",
    "pscomputername",
    "runspaceid",
    "enabled",
    "locked_out",
    "password_last_set",
    "last_logon_date",
    "password_never_expires",
}

AD_DETAIL_ORDER = {
    "user": [
        "name",
        "sam_account_name",
        "user_principal_name",
        "enabled",
        "locked_out",
        "email",
        "department",
        "title",
        "description",
        "office",
        "office_phone",
        "mobile_phone",
        "manager",
        "password_last_set",
        "last_logon_date",
        "password_never_expires",
        "distinguished_name",
    ],
    "group": [
        "name",
        "sam_account_name",
        "group_scope",
        "group_category",
        "description",
        "managed_by",
        "distinguished_name",
    ],
}


def stringify_ad_value(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dict):
        return json.dumps(value, default=str, ensure_ascii=False)
    if isinstance(value, list):
        return "\n".join(stringify_ad_value(item) for item in value if item not in (None, ""))
    return str(value)


def normalize_ad_attribute_name(name: str) -> str:
    text = str(name or "").strip()
    lowered = text.lower().replace("-", "_")
    direct_map = {
        "name": "name",
        "samaccountname": "sam_account_name",
        "sam_account_name": "sam_account_name",
        "userprincipalname": "user_principal_name",
        "user_principal_name": "user_principal_name",
        "emailaddress": "email",
        "email": "email",
        "department": "department",
        "title": "title",
        "description": "description",
        "office": "office",
        "officephone": "office_phone",
        "office_phone": "office_phone",
        "mobilephone": "mobile_phone",
        "mobile_phone": "mobile_phone",
        "passwordlastset": "password_last_set",
        "password_last_set": "password_last_set",
        "lastlogondate": "last_logon_date",
        "last_logon_date": "last_logon_date",
        "passwordneverexpires": "password_never_expires",
        "password_never_expires": "password_never_expires",
        "manager": "manager",
        "distinguishedname": "distinguished_name",
        "distinguished_name": "distinguished_name",
        "enabled": "enabled",
        "lockedout": "locked_out",
        "locked_out": "locked_out",
        "groupscope": "group_scope",
        "group_scope": "group_scope",
        "groupcategory": "group_category",
        "group_category": "group_category",
        "managedby": "managed_by",
        "managed_by": "managed_by",
        "memberof": "member_of",
        "member_of": "member_of",
    }
    if lowered in direct_map:
        return direct_map[lowered]
    if lowered in {"samaccountname", "sam_account_name"}:
        return "sam_account_name"
    return lowered


def build_ad_attribute_rows(source: dict, kind: str) -> list[dict]:
    normalized_source = {}
    for raw_key, raw_value in source.items():
        normalized_source[normalize_ad_attribute_name(raw_key)] = raw_value

    ordered_keys = []
    seen = set()
    for key in AD_DETAIL_ORDER.get(kind, []):
        if key in normalized_source and key not in seen:
            ordered_keys.append(key)
            seen.add(key)
    for key in sorted(normalized_source.keys(), key=lambda item: item.lower()):
        normalized = normalize_ad_attribute_name(key)
        if normalized in seen:
            continue
        ordered_keys.append(normalized)
        seen.add(normalized)

    rows = []
    for key in ordered_keys:
        raw_value = normalized_source.get(key)

        editable = key not in AD_OBJECT_DENYLIST and not key.startswith("is") and not key.endswith("computed")
        if key in {"member_of", "members"}:
            editable = False
        rows.append(
            {
                "key": key,
                "raw_key": next((raw_key for raw_key in source.keys() if normalize_ad_attribute_name(raw_key) == key), key),
                "label": key.replace("_", " ").title(),
                "value": stringify_ad_value(raw_value),
                "editable": editable,
                "multivalue": isinstance(raw_value, list),
            }
        )
    return rows


def invalidate_dns_tree_cache() -> None:
    delete_dns_cache()
    DNS_TREE_CACHE["expires"] = 0.0
    DNS_TREE_CACHE["value"] = None
    RECORDS_CACHE["expires"] = 0.0
    RECORDS_CACHE["value"] = {}
    DNS_CACHE["tree"]["expires"] = 0.0
    DNS_CACHE["tree"]["value"] = None
    DNS_CACHE["records"].clear()
    DNS_CACHE["delegations"].clear()
    DNS_CACHE["forwarders"]["expires"] = 0.0
    DNS_CACHE["forwarders"]["value"] = None


def normalize_dns_tree(tree: dict | None) -> dict:
    if not isinstance(tree, dict):
        return {"forward": [], "reverse": [], "other": [], "forwarders": [], "delegations": []}
    normalized = dict(tree)
    normalized["forward"] = list(normalized.get("forward") or [])
    normalized["reverse"] = list(normalized.get("reverse") or [])
    normalized["other"] = list(normalized.get("other") or [])
    normalized["delegations"] = list(normalized.get("delegations") or [])
    normalized["forwarders"] = normalize_forwarder_rows(json.dumps(normalized.get("forwarders") or [], default=str))
    return normalized


def build_dns_tree() -> dict:
    server_arg = dns_server_arg()

    zones_script = f"""
Get-DnsServerZone {server_arg} |
Select-Object ZoneName, ZoneType, IsDsIntegrated, IsReverseLookupZone, IsAutoCreated, IsSigned, DynamicUpdate, ReplicationScope, Aging |
ConvertTo-Json -Depth 5
"""
    forwarders_script = f"""
Get-DnsServerForwarder {server_arg} |
Select-Object @{{
    Name = 'IPAddress'
    Expression = {{
        $addresses = @($_.IPAddress | ForEach-Object {{
            if ($_.Address -ne $null) {{
                try {{ [System.Net.IPAddress]::Parse([string]$_.Address).ToString() }} catch {{ $_.IPAddressToString }}
            }} elseif ($_.IPAddressToString) {{
                $_.IPAddressToString
            }} else {{
                $_.ToString()
            }}
        }})
        ($addresses -join ', ')
    }}
}}, UseRecursion, Timeout |
ConvertTo-Json -Depth 5
"""
    delegations_script = f"""
Get-DnsServerZoneDelegation {server_arg} -Name {ps_quote(DNS_ZONE)} |
Select-Object Name, ChildZoneName, NameServer, IPAddress |
ConvertTo-Json -Depth 5
"""

    zones = normalize_zone_rows(run_dns_ps(zones_script))
    forwarders = normalize_forwarder_rows(run_dns_ps(forwarders_script))
    delegations = normalize_delegation_rows(run_dns_ps(delegations_script))

    grouped = {
        "forward": [],
        "reverse": [],
        "other": [],
    }
    for zone in zones:
        if zone["reverse"]:
            grouped["reverse"].append(zone)
        elif zone["type"] in {"Forwarder", "Stub"}:
            grouped["other"].append(zone)
        else:
            grouped["forward"].append(zone)

    return {
        "forward": sorted(grouped["forward"], key=lambda item: item["name"].lower()),
        "reverse": sorted(grouped["reverse"], key=lambda item: item["name"].lower()),
        "other": sorted(grouped["other"], key=lambda item: item["name"].lower()),
        "forwarders": forwarders,
        "delegations": delegations,
    }


def get_dns_tree() -> dict:
    now = monotonic()
    cached = DNS_TREE_CACHE["value"]
    if cached is not None and now < DNS_TREE_CACHE["expires"]:
        return cached

    cached_tree = load_cached_tree()
    if cached_tree is not None:
        DNS_TREE_CACHE["value"] = cached_tree
        DNS_TREE_CACHE["expires"] = now + DNS_CACHE_REFRESH_SECONDS
        return cached_tree

    tree = refresh_dns_cache_once()
    DNS_TREE_CACHE["value"] = tree
    DNS_TREE_CACHE["expires"] = now + DNS_CACHE_REFRESH_SECONDS
    return tree


def get_zone_choices() -> list[str]:
    try:
        tree = get_dns_tree()
    except Exception:
        return []
    choices = []
    seen = set()
    for item in tree["forward"] + tree["reverse"] + tree["other"]:
        name = item.get("name", "").strip().rstrip(".")
        if name and name not in seen:
            seen.add(name)
            choices.append(name)
    choices.sort(key=str.lower)
    return choices


def get_zone_choice_groups() -> dict[str, list[str]]:
    try:
        tree = get_dns_tree()
    except Exception:
        return {"forward": [], "reverse": [], "other": []}

    def collect(items: list[dict]) -> list[str]:
        names = []
        seen = set()
        for item in items:
            name = item.get("name", "").strip().rstrip(".")
            if name and name not in seen:
                seen.add(name)
                names.append(name)
        names.sort(key=str.lower)
        return names

    return {
        "forward": collect(tree["forward"]),
        "reverse": collect(tree["reverse"]),
        "other": collect(tree["other"]),
    }


@app.context_processor
def inject_shared_context():
    groups = get_zone_choice_groups()
    choices = groups["forward"] + groups["reverse"] + groups["other"]
    return {
        "zone_choices": choices,
        "zone_choice_groups": groups,
    }


@app.before_request
def bootstrap_dns_cache():
    global DNS_CACHE_BOOTSTRAPPED
    if DNS_CACHE_BOOTSTRAPPED:
        return
    DNS_CACHE_BOOTSTRAPPED = True
    ensure_dns_cache_warm()
    start_dns_cache_refresher()


def get_records_from_dns(zone_name: str, name: str, record_type: str, recursive: bool) -> list[dict]:
    server_arg = dns_server_arg()
    name_filter = ""
    if name:
        name_filter = f" | Where-Object {{$_.HostName -like {ps_quote('*' + name + '*')}}}"

    rr_type_arg = ""
    if record_type not in {"", "ALL"}:
        rr_type_arg = f" -RRType {ps_quote(record_type)}"

    if recursive:
        scope_filter = ""
        script = f"""
$records = foreach ($zone in (Get-DnsServerZone {server_arg} | Where-Object {{$_.ZoneType -in 'Primary', 'Secondary', 'Stub'}})) {{
    Get-DnsServerResourceRecord {server_arg} -ZoneName $zone.ZoneName{rr_type_arg}{name_filter} |
    Select-Object @{{Name='ZoneName';Expression={{$zone.ZoneName}}}}, HostName, RecordType, TimeToLive, {dns_record_value_expression()}
}}
$records{scope_filter} | ConvertTo-Json -Depth 5
"""
    else:
        script = f"""
Get-DnsServerResourceRecord {server_arg} -ZoneName {ps_quote(zone_name)}{rr_type_arg}{name_filter} |
Select-Object @{{Name='ZoneName';Expression={{{ps_quote(zone_name)}}}}}, HostName, RecordType, TimeToLive, {dns_record_value_expression()} |
ConvertTo-Json -Depth 5
"""
    return normalize_record_rows(run_dns_ps(script))


def query_records(zone_name: str, name: str, record_type: str, recursive: bool) -> list[dict]:
    key = cached_record_key(zone_name, name, record_type, recursive)
    now = monotonic()
    cached_value = DNS_CACHE["records"].get(key)
    if cached_value is not None and now < cached_value["expires"]:
        return cached_value["value"]
    cached_rows = load_cached_records(zone_name, name, record_type, recursive)
    if cached_rows is not None:
        DNS_CACHE["records"][key] = {"expires": now + DNS_CACHE_REFRESH_SECONDS, "value": cached_rows}
        return cached_rows
    rows = get_records_from_dns(zone_name, name, record_type, recursive)
    cache_dns_payload("records", key, rows)
    DNS_CACHE["records"][key] = {"expires": now + DNS_CACHE_REFRESH_SECONDS, "value": rows}
    return rows


def zone_record_preview(zone_name: str, record_type: str = "ALL", limit: int | None = None) -> list[dict]:
    rows = query_records(zone_name, "", record_type, False)
    return rows if limit is None else rows[: max(0, limit)]


def query_zone_rows(search: str = "") -> list[dict]:
    server_arg = dns_server_arg()
    where_clause = ""
    if search:
        where_clause = f" | Where-Object {{$_.ZoneName -like {ps_quote('*' + search + '*')}}}"
    zones_script = f"""
Get-DnsServerZone {server_arg}{where_clause} |
Select-Object ZoneName, ZoneType, IsDsIntegrated, IsReverseLookupZone, IsAutoCreated, IsSigned, DynamicUpdate, ReplicationScope, Aging |
ConvertTo-Json -Depth 5
"""
    return normalize_zone_rows(run_dns_ps(zones_script))


def query_forwarder_rows() -> list[dict]:
    cached_tree = normalize_dns_tree(get_dns_tree())
    forwarders = cached_tree.get("forwarders", [])
    if not forwarders:
        return []
    if isinstance(forwarders, list) and forwarders and isinstance(forwarders[0], dict) and "address" in forwarders[0]:
        return forwarders
    return normalize_forwarder_rows(json.dumps(forwarders, default=str))


def get_delegation_rows_from_dns(zone_name: str) -> list[dict]:
    server_arg = dns_server_arg()
    delegations_script = f"""
Get-DnsServerZoneDelegation {server_arg} -Name {ps_quote(zone_name)} |
Select-Object Name, ChildZoneName, NameServer, IPAddress |
ConvertTo-Json -Depth 5
"""
    return normalize_delegation_rows(run_dns_ps(delegations_script))


def query_delegation_rows(zone_name: str) -> list[dict]:
    key = cached_delegation_key(zone_name)
    now = monotonic()
    cached_value = DNS_CACHE["delegations"].get(key)
    if cached_value is not None and now < cached_value["expires"]:
        return cached_value["value"]

    cached_rows = load_cached_delegations(zone_name)
    if cached_rows is not None:
        DNS_CACHE["delegations"][key] = {"expires": now + DNS_CACHE_REFRESH_SECONDS, "value": cached_rows}
        return cached_rows

    rows = get_delegation_rows_from_dns(zone_name)
    cache_dns_payload("delegations", key, rows)
    DNS_CACHE["delegations"][key] = {"expires": now + DNS_CACHE_REFRESH_SECONDS, "value": rows}
    return rows


def query_ad_users(search: str = "") -> list[dict]:
    search = search.strip()
    cache_key = f"search:{search.lower()}"
    cached_rows = load_dns_payload("ad_users", cache_key, DNS_CACHE_REFRESH_SECONDS)
    if isinstance(cached_rows, list):
        return cached_rows
    if search:
        filter_expr = f"Name -like {ps_quote('*' + search + '*')} -or SamAccountName -like {ps_quote('*' + search + '*')}"
    else:
        filter_expr = "*"
    script = f"""
Import-Module ActiveDirectory -ErrorAction Stop
Get-ADUser -Filter {ps_quote(filter_expr)} -Properties EmailAddress, Department, Title -ResultSetSize 50 |
Select-Object Name, SamAccountName, Enabled, EmailAddress, Department, Title, DistinguishedName |
ConvertTo-Json -Depth 5
"""
    rows = normalize_user_rows(run_dns_ps(script))
    rows = sorted(rows, key=lambda item: item["name"].lower())
    cache_dns_payload("ad_users", cache_key, rows)
    return rows


def query_ad_groups(search: str = "") -> list[dict]:
    search = search.strip()
    cache_key = f"search:{search.lower()}"
    cached_rows = load_dns_payload("ad_groups", cache_key, DNS_CACHE_REFRESH_SECONDS)
    if isinstance(cached_rows, list):
        return cached_rows
    if search:
        filter_expr = f"Name -like {ps_quote('*' + search + '*')} -or SamAccountName -like {ps_quote('*' + search + '*')}"
    else:
        filter_expr = "*"
    script = f"""
Import-Module ActiveDirectory -ErrorAction Stop
Get-ADGroup -Filter {ps_quote(filter_expr)} -Properties Description -ResultSetSize 50 |
Select-Object Name, SamAccountName, GroupScope, GroupCategory, Description, DistinguishedName |
ConvertTo-Json -Depth 5
"""
    rows = normalize_group_rows(run_dns_ps(script))
    rows = sorted(rows, key=lambda item: item["name"].lower())
    cache_dns_payload("ad_groups", cache_key, rows)
    return rows


def query_ad_schema_attributes(kind: str) -> list[str]:
    kind = (kind or "").strip().lower()
    if kind not in {"user", "group"}:
        return []
    cache_key = f"{kind}"
    cached = load_dns_payload("ad_schema_attributes", cache_key, DNS_CACHE_REFRESH_SECONDS)
    if isinstance(cached, list):
        return cached

    class_name = "user" if kind == "user" else "group"
    script = f"""
Import-Module ActiveDirectory -ErrorAction Stop
$schemaNC = (Get-ADRootDSE).SchemaNamingContext
$seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$className = {ps_quote(class_name)}
while ($className) {{
    $class = Get-ADObject -SearchBase $schemaNC -LDAPFilter "(lDAPDisplayName=$className)" -Properties lDAPDisplayName,mayContain,mustContain,systemMayContain,systemMustContain,subClassOf
    if (-not $class) {{ break }}
    foreach ($attr in @($class.mustContain + $class.mayContain + $class.systemMustContain + $class.systemMayContain)) {{
        if ($attr) {{ [void]$seen.Add([string]$attr) }}
    }}
    $className = $class.subClassOf
}}
$seen | Sort-Object | ConvertTo-Json -Depth 4
"""
    rows = parse_json_rows(run_dns_ps(script))
    attrs = [normalize_ad_attribute_name(item) for item in rows if item]
    attrs = [item for item in attrs if item]
    cache_dns_payload("ad_schema_attributes", cache_key, attrs)
    return attrs


def query_ad_user_details(sam_account_name: str) -> dict:
    sam_account_name = sam_account_name.strip()
    if not sam_account_name:
        return {}
    cache_key = f"v2:{sam_account_name.lower()}"
    cached = load_dns_payload("ad_user_detail", cache_key, DNS_CACHE_REFRESH_SECONDS)
    if isinstance(cached, dict):
        return cached
    script = f"""
Import-Module ActiveDirectory -ErrorAction Stop
$user = Get-ADUser -Identity {ps_quote(sam_account_name)} -Properties *
$groups = @()
if ($user.MemberOf) {{
    $groups = foreach ($dn in $user.MemberOf) {{
        try {{ (Get-ADGroup -Identity $dn).SamAccountName }} catch {{ $dn }}
    }}
}}
[pscustomobject]@{{
    Raw = $user
    MemberOfResolved = $groups
}} | ConvertTo-Json -Depth 10
"""
    rows = parse_json_rows(run_dns_ps(script))
    source = rows[0] if rows else {}
    raw = source.get("Raw", {}) if isinstance(source.get("Raw", {}), dict) else {}
    attributes = build_ad_attribute_rows(raw, "user")
    normalized_source = {
        "name": raw.get("Name", ""),
        "sam_account_name": raw.get("SamAccountName", ""),
        "user_principal_name": raw.get("UserPrincipalName", ""),
        "enabled": raw.get("Enabled", ""),
        "locked_out": raw.get("LockedOut", ""),
        "email": raw.get("EmailAddress", ""),
        "department": raw.get("Department", ""),
        "title": raw.get("Title", ""),
        "description": raw.get("Description", ""),
        "office": raw.get("Office", ""),
        "office_phone": raw.get("OfficePhone", ""),
        "mobile_phone": raw.get("MobilePhone", ""),
        "password_last_set": raw.get("PasswordLastSet", ""),
        "last_logon_date": raw.get("LastLogonDate", ""),
        "password_never_expires": raw.get("PasswordNeverExpires", ""),
        "manager": raw.get("Manager", ""),
        "distinguished_name": raw.get("DistinguishedName", ""),
        "member_of": source.get("MemberOfResolved", []) or [],
    }
    result = {
        **normalized_source,
        "attributes": attributes,
        "schema_attributes": query_ad_schema_attributes("user"),
    }
    if result:
        cache_dns_payload("ad_user_detail", cache_key, result)
    return result


def query_ad_group_details(sam_account_name: str) -> dict:
    sam_account_name = sam_account_name.strip()
    if not sam_account_name:
        return {}
    cache_key = f"v2:{sam_account_name.lower()}"
    cached = load_dns_payload("ad_group_detail", cache_key, DNS_CACHE_REFRESH_SECONDS)
    if isinstance(cached, dict):
        return cached
    script = f"""
Import-Module ActiveDirectory -ErrorAction Stop
$group = Get-ADGroup -Identity {ps_quote(sam_account_name)} -Properties *
$members = @()
if ($group.Members) {{
    $members = foreach ($dn in $group.Members) {{
        try {{
            $obj = Get-ADObject -Identity $dn -Properties ObjectClass, SamAccountName, Name
            [pscustomobject]@{{ Name = $obj.Name; SamAccountName = $obj.SamAccountName; ObjectClass = $obj.ObjectClass; DistinguishedName = $dn }}
        }} catch {{
            [pscustomobject]@{{ Name = $dn; SamAccountName = ''; ObjectClass = ''; DistinguishedName = $dn }}
        }}
    }}
}}
$parentGroups = @()
if ($group.MemberOf) {{
    $parentGroups = foreach ($dn in $group.MemberOf) {{
        try {{ (Get-ADGroup -Identity $dn).SamAccountName }} catch {{ $dn }}
    }}
}}
[pscustomobject]@{{
    Raw = $group
    MembersResolved = $members
    MemberOfResolved = $parentGroups
}} | ConvertTo-Json -Depth 6
"""
    rows = parse_json_rows(run_dns_ps(script))
    source = rows[0] if rows else {}
    raw = source.get("Raw", {}) if isinstance(source.get("Raw", {}), dict) else {}
    attributes = build_ad_attribute_rows(raw, "group")
    result = {
        "name": raw.get("Name", ""),
        "sam_account_name": raw.get("SamAccountName", ""),
        "description": raw.get("Description", ""),
        "group_scope": raw.get("GroupScope", ""),
        "group_category": raw.get("GroupCategory", ""),
        "managed_by": raw.get("ManagedBy", ""),
        "distinguished_name": raw.get("DistinguishedName", ""),
        "members": source.get("MembersResolved", []) or [],
        "member_of": source.get("MemberOfResolved", []) or [],
        "attributes": attributes,
        "schema_attributes": query_ad_schema_attributes("group"),
    }
    if result:
        cache_dns_payload("ad_group_detail", cache_key, result)
    return result


def build_ad_user_create_script(params: dict) -> str:
    password = params.get("password", "").strip()
    enabled = params.get("enabled", "true").strip().lower() in {"1", "true", "yes", "on"}
    parts = [
        "Import-Module ActiveDirectory -ErrorAction Stop",
        f"$params = @{{ Name = {ps_quote(params.get('name', ''))}; SamAccountName = {ps_quote(params.get('sam_account_name', ''))}; Path = {ps_quote(params.get('path', '') or '')} }}",
    ]
    if params.get("given_name"):
        parts.append(f"$params.GivenName = {ps_quote(params.get('given_name', ''))}")
    if params.get("surname"):
        parts.append(f"$params.Surname = {ps_quote(params.get('surname', ''))}")
    if params.get("display_name"):
        parts.append(f"$params.DisplayName = {ps_quote(params.get('display_name', ''))}")
    if params.get("email"):
        parts.append(f"$params.EmailAddress = {ps_quote(params.get('email', ''))}")
    if params.get("department"):
        parts.append(f"$params.Department = {ps_quote(params.get('department', ''))}")
    if params.get("title"):
        parts.append(f"$params.Title = {ps_quote(params.get('title', ''))}")
    if params.get("description"):
        parts.append(f"$params.Description = {ps_quote(params.get('description', ''))}")
    if params.get("office"):
        parts.append(f"$params.Office = {ps_quote(params.get('office', ''))}")
    if params.get("office_phone"):
        parts.append(f"$params.OfficePhone = {ps_quote(params.get('office_phone', ''))}")
    if params.get("mobile_phone"):
        parts.append(f"$params.MobilePhone = {ps_quote(params.get('mobile_phone', ''))}")
    if params.get("upn"):
        parts.append(f"$params.UserPrincipalName = {ps_quote(params.get('upn', ''))}")
    if password:
        parts.append(f"$secure = ConvertTo-SecureString {ps_quote(password)} -AsPlainText -Force")
        parts.append("$params.AccountPassword = $secure")
        parts.append("$params.Enabled = $true" if enabled else "$params.Enabled = $false")
    else:
        parts.append("$params.Enabled = $false")
    parts.append("New-ADUser @params")
    return "\n".join(parts)


def build_ad_user_update_script(sam_account_name: str, params: dict) -> str:
    updates = []
    enabled_raw = params.get("enabled")
    enabled_value = None
    if enabled_raw is not None:
        enabled_value = str(enabled_raw).strip().lower() in {"1", "true", "yes", "on"}
    if params.get("given_name"):
        updates.append(f"-GivenName {ps_quote(params.get('given_name', ''))}")
    if params.get("surname"):
        updates.append(f"-Surname {ps_quote(params.get('surname', ''))}")
    if params.get("display_name"):
        updates.append(f"-DisplayName {ps_quote(params.get('display_name', ''))}")
    if params.get("email"):
        updates.append(f"-EmailAddress {ps_quote(params.get('email', ''))}")
    if params.get("department"):
        updates.append(f"-Department {ps_quote(params.get('department', ''))}")
    if params.get("title"):
        updates.append(f"-Title {ps_quote(params.get('title', ''))}")
    if params.get("description"):
        updates.append(f"-Description {ps_quote(params.get('description', ''))}")
    if params.get("office"):
        updates.append(f"-Office {ps_quote(params.get('office', ''))}")
    if params.get("office_phone"):
        updates.append(f"-OfficePhone {ps_quote(params.get('office_phone', ''))}")
    if params.get("mobile_phone"):
        updates.append(f"-MobilePhone {ps_quote(params.get('mobile_phone', ''))}")
    if params.get("upn"):
        updates.append(f"-UserPrincipalName {ps_quote(params.get('upn', ''))}")
    parts = ["Import-Module ActiveDirectory -ErrorAction Stop"]
    if params.get("name"):
        parts.append(f"$user = Get-ADUser -Identity {ps_quote(sam_account_name)}")
        parts.append(f"Rename-ADObject -Identity $user.DistinguishedName -NewName {ps_quote(params.get('name', ''))}")
    if updates:
        parts.append(f"Set-ADUser -Identity {ps_quote(sam_account_name)} {' '.join(updates)}")
    if enabled_value is not None:
        parts.append(f"{'Enable' if enabled_value else 'Disable'}-ADAccount -Identity {ps_quote(sam_account_name)}")
    if params.get("path"):
        parts.append(f"Move-ADObject -Identity (Get-ADUser -Identity {ps_quote(sam_account_name)}).DistinguishedName -TargetPath {ps_quote(params.get('path', ''))}")
    if len(parts) == 1:
        raise RuntimeError("No user updates were supplied.")
    return "\n".join(parts)


def build_ad_group_create_script(params: dict) -> str:
    parts = [
        "Import-Module ActiveDirectory -ErrorAction Stop",
        "New-ADGroup",
        f"-Name {ps_quote(params.get('name', ''))}",
        f"-SamAccountName {ps_quote(params.get('sam_account_name', ''))}",
        f"-GroupScope {ps_quote(params.get('scope', 'Global'))}",
        f"-GroupCategory {ps_quote(params.get('category', 'Security'))}",
    ]
    if params.get("path"):
        parts.extend(["-Path", ps_quote(params.get("path", ""))])
    if params.get("description"):
        parts.extend(["-Description", ps_quote(params.get("description", ""))])
    return " ".join(parts)


def build_ad_group_update_script(sam_account_name: str, params: dict) -> str:
    updates = []
    if params.get("scope"):
        updates.append(f"-GroupScope {ps_quote(params.get('scope', ''))}")
    if params.get("category"):
        updates.append(f"-GroupCategory {ps_quote(params.get('category', ''))}")
    if params.get("description") is not None:
        updates.append(f"-Description {ps_quote(params.get('description', ''))}")
    parts = ["Import-Module ActiveDirectory -ErrorAction Stop"]
    if params.get("name"):
        parts.append(f"$group = Get-ADGroup -Identity {ps_quote(sam_account_name)}")
        parts.append(f"Rename-ADObject -Identity $group.DistinguishedName -NewName {ps_quote(params.get('name', ''))}")
    if updates:
        parts.append(f"Set-ADGroup -Identity {ps_quote(sam_account_name)} {' '.join(updates)}")
    if params.get("path"):
        parts.append(f"Move-ADObject -Identity (Get-ADGroup -Identity {ps_quote(sam_account_name)}).DistinguishedName -TargetPath {ps_quote(params.get('path', ''))}")
    if len(parts) == 1:
        raise RuntimeError("No group updates were supplied.")
    return "\n".join(parts)


def build_ad_group_membership_script(sam_account_name: str, action: str, members: list[str]) -> str:
    member_array = ps_array_literal(members)
    if action == "add":
        return f"""
Import-Module ActiveDirectory -ErrorAction Stop
Add-ADGroupMember -Identity {ps_quote(sam_account_name)} -Members {member_array}
"""
    if action == "remove":
        return f"""
Import-Module ActiveDirectory -ErrorAction Stop
Remove-ADGroupMember -Identity {ps_quote(sam_account_name)} -Members {member_array} -Confirm:$false
"""
    raise RuntimeError("Unsupported membership action.")


def build_ad_user_group_membership_script(sam_account_name: str, action: str, groups: list[str]) -> str:
    group_array = ps_array_literal(groups)
    if action == "add":
        return f"""
Import-Module ActiveDirectory -ErrorAction Stop
Add-ADPrincipalGroupMembership -Identity {ps_quote(sam_account_name)} -MemberOf {group_array}
"""
    if action == "remove":
        return f"""
Import-Module ActiveDirectory -ErrorAction Stop
Remove-ADPrincipalGroupMembership -Identity {ps_quote(sam_account_name)} -MemberOf {group_array} -Confirm:$false
"""
    raise RuntimeError("Unsupported user membership action.")


def build_ad_object_attribute_update_script(kind: str, dn: str, sam_account_name: str, attribute: str, value: str) -> str:
    attribute = (attribute or "").strip()
    if not attribute:
        raise RuntimeError("Attribute name is required.")
    normalized = normalize_ad_attribute_name(attribute)
    kind = (kind or "").strip().lower()
    value = "" if value is None else str(value)
    parts = ["Import-Module ActiveDirectory -ErrorAction Stop"]

    if normalized == "name":
        if not value.strip():
            raise RuntimeError("Name cannot be empty.")
        if kind == "user":
            parts.append(f"$obj = Get-ADUser -Identity {ps_quote(dn)}")
        elif kind == "group":
            parts.append(f"$obj = Get-ADGroup -Identity {ps_quote(dn)}")
        else:
            parts.append(f"$obj = Get-ADObject -Identity {ps_quote(dn)}")
        parts.append(f"Rename-ADObject -Identity $obj.DistinguishedName -NewName {ps_quote(value.strip())}")
        return "\n".join(parts)

    if normalized == "sam_account_name":
        if not value.strip():
            raise RuntimeError("SamAccountName cannot be empty.")
        if kind == "user":
            parts.append(f"Set-ADUser -Identity {ps_quote(dn)} -SamAccountName {ps_quote(value.strip())}")
        elif kind == "group":
            parts.append(f"Set-ADGroup -Identity {ps_quote(dn)} -SamAccountName {ps_quote(value.strip())}")
        else:
            parts.append(f"Set-ADObject -Identity {ps_quote(dn)} -Replace @{{ {ps_quote('sAMAccountName')} = {ps_quote(value.strip())} }}")
        return "\n".join(parts)

    if normalized == "enabled" and kind == "user":
        enabled = value.strip().lower() in {"1", "true", "yes", "on"}
        parts.append(f"{'Enable' if enabled else 'Disable'}-ADAccount -Identity {ps_quote(dn)}")
        return "\n".join(parts)

    if normalized == "user_principal_name" and kind == "user":
        if value.strip():
            parts.append(f"Set-ADUser -Identity {ps_quote(dn)} -UserPrincipalName {ps_quote(value.strip())}")
        else:
            parts.append(f"Set-ADUser -Identity {ps_quote(dn)} -Clear {ps_quote('userPrincipalName')}")
        return "\n".join(parts)

    if kind == "user" and normalized in {"email", "department", "title", "description", "office", "office_phone", "mobile_phone", "manager"}:
        param_map = {
            "email": "EmailAddress",
            "department": "Department",
            "title": "Title",
            "description": "Description",
            "office": "Office",
            "office_phone": "OfficePhone",
            "mobile_phone": "MobilePhone",
            "manager": "Manager",
        }
        param_name = param_map[normalized]
        if value.strip():
            parts.append(f"Set-ADUser -Identity {ps_quote(dn)} -{param_name} {ps_quote(value.strip())}")
        else:
            clear_name = {
                "email": "emailAddress",
                "department": "department",
                "title": "title",
                "description": "description",
                "office": "office",
                "office_phone": "officePhone",
                "mobile_phone": "mobilePhone",
                "manager": "manager",
            }[normalized]
            parts.append(f"Set-ADUser -Identity {ps_quote(dn)} -Clear {ps_quote(clear_name)}")
        return "\n".join(parts)

    if kind == "group" and normalized in {"group_scope", "group_category", "description", "managed_by"}:
        if normalized == "group_scope":
            if value.strip():
                parts.append(f"Set-ADGroup -Identity {ps_quote(dn)} -GroupScope {ps_quote(value.strip())}")
            return "\n".join(parts)
        if normalized == "group_category":
            if value.strip():
                parts.append(f"Set-ADGroup -Identity {ps_quote(dn)} -GroupCategory {ps_quote(value.strip())}")
            return "\n".join(parts)
        if normalized == "description":
            if value.strip():
                parts.append(f"Set-ADGroup -Identity {ps_quote(dn)} -Description {ps_quote(value.strip())}")
            else:
                parts.append(f"Set-ADGroup -Identity {ps_quote(dn)} -Clear {ps_quote('description')}")
            return "\n".join(parts)
        if normalized == "managed_by":
            if value.strip():
                parts.append(f"Set-ADGroup -Identity {ps_quote(dn)} -ManagedBy {ps_quote(value.strip())}")
            else:
                parts.append(f"Set-ADGroup -Identity {ps_quote(dn)} -Clear {ps_quote('managedBy')}")
            return "\n".join(parts)

    if normalized in {"member_of", "members"}:
        raise RuntimeError("Membership is edited from the Membership panel.")

    if not value.strip():
        parts.append(f"Set-ADObject -Identity {ps_quote(dn)} -Clear {ps_quote(attribute)}")
        return "\n".join(parts)

    if "\n" in value:
        replace_value = ps_array_literal(csv_items(value))
    else:
        replace_value = ps_quote(value.strip())
    parts.append(f"Set-ADObject -Identity {ps_quote(dn)} -Replace @{{ {ps_quote(attribute)} = {replace_value} }}")
    return "\n".join(parts)


def build_ad_user_password_script(sam_account_name: str, password: str, force_change: bool) -> str:
    force_change_arg = "$true" if force_change else "$false"
    return f"""
Import-Module ActiveDirectory -ErrorAction Stop
$secure = ConvertTo-SecureString {ps_quote(password)} -AsPlainText -Force
Set-ADAccountPassword -Identity {ps_quote(sam_account_name)} -Reset -NewPassword $secure
Set-ADUser -Identity {ps_quote(sam_account_name)} -ChangePasswordAtLogon {force_change_arg}
"""


def build_record_add_script(zone_name: str, record_type: str, name: str, target: str, ttl: int, preference: str = "", priority: str = "", weight: str = "", port: str = "") -> str:
    server_arg = dns_server_arg()
    ttl_arg = f"([TimeSpan]::FromSeconds({int(ttl)}))"

    if record_type == "A":
        return f"Add-DnsServerResourceRecordA {server_arg} -ZoneName {ps_quote(zone_name)} -Name {ps_quote(name)} -IPv4Address {ps_quote(target)} -TimeToLive {ttl_arg}"
    if record_type == "AAAA":
        return f"Add-DnsServerResourceRecordAAAA {server_arg} -ZoneName {ps_quote(zone_name)} -Name {ps_quote(name)} -IPv6Address {ps_quote(target)} -TimeToLive {ttl_arg}"
    if record_type == "CNAME":
        target = target.rstrip(".") + "."
        return f"Add-DnsServerResourceRecordCName {server_arg} -ZoneName {ps_quote(zone_name)} -Name {ps_quote(name)} -HostNameAlias {ps_quote(target)} -TimeToLive {ttl_arg}"
    if record_type == "NS":
        target = target.rstrip(".") + "."
        return f"Add-DnsServerResourceRecord {server_arg} -ZoneName {ps_quote(zone_name)} -Name {ps_quote(name)} -NameServer {ps_quote(target)} -NS -TimeToLive {ttl_arg}"
    if record_type == "MX":
        target = target.rstrip(".") + "."
        return f"Add-DnsServerResourceRecordMX {server_arg} -ZoneName {ps_quote(zone_name)} -Name {ps_quote(name)} -MailExchange {ps_quote(target)} -Preference {int(preference or '0')} -TimeToLive {ttl_arg}"
    if record_type == "SRV":
        target = target.rstrip(".") + "."
        return f"Add-DnsServerResourceRecord {server_arg} -ZoneName {ps_quote(zone_name)} -Name {ps_quote(name)} -DomainName {ps_quote(target)} -Priority {int(priority or '0')} -Weight {int(weight or '0')} -Port {int(port or '0')} -Srv -TimeToLive {ttl_arg}"
    if record_type == "PTR":
        target = target.rstrip(".") + "."
        return f"Add-DnsServerResourceRecordPtr {server_arg} -ZoneName {ps_quote(zone_name)} -Name {ps_quote(name)} -PtrDomainName {ps_quote(target)} -TimeToLive {ttl_arg}"
    if record_type == "TXT":
        return f"Add-DnsServerResourceRecord {server_arg} -ZoneName {ps_quote(zone_name)} -Name {ps_quote(name)} -Txt -DescriptiveText {ps_quote(target)} -TimeToLive {ttl_arg}"
    raise RuntimeError(f"Unsupported record type: {record_type}")


def build_record_edit_script(original_zone: str, original_name: str, original_type: str, original_target: str, zone_name: str, name: str, record_type: str, target: str, ttl: int, preference: str = "", priority: str = "", weight: str = "", port: str = "") -> str:
    remove_record_data = f" -RecordData {ps_quote(original_target)}" if original_target else ""
    delete_part = f"Remove-DnsServerResourceRecord {dns_server_arg()} -ZoneName {ps_quote(original_zone)} -Name {ps_quote(original_name)} -RRType {ps_quote(original_type)}{remove_record_data} -Force"
    add_part = build_record_add_script(zone_name, record_type, name, target, ttl, preference=preference, priority=priority, weight=weight, port=port)
    return f"""
$existing = Get-DnsServerResourceRecord {dns_server_arg()} -ZoneName {ps_quote(original_zone)} -Name {ps_quote(original_name)} -RRType {ps_quote(original_type)} -ErrorAction Stop
{delete_part}
{add_part}
"""


def current_return_to() -> str:
    return (request.form.get("return_to") or request.args.get("return_to") or "").strip()


def safe_return_to(default: str) -> str:
    target = current_return_to()
    parsed = urlparse(target)
    if target.startswith("/") and not target.startswith("//") and not parsed.scheme and not parsed.netloc:
        return target
    return default


def _oauth_state_path(state: str) -> Path:
    return OAUTH_STATE_DIR / f"{state}.json"


def save_oauth_state(state: str, data: dict) -> None:
    OAUTH_STATE_DIR.mkdir(parents=True, exist_ok=True)
    _oauth_state_path(state).write_text(json.dumps(data), encoding="utf-8")


def load_oauth_state(state: str) -> dict | None:
    path = _oauth_state_path(state)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None


def clear_oauth_state(state: str) -> None:
    try:
        _oauth_state_path(state).unlink()
    except FileNotFoundError:
        pass


def restore_oauth_state_to_session(state: str) -> bool:
    restored_state = load_oauth_state(state)
    if restored_state is None:
        return False
    session[f"_state_idp_{state}"] = {
        "data": restored_state,
        "exp": 9999999999,
    }
    return True


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def token_endpoint_auth_methods():
    if OIDC_TOKEN_ENDPOINT_AUTH_METHOD:
        return [OIDC_TOKEN_ENDPOINT_AUTH_METHOD]

    supported = []
    try:
        metadata = oauth.idp.load_server_metadata() or {}
        supported = metadata.get("token_endpoint_auth_methods_supported") or []
    except Exception:
        supported = []

    preferred = ["client_secret_post", "client_secret_basic", "none"]
    if supported:
        return [method for method in preferred if method in supported] or supported
    return preferred


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        groups = session.get("user", {}).get("groups", [])
        if ALLOWED_ADMIN_GROUP not in groups:
            flash("You are signed in, but you are not authorized to manage DNS records.", "error")
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper


@app.route("/login")
def login():
    # Keep the callback bound to the host the user is actually using.
    redirect_uri = OIDC_REDIRECT_URI or url_for("callback", _external=True)
    response = oauth.idp.authorize_redirect(redirect_uri)
    location = response.headers.get("Location", "")
    state = parse_qs(urlparse(location).query).get("state", [None])[0]
    if state:
        state_key = f"_state_idp_{state}"
        state_data = session.get(state_key)
        if state_data and isinstance(state_data, dict):
            save_oauth_state(state, state_data.get("data", {}))
    return response


@app.route("/auth/callback")
def callback():
    try:
        state = request.args.get("state")
        if not state:
            session.clear()
            flash("Missing OAuth state in callback. Please sign in again.", "error")
            return redirect(url_for("login"))

        # Always prefer the persisted state entry for this callback state value.
        # This protects against lost/stale in-memory session entries behind proxies.
        restore_oauth_state_to_session(state)

        state_key = f"_state_idp_{state}"
        if state_key not in session:
            session.clear()
            flash("Your login session expired before callback completed. Please sign in again.", "error")
            return redirect(url_for("login"))

        token = oauth.idp.authorize_access_token()
        clear_oauth_state(state)
    except MismatchingStateError:
        state = request.args.get("state")
        if state and restore_oauth_state_to_session(state):
            try:
                token = oauth.idp.authorize_access_token()
                clear_oauth_state(state)
            except MismatchingStateError:
                session.clear()
                flash("Your login session could not be verified. Please sign in again from the same host (for example, stick to either localhost or 127.0.0.1).", "error")
                return redirect(url_for("login"))
        else:
            session.clear()
            flash("Your login session could not be verified. Please sign in again from the same host (for example, stick to either localhost or 127.0.0.1).", "error")
            return redirect(url_for("login"))
    except OAuthError as exc:
        if "invalid_client" not in str(exc).lower():
            raise

        state = request.args.get("state")
        methods = token_endpoint_auth_methods()
        for method in methods[1:]:
            oauth.idp.client_kwargs["token_endpoint_auth_method"] = method
            try:
                if state:
                    restore_oauth_state_to_session(state)
                token = oauth.idp.authorize_access_token()
                if state:
                    clear_oauth_state(state)
                break
            except MismatchingStateError:
                # State can be consumed on a failed token exchange attempt.
                # Try the next auth method with a fresh restored state.
                continue
            except OAuthError as retry_exc:
                if "invalid_client" not in str(retry_exc).lower():
                    raise
        else:
            session.clear()
            flash(
                "The identity provider rejected the client credentials. Check the OIDC client ID/secret and the token endpoint auth method, then try again.",
                "error",
            )
            return redirect(url_for("login"))
    userinfo = token.get("userinfo") or oauth.idp.userinfo()

    # For Entra/Authentik/Keycloak, expose group names in the token as `groups` if possible.
    # Otherwise change this mapping to match your claim, e.g. roles, memberOf, or groups.
    session["user"] = {
        "name": userinfo.get("name") or userinfo.get("preferred_username") or userinfo.get("email"),
        "email": userinfo.get("email") or userinfo.get("preferred_username"),
        "groups": userinfo.get("groups", []),
    }
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/")
@login_required
def index():
    user = session["user"]
    can_manage = ALLOWED_ADMIN_GROUP in user.get("groups", [])
    zone_search = request.args.get("zone_search", "").strip()
    record_name = request.args.get("record_name", "").strip()
    record_zone = request.args.get("record_zone", "").strip().rstrip(".")
    record_type = request.args.get("record_type", "ALL").strip().upper()
    record_recursive = request.args.get("record_recursive", "").strip().lower() in {"1", "true", "yes", "on"}
    delegation_zone = request.args.get("delegation_zone", DNS_ZONE).strip().rstrip(".") or DNS_ZONE
    record_zone_ui = record_zone or (DNS_ZONE if not record_recursive and not record_name else "")
    tree = None
    try:
        tree = get_dns_tree()
    except Exception as e:
        flash(str(e), "error")
        tree = {"forward": [], "reverse": [], "other": [], "forwarders": [], "delegations": []}
    zone_rows = []
    forward_zone_rows = []
    reverse_zone_rows = []
    forwarder_rows = []
    delegation_rows = []
    try:
        if zone_search:
            zone_rows = query_zone_rows(zone_search)
            forward_zone_rows = [item for item in zone_rows if not item.get("reverse")]
            reverse_zone_rows = [item for item in zone_rows if item.get("reverse")]
        else:
            forward_zone_rows = tree["forward"]
            reverse_zone_rows = tree["reverse"]
            zone_rows = forward_zone_rows + reverse_zone_rows
    except Exception as e:
        flash(str(e), "error")
    try:
        forwarder_rows = query_forwarder_rows()
    except Exception as e:
        flash(str(e), "error")
    try:
        delegation_rows = tree["delegations"] if delegation_zone == DNS_ZONE else query_delegation_rows(delegation_zone)
    except Exception as e:
        flash(str(e), "error")
    zone_choices = []
    seen_zone_names = set()
    for item in tree["forward"] + tree["reverse"] + tree["other"]:
        name = item.get("name", "").strip().rstrip(".")
        if name and name not in seen_zone_names:
            seen_zone_names.add(name)
            zone_choices.append(name)
    zone_choices.sort(key=str.lower)
    scope_label = record_zone or ("all zones" if record_recursive or (not record_zone and record_name) else DNS_ZONE)
    return render_template(
        "index.html",
        zone=DNS_ZONE,
        server=DNS_SERVER,
        user=user,
        can_manage=can_manage,
        tree=tree,
        zone_rows=zone_rows,
        forward_zone_rows=forward_zone_rows,
        reverse_zone_rows=reverse_zone_rows,
        zone_count=len(zone_rows),
        zone_search=zone_search,
        forwarder_rows=forwarder_rows,
        delegation_rows=delegation_rows,
        delegation_zone=delegation_zone,
    )


@app.route("/records")
@login_required
def records():
    name = request.args.get("name", "").strip()
    zone_name = request.args.get("zone", "").strip().rstrip(".")
    record_type = request.args.get("type", "ALL").strip().upper()
    recursive = request.args.get("recursive", "").strip().lower() in {"1", "true", "yes", "on"}

    if not zone_name and not recursive and not name:
        zone_name = DNS_ZONE

    records = []
    search_scope = "recursive" if recursive or (not zone_name and name) else ("zone" if zone_name else "default")
    try:
        records = query_records(zone_name or DNS_ZONE, name, record_type, search_scope == "recursive")
        output = json.dumps(records)
    except Exception as e:
        flash(str(e), "error")
        output = ""
    user = session["user"]
    can_manage = ALLOWED_ADMIN_GROUP in user.get("groups", [])
    scope_label = zone_name or ("all zones" if search_scope == "recursive" else DNS_ZONE)
    return render_template(
        "records.html",
        records=records,
        name=name,
        zone_name=zone_name,
        record_type=record_type,
        recursive=search_scope == "recursive",
        search_scope=search_scope,
        output=output,
        can_manage=can_manage,
        user=user,
        zone=DNS_ZONE,
        scope_label=scope_label,
        server=DNS_SERVER,
    )


@app.route("/identity")
@login_required
def identity():
    user = session["user"]
    can_manage = ALLOWED_ADMIN_GROUP in user.get("groups", [])
    user_search = request.args.get("user_search", "").strip()
    group_search = request.args.get("group_search", "").strip()

    users = []
    groups = []
    try:
        users = query_ad_users(user_search)
    except Exception as e:
        flash(f"Users: {e}", "error")
    try:
        groups = query_ad_groups(group_search)
    except Exception as e:
        flash(f"Groups: {e}", "error")

    return render_template(
        "identity.html",
        user=user,
        can_manage=can_manage,
        server=DNS_SERVER,
        zone=DNS_ZONE,
        user_search=user_search,
        group_search=group_search,
        users=users,
        groups=groups,
    )


@app.route("/api/ad/user")
@login_required
def api_ad_user():
    sam = request.args.get("sam", "").strip()
    try:
        return jsonify({"user": query_ad_user_details(sam)})
    except Exception as e:
        return jsonify({"error": str(e), "user": {}}), 200


@app.route("/api/ad/group")
@login_required
def api_ad_group():
    sam = request.args.get("sam", "").strip()
    try:
        return jsonify({"group": query_ad_group_details(sam)})
    except Exception as e:
        return jsonify({"error": str(e), "group": {}}), 200


@app.route("/api/ad/search/users")
@login_required
def api_ad_search_users():
    query = request.args.get("q", "").strip()
    try:
        return jsonify({"users": query_ad_users(query)})
    except Exception as e:
        return jsonify({"error": str(e), "users": []}), 200


@app.route("/api/ad/search/groups")
@login_required
def api_ad_search_groups():
    query = request.args.get("q", "").strip()
    try:
        return jsonify({"groups": query_ad_groups(query)})
    except Exception as e:
        return jsonify({"error": str(e), "groups": []}), 200


@app.route("/api/ad/schema")
@login_required
def api_ad_schema():
    kind = request.args.get("kind", "").strip().lower()
    try:
        return jsonify({"kind": kind, "attributes": query_ad_schema_attributes(kind)})
    except Exception as e:
        return jsonify({"error": str(e), "kind": kind, "attributes": []}), 200


@app.route("/identity/actions", methods=["POST"])
@login_required
@admin_required
def identity_actions():
    action = request.form.get("action", "").strip().lower()
    return_to = safe_return_to(url_for("identity"))

    try:
        if action == "user-create":
            script = build_ad_user_create_script(request.form)
            run_dns_ps(script)
            flash("User created.", "success")
        elif action == "user-update":
            sam = request.form.get("sam_account_name", "").strip()
            if not sam:
                raise RuntimeError("samAccountName is required.")
            script = build_ad_user_update_script(sam, request.form)
            run_dns_ps(script)
            flash("User updated.", "success")
        elif action == "user-delete" or action == "delete":
            sam = request.form.get("sam_account_name", "").strip()
            if not sam:
                raise RuntimeError("samAccountName is required.")
            run_dns_ps(f"Import-Module ActiveDirectory -ErrorAction Stop\nRemove-ADUser -Identity {ps_quote(sam)} -Confirm:$false")
            flash("User deleted.", "success")
        elif action == "user-enable" or action == "enable":
            sam = request.form.get("sam_account_name", "").strip()
            run_dns_ps(f"Import-Module ActiveDirectory -ErrorAction Stop\nEnable-ADAccount -Identity {ps_quote(sam)}")
            flash("User enabled.", "success")
        elif action == "user-disable" or action == "disable":
            sam = request.form.get("sam_account_name", "").strip()
            run_dns_ps(f"Import-Module ActiveDirectory -ErrorAction Stop\nDisable-ADAccount -Identity {ps_quote(sam)}")
            flash("User disabled.", "success")
        elif action == "user-reset-password" or action == "reset-password":
            sam = request.form.get("sam_account_name", "").strip()
            password = request.form.get("password", "").strip()
            if not sam or not password:
                raise RuntimeError("samAccountName and password are required.")
            force_change = request.form.get("force_change") in {"1", "true", "yes", "on"}
            run_dns_ps(build_ad_user_password_script(sam, password, force_change))
            flash("Password reset.", "success")
        elif action == "group-create":
            script = build_ad_group_create_script(request.form)
            run_dns_ps(script)
            flash("Group created.", "success")
        elif action == "group-update":
            sam = request.form.get("sam_account_name", "").strip()
            if not sam:
                raise RuntimeError("samAccountName is required.")
            script = build_ad_group_update_script(sam, request.form)
            run_dns_ps(script)
            flash("Group updated.", "success")
        elif action == "group-delete":
            sam = request.form.get("sam_account_name", "").strip()
            if not sam:
                raise RuntimeError("samAccountName is required.")
            run_dns_ps(f"Import-Module ActiveDirectory -ErrorAction Stop\nRemove-ADGroup -Identity {ps_quote(sam)} -Confirm:$false")
            flash("Group deleted.", "success")
        elif action == "group-add-member":
            sam = request.form.get("sam_account_name", "").strip()
            members = csv_items(request.form.get("members", ""))
            if not sam or not members:
                raise RuntimeError("Group and at least one member are required.")
            run_dns_ps(build_ad_group_membership_script(sam, "add", members))
            flash("Group members added.", "success")
        elif action == "group-remove-member":
            sam = request.form.get("sam_account_name", "").strip()
            members = csv_items(request.form.get("members", ""))
            if not sam or not members:
                raise RuntimeError("Group and at least one member are required.")
            run_dns_ps(build_ad_group_membership_script(sam, "remove", members))
            flash("Group members removed.", "success")
        elif action == "user-add-group":
            sam = request.form.get("sam_account_name", "").strip()
            groups = csv_items(request.form.get("members", ""))
            if not sam or not groups:
                raise RuntimeError("User and at least one group are required.")
            run_dns_ps(build_ad_user_group_membership_script(sam, "add", groups))
            flash("User added to groups.", "success")
        elif action == "user-remove-group":
            sam = request.form.get("sam_account_name", "").strip()
            groups = csv_items(request.form.get("members", ""))
            if not sam or not groups:
                raise RuntimeError("User and at least one group are required.")
            run_dns_ps(build_ad_user_group_membership_script(sam, "remove", groups))
            flash("User removed from groups.", "success")
        elif action == "attribute-update":
            kind = request.form.get("object_kind", "").strip().lower()
            dn = request.form.get("distinguished_name", "").strip()
            sam = request.form.get("sam_account_name", "").strip()
            attribute = request.form.get("attribute", "").strip()
            value = request.form.get("value", "")
            if not kind or not dn or not sam or not attribute:
                raise RuntimeError("Object, DN, and attribute are required.")
            script = build_ad_object_attribute_update_script(kind, dn, sam, attribute, value)
            run_dns_ps(script)
            flash("Attribute updated.", "success")
        else:
            raise RuntimeError("Unsupported identity action.")
        delete_dns_cache("ad_users")
        delete_dns_cache("ad_groups")
        delete_dns_cache("ad_user_detail")
        delete_dns_cache("ad_group_detail")
    except Exception as e:
        flash(str(e), "error")

    return redirect(return_to)


@app.route("/records/add", methods=["GET", "POST"])
@login_required
@admin_required
def add_record():
    if request.method == "POST":
        record_type = request.form["type"].upper().strip()
        zone_name = request.form.get("zone", DNS_ZONE).strip().rstrip(".") or DNS_ZONE
        name = request.form["name"].strip().rstrip(".")
        target = request.form.get("value", "").strip()
        ttl = int(request.form.get("ttl", "3600") or "3600")
        preference = request.form.get("preference", "").strip()
        priority = request.form.get("priority", "").strip()
        weight = request.form.get("weight", "").strip()
        port = request.form.get("port", "").strip()
        script = build_record_add_script(
            zone_name,
            record_type,
            name,
            target,
            ttl,
            preference=preference,
            priority=priority,
            weight=weight,
            port=port,
        )

        try:
            run_dns_ps(script)
            invalidate_dns_tree_cache()
            flash(f"Added {record_type} record: {name}.{zone_name}", "success")
            return redirect(safe_return_to(url_for("records", zone=zone_name, name=name, type=record_type)))
        except Exception as e:
            flash(str(e), "error")

    user = session["user"]
    can_manage = ALLOWED_ADMIN_GROUP in user.get("groups", [])
    return render_template("add.html", zone=DNS_ZONE, can_manage=can_manage, user=user, server=DNS_SERVER)


@app.route("/records/edit", methods=["POST"])
@login_required
@admin_required
def edit_record():
    original_zone = request.form.get("original_zone", DNS_ZONE).strip().rstrip(".") or DNS_ZONE
    original_name = request.form.get("original_name", "").strip().rstrip(".")
    original_type = request.form.get("original_type", "").strip().upper()
    original_target = request.form.get("original_target", "").strip()
    zone_name = request.form.get("zone", original_zone).strip().rstrip(".") or original_zone
    name = request.form.get("name", original_name).strip().rstrip(".")
    record_type = request.form.get("type", original_type).strip().upper()
    target = request.form.get("value", original_target).strip()
    ttl = int(request.form.get("ttl", "3600") or "3600")
    preference = request.form.get("preference", "").strip()
    priority = request.form.get("priority", "").strip()
    weight = request.form.get("weight", "").strip()
    port = request.form.get("port", "").strip()

    protected_prefixes = ("_msdcs", "_sites", "_tcp", "_udp", "domaindnszones", "forestdnszones")
    if name.lower().startswith(protected_prefixes) or original_name.lower().startswith(protected_prefixes):
        flash("Refusing to edit AD/system DNS records.", "error")
        return redirect(safe_return_to(url_for("records", zone=zone_name, name=name, type=record_type)))

    script = build_record_edit_script(
        original_zone,
        original_name,
        original_type,
        original_target,
        zone_name,
        name,
        record_type,
        target,
        ttl,
        preference=preference,
        priority=priority,
        weight=weight,
        port=port,
    )
    try:
        run_dns_ps(script)
        invalidate_dns_tree_cache()
        flash(f"Updated {record_type} record: {name}.{zone_name}", "success")
    except Exception as e:
        flash(str(e), "error")
    return redirect(safe_return_to(url_for("records", zone=zone_name, name=name, type=record_type)))


@app.route("/records/delete", methods=["POST"])
@login_required
@admin_required
def delete_record():
    record_type = request.form["type"].upper().strip()
    zone_name = request.form.get("zone", DNS_ZONE).strip().rstrip(".") or DNS_ZONE
    name = request.form["name"].strip().rstrip(".")
    record_value = request.form.get("value", "").strip()
    server_arg = dns_server_arg()

    protected_prefixes = ("_msdcs", "_sites", "_tcp", "_udp", "domaindnszones", "forestdnszones")
    if name.lower().startswith(protected_prefixes):
        flash("Refusing to delete AD/system DNS records.", "error")
        return redirect(safe_return_to(url_for("records", zone=zone_name, name=name, type=record_type)))

    if record_value:
        record_data_arg = f" -RecordData {ps_quote(record_value)}"
    else:
        record_data_arg = ""

    script = f"""
    $record = Get-DnsServerResourceRecord {server_arg} -ZoneName {ps_quote(zone_name)} -Name {ps_quote(name)} -RRType {ps_quote(record_type)} -ErrorAction Stop
Remove-DnsServerResourceRecord {server_arg} -ZoneName {ps_quote(zone_name)} -Name {ps_quote(name)} -RRType {ps_quote(record_type)}{record_data_arg} -Force
"""
    try:
        run_dns_ps(script)
        invalidate_dns_tree_cache()
        flash(f"Deleted {record_type} record: {name}.{zone_name}", "success")
    except Exception as e:
        flash(str(e), "error")
    return redirect(safe_return_to(url_for("records", zone=zone_name, name=name, type=record_type)))


@app.route("/api/zone-records")
@login_required
def api_zone_records():
    zone_name = request.args.get("zone", DNS_ZONE).strip().rstrip(".") or DNS_ZONE
    record_type = request.args.get("type", "ALL").strip().upper()

    try:
        records = zone_record_preview(zone_name, record_type)
        return jsonify({"zone": zone_name, "type": record_type, "records": records})
    except Exception as e:
        return jsonify({"zone": zone_name, "type": record_type, "error": str(e), "records": []}), 200


@app.route("/api/zone-delegations")
@login_required
def api_zone_delegations():
    zone_name = request.args.get("zone", DNS_ZONE).strip().rstrip(".") or DNS_ZONE

    try:
        delegations = query_delegation_rows(zone_name)
        return jsonify({"zone": zone_name, "delegations": delegations})
    except Exception as e:
        return jsonify({"zone": zone_name, "error": str(e), "delegations": []}), 200


@app.route("/zones", methods=["GET", "POST"])
@login_required
@admin_required
def zones():
    server_arg = dns_server_arg()
    search = request.args.get("name", "").strip()

    if request.method == "POST":
        action = request.form.get("action", "").strip().lower()
        try:
            if action == "create":
                zone_type = request.form.get("zone_type", "primary").strip().lower()
                zone_name = request.form.get("zone_name", "").strip().rstrip(".")
                reverse_network = request.form.get("reverse_network", "").strip()
                zone_file = request.form.get("zone_file", "").strip()
                replication_scope = request.form.get("replication_scope", "Forest").strip() or "Forest"
                master_servers = ps_array_literal(csv_items(request.form.get("master_servers", "")))

                if not zone_name and not reverse_network:
                    raise RuntimeError("Zone name or reverse network ID is required.")

                if zone_type == "primary":
                    if reverse_network:
                        if zone_file:
                            script = f"Add-DnsServerPrimaryZone {server_arg} -NetworkID {ps_quote(reverse_network)} -ZoneFile {ps_quote(zone_file)} -PassThru"
                        else:
                            script = f"Add-DnsServerPrimaryZone {server_arg} -NetworkID {ps_quote(reverse_network)} -ReplicationScope {ps_quote(replication_scope)} -PassThru"
                    else:
                        if zone_file:
                            script = f"Add-DnsServerPrimaryZone {server_arg} -Name {ps_quote(zone_name)} -ZoneFile {ps_quote(zone_file)} -PassThru"
                        else:
                            script = f"Add-DnsServerPrimaryZone {server_arg} -Name {ps_quote(zone_name)} -ReplicationScope {ps_quote(replication_scope)} -PassThru"
                elif zone_type == "secondary":
                    if reverse_network:
                        if zone_file:
                            script = f"Add-DnsServerSecondaryZone {server_arg} -NetworkID {ps_quote(reverse_network)} -ZoneFile {ps_quote(zone_file)} -MasterServers {master_servers} -PassThru"
                        else:
                            script = f"Add-DnsServerSecondaryZone {server_arg} -NetworkID {ps_quote(reverse_network)} -MasterServers {master_servers} -PassThru"
                    else:
                        if zone_file:
                            script = f"Add-DnsServerSecondaryZone {server_arg} -Name {ps_quote(zone_name)} -ZoneFile {ps_quote(zone_file)} -MasterServers {master_servers} -PassThru"
                        else:
                            script = f"Add-DnsServerSecondaryZone {server_arg} -Name {ps_quote(zone_name)} -MasterServers {master_servers} -PassThru"
                elif zone_type == "stub":
                    if reverse_network:
                        if zone_file:
                            script = f"Add-DnsServerStubZone {server_arg} -NetworkID {ps_quote(reverse_network)} -MasterServers {master_servers} -ZoneFile {ps_quote(zone_file)} -PassThru"
                        else:
                            script = f"Add-DnsServerStubZone {server_arg} -NetworkID {ps_quote(reverse_network)} -MasterServers {master_servers} -PassThru"
                    else:
                        if zone_file:
                            script = f"Add-DnsServerStubZone {server_arg} -Name {ps_quote(zone_name)} -MasterServers {master_servers} -ZoneFile {ps_quote(zone_file)} -PassThru"
                        else:
                            script = f"Add-DnsServerStubZone {server_arg} -Name {ps_quote(zone_name)} -MasterServers {master_servers} -PassThru"
                else:
                    raise RuntimeError("Unsupported zone type.")

                run_dns_ps(script)
                invalidate_dns_tree_cache()
                flash("Zone created successfully.", "success")
            elif action == "delete":
                zone_name = request.form.get("zone_name", "").strip().rstrip(".")
                if not zone_name:
                    raise RuntimeError("Zone name is required.")
                protected_prefixes = ("_msdcs", "_sites", "_tcp", "_udp", "domaindnszones", "forestdnszones")
                if zone_name.lower().startswith(protected_prefixes):
                    raise RuntimeError("Refusing to delete AD/system DNS zones.")
                run_dns_ps(f"Remove-DnsServerZone {server_arg} -Name {ps_quote(zone_name)} -Force")
                invalidate_dns_tree_cache()
                flash(f"Deleted zone: {zone_name}", "success")
            elif action == "aging":
                zone_name = request.form.get("zone_name", "").strip().rstrip(".")
                aging_enabled = request.form.get("aging_enabled") == "on"
                if not zone_name:
                    raise RuntimeError("Zone name is required.")
                run_dns_ps(
                    f"Set-DnsServerZoneAging {server_arg} -Name {ps_quote(zone_name)} -Aging ${'True' if aging_enabled else 'False'} -PassThru"
                )
                invalidate_dns_tree_cache()
                flash(f"Aging updated for zone: {zone_name}", "success")
            else:
                raise RuntimeError("Unsupported zone action.")
        except Exception as e:
            flash(str(e), "error")
        if request.method == "POST":
            return redirect(safe_return_to(url_for("index") + "#forward-zones"))

    zone_rows = []
    try:
        zone_rows = query_zone_rows(search)
    except Exception as e:
        flash(str(e), "error")

    user = session["user"]
    can_manage = ALLOWED_ADMIN_GROUP in user.get("groups", [])
    return render_template(
        "zones.html",
        zone_rows=zone_rows,
        zone_count=len(zone_rows),
        search=search,
        can_manage=can_manage,
        user=user,
        server=DNS_SERVER,
        zone=DNS_ZONE,
    )


@app.route("/forwarders", methods=["GET", "POST"])
@login_required
@admin_required
def forwarders():
    server_arg = dns_server_arg()
    if request.method == "POST":
        action = request.form.get("action", "").strip().lower()
        addresses = ps_array_literal(csv_items(request.form.get("addresses", "")))
        try:
            if action == "add":
                run_dns_ps(f"Add-DnsServerForwarder {server_arg} -IPAddress {addresses} -PassThru")
                invalidate_dns_tree_cache()
                flash("Forwarder added.", "success")
            elif action == "remove":
                run_dns_ps(f"Remove-DnsServerForwarder {server_arg} -IPAddress {addresses} -PassThru")
                invalidate_dns_tree_cache()
                flash("Forwarder removed.", "success")
            else:
                raise RuntimeError("Unsupported forwarder action.")
        except Exception as e:
            flash(str(e), "error")
        return redirect(safe_return_to(url_for("index") + "#forwarders"))

    forwarder_rows = []
    try:
        forwarder_rows = query_forwarder_rows()
    except Exception as e:
        flash(str(e), "error")

    user = session["user"]
    can_manage = ALLOWED_ADMIN_GROUP in user.get("groups", [])
    return render_template(
        "forwarders.html",
        forwarder_rows=forwarder_rows,
        can_manage=can_manage,
        user=user,
        server=DNS_SERVER,
        zone=DNS_ZONE,
    )


@app.route("/delegations", methods=["GET", "POST"])
@login_required
@admin_required
def delegations():
    server_arg = dns_server_arg()
    zone_name = request.args.get("zone", DNS_ZONE).strip().rstrip(".")

    if request.method == "POST":
        action = request.form.get("action", "").strip().lower()
        try:
            if action == "add":
                parent_zone = request.form.get("parent_zone", zone_name).strip().rstrip(".")
                child_zone = request.form.get("child_zone", "").strip().rstrip(".")
                name_server = request.form.get("name_server", "").strip().rstrip(".")
                ip_address = request.form.get("ip_address", "").strip()
                if not parent_zone or not child_zone or not name_server or not ip_address:
                    raise RuntimeError("Parent zone, child zone, name server, and IP address are required.")
                run_dns_ps(
                    f"Add-DnsServerZoneDelegation {server_arg} -Name {ps_quote(parent_zone)} -ChildZoneName {ps_quote(child_zone)} -NameServer {ps_quote(name_server)} -IPAddress {ps_quote(ip_address)} -PassThru"
                )
                invalidate_dns_tree_cache()
                flash("Delegation added.", "success")
            elif action == "remove":
                parent_zone = request.form.get("parent_zone", zone_name).strip().rstrip(".")
                child_zone = request.form.get("child_zone", "").strip().rstrip(".")
                if not parent_zone or not child_zone:
                    raise RuntimeError("Parent zone and child zone are required.")
                run_dns_ps(
                    f"Remove-DnsServerZoneDelegation {server_arg} -Name {ps_quote(parent_zone)} -ChildZoneName {ps_quote(child_zone)} -Force"
                )
                invalidate_dns_tree_cache()
                flash("Delegation removed.", "success")
            else:
                raise RuntimeError("Unsupported delegation action.")
        except Exception as e:
            flash(str(e), "error")
        return redirect(safe_return_to(url_for("index") + "#delegations"))

    delegation_rows = []
    try:
        delegation_rows = query_delegation_rows(zone_name)
    except Exception as e:
        flash(str(e), "error")

    user = session["user"]
    can_manage = ALLOWED_ADMIN_GROUP in user.get("groups", [])
    return render_template(
        "delegations.html",
        delegation_rows=delegation_rows,
        can_manage=can_manage,
        user=user,
        server=DNS_SERVER,
        zone=zone_name,
    )


if __name__ == "__main__":
    if FLASK_DEBUG:
        app.run(host=HOST, port=PORT, debug=True)
    else:
        try:
            from waitress import serve

            serve(app, host=HOST, port=PORT)
        except ImportError:
            app.run(host=HOST, port=PORT, debug=False)
