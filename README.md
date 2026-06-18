# AD DNS Manager

Flask web UI for managing Microsoft AD DNS records using SSO and PowerShell DNS cmdlets.

## Model

- AD DNS remains authoritative for `local.ndhansen.com`.
- Flask authenticates users with OIDC.
- Authorized users can manage zones, forwarders, delegations, reverse lookup zones, and DNS records.
- PowerShell runs `DnsServer` cmdlets against your DC.

## Install on Windows Server or a Windows management VM

```powershell
Install-WindowsFeature RSAT-DNS-Server
winget install Python.Python.3.12
winget install Microsoft.PowerShell
```

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
notepad .env
python app.py
```

If port `8080` is already in use, set `PORT` before starting the app:

```powershell
$env:PORT = 8081
python app.py
```

For release or production-like runs, set `FLASK_DEBUG=false` and use a real `FLASK_SECRET_KEY`. The app will start with `waitress` automatically when debug mode is off.

## Required permissions

The DNS-changing identity should be a dedicated service account with only the permissions it needs for the target zone.

- If you run the app directly on Windows in `DNS_EXECUTION_MODE=local`, run the Flask process itself as that service account.
- If you run the app on Linux or another host in `DNS_EXECUTION_MODE=winrm`, set `WINRM_USERNAME` and either `WINRM_PASSWORD` or `WINRM_PASSWORD_FILE` so the DNS commands execute through that service account over WinRM. For a quick test, that can be your Domain Admin account.

Do not run the app as Domain Admin if you can avoid it.

## Run on Linux and manage AD DNS remotely

When this app runs on Linux, `DnsServer` cmdlets must execute on a Windows host. Use `DNS_EXECUTION_MODE=winrm` so the app runs DNS commands via PowerShell remoting.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Set at least these variables in `.env`:

```dotenv
DNS_ZONE=example.com
DNS_SERVER=dc01.example.com
DNS_EXECUTION_MODE=winrm
WINRM_AUTH=Kerberos
WINRM_USE_SSL=false
PWSH_REMOTE_TRANSPORT=wsman
WINRM_USERNAME=dns-web-svc
WINRM_PASSWORD_FILE=/run/secrets/winrm-password
# Optional helper if your account should be expanded to DOMAIN\\user.
# Use the NetBIOS domain name here if needed.
WINRM_DOMAIN=CONTOSO

# If behind reverse proxy (nginx/traefik), trust one proxy hop.
TRUST_PROXY=1
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_SAMESITE=Lax

# Explicit callback URL is the most reliable SSO setting behind proxies.
OIDC_REDIRECT_URI=https://dns-manager.example.com/auth/callback
```

If you see `no supported WSMan client library was found` on Linux:

1) Keep `PWSH_REMOTE_TRANSPORT=wsman` and install WSMan support for PowerShell on Linux, or
2) Switch to SSH transport.

Use `ssh_exec` when your Windows host only has Windows PowerShell (no PowerShell 7 `-sshs` subsystem):

```dotenv
DNS_EXECUTION_MODE=winrm
PWSH_REMOTE_TRANSPORT=ssh_exec
WINRM_USERNAME=dns-web-svc
PWSH_SSH_PORT=22
PWSH_SSH_KEY_FILE=/home/dns-web/.ssh/id_ed25519
```

Use `ssh` only when the Windows host is configured with a PowerShell 7 SSH remoting subsystem:

```dotenv
DNS_EXECUTION_MODE=winrm
PWSH_REMOTE_TRANSPORT=ssh
WINRM_USERNAME=dns-web-svc
PWSH_SSH_PORT=22
PWSH_SSH_KEY_FILE=/home/dns-web/.ssh/id_ed25519
```

For all SSH-based modes, the Windows host must have OpenSSH Server enabled.

Start the app:

```bash
python app.py
```

## SSO notes

Your identity provider should send group names in a `groups` claim. Set `ALLOWED_ADMIN_GROUP` to the group allowed to manage records.

If the callback fails with `invalid_client`, set `OIDC_TOKEN_ENDPOINT_AUTH_METHOD` to the method your provider expects, usually `client_secret_post` or `client_secret_basic`.

### Common SSO failure checks

- `MismatchingStateError`: make sure login and callback use the same hostname and scheme.
- `MismatchingStateError` behind proxy: set `TRUST_PROXY=1` and configure your proxy to send `X-Forwarded-Proto` and `X-Forwarded-Host`.
- Callback mismatch at IdP: set `OIDC_REDIRECT_URI` explicitly and register that exact URI with your identity provider.
- Cookies dropped on HTTPS: set `SESSION_COOKIE_SECURE=true` when serving over HTTPS.
- Group-based authorization fails: verify your IdP sends `groups` in the ID token or userinfo response.

## Safety notes

This starter app refuses to delete obvious AD/system record prefixes. Expand this before production use.
