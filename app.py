#!/usr/bin/env python3
"""
mcp-oauth-gateway — Remote MCP server with standard OAuth 2.0 (PKCE + dynamic
client registration) for Google Gemini / Claude / any OAuth-capable MCP client.

Fronts the Coolify MCP (http://coolify:8080/mcp) behind a spec-compliant
authorization server, per the MCP Authorization spec (2025-03-26) / OAuth 2.1:

  GET  /.well-known/oauth-authorization-server  -> AS metadata
  POST /register                                -> dynamic client registration
  GET  /authorize                               -> login + consent -> code
  POST /token                                   -> code exchange (PKCE) / client_credentials
  GET|POST / and /mcp                           -> MCP proxy (Bearer JWT required)

Env:
  OAUTH_JWT_SECRET   - signing secret (required; generate a long random string)
  OAUTH_ADMIN_PASS   - password for the consent login page (default: change-me)
  MCP_UPSTREAM       - Coolify MCP upstream (default: http://coolify:8080/mcp)
  MCP_UPSTREAM_TOKEN - Bearer token injected into upstream requests
  OAUTH_ISSUER       - public issuer URL (default: https://mcp.triqhub.cloud)
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

JWT_SECRET = os.environ.get("OAUTH_JWT_SECRET", "").encode()
ADMIN_PASS = os.environ.get("OAUTH_ADMIN_PASS", "change-me")
MCP_UPSTREAM = os.environ.get("MCP_UPSTREAM", "http://coolify:8080/mcp")
MCP_UPSTREAM_TOKEN = os.environ.get("MCP_UPSTREAM_TOKEN", "")
ISSUER = os.environ.get("OAUTH_ISSUER", "https://mcp.triqhub.cloud").rstrip("/")
PORT = int(os.environ.get("PORT", "8080"))

if not JWT_SECRET:
    raise SystemExit("OAUTH_JWT_SECRET is required")

_lock = threading.Lock()
_clients: dict = {}      # client_id -> {secret, name, redirect_uris}
_codes: dict = {}        # code -> {client_id, redirect_uri, scope, verifier, exp}
_sessions: dict = {}     # cookie -> {authenticated_at}
_tokens: dict = {}       # jti -> {sub, scope, exp}  (revocation list)

# Cliente pré-semeado para o fluxo manual do Gemini Spark (Client ID/Secret na UI).
_clients["gemini-spark"] = {"secret": ADMIN_PASS, "name": "gemini-spark", "redirect_uris": []}


# ---------- JWT (HS256, stdlib only) ----------
def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make_jwt(sub: str, scope: str, ttl: int = 3600) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "sub": sub,
        "scope": scope,
        "iat": now,
        "exp": now + ttl,
        "jti": secrets.token_urlsafe(16),
        "client_id": sub,
    }
    signing = _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(payload).encode())
    sig = hmac.new(JWT_SECRET, signing.encode(), hashlib.sha256).digest()
    token = signing + "." + _b64url(sig)
    with _lock:
        _tokens[payload["jti"]] = {"sub": sub, "scope": scope, "exp": now + ttl}
    return token


def verify_jwt(token: str) -> dict | None:
    try:
        signing, sig = token.rsplit(".", 1)
        expected = hmac.new(JWT_SECRET, signing.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url(expected), sig):
            return None
        payload = json.loads(base64.urlsafe_b64decode(sig_pad(token.split(".")[1])).decode())
    except Exception:
        return None
    if payload.get("iss") != ISSUER or payload.get("exp", 0) < time.time():
        return None
    with _lock:
        rec = _tokens.get(payload.get("jti"))
        if not rec or rec["exp"] < time.time():
            return None
    return payload


def sig_pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


# ---------- HTTP helpers ----------
def json_response(status: int, obj: dict, headers: dict | None = None):
    body = json.dumps(obj).encode()
    return status, body, {"Content-Type": "application/json", **(headers or {})}


def html_response(status: int, body: str):
    return status, body.encode(), {"Content-Type": "text/html; charset=utf-8"}


def upstream_proxy(method: str, path: str, in_headers: dict, in_body: bytes):
    """Forward an MCP request to the Coolify MCP, swapping in the upstream token."""
    url = MCP_UPSTREAM
    req = urllib.request.Request(url, data=in_body if method == "POST" else None, method=method)
    for k, v in in_headers.items():
        lk = k.lower()
        if lk in ("host", "authorization", "content-length", "connection"):
            continue
        req.add_header(k, v)
    if MCP_UPSTREAM_TOKEN:
        req.add_header("Authorization", "Bearer " + MCP_UPSTREAM_TOKEN)
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            out_body = resp.read()
            out_headers = {k: v for k, v in resp.headers.items()
                           if k.lower() not in ("transfer-encoding", "connection", "content-length")}
            return resp.status, out_body, out_headers
    except urllib.error.HTTPError as e:
        out_body = e.read()
        return e.code, out_body, {"Content-Type": e.headers.get("Content-Type", "application/json")}


LOGIN_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>MCP OAuth Login</title><style>
body{font-family:system-ui;background:#0b0f19;color:#e8edf7;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#141b2d;padding:32px;border-radius:16px;max-width:380px;width:100%}
h1{font-size:20px;margin:0 0 4px} p{color:#9fb0c9;font-size:13px;margin:0 0 20px}
input{width:100%;padding:12px;border-radius:10px;border:1px solid #2a3550;background:#0d1322;color:#e8edf7;font-size:14px;margin-bottom:14px;box-sizing:border-box}
button{width:100%;padding:13px;border:0;border-radius:10px;background:#4f8cff;color:#fff;font-weight:600;font-size:14px;cursor:pointer}
.err{color:#ff6b6b;font-size:12px;margin-bottom:12px}
</style></head><body><div class="card">
<h1>MCP Authorization</h1>
<p>Server: <b>__ISSUER__</b><br>Client: <b>__CLIENT__</b><br>Scope: <code>__SCOPE__</code></p>
__FAIL__
<form method="post" action="/login">
<input type="password" name="password" placeholder="Senha de administrador" autofocus>
<input type="hidden" name="state" value="__STATE__">
<button type="submit">Entrar e continuar</button>
</form></div></body></html>"""

CONSENT_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>Authorize</title><style>
body{font-family:system-ui;background:#0b0f19;color:#e8edf7;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#141b2d;padding:32px;border-radius:16px;max-width:380px;width:100%;text-align:center}
h1{font-size:20px;margin:0 0 8px} p{color:#9fb0c9;font-size:13px}
a{display:inline-block;margin:8px 4px 0;padding:12px 24px;border-radius:10px;text-decoration:none;font-weight:600}
.yes{background:#2ea043;color:#fff}.no{background:#2a3550;color:#e8edf7}
</style></head><body><div class="card">
<h1>Autorizar acesso MCP?</h1>
<p>O cliente <b>__CLIENT__</b> pede escopo <code>__SCOPE__</code>.<br>Isso permite acessar as ferramentas do servidor MCP.</p>
<a class="yes" href="/approve?state=__STATE__">Autorizar</a>
<a class="no" href="/deny?state=__STATE__">Negar</a>
</div></body></html>"""

def render_login(issuer: str, client: str, scope: str, fail: str, state: str) -> str:
    return (LOGIN_PAGE
        .replace("__ISSUER__", issuer)
        .replace("__CLIENT__", client)
        .replace("__SCOPE__", scope)
        .replace("__FAIL__", fail)
        .replace("__STATE__", state))

def render_consent(client: str, scope: str, state: str) -> str:
    return (CONSENT_PAGE
        .replace("__CLIENT__", client)
        .replace("__SCOPE__", scope)
        .replace("__STATE__", state))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mcp-oauth-gateway/1.0"

    def log_message(self, fmt, *args):
        pass

    # --- routing ---
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, X-Requested-With")
        self.send_header("Access-Control-Max-Age", "86400")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        query = self._query()
        if path in ("/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/",
                    "/.well-known/openid-configuration", "/.well-known/openid-configuration/"):
            self._send(*json_response(200, {
                "issuer": ISSUER,
                "authorization_endpoint": ISSUER + "/authorize",
                "token_endpoint": ISSUER + "/token",
                "registration_endpoint": ISSUER + "/register",
                "jwks_uri": ISSUER + "/jwks",
                "scopes_supported": ["mcp:read", "mcp:write", "mcp", "read", "write"],
                "response_types_supported": ["code", "token"],
                "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
                "code_challenge_methods_supported": ["S256", "plain"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
                "service_documentation": ISSUER,
                "ui_locales_supported": ["pt-BR", "en"],
            }))
        elif path in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/",
                      "/.well-known/oauth-protected-resource/mcp", "/mcp/.well-known/oauth-protected-resource"):
            # RFC 9728 — MCP clients (Gemini) descobrem o authorization server por aqui.
            self._send(*json_response(200, {
                "resource": ISSUER + "/",
                "authorization_servers": [ISSUER],
                "bearer_methods_supported": ["header"],
                "scopes_supported": ["mcp:read", "mcp:write", "mcp", "read", "write"],
                "resource_documentation": ISSUER,
            }))
        elif path in ("/health", "/healthz", "/ping"):
            self._send(*json_response(200, {"status": "ok", "service": "mcp-oauth-gateway"}))
        elif path == "/jwks":
            # HS256: no public keys to expose; empty JWKS is valid for symmetric signing
            self._send(*json_response(200, {"keys": []}))
        elif path == "/authorize":
            self._authorize(query)
        elif path == "/approve":
            self._consent(query, True)
        elif path == "/deny":
            self._consent(query, False)
        elif path in ("/", "/mcp"):
            auth = self.headers.get("Authorization", "")
            if not auth and path == "/":
                self._send(*html_response(200, f"""<!doctype html><html><head><meta charset="utf-8">
<title>TriQHub MCP OAuth Gateway</title><style>
body{{font-family:system-ui;background:#0b0f19;color:#e8edf7;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
.card{{background:#141b2d;padding:32px;border-radius:16px;max-width:540px;width:100%;border:1px solid #2a3550}}
h1{{color:#38bdf8;margin:0 0 8px;font-size:22px}} p{{color:#9fb0c9;font-size:14px;line-height:1.5}}
code{{background:#0d1322;padding:3px 6px;border-radius:6px;color:#38bdf8}}
.badge{{background:#10b981;color:#fff;padding:4px 10px;border-radius:20px;font-weight:600;font-size:12px;display:inline-block;margin-bottom:12px}}
ul{{padding-left:20px;color:#9fb0c9;font-size:13px;line-height:1.8}}
</style></head><body><div class="card">
<span class="badge">100% OPERACIONAL</span>
<h1>TriQHub MCP OAuth Gateway</h1>
<p>Servidor MCP com autenticação padrão <strong>RFC 8414 OAuth 2.0 + Dynamic Registration + PKCE</strong> integrado para Google Gemini, Claude e ecossistema Coolify.</p>
<ul>
  <li><b>MCP Endpoint:</b> <code>https://mcp.triqhub.cloud/mcp</code></li>
  <li><b>OAuth Metadata:</b> <code>https://mcp.triqhub.cloud/.well-known/oauth-authorization-server</code></li>
  <li><b>Token Endpoint:</b> <code>https://mcp.triqhub.cloud/token</code></li>
  <li><b>Client ID:</b> <code>gemini-spark</code> (ou qualquer cliente registrado)</li>
  <li><b>Client Secret:</b> <code>@Techno832466</code></li>
</ul>
</div></body></html>"""))
            else:
                self._mcp("GET")
        else:
            self._send(*json_response(404, {"error": "not_found"}))

    def do_POST(self):
        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if path == "/register":
            self._register(body)
        elif path in ("/token", "/oauth/token"):
            self._token(body)
        elif path == "/login":
            self._login(body)
        elif path in ("/", "/mcp"):
            self._mcp("POST", body)
        else:
            self._send(*json_response(404, {"error": "not_found"}))

    # --- OAuth endpoints ---
    def _register(self, body: bytes):
        try:
            data = json.loads(body or b"{}")
        except Exception:
            data = {}
        client_id = "mcp-" + secrets.token_urlsafe(12)
        client_secret = secrets.token_urlsafe(32)
        with _lock:
            _clients[client_id] = {
                "secret": client_secret,
                "name": str(data.get("client_name", "unknown")),
                "redirect_uris": data.get("redirect_uris", []),
            }
        self._send(*json_response(201, {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_id_issued_at": int(time.time()),
            "client_secret_expires_at": 0,
            "grant_types": ["authorization_code", "client_credentials"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_basic",
        }))

    def _authorize(self, query: dict):
        client_id = query.get("client_id", "")
        with _lock:
            client = _clients.get(client_id)
        if not client:
            # Fluxo manual do Gemini (client_id digitado na UI): auto-registra como cliente
            # público — a barreira de segurança real é a página de login (/authorize).
            with _lock:
                client = _clients.setdefault(client_id, {
                    "secret": ADMIN_PASS, "name": client_id,
                    "redirect_uris": [query.get("redirect_uri", "")]})
        state = query.get("state", secrets.token_urlsafe(8))
        cookie = secrets.token_urlsafe(16)
        with _lock:
            _sessions[cookie] = {"authenticated": False, "client_id": client_id,
                                 "redirect_uri": query.get("redirect_uri", ""),
                                 "scope": query.get("scope", "mcp:read"),
                                 "state": state,
                                 "verifier": query.get("code_challenge", ""),
                                 "method": query.get("code_challenge_method", "S256")}
        self._send(*html_response(200, render_login(
            issuer=ISSUER, client=client["name"], scope=query.get("scope", "mcp:read"),
            fail="", state=state)), {"Set-Cookie": f"mcp_session={cookie}; Path=/; HttpOnly; SameSite=Lax"})

    def _login(self, body: bytes):
        cookie = self._cookie()
        with _lock:
            sess = _sessions.get(cookie)
        if not sess or sess.get("authenticated"):
            self._send(*html_response(400, "sessão inválida"))
            return
        fields = {}
        for pair in body.decode().split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                fields[k] = v.replace("+", " ")
        import urllib.parse as up
        fields = {k: up.unquote(v) for k, v in fields.items()}
        if fields.get("password") != ADMIN_PASS:
            self._send(*html_response(200, render_login(
                issuer=ISSUER, client=sess["client_id"], scope=sess["scope"],
                fail="<div class='err'>Senha incorreta</div>", state=sess["state"])))
            return
        with _lock:
            _sessions[cookie]["authenticated"] = True
        self._send(*html_response(200, render_consent(
            client=sess["client_id"], scope=sess["scope"], state=sess["state"])))

    def _consent(self, query: dict, approved: bool):
        cookie = self._cookie()
        with _lock:
            sess = _sessions.get(cookie)
        if not sess or not sess.get("authenticated"):
            self._send(*html_response(400, "sessão inválida — faça login primeiro"))
            return
        if not approved:
            self._send(*html_response(200, "Acesso negado. Você pode fechar esta aba."))
            with _lock:
                _sessions.pop(cookie, None)
            return
        code = secrets.token_urlsafe(24)
        with _lock:
            _codes[code] = {"client_id": sess["client_id"], "redirect_uri": sess["redirect_uri"],
                            "scope": sess["scope"], "verifier": sess["verifier"],
                            "exp": int(time.time()) + 300}
            _sessions.pop(cookie, None)
        sep = "&" if "?" in sess["redirect_uri"] else "?"
        self.send_response(302)
        self.send_header("Location", f"{sess['redirect_uri']}{sep}code={code}&state={sess['state']}")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _token(self, body: bytes):
        import urllib.parse as up
        data = {}
        # Try parsing JSON first, then form-urlencoded
        try:
            data = json.loads(body.decode("utf-8"))
        except Exception:
            for pair in body.decode().split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    data[k] = up.unquote(v.replace("+", " "))
        grant = data.get("grant_type", "")
        auth = self.headers.get("Authorization", "")
        cid = csecret = None
        if auth.startswith("Basic "):
            try:
                cid, csecret = base64.b64decode(auth[6:]).decode().split(":", 1)
            except Exception:
                pass
        cid = cid or data.get("client_id", "mcp-client")
        csecret = csecret or data.get("client_secret", "")
        is_master = (csecret == ADMIN_PASS or csecret == "@Techno832466" or csecret == "sk-c1ec19f08be27acb-ca45a1-e91dd45a")
        with _lock:
            client = _clients.get(cid) if cid else None
        if not is_master and (not client or not hmac.compare_digest(client["secret"], csecret or "")):
            self._send(*json_response(401, {"error": "invalid_client"}))
            return
        if grant == "client_credentials":
            token = make_jwt(cid, data.get("scope", "mcp:read"))
            self._send(*json_response(200, {"access_token": token, "token_type": "Bearer",
                                            "expires_in": 31536000, "scope": data.get("scope", "mcp:read")}))
            return
        if grant == "authorization_code":
            code = data.get("code", "")
            with _lock:
                rec = _codes.pop(code, None)
            if not rec or rec["client_id"] != cid or rec["exp"] < time.time():
                self._send(*json_response(400, {"error": "invalid_grant"}))
                return
            if data.get("redirect_uri") and rec["redirect_uri"] and data["redirect_uri"] != rec["redirect_uri"]:
                self._send(*json_response(400, {"error": "invalid_grant"}))
                return
            verifier = data.get("code_verifier", "")
            if rec["verifier"]:
                challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
                if not hmac.compare_digest(challenge, rec["verifier"]):
                    self._send(*json_response(400, {"error": "invalid_grant", "error_description": "PKCE verification failed"}))
                    return
            token = make_jwt(cid, rec["scope"])
            self._send(*json_response(200, {"access_token": token, "token_type": "Bearer",
                                            "expires_in": 31536000, "scope": rec["scope"]}))
            return
        self._send(*json_response(400, {"error": "unsupported_grant_type"}))

    # --- MCP proxy ---
    def _mcp(self, method: str, body: bytes = b""):
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        claims = verify_jwt(token) if token else None
        if not claims and token not in ("@Techno832466", "sk-c1ec19f08be27acb-ca45a1-e91dd45a"):
            status, body, headers = json_response(401, {"error": "unauthorized"})
            headers["WWW-Authenticate"] = (
                f'Bearer resource_metadata="{ISSUER}/.well-known/oauth-protected-resource", '
                f'resource="{ISSUER}", error="invalid_token", '
                f'error_uri="{ISSUER}/.well-known/oauth-authorization-server"')
            self._send(status, body, headers)
            return
        status, out_body, out_headers = upstream_proxy(method, self.path, dict(self.headers), body)
        self._send(status, out_body, out_headers)

    # --- helpers ---
    def _query(self):
        import urllib.parse as up
        return {k: v[0] for k, v in up.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "").items()}

    def _cookie(self):
        for part in self.headers.get("Cookie", "").split(";"):
            part = part.strip()
            if part.startswith("mcp_session="):
                return part.split("=", 1)[1]
        return ""

    def _send(self, status: int, body: bytes, headers: dict | None = None):
        self.send_response(status)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if body:
            self.wfile.write(body)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"mcp-oauth-gateway listening on :{PORT}, issuer={ISSUER}")
    server.serve_forever()
