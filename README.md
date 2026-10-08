# mcp-oauth-gateway

Remote MCP server with **standard OAuth 2.0** (PKCE + dynamic client
registration) that fronts the Coolify MCP — the auth method Google Gemini,
Claude and other OAuth-capable MCP clients require for remote MCP servers.

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/oauth-authorization-server` | Authorization server metadata (RFC 8414) |
| `POST /register` | Dynamic client registration (RFC 7591) |
| `GET /authorize` | Login (admin password) + consent -> authorization code |
| `POST /token` | Code exchange with PKCE (S256) or client_credentials |
| `GET/POST /` and `/mcp` | MCP proxy — requires `Authorization: Bearer <jwt>` |

## Env

- `OAUTH_JWT_SECRET` — HS256 signing secret (**required**, generate with `openssl rand -hex 32`)
- `OAUTH_ADMIN_PASS` — password for the consent login page
- `MCP_UPSTREAM` — Coolify MCP URL (default `http://coolify:8080/mcp`)
- `MCP_UPSTREAM_TOKEN` — Bearer token injected into upstream requests
- `OAUTH_ISSUER` — public issuer URL (default `https://mcp.triqhub.cloud`)

## Flow (what Gemini does)

1. `GET /.well-known/oauth-authorization-server` on the MCP host
2. `POST /register` -> `client_id` / `client_secret`
3. `GET /authorize?...&code_challenge=...&code_challenge_method=S256` -> login -> consent -> `code`
4. `POST /token` (PKCE verifier) -> `access_token`
5. MCP calls with `Authorization: Bearer <access_token>`

HS256 is used (symmetric) — tokens are validated locally, no JWKS needed.
