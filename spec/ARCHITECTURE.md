# Graylog OAuth2 Auth Proxy — Architecture

> A purpose-built Go reverse proxy that integrates Graylog OSS with Microsoft Entra ID via OIDC,
> featuring automatic user provisioning, App Role–based access control, and native SSE streaming
> support for the Graylog 7.x MCP API.

---

## Problem Statement

The standard `oauth2proxy` + Graylog Trusted Header Authentication setup requires administrators to
manually create users in Graylog before they can log in. This proxy eliminates that requirement by:

- Automatically creating Graylog users on first login
- Synchronising Entra ID App Roles to Graylog roles on every login
- Supporting long-lived SSE connections required by the Graylog 7.x MCP endpoint
- Maintaining full HTTPS between all internal components

---

## Architecture Overview

```
Internet
   │
   │  HTTPS :443 (public cert / Let's Encrypt)
   ▼
┌─────────────────────────────┐
│        Traefik Ingress       │   TLS termination, routing
│  Router → /api/mcp/* (SSE)  │
│  Router → /*  (web + api)   │
└──────────────┬──────────────┘
               │ HTTPS (internal TLS / internal CA)
               ▼
┌─────────────────────────────────────────────────┐
│           Custom Go Auth Proxy                   │
│                                                  │
│  ┌─────────────┐   ┌──────────────────────────┐ │
│  │ OIDC Handler│   │     JWT Validator         │ │──── HTTPS ──► Microsoft
│  │ PKCE + state│   │  JWKS sig · aud · iss     │ │             Entra ID
│  └─────────────┘   └──────────────────────────┘ │
│                                                  │
│  ┌─────────────────────────────────────────────┐ │
│  │              Role Mapper                     │ │
│  │  Entra App Role  →  Graylog Role             │ │
│  │  graylog-admin   →  Admin                    │ │
│  │  graylog-analyst →  Analyst (custom)         │ │
│  │  graylog-reader  →  Reader (default)         │ │
│  └─────────────────────────────────────────────┘ │
│                                                  │
│  ┌─────────────────────────────────────────────┐ │
│  │           Graylog Provisioner                │ │
│  │  GET /users/{username}                       │ │──── HTTPS ──► Graylog
│  │  POST /users  (create if missing)            │ │             REST API
│  │  PUT  /users/{username}/roles  (sync always) │ │
│  └─────────────────────────────────────────────┘ │
│                                                  │
│  ┌────────────────┐  ┌───────────────────────┐  │
│  │ Session Manager│  │   Header Injector      │  │
│  │ AES-GCM cookie │  │ Strip · Set            │  │
│  │ Stateless      │  │ X-Remote-User: <upn>   │  │
│  └────────────────┘  └───────────────────────┘  │
│                                                  │
│  ┌─────────────────────────────────────────────┐ │
│  │           Reverse Proxy                      │ │
│  │  httputil.ReverseProxy  →  Web UI traffic    │ │──── HTTPS ──► Graylog
│  │  io.Copy SSE stream     →  MCP /api/mcp/sse  │ │             Web + MCP
│  └─────────────────────────────────────────────┘ │
│                                                  │
│  Prometheus /metrics · /healthz · /readyz        │
│  Structured JSON logging (log/slog)              │
└─────────────────────────────────────────────────┘

                              ┌──────────────────────────┐
                              │       Graylog 7.x         │
                              │  Web UI (Trusted Header)  │
                              │  REST API (provisioning)  │
                              │  MCP Endpoint (SSE 7.x)  │
                              │  MongoDB + OpenSearch     │
                              └──────────────────────────┘
```

> See `architecture.drawio` for the full diagram (open with [draw.io](https://app.diagrams.net)).

---

## Component Breakdown

### Traefik Ingress

- Terminates public TLS (Let's Encrypt or corporate cert)
- Re-encrypts to the proxy over internal TLS (internal CA or self-signed with SANs)
- Routes all traffic to the auth proxy — Graylog is **not** directly reachable
- Special routing rule for `/api/mcp/` preserves SSE connection headers (`Connection`, `Transfer-Encoding`)

### Custom Go Auth Proxy

| Module | Responsibility |
|---|---|
| **OIDC Handler** | Redirects to Entra ID, handles callback, validates ID token with PKCE + state + nonce |
| **JWT Validator** | Verifies token signature via JWKS, validates `aud`, `iss`, `exp` claims |
| **Role Mapper** | Translates `roles` claim from JWT into Graylog role names via config map |
| **Graylog Provisioner** | Creates missing users, syncs roles on every login via Graylog REST API |
| **Session Manager** | Issues signed + encrypted session cookie (AES-GCM); stateless, no Redis |
| **Header Injector** | Strips any incoming `X-Remote-User` header, injects validated username |
| **Reverse Proxy** | Standard `httputil.ReverseProxy` for web traffic; `io.Copy` for SSE streams |

### Microsoft Entra ID

- **App Roles** (preferred over groups): defined in the App Registration, always present in JWT
- Roles appear in the `roles` claim in the ID token — no Graph API calls needed
- JWKS endpoint cached with automatic refresh on key rotation

### Graylog 7.x

- **Trusted Header Authentication** plugin enabled — reads `X-Remote-User`
- **Service account** with `User Manager` role used by the proxy for provisioning
- MCP endpoint (`/api/mcp/sse`) exposed via the proxy for AI tool integration
- Graylog is network-isolated: only reachable from the proxy container/pod

---

## Authentication & Authorisation Flow

```
1.  User navigates to https://graylog.company.com
2.  Proxy checks session cookie → not found
3.  Proxy redirects to Entra ID with PKCE challenge
4.  User authenticates with Entra ID (MFA etc.)
5.  Entra ID redirects back to /oauth/callback with auth code
6.  Proxy exchanges code for tokens (PKCE verifier)
7.  Proxy validates ID token (JWKS signature, aud, iss, exp)
8.  Proxy extracts preferred_username + roles from JWT
9.  Proxy calls Graylog API:
      a. Check if user exists
      b. Create user if missing (random unusable password)
      c. Sync Graylog roles from mapped Entra roles
10. Proxy issues encrypted session cookie
11. Proxy forwards request to Graylog with X-Remote-User header
12. Graylog creates session for the user (trusted header)
13. User sees Graylog UI

Subsequent requests:
  → Proxy validates session cookie
  → Injects X-Remote-User
  → Forwards to Graylog
  (No Entra round-trip until cookie expires)
```

---

## MCP / SSE Flow (Graylog 7.x)

```
1.  MCP client connects to https://graylog.company.com/api/mcp/sse
2.  Proxy validates session cookie (or API token header)
3.  Proxy opens upstream SSE connection to Graylog
4.  io.Copy pipes bytes bidirectionally without buffering
5.  Connection held open for duration of MCP session
6.  On client disconnect: upstream connection cancelled via context
```

**Why Go matters here:** Each SSE connection is a goroutine (~8KB stack). 1,000 concurrent
MCP sessions cost ~8MB RAM. Python async workers under similar load require significant tuning.

---

## Security Considerations

| Control | Implementation |
|---|---|
| TLS everywhere | Public → Traefik → Proxy → Graylog, all HTTPS |
| Header spoofing prevention | Proxy strips `X-Remote-User` before forwarding |
| Token validation | Full JWKS signature check, not just decode |
| PKCE | Prevents auth code interception attacks |
| Session security | AES-GCM encrypted + HMAC-SHA256 signed cookie |
| Network isolation | Graylog port not exposed outside cluster |
| Least privilege | Service account has only `User Manager` role |
| Secret management | All secrets via environment variables / k8s secrets |

---

## Configuration

All configuration is via environment variables:

```env
# Entra ID
ENTRA_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
ENTRA_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
ENTRA_CLIENT_SECRET=<secret>
ENTRA_REDIRECT_URL=https://graylog.company.com/oauth/callback

# Graylog
GRAYLOG_URL=https://graylog.internal:9000
GRAYLOG_SERVICE_TOKEN=<service-account-token>

# Proxy
LISTEN_ADDR=:8443
TLS_CERT_FILE=/certs/tls.crt
TLS_KEY_FILE=/certs/tls.key
SESSION_KEY=<32-byte-hex-secret>

# Role mapping (JSON)
ROLE_MAP='{"graylog-admin":"Admin","graylog-analyst":"Analyst","graylog-reader":"Reader"}'
DEFAULT_ROLE=Reader
```

---

## Project Structure

```
graylog-auth-proxy/
├── cmd/
│   └── proxy/
│       └── main.go              # Entry point, wiring
├── internal/
│   ├── config/
│   │   └── config.go            # Env-based config + validation
│   ├── oidc/
│   │   └── handler.go           # Entra ID OIDC flow (login, callback)
│   ├── jwt/
│   │   └── validator.go         # JWKS fetch, token validation
│   ├── roles/
│   │   └── mapper.go            # Entra App Role → Graylog role mapping
│   ├── graylog/
│   │   └── client.go            # Graylog REST API client
│   ├── provision/
│   │   └── provisioner.go       # User create / role sync logic
│   ├── session/
│   │   └── manager.go           # AES-GCM cookie session
│   ├── proxy/
│   │   ├── handler.go           # Auth middleware, header injection
│   │   └── sse.go               # SSE / MCP streaming proxy
│   └── observability/
│       └── metrics.go           # Prometheus metrics, health endpoints
├── test/
│   ├── unit/                    # Unit tests per package
│   ├── integration/             # Integration tests (testcontainers)
│   └── dast/                    # OWASP ZAP config + scripts
├── .github/
│   └── workflows/
│       ├── ci.yml               # PR pipeline: lint, SAST, SCA, test
│       └── cd.yml               # Main pipeline: build, DAST, push, deploy
├── Dockerfile
├── docker-compose.yml           # Local dev stack
├── go.mod
└── go.sum
```

---

## Dependencies

| Library | Purpose |
|---|---|
| `coreos/go-oidc/v3` | OIDC provider, token verification |
| `golang.org/x/oauth2` | OAuth2 client, PKCE |
| `gorilla/securecookie` | Encrypted + signed session cookie |
| `prometheus/client_golang` | Metrics |
| `stretchr/testify` | Unit test assertions |
| `testcontainers/testcontainers-go` | Integration test containers |

All stdlib: `net/http`, `net/http/httputil`, `log/slog`, `crypto/tls`

---

## Deployment

### Docker Compose (dev/staging)

```yaml
services:
  proxy:
    image: ghcr.io/org/graylog-auth-proxy:latest
    ports:
      - "8443:8443"
    environment:
      - ENTRA_TENANT_ID=${ENTRA_TENANT_ID}
      # ... other vars
    volumes:
      - ./certs:/certs:ro
    depends_on:
      - graylog
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: graylog-auth-proxy
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: proxy
          image: ghcr.io/org/graylog-auth-proxy:latest
          ports:
            - containerPort: 8443
          envFrom:
            - secretRef:
                name: graylog-proxy-secrets
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8443
              scheme: HTTPS
          readinessProbe:
            httpGet:
              path: /readyz
              port: 8443
              scheme: HTTPS
```
