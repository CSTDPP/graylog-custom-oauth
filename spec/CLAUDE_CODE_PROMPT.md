# Claude Code — Implementation Prompt
# Graylog OAuth2 Auth Proxy (Go)

Paste this entire file as your first message to Claude Code.

---

## Project Goal

Build a production-grade Go reverse proxy that:
- Authenticates users via Microsoft Entra ID (OIDC / OAuth2 with PKCE)
- Auto-provisions Graylog users on first login via the Graylog REST API
- Syncs Entra ID App Roles → Graylog roles on every login
- Proxies web UI traffic and long-lived SSE connections (Graylog 7.x MCP endpoint)
- Maintains HTTPS on all internal connections
- Ships with an enterprise-grade GitHub Actions CI/CD pipeline

Read `ARCHITECTURE.md` before starting — it contains the full component breakdown,
auth flow, configuration reference, and project structure you must follow.

---

## Implementation Requirements

### Language & Runtime
- Go 1.22+ (use the latest stable version)
- Modules-based project (`go.mod`)
- No `init()` functions — explicit dependency wiring in `main.go` only
- All errors handled explicitly — no `_` for error returns
- `context.Context` threaded through all I/O operations
- Structured logging with `log/slog` (JSON output in production)

### Project Layout
Follow the structure in `ARCHITECTURE.md` exactly:
```
cmd/proxy/main.go
internal/config/
internal/oidc/
internal/jwt/
internal/roles/
internal/graylog/
internal/provision/
internal/session/
internal/proxy/
internal/observability/
test/unit/
test/integration/
test/dast/
.github/workflows/
Dockerfile
docker-compose.yml
```

---

## Module-by-Module Specification

### 1. `internal/config/config.go`
- Load all config from environment variables
- Validate required fields at startup — fail fast with clear error message
- Parse `ROLE_MAP` as JSON into `map[string]string`
- Parse TLS cert/key paths, listen address, session key (must be 32 bytes hex)
- Expose a single `Config` struct — no global variables

### 2. `internal/oidc/handler.go`
- Use `github.com/coreos/go-oidc/v3/oidc` + `golang.org/x/oauth2`
- Implement `GET /oauth/login`: generate state + PKCE verifier, store in session, redirect to Entra
- Implement `GET /oauth/callback`: validate state, exchange code (with PKCE verifier), return validated token
- Implement `GET /oauth/logout`: clear session cookie, redirect to Entra ID logout endpoint
- Use `oauth2.S256ChallengeOption` for PKCE
- Nonce validation on ID token

### 3. `internal/jwt/validator.go`
- Use `go-oidc` provider's `Verifier` — do NOT manually decode without signature check
- Validate: signature (JWKS auto-refresh), `aud` matches client ID, `iss` matches tenant, `exp`
- Extract claims: `preferred_username` (or `upn`), `name`, `email`, `roles []string`
- JWKS keys cached; handle key rotation (retry once on signature failure)

### 4. `internal/roles/mapper.go`
- Accept `map[string]string` role map from config
- `Map(entryRoles []string) []string` — returns Graylog role names
- Returns `[]string{defaultRole}` if no roles match (never return empty)
- Unit-testable with no external dependencies

### 5. `internal/graylog/client.go`
- HTTP client with `tls.Config` (support custom CA cert via env var `GRAYLOG_CA_CERT_FILE`)
- Methods:
  - `GetUser(ctx, username) (*User, error)` — returns nil if 404
  - `CreateUser(ctx, user CreateUserRequest) error`
  - `UpdateUserRoles(ctx, username string, roles []string) error`
- Use `Authorization: Bearer <token>` header with Graylog service account token
- Retry logic: 3 attempts with exponential backoff on 5xx / network errors
- Request/response logging at DEBUG level

### 6. `internal/provision/provisioner.go`
- `Provision(ctx, userInfo UserInfo) error` — idempotent
- Algorithm:
  1. Call `GetUser` — if error return error
  2. If nil (not found): call `CreateUser` with a random 32-char password (never used, SSO only)
  3. Always call `UpdateUserRoles` (syncs on every login, not just creation)
- Log user creation and role changes at INFO level

### 7. `internal/session/manager.go`
- Use `github.com/gorilla/securecookie`
- Encrypt with AES-GCM + HMAC-SHA256 using `SESSION_KEY`
- Session struct: `{ Username, Email, Name, Roles, IssuedAt, ExpiresAt }`
- Cookie: `HttpOnly`, `Secure`, `SameSite=Lax`, configurable max-age (default 8h)
- `Get(r *http.Request) (*Session, error)` and `Set(w, session) error`
- `Clear(w)` for logout

### 8. `internal/proxy/handler.go`
- Main auth middleware:
  1. Check session cookie → valid: proceed; invalid/missing: redirect to `/oauth/login`
  2. Strip `X-Remote-User`, `X-Remote-Email`, `X-Remote-Name` from incoming request (prevent spoofing)
  3. Inject `X-Remote-User: <username>` from session
  4. Call provisioner (with timeout context, e.g. 5s) — fail closed on error
  5. Forward to reverse proxy

### 9. `internal/proxy/sse.go`
- Detect SSE requests: path prefix `/api/mcp/` or `Accept: text/event-stream`
- Disable response buffering: flush immediately, set `X-Accel-Buffering: no`
- Use `io.Copy` with context cancellation — clean up goroutine on disconnect
- Preserve headers: `Content-Type`, `Cache-Control`, `Connection`
- Add `Flush()` calls compatible with `http.Flusher`
- Timeout: no read timeout on SSE connections (use context cancellation instead)

### 10. `internal/observability/metrics.go`
- Prometheus metrics:
  - `proxy_requests_total{method, path_pattern, status}` (counter)
  - `proxy_request_duration_seconds{method, path_pattern}` (histogram)
  - `proxy_auth_operations_total{operation, result}` — login, logout, provision, error (counter)
  - `proxy_sse_connections_active` (gauge)
  - `graylog_api_requests_total{operation, status}` (counter)
- `GET /metrics` — Prometheus scrape endpoint (not proxied to Graylog)
- `GET /healthz` — liveness: returns 200 if server is running
- `GET /readyz` — readiness: checks Graylog reachability + Entra JWKS reachability

### 11. `cmd/proxy/main.go`
- Wire all components
- Graceful shutdown: `os.Signal` → `context.WithTimeout(15s)` → `server.Shutdown()`
- Log startup config (redact secrets) at INFO level
- TLS server: load cert from file, `tls.Config` with `MinVersion: tls.VersionTLS12`

---

## Testing Requirements

### Unit Tests (`test/unit/` or `*_test.go` alongside source)

Write unit tests for every package. Minimum coverage targets:

| Package | Coverage target |
|---|---|
| `config` | 90% |
| `jwt` | 85% |
| `roles` | 100% |
| `provision` | 85% |
| `session` | 90% |
| `proxy/handler` | 80% |
| `proxy/sse` | 75% |

Key test cases to include:
- `roles`: empty input → default role; unknown role → default; multi-role; exact mapping
- `jwt`: expired token rejected; wrong audience rejected; missing roles claim → empty slice
- `provision`: user exists → only update roles; user missing → create then update roles
- `session`: set/get round-trip; expired session rejected; tampered cookie rejected
- `proxy/handler`: missing session → redirect; valid session → X-Remote-User injected; spoofed header → stripped
- `proxy/sse`: SSE path detected; non-SSE path uses standard proxy; context cancellation cleans up

Use `github.com/stretchr/testify` for assertions.
Use `net/http/httptest` for HTTP handler tests.
Mock the Graylog client interface — do not call real Graylog in unit tests.

### Integration Tests (`test/integration/`)

Use `github.com/testcontainers/testcontainers-go`:
- Spin up a real Graylog container (MongoDB + OpenSearch + Graylog)
- Start the proxy pointed at the container
- Test full provisioning flow: call proxy with a mock OIDC token → verify user created in Graylog
- Test role sync: change roles in token → call proxy again → verify Graylog roles updated
- Test SSE path: open `/api/mcp/sse` → verify connection held open → verify context cancel closes it

Tag integration tests with `//go:build integration` so they don't run in unit test pass.

### DAST (`test/dast/`)
- Include an OWASP ZAP automation framework config (`zap-config.yaml`)
- Configure ZAP to scan:
  - `GET /oauth/login` — check for open redirect
  - `GET /` (unauthenticated) — should redirect, not expose Graylog
  - `GET /metrics` — should not require auth but not expose sensitive data
  - `/api/mcp/sse` — check SSE endpoint auth enforcement
- Include a `zap-rules.tsv` with false-positive suppressions for known non-issues
- ZAP alerts of HIGH or CRITICAL fail the pipeline

---

## GitHub Actions Pipeline

### File: `.github/workflows/ci.yml` (PR / push to non-main)

```
Triggers: pull_request, push to feature branches

Jobs (run in parallel where possible):

1. lint
   - golangci-lint (latest) with config:
     - errcheck, govet, staticcheck, gosimple, unused, ineffassign
     - revive for style
     - gocritic for code smell
   - go vet
   - gofmt check (fail if unformatted)

2. sast
   - gosec (github.com/securego/gosec) — fail on HIGH/CRITICAL findings
     Rules: G101 (hardcoded creds), G304 (file path), G402 (TLS config), G501 (weak crypto)
   - Semgrep with go.lang.security ruleset
   - Upload SARIF results to GitHub Advanced Security (Code Scanning)

3. sca
   - govulncheck (golang.org/x/vuln/cmd/govulncheck) — fail on any vulnerability in dependencies
   - Trivy filesystem scan on go.mod/go.sum — fail on CRITICAL/HIGH CVEs
   - Nancy (sonatype) for additional OSS index check
   - Upload results to GitHub Security tab

4. unit-test
   - go test ./... -race -count=1 -coverprofile=coverage.out
   - go tool cover — fail if total coverage < 80%
   - Upload coverage report as artifact
   - Report coverage delta in PR comment

5. build
   - docker build (multi-stage):
     Stage 1: golang:1.22-alpine — build binary with CGO_DISABLED=1
     Stage 2: scratch — copy binary only, no shell, no package manager
   - Verify image starts and /healthz returns 200
   - Trivy image scan — fail on CRITICAL CVEs in final image
```

### File: `.github/workflows/cd.yml` (push to main / release tag)

```
Triggers: push to main, push of v* tag

Jobs (sequential):

1. All CI jobs above (reuse as needs: dependency)

2. integration-test
   - go test -tags=integration ./test/integration/... -timeout 10m
   - Requires: Docker-in-Docker or testcontainers-cloud

3. dast
   - Start proxy + Graylog stack with docker-compose (test profile)
   - Run OWASP ZAP automation framework: zap-automation-framework -config test/dast/zap-config.yaml
   - Fail pipeline on HIGH/CRITICAL findings
   - Upload ZAP report as artifact + to GitHub Security tab (SARIF)

4. build-and-push
   - Build multi-arch image (amd64, arm64) using docker buildx
   - Sign image with cosign (keyless OIDC signing)
   - Push to ghcr.io/org/graylog-auth-proxy:sha-${{ github.sha }}
   - Push :latest (main) or :v${{ tag }} (release)
   - Generate SBOM with syft, attach to image with cosign

5. deploy (release tag only)
   - kubectl set image deployment/graylog-auth-proxy proxy=ghcr.io/org/...
   - Wait for rollout: kubectl rollout status
   - Smoke test: curl /healthz on new pod
```

### Dockerfile

```dockerfile
# Stage 1: Build
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s -X main.version=$(git describe --tags --always)" \
    -o proxy ./cmd/proxy

# Stage 2: Runtime — scratch for minimal attack surface
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/proxy /proxy
USER 65534:65534
EXPOSE 8443
ENTRYPOINT ["/proxy"]
```

### golangci-lint config (`.golangci.yml`)

```yaml
linters:
  enable:
    - errcheck
    - gosimple
    - govet
    - ineffassign
    - staticcheck
    - unused
    - gosec
    - revive
    - gocritic
    - exhaustive
    - wrapcheck
    - contextcheck

linters-settings:
  gosec:
    severity: medium
    confidence: medium
  errcheck:
    check-type-assertions: true
    check-blank: true
  gocritic:
    enabled-tags: [diagnostic, style, performance]
```

---

## Acceptance Criteria

Before considering the implementation complete, verify:

- [ ] `go build ./...` succeeds with zero warnings
- [ ] `golangci-lint run` passes with zero findings
- [ ] `gosec ./...` passes with zero HIGH/CRITICAL findings
- [ ] `govulncheck ./...` reports zero vulnerabilities
- [ ] `go test ./... -race` passes with coverage ≥ 80%
- [ ] Integration tests pass against a real Graylog container
- [ ] Docker image builds and runs: `curl -k https://localhost:8443/healthz` returns `{"status":"ok"}`
- [ ] ZAP DAST scan returns zero HIGH/CRITICAL findings
- [ ] Image size (scratch-based) is under 30MB
- [ ] All secrets configurable via environment — zero hardcoded values
- [ ] Unauthenticated request to `/` redirects to Entra ID (not 200 or 500)
- [ ] `X-Remote-User` header in incoming request is stripped (cannot be spoofed)
- [ ] SSE connection to `/api/mcp/sse` streams without buffering (verify with `curl -N`)
- [ ] Graceful shutdown drains in-flight requests before exit

---

## What NOT to Do

- Do not use `gorilla/mux` — stdlib `net/http.ServeMux` is sufficient
- Do not use `gin` or `echo` — adds unnecessary weight for a proxy
- Do not store sessions in Redis — stateless cookie is the requirement
- Do not call the Graylog Graph API or any external API other than Graylog REST and Entra OIDC endpoints
- Do not use `jwt-go` alone for token validation — must use `go-oidc` verifier (signature check)
- Do not log raw tokens, session cookies, or passwords at any log level
- Do not use `http.DefaultClient` — always use a configured client with timeout and custom TLS
- Do not expose Graylog directly — all traffic must pass through the proxy
