# Implementation Review — graylog-auth-proxy

A neutral, reviewer-style read of the codebase as of 2026-04-08, after the
initial GitOps integration in `docker-k8s-dev`. The goal is to capture what is
solid, what is fragile, and what is missing — without re-litigating the
existing design.

Scope: `cmd/`, `internal/`, `chart/`, `spec/`. Integration tests glanced at,
not exercised. No runtime profiling.

## Summary

The proxy does its job. The OIDC dance is conventional and uses PKCE+state.
The Graylog client is small and easy to follow. The recent fixes (basic-auth
instead of Bearer, role-membership endpoints, provisioning cache,
`prompt=select_account`) addressed real bugs that would each have blocked
production use. The codebase is at the "works end-to-end in dev, ready for
user acceptance" stage and should not yet be considered hardened.

## Strengths

- **Tight scope.** ~2.7k LOC across `cmd` + `internal`, single binary, no
  framework. Easy to read end-to-end in one sitting.
- **Layered packages.** `oidc`, `session`, `graylog`, `provision`, `proxy`,
  `roles` each have a clear single responsibility. Tests live next to the
  code they cover.
- **PKCE is on by default** with `code_challenge_method=S256` and a
  per-request state cookie. The temp cookie is `HttpOnly`, `Secure`,
  `SameSite=Lax` with a short max-age — sensible defaults.
- **Graylog client uses HTTP Basic Auth with `:token`** as Graylog requires,
  and now also sends `X-Requested-By` on every request. After PR #14 these
  are the only auth code paths in the client, so future changes can't
  regress.
- **Role updates use `/api/roles/{name}/members/{user}` PUT/DELETE** with a
  computed add/remove diff against current roles, instead of the
  full-payload `PUT /api/users/{name}` that returns 500 on partial bodies.
  This is the right Graylog idiom.
- **Per-session provisioning cache (`internal/proxy/handler.go`)** keyed by
  `username + sorted roles hash` with a 10-minute TTL eliminates the
  per-request Graylog hammering observed in dev and naturally re-syncs when
  the role set changes.
- **SSE handler is its own type** with its own transport — the team
  recognised that SSE under the standard `httputil.ReverseProxy` needed
  separate flush/buffering handling.
- **Helm chart supports three TLS modes** (static secret, cert-manager
  external issuer, cert-manager self-signed) and ships PDB, ServiceMonitor,
  PrometheusRule, and a connection test. That is more operational maturity
  than most internal tools start with.
- **`/oauth/logout` is now correctly minimal** — clears the proxy cookie and
  redirects to `/`, so combined with `prompt=select_account` users can pick
  a different identity without being signed out of Entra entirely.

## Risks and rough edges

### Correctness

1. **Bootstrap Job has two known dead branches** that emit warnings but
   don't fail:
   - The `org.graylog2.users.UserConfiguration` PUT includes an `@type`
     field Graylog rejects. The job continues because the existing config
     already permits Admin token creation.
   - The `HTTPHeaderAuthConfig` PUT references a class that does not exist
     in Graylog 7. The Trusted Header authenticator must be configured via
     the Authentication Services backend API or the UI.
   Both should be fixed or removed, with the manual setup documented.

2. **`oidc.Handler` carries `tenantID` and `redirectURL` fields** that became
   unused after the logout simplification. They should be removed; otherwise
   future readers will assume they're load-bearing.

3. **The provisioning cache key uses a custom insertion sort** for the role
   slice. It's correct for the small lists involved but the standard library
   `slices.Sort` is shorter and stdlib-blessed.

### Security

1. **`/oauth/logout` is a GET that mutates state.** Standard CSRF concern.
   The blast radius is small (an attacker can log a victim out, nothing
   else), but the convention is POST + token. Worth a conscious decision
   either way.

2. **Strip header list is only the four `*Remote*` headers.** If Graylog or
   any future backend ever trusts additional headers (`X-Forwarded-User`,
   `X-Auth-Request-User`, `X-Authenticated-User`), the proxy will happily
   forward whatever the client sends. The strip list should be a documented
   superset of "all headers any backend might trust".

3. **No rate limiting on `/oauth/login` or `/oauth/callback`.** OIDC code
   replay is bounded by Entra anyway, but rate-limiting failed callbacks
   makes log noise and abuse cheaper to spot.

4. **Session HMAC key rotation is undocumented.** A key change today
   invalidates every session. Either accept it (and document) or support a
   list of accepted keys with one signing key.

### Operability

1. **The chart pins `appVersion: latest`.** This forced the consuming
   GitOps repo to set `imagePullPolicy: Always` to actually pick up new
   builds, which is exactly the failure mode `latest` is famous for.
   Releases should pin a real semver tag (and ideally a digest).

2. **No structured access logging.** Today the only request-level signal is
   the Prometheus counters. A one-line-per-request access log (method, path,
   status, duration, username) would make incident investigation much
   easier.

3. **Failure modes return `503 Service Unavailable` as plain text.** A
   minimal HTML error page with a request ID would be friendlier and would
   make tickets easier to triage.

4. **The provisioning cache is an unbounded `sync.Map`.** Fine for the
   expected user count but for a long-running pod with thousands of
   distinct users a TTL LRU would be more disciplined.

### Testing

1. The new role-membership diff logic in `UpdateUserRoles` does not yet
   have a focused unit test asserting the exact PUT/DELETE call sequence.
2. The provisioning cache (`provisionFresh`, `provisionCacheKey`) is
   untested. Both behaviours (TTL expiry, role-set change invalidation) are
   trivially testable.
3. `prompt=select_account` is only verified manually — a small unit test on
   the constructed auth URL would prevent silent regressions.
4. The chart has no `helm lint` / `helm template` smoke test in CI.

### UX

1. **Graylog's own "Sign out" button does not hit `/oauth/logout`**, so
   users have to know about the proxy URL to fully drop the session. In
   Graylog Enterprise this is configurable via the Customization plugin and
   should be wired up.
2. **No `/oauth/whoami`** endpoint means there's no easy way to ask the
   proxy "who does it think I am?" during debugging.

## What is explicitly out of scope of this review

- Performance under load.
- A line-by-line security audit of the OIDC implementation. The standard
  `golang.org/x/oauth2` and `github.com/coreos/go-oidc` libraries are
  trusted; the glue code looks conventional but has not been audited.
- The Helm chart's RBAC and PSP/PSA posture (only skimmed).

## Recommended next steps

Roughly the order I would tackle them:

1. Clean up the bootstrap Job (the two dead branches) and document the
   manual Trusted Header authentication-service setup.
2. Add unit tests for `UpdateUserRoles` and the provisioning cache.
3. Pin a real chart `appVersion` per release and remove the
   `imagePullPolicy: Always` workaround in the consuming GitOps repo.
4. Add structured access logging.
5. Wire Graylog's Sign-out button to `/oauth/logout`.
6. Decide on CSRF protection for `/oauth/logout`.

All of the above are tracked in [`../TODO.md`](../TODO.md).
