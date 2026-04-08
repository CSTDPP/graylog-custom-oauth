# TODO

Tracked work for `graylog-auth-proxy`. Items are roughly ordered by priority
within each section. See [`docs/REVIEW.md`](./docs/REVIEW.md) for the rationale
behind most of these.

## Correctness

- [ ] **Bootstrap Job: drop the dead `@type` field on UserConfiguration PUT.**
      The current PUT to `org.graylog2.users.UserConfiguration` is rejected by
      Graylog because `@type` is not an accepted property. The job continues
      because the existing config already permits the Admin user to mint
      tokens, but the WARNING is misleading. Either drop the call or send a
      proper merged payload without `@type`.
- [ ] **Bootstrap Job: stop attempting to enable `HTTPHeaderAuthConfig` via
      cluster_config.** That class does not exist in Graylog 7. The Trusted
      HTTP Header authenticator must be configured as an Authentication
      Service backend (UI or `/api/system/authentication/services/backends`).
      Either implement that or remove the placeholder and document the manual
      step.
- [ ] **Provisioner role sync correctness on first request.** The cache key
      uses `username + roles-hash`; on a brand-new login it correctly misses
      and provisions, but the role-set returned by `GetUser` immediately after
      `CreateUser` is sometimes the requested set, sometimes empty depending
      on Graylog's response timing. Add a small post-create assertion or rely
      solely on the membership endpoints (skip GetUser for the create path).
- [ ] **`url`/`tenantID`/`redirectURL` fields on `oidc.Handler` are now
      unused** after the logout simplification — remove them and shrink the
      constructor.

## Security

- [ ] **Confirm the cookie session manager rotates HMAC keys cleanly.** Today
      a key change invalidates every session. Add a documented rotation
      procedure or support a list of accepted keys.
- [ ] **Audit `Strip` headers default list.** It currently strips
      `Remote-User`, `X-Remote-User`, `X-Remote-Email`, `X-Remote-Name`. Any
      other headers Graylog might trust (`X-Forwarded-User`, etc.) should be
      added to prevent client spoofing.
- [ ] **Rate-limit failed logins / OIDC callback errors** to make brute-force
      and replay-style attacks against the callback endpoint less attractive.
- [ ] **CSRF on `/oauth/logout`.** It's a GET that mutates server state
      (clears the session cookie). Either move to POST with a CSRF token, or
      accept the risk and document it (logout-CSRF is generally low impact
      but worth a conscious decision).

## Operability

- [ ] **`pullPolicy: Always` is currently set in the consuming HelmRelease**
      because the chart pins `appVersion: latest`. Switch the chart to a real
      semver appVersion per release and remove the `Always` workaround
      downstream.
- [ ] **Image tag in the chart should default to a digest** so rollbacks are
      reproducible.
- [ ] **Emit a structured access log** (one line per forwarded request with
      method, path, status, duration, username) instead of relying solely on
      the Graylog backend logs.
- [ ] **Expose `/oauth/whoami`** returning the current session's username and
      mapped roles, for debugging and for a UI "logged in as" widget.
- [ ] **Provide a Grafana dashboard JSON** that ships with the chart and
      visualises the existing Prometheus metrics
      (`auth_operations_total{operation,result}`, request latencies, SSE
      connection counts).

## UX

- [ ] **Wire Graylog's "Sign out" button to `/oauth/logout`.** In Graylog
      Enterprise this is configurable via the Customization plugin
      (`logoutRedirectUrl` or equivalent). Today users have to navigate to
      `/oauth/logout` manually to fully drop the proxy session.
- [ ] **Friendly error pages.** `503 Service Unavailable` on a provisioning
      failure is opaque. Render a small HTML page with a request ID and a
      "try again" link.

## Testing

- [ ] **Cover the role-membership diff path** (`UpdateUserRoles`) with a
      table-driven unit test that asserts the exact PUT/DELETE calls for
      add/remove/no-op cases.
- [ ] **Cover the provisioning cache** (`provisionFresh`,
      `provisionCacheKey`) including TTL expiry and role-set change
      invalidation.
- [ ] **Integration test for the `prompt=select_account` query parameter** —
      currently only verified manually.
- [ ] **CI smoke test for the chart** using `helm lint` + `helm template`
      against each TLS mode.

## Documentation

- [ ] **Add a `docs/OPERATIONS.md`** describing: how to rotate the API token,
      how to recover when the bootstrap Job fails, how to read the metrics,
      and how to enable debug logging.
- [ ] **Add a `docs/ENTRA_SETUP.md` to this repo** mirroring the one in the
      consuming GitOps repo, so external adopters have a self-contained guide.
- [ ] **Document the trusted-header authentication service setup in Graylog
      Enterprise** (the manual UI step that this proxy depends on).

## Nice to have

- [ ] Replace the in-memory provisioning cache with a small TTL LRU library
      so the map doesn't grow unbounded for very long-running pods with many
      distinct users.
- [ ] Helm chart `tests/` that exercise the readiness probe via the published
      ServiceMonitor target instead of busybox.
- [ ] Multi-arch image build (currently amd64-only).
