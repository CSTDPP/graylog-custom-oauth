# TODO

Tracked work for `graylog-auth-proxy`. Items are roughly ordered by priority
within each section. See [`docs/REVIEW.md`](./docs/REVIEW.md) for the rationale
behind most of these.

## Correctness

- [ ] **Provisioner role sync correctness on first request.** The cache key
      uses `username + roles-hash`; on a brand-new login it correctly misses
      and provisions, but the role-set returned by `GetUser` immediately after
      `CreateUser` is sometimes the requested set, sometimes empty depending
      on Graylog's response timing. Add a small post-create assertion or rely
      solely on the membership endpoints (skip GetUser for the create path).
- [ ] **`tenantID`/`redirectURL` fields on `oidc.Handler` are now unused**
      after the logout simplification — remove them and shrink the
      constructor. Both are assigned in `NewHandler` and never read
      (`internal/oidc/handler.go:44-45`). There is no `url` field; an earlier
      revision of this list named one.

## Security

- [ ] **Confirm the cookie session manager rotates HMAC keys cleanly.** Today
      a key change invalidates every session. Add a documented rotation
      procedure or support a list of accepted keys.
- [ ] **Audit `Strip` headers default list.** (In flight: PR #27.) The
      default was **not** what an earlier revision of this item claimed: it
      stripped only `X-Remote-User`, `X-Remote-Email`, `X-Remote-Name` —
      `Remote-User`, the conventional name for Graylog's Trusted HTTP Header
      authenticator, was missing. Not exploitable under the configuration
      `spec/ARCHITECTURE.md` documents (Graylog reads `X-Remote-User`, which
      is stripped and then overwritten by `Header.Set`), but a Graylog
      pointed at the unprefixed spelling would have accepted a client-supplied
      identity.
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

## Build & CI

- [ ] **Move the `settings:` block in `.golangci.yml` under `linters:`.** At
      the top level it is invalid for schema `version: "2"`:
      `golangci-lint config verify` rejects the file and `run` silently
      ignores the block, so `gosec.severity`, `gosec.confidence`,
      `errcheck.check-type-assertions`, `errcheck.check-blank` and the
      `gocritic` tags have never actually been in effect. Relocating it is not
      free — it surfaces 11 further findings (10 `errcheck` from
      `check-blank`, 1 `gocritic` `importShadow` at
      `internal/proxy/handler.go:208`). Decide: enable and fix, or drop the
      block.
- [ ] **Run CI on pushes to `main`.** `ci.yml` has `branches-ignore: [main]`,
      so the default branch is never re-linted after a merge. This is why the
      gosec G124 breakage (fixed in PR #26) stayed invisible for three months
      and only ever surfaced as red Dependabot PRs.
- [ ] **Raise the 30% coverage gate** (`ci.yml`). That is low for a component
      sitting on the authentication path; the packages that matter most
      (`oidc`, `graylog`, `jwt`) currently have no unit tests at all.

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

## Tracked elsewhere (not actionable in this repository)

The bootstrap Job lives in the consuming GitOps repo, not here — grepping this
repository for `UserConfiguration` or `HTTPHeaderAuthConfig` finds only this
file and `docs/REVIEW.md`. Both items are real; they just cannot be fixed by a
commit to `graylog-auth-proxy`. Note that `docs/REVIEW.md` lists the first of
them as recommended next step #1.

- [ ] **Bootstrap Job: drop the dead `@type` field on the
      `org.graylog2.users.UserConfiguration` PUT.** Graylog rejects `@type` as
      a property. The job continues because the existing config already
      permits the Admin user to mint tokens, but the WARNING is misleading.
- [ ] **Bootstrap Job: stop attempting to enable `HTTPHeaderAuthConfig` via
      cluster_config.** That class does not exist in Graylog 7. The Trusted
      HTTP Header authenticator must be configured as an Authentication
      Service backend (UI or `/api/system/authentication/services/backends`).

## Done

- [x] **Grafana dashboard ships with the chart** —
      `chart/templates/grafana-dashboard.yaml`.
- [x] **Multi-arch image build** — `cd.yml` builds
      `linux/amd64,linux/arm64` via buildx.
- [x] **Pin CI tool versions** — golangci-lint, gosec, govulncheck and
      trivy-action no longer float on `@latest`/`@master` (PR #26).
- [x] **Unblock the Lint job** — gosec G124 excluded for the session cookie
      test fixtures (PR #26).
