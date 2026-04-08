# graylog-auth-proxy

A small Go reverse proxy that puts Microsoft Entra ID (Azure AD) in front of
Graylog OSS / Enterprise. It authenticates users via OIDC, auto-provisions them
in Graylog on first login, syncs Entra App Roles to Graylog roles, and forwards
the authenticated identity via Graylog's Trusted HTTP Header authenticator —
including correct handling of long-lived Server-Sent Event (SSE) streams used
by Graylog 7.x.

> **Status:** internal use, in user acceptance. Not yet production-hardened —
> see [`TODO.md`](./TODO.md) and the review notes in [`docs/REVIEW.md`](./docs/REVIEW.md).

## Why this exists

The standard `oauth2-proxy` + Graylog setup requires administrators to
pre-create every Graylog user. It also doesn't keep group/role memberships in
sync, and its handling of SSE under the Graylog MCP endpoint is fragile. This
proxy replaces that combination with a single binary that:

- terminates the OIDC dance with Entra ID (PKCE, state, nonce),
- creates the user in Graylog on first login,
- diff-syncs Graylog role membership against the mapped Entra App Roles,
- injects the trusted-header identity on every forwarded request,
- streams SSE responses through unchunked, with the right flush semantics.

## Documentation map

| Topic | File |
| --- | --- |
| Architecture, request flow, threat model | [`spec/ARCHITECTURE.md`](./spec/ARCHITECTURE.md) |
| Architecture diagram (source) | [`spec/architecture.drawio`](./spec/architecture.drawio) |
| Original implementation prompt | [`spec/CLAUDE_CODE_PROMPT.md`](./spec/CLAUDE_CODE_PROMPT.md) |
| Helm chart usage, values, TLS modes | [`chart/README.md`](./chart/README.md) |
| Default chart values | [`chart/values.yaml`](./chart/values.yaml) |
| Implementation review (neutral) | [`docs/REVIEW.md`](./docs/REVIEW.md) |
| Outstanding work | [`TODO.md`](./TODO.md) |

## Repository layout

```
cmd/proxy/         entrypoint
internal/config/   env / file-secret loading and validation
internal/oidc/     PKCE OIDC handler, callback, logout
internal/session/  HMAC-signed cookie session manager
internal/graylog/  Graylog REST client (basic-auth API token)
internal/provision/ user create + role-membership sync
internal/proxy/    auth middleware + reverse proxy + SSE handler
internal/roles/    Entra → Graylog role name mapping
internal/jwt/      ID token / claim helpers
internal/observability/ Prometheus metrics
chart/             Helm chart (published as OCI)
spec/              architecture, design notes
test/integration/  end-to-end tests against a real Graylog
```

## Quick start

For a Kubernetes deployment, follow [`chart/README.md`](./chart/README.md).
For local development, see `docker-compose.yml`.

## Contributing

This project is currently single-maintainer and tracks immediate needs of the
internal Graylog rollout. Before opening a PR for non-trivial work, scan
[`TODO.md`](./TODO.md) and [`docs/REVIEW.md`](./docs/REVIEW.md) — many of the
obvious follow-ups are already known and prioritised.
