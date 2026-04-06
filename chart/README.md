# graylog-auth-proxy

A Helm chart that deploys an OAuth2/OIDC reverse proxy for Graylog. The proxy authenticates users via Microsoft Entra ID (Azure AD), automatically provisions Graylog user accounts on first login, continuously syncs Entra ID group memberships to Graylog roles, and proxies all traffic to the Graylog web UI including Server-Sent Events (SSE) streams.

## Prerequisites

- Kubernetes 1.24+
- Helm 3
- cert-manager (optional, required for `certManager` or `certManagerSelfSigned` TLS modes)
- Graylog with **Trusted Header Authentication** enabled (the proxy sends the authenticated username via a configurable HTTP header)
- A Microsoft Entra ID App Registration with an OAuth2/OIDC configuration

## Installation

```bash
helm install graylog-proxy ./chart -f values.yaml -n graylog
```

Or from an OCI registry (if published):

```bash
helm install graylog-proxy oci://ghcr.io/cstdpp/helm-charts/graylog-auth-proxy \
  --version 0.1.0 \
  -f values.yaml \
  -n graylog
```

## Configuration

### TLS Modes

The proxy terminates TLS on its own listener. Three modes are supported, controlled by `tls.mode`:

#### Static (existing TLS secret)

Use a pre-existing Kubernetes TLS Secret (e.g. created manually or by an external process):

```yaml
tls:
  mode: static
  secretName: my-existing-tls-secret
```

#### cert-manager ACME (Let's Encrypt)

Automatically obtain and renew a certificate from an ACME provider via a cert-manager `ClusterIssuer`. Requires cert-manager to be installed in the cluster.

```yaml
tls:
  mode: certManager
  certManager:
    clusterIssuerName: letsencrypt-prod
    duration: "8760h"      # 1 year
    renewBefore: "720h"    # 30 days
```

The chart creates a `Certificate` resource whose `dnsNames` are derived from `ingress.hosts` and the service FQDN.

#### cert-manager Self-Signed (internal)

For development or internal clusters where a trusted CA is not needed. The chart creates a full self-signed CA chain (self-signed issuer, CA certificate, CA issuer, server certificate):

```yaml
tls:
  mode: certManagerSelfSigned
  selfSigned:
    duration: "8760h"
    renewBefore: "720h"
```

### OIDC Authentication

Two authentication modes are available, controlled by `oidc.mode`:

#### Client Secret

The proxy authenticates to Entra ID using a client secret stored in a Kubernetes Secret:

```yaml
oidc:
  mode: secret
  tenantId: "00000000-0000-0000-0000-000000000000"
  clientId: "11111111-1111-1111-1111-111111111111"
  redirectUrl: "https://graylog.company.com/oauth/callback"
  existingSecretName: graylog-oidc-secret
  existingSecretKey: client-secret     # key within the Secret
```

Create the Secret ahead of time:

```bash
kubectl create secret generic graylog-oidc-secret \
  --from-literal=client-secret='your-client-secret-value' \
  -n graylog
```

#### Workload Identity (Azure)

For Azure Kubernetes Service (AKS) clusters with Workload Identity enabled. The proxy authenticates using federated credentials -- no client secret is needed:

```yaml
oidc:
  mode: workloadIdentity
  tenantId: "00000000-0000-0000-0000-000000000000"
  clientId: "11111111-1111-1111-1111-111111111111"
  redirectUrl: "https://graylog.company.com/oauth/callback"

workloadIdentity:
  enabled: true
  serviceAccountAnnotations:
    azure.workload.identity/client-id: "11111111-1111-1111-1111-111111111111"
  podLabels:
    azure.workload.identity/use: "true"
```

### Secret Management

All sensitive values are **mounted as files** under `/run/secrets/` rather than passed as environment variable values. The proxy reads `*_FILE` environment variables that point to the mounted file paths. This avoids secrets appearing in `kubectl describe pod` or process listings.

Three secrets are required:

| Secret | Purpose | Env var pointing to file | How to provide |
|--------|---------|--------------------------|----------------|
| OIDC client secret | Authenticates to Entra ID (only in `secret` mode) | `ENTRA_CLIENT_SECRET_FILE` | `oidc.existingSecretName` |
| Session key | Encrypts session cookies (32-byte hex string) | `SESSION_KEY_FILE` | `session.existingSecretName` or `session.key` (chart creates Secret) |
| Graylog service token | Calls Graylog API for user provisioning and role sync | `GRAYLOG_SERVICE_TOKEN_FILE` | `graylog.serviceToken.existingSecretName` |

For the **session key**, you can either provide an existing Secret or let the chart generate one by setting `session.key` inline:

```yaml
# Option A: existing Secret
session:
  existingSecretName: graylog-session-secret
  existingSecretKey: session-key

# Option B: chart-managed Secret (provide the key inline)
session:
  key: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
```

### Role Mapping

The proxy maps Entra ID app role claims to Graylog roles. Two configuration methods are available:

#### Inline (chart generates ConfigMap)

Provide the mapping directly in values. The chart creates a ConfigMap containing the JSON-serialized map:

```yaml
roleMap:
  inline:
    graylog-admin: "Admin"
    graylog-analyst: "Analyst"
    graylog-reader: "Reader"
  defaultRole: "Reader"
```

#### Existing ConfigMap

Reference a ConfigMap that already exists in the namespace:

```yaml
roleMap:
  existingConfigMapName: my-graylog-role-map
  configMapKey: ROLE_MAP          # key containing JSON role map
  defaultRole: "Reader"
```

The ConfigMap value must be a JSON object mapping Entra role names to Graylog role names:

```json
{"graylog-admin":"Admin","graylog-analyst":"Analyst","graylog-reader":"Reader"}
```

### Header Configuration

The proxy injects the authenticated user's identity into upstream requests and strips potentially spoofed headers from incoming requests.

```yaml
headers:
  # Header sent to Graylog with the authenticated username
  remoteUserHeader: "X-Remote-User"

  # Headers stripped from incoming client requests to prevent spoofing
  strip:
    - "X-Remote-User"
    - "X-Remote-Email"
    - "X-Remote-Name"

  # Additional headers injected into every proxied request
  inject:
    X-Custom-Source: "auth-proxy"
```

### Graylog Backend TLS

When Graylog itself uses TLS with a self-signed or internal CA certificate, configure the proxy to trust that CA:

```yaml
graylog:
  url: "https://graylog-svc.graylog:9000"
  caCert:
    enabled: true
    secretName: graylog-ca-secret
    key: ca.crt                    # key within the Secret containing the PEM certificate
```

The CA certificate is mounted at `/ca/ca.crt` and passed to the proxy via the `GRAYLOG_CA_CERT_FILE` environment variable.

### Service and Ingress

#### Service

```yaml
service:
  type: LoadBalancer
  port: 8443
  annotations:
    external-dns.alpha.kubernetes.io/hostname: graylog.company.com
    service.beta.kubernetes.io/azure-load-balancer-internal: "true"
```

#### Ingress

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
    nginx.ingress.kubernetes.io/ssl-passthrough: "false"
  hosts:
    - host: graylog.company.com
      paths:
        - path: /
          pathType: ImplementationSpecific
  tls:
    - secretName: graylog-proxy-tls
      hosts:
        - graylog.company.com
```

### Observability

#### ServiceMonitor (Prometheus Operator)

Enable automatic Prometheus scraping of the `/metrics` endpoint:

```yaml
metrics:
  serviceMonitor:
    enabled: true
    interval: "30s"
    labels:
      release: prometheus        # match your Prometheus instance
```

#### Alerting Rules (PrometheusRule)

Built-in alerts for common failure modes:

```yaml
metrics:
  prometheusRule:
    enabled: true
    labels:
      release: prometheus
    additionalRules: []          # add custom rules here
```

Included alerts:
- **GraylogAuthProxyDown** — no healthy proxy instances for 5+ minutes (critical)
- **GraylogAuthProxyHighErrorRate** — >10% provisioning failures (warning)
- **GraylogAuthProxyHighLatency** — p99 latency > 5s (warning)
- **GraylogBackendUnreachable** — >50% Graylog API 5xx errors (critical)
- **GraylogAuthProxySSEConnectionsHigh** — >100 active SSE connections (warning)

#### Grafana Dashboard

Auto-discovered by the Grafana sidecar (requires `grafana_dashboard: "1"` label):

```yaml
metrics:
  grafanaDashboard:
    enabled: true
    annotations:
      grafana_folder: "Infrastructure"
```

Panels: request rate, latency percentiles (p50/p95/p99), auth operations, active SSE connections, Graylog API requests, pod restarts, memory and CPU usage.

### High Availability

#### Pod Disruption Budget

Ensure minimum availability during cluster maintenance:

```yaml
pdb:
  enabled: true
  maxUnavailable: 1              # or use minAvailable: 1
```

#### Topology Spread

Distribute pods across availability zones:

```yaml
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: DoNotSchedule
```

### Extensibility

#### Extra Volumes and Mounts

Add custom volumes (e.g. additional CA certs, shared config):

```yaml
extraVolumes:
  - name: custom-certs
    secret:
      secretName: my-custom-certs

extraVolumeMounts:
  - name: custom-certs
    mountPath: /etc/custom-certs
    readOnly: true
```

#### Flux CD Integration

Add Flux kustomization labels:

```yaml
flux:
  enabled: true
  kustomization:
    name: graylog-auth-proxy
    namespace: flux-system

deploymentAnnotations:
  kustomize.toolkit.fluxcd.io/reconcile: "enabled"
```

## Full Example

A complete `values.yaml` for a typical production deployment using ACME TLS, client secret OIDC, ingress with external-dns, and internal CA trust for the Graylog backend:

```yaml
replicaCount: 2

image:
  repository: ghcr.io/cstdpp/graylog-auth-proxy
  tag: "1.0.0"

oidc:
  tenantId: "00000000-0000-0000-0000-000000000000"
  clientId: "11111111-1111-1111-1111-111111111111"
  redirectUrl: "https://graylog.company.com/oauth/callback"
  mode: secret
  existingSecretName: graylog-oidc-secret
  existingSecretKey: client-secret

session:
  existingSecretName: graylog-session-secret
  existingSecretKey: session-key
  maxAge: "8h"

graylog:
  url: "https://graylog-svc.graylog:9000"
  serviceToken:
    existingSecretName: graylog-service-token
    existingSecretKey: service-token
  caCert:
    enabled: true
    secretName: graylog-ca-secret
    key: ca.crt

roleMap:
  inline:
    graylog-admin: "Admin"
    graylog-analyst: "Analyst"
    graylog-reader: "Reader"
  defaultRole: "Reader"

headers:
  remoteUserHeader: "X-Remote-User"
  strip:
    - "X-Remote-User"
    - "X-Remote-Email"
    - "X-Remote-Name"

tls:
  mode: certManager
  certManager:
    clusterIssuerName: letsencrypt-prod
    duration: "8760h"
    renewBefore: "720h"

service:
  type: ClusterIP
  port: 8443

ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
    external-dns.alpha.kubernetes.io/hostname: graylog.company.com
  hosts:
    - host: graylog.company.com
      paths:
        - path: /
          pathType: ImplementationSpecific
  tls:
    - secretName: graylog-proxy-tls
      hosts:
        - graylog.company.com

resources:
  limits:
    cpu: 500m
    memory: 128Mi
  requests:
    cpu: 100m
    memory: 64Mi

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 5
  targetCPUUtilizationPercentage: 80

pdb:
  enabled: true
  maxUnavailable: 1

topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: DoNotSchedule

metrics:
  serviceMonitor:
    enabled: true
    labels:
      release: prometheus
  prometheusRule:
    enabled: true
  grafanaDashboard:
    enabled: true
```

## Values Reference

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `replicaCount` | int | `1` | Number of proxy replicas |
| `image.repository` | string | `ghcr.io/cstdpp/graylog-auth-proxy` | Container image repository |
| `image.tag` | string | `""` (appVersion) | Image tag; defaults to `Chart.appVersion` |
| `image.pullPolicy` | string | `IfNotPresent` | Image pull policy |
| `image.pullSecrets` | list | `[]` | Image pull secrets |
| `oidc.tenantId` | string | `""` | Entra ID tenant ID |
| `oidc.clientId` | string | `""` | App registration client ID |
| `oidc.redirectUrl` | string | `""` | OAuth2 redirect URL |
| `oidc.mode` | string | `"secret"` | Auth mode: `secret` or `workloadIdentity` |
| `oidc.existingSecretName` | string | `""` | Secret containing the OIDC client secret |
| `oidc.existingSecretKey` | string | `"client-secret"` | Key within the OIDC secret |
| `workloadIdentity.enabled` | bool | `false` | Enable Azure Workload Identity |
| `workloadIdentity.serviceAccountAnnotations` | object | `{}` | Annotations added to the ServiceAccount |
| `workloadIdentity.podLabels` | object | `{}` | Labels added to pods for workload identity |
| `session.existingSecretName` | string | `""` | Existing Secret for session key |
| `session.existingSecretKey` | string | `"session-key"` | Key within the session secret |
| `session.key` | string | `""` | Inline session key (chart creates Secret if `existingSecretName` is empty) |
| `session.maxAge` | string | `"8h"` | Session cookie max age |
| `graylog.url` | string | `""` | Graylog backend URL |
| `graylog.serviceToken.existingSecretName` | string | `""` | Secret containing the Graylog service token |
| `graylog.serviceToken.existingSecretKey` | string | `"service-token"` | Key within the service token secret |
| `graylog.caCert.enabled` | bool | `false` | Enable custom CA trust for Graylog backend |
| `graylog.caCert.secretName` | string | `""` | Secret containing the CA certificate |
| `graylog.caCert.key` | string | `"ca.crt"` | Key within the CA secret |
| `roleMap.inline` | object | `{}` | Inline Entra role to Graylog role mapping |
| `roleMap.existingConfigMapName` | string | `""` | Existing ConfigMap with role mapping |
| `roleMap.configMapKey` | string | `"ROLE_MAP"` | Key in the ConfigMap containing JSON role map |
| `roleMap.defaultRole` | string | `"Reader"` | Default Graylog role when no mapping matches |
| `headers.remoteUserHeader` | string | `"X-Remote-User"` | Header name for the authenticated username |
| `headers.inject` | object | `{}` | Additional headers injected into proxied requests |
| `headers.strip` | list | `["X-Remote-User", "X-Remote-Email", "X-Remote-Name"]` | Headers stripped from incoming requests |
| `tls.mode` | string | `"static"` | TLS mode: `static`, `certManager`, or `certManagerSelfSigned` |
| `tls.secretName` | string | `""` | TLS Secret name (for `static` mode) |
| `tls.certManager.clusterIssuerName` | string | `""` | ClusterIssuer name for ACME certificates |
| `tls.certManager.duration` | string | `"8760h"` | Certificate duration |
| `tls.certManager.renewBefore` | string | `"720h"` | Renew before expiry |
| `tls.selfSigned.duration` | string | `"8760h"` | Self-signed certificate duration |
| `tls.selfSigned.renewBefore` | string | `"720h"` | Self-signed renew before expiry |
| `service.type` | string | `ClusterIP` | Service type |
| `service.port` | int | `8443` | Service port |
| `service.annotations` | object | `{}` | Service annotations |
| `ingress.enabled` | bool | `false` | Enable Ingress |
| `ingress.className` | string | `""` | Ingress class name |
| `ingress.annotations` | object | `{}` | Ingress annotations |
| `ingress.hosts` | list | `[]` | Ingress host rules |
| `ingress.tls` | list | `[]` | Ingress TLS configuration |
| `serviceAccount.create` | bool | `true` | Create a ServiceAccount |
| `serviceAccount.automount` | bool | `true` | Automount service account token |
| `serviceAccount.annotations` | object | `{}` | ServiceAccount annotations |
| `serviceAccount.nameOverride` | string | `""` | Override the ServiceAccount name |
| `podAnnotations` | object | `{}` | Additional pod annotations |
| `podLabels` | object | `{}` | Additional pod labels |
| `resources.limits.cpu` | string | `"500m"` | CPU limit |
| `resources.limits.memory` | string | `"128Mi"` | Memory limit |
| `resources.requests.cpu` | string | `"100m"` | CPU request |
| `resources.requests.memory` | string | `"64Mi"` | Memory request |
| `livenessProbe.enabled` | bool | `true` | Enable liveness probe |
| `livenessProbe.initialDelaySeconds` | int | `5` | Liveness probe initial delay |
| `livenessProbe.periodSeconds` | int | `10` | Liveness probe period |
| `livenessProbe.timeoutSeconds` | int | `3` | Liveness probe timeout |
| `livenessProbe.failureThreshold` | int | `3` | Liveness probe failure threshold |
| `livenessProbe.successThreshold` | int | `1` | Liveness probe success threshold |
| `readinessProbe.enabled` | bool | `true` | Enable readiness probe |
| `readinessProbe.initialDelaySeconds` | int | `3` | Readiness probe initial delay |
| `readinessProbe.periodSeconds` | int | `10` | Readiness probe period |
| `readinessProbe.timeoutSeconds` | int | `3` | Readiness probe timeout |
| `readinessProbe.failureThreshold` | int | `3` | Readiness probe failure threshold |
| `readinessProbe.successThreshold` | int | `1` | Readiness probe success threshold |
| `autoscaling.enabled` | bool | `false` | Enable HorizontalPodAutoscaler |
| `autoscaling.minReplicas` | int | `1` | Minimum replicas |
| `autoscaling.maxReplicas` | int | `5` | Maximum replicas |
| `autoscaling.targetCPUUtilizationPercentage` | int | `80` | Target CPU utilization |
| `nodeSelector` | object | `{}` | Node selector |
| `tolerations` | list | `[]` | Tolerations |
| `affinity` | object | `{}` | Affinity rules |
| `topologySpreadConstraints` | list | `[]` | Pod topology spread constraints |
| `terminationGracePeriodSeconds` | int | `30` | Graceful shutdown timeout |
| `pdb.enabled` | bool | `false` | Create PodDisruptionBudget |
| `pdb.minAvailable` | string | `""` | Min available pods (exclusive with maxUnavailable) |
| `pdb.maxUnavailable` | int | `1` | Max unavailable pods |
| `metrics.serviceMonitor.enabled` | bool | `false` | Create ServiceMonitor |
| `metrics.serviceMonitor.interval` | string | `"30s"` | Scrape interval |
| `metrics.serviceMonitor.labels` | object | `{}` | Extra ServiceMonitor labels |
| `metrics.prometheusRule.enabled` | bool | `false` | Create PrometheusRule with alerts |
| `metrics.prometheusRule.labels` | object | `{}` | Extra PrometheusRule labels |
| `metrics.prometheusRule.additionalRules` | list | `[]` | Custom alerting rules |
| `metrics.grafanaDashboard.enabled` | bool | `false` | Create Grafana dashboard ConfigMap |
| `metrics.grafanaDashboard.labels` | object | `{}` | Extra dashboard labels |
| `metrics.grafanaDashboard.annotations` | object | `{}` | Dashboard annotations (e.g. folder) |
| `extraEnv` | list | `[]` | Extra environment variables |
| `extraVolumes` | list | `[]` | Extra pod volumes |
| `extraVolumeMounts` | list | `[]` | Extra container volume mounts |
| `deploymentAnnotations` | object | `{}` | Deployment annotations |
| `flux.enabled` | bool | `false` | Add Flux CD labels |
| `flux.kustomization.name` | string | `""` | Flux kustomization name |
| `flux.kustomization.namespace` | string | `"flux-system"` | Flux kustomization namespace |
