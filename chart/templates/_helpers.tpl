{{/*
Expand the name of the chart.
*/}}
{{- define "graylog-auth-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "graylog-auth-proxy.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "graylog-auth-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "graylog-auth-proxy.labels" -}}
helm.sh/chart: {{ include "graylog-auth-proxy.chart" . }}
{{ include "graylog-auth-proxy.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "graylog-auth-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "graylog-auth-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "graylog-auth-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.nameOverride }}
{{- .Values.serviceAccount.nameOverride }}
{{- else }}
{{- printf "%s-sa" (include "graylog-auth-proxy.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Return the TLS secret name.
For static mode, returns tls.secretName; for cert-manager modes, returns fullname-tls.
*/}}
{{- define "graylog-auth-proxy.tls.secretName" -}}
{{- if and .Values.tls .Values.tls.secretName }}
{{- .Values.tls.secretName }}
{{- else }}
{{- printf "%s-tls" (include "graylog-auth-proxy.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Return the session secret name.
Returns session.existingSecretName if set, otherwise fullname-session.
*/}}
{{- define "graylog-auth-proxy.sessionSecretName" -}}
{{- if and .Values.session .Values.session.existingSecretName }}
{{- .Values.session.existingSecretName }}
{{- else }}
{{- printf "%s-session" (include "graylog-auth-proxy.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Return the role map ConfigMap name.
Returns roleMap.existingConfigMapName if set, otherwise fullname-role-map.
*/}}
{{- define "graylog-auth-proxy.roleMapConfigMapName" -}}
{{- if and .Values.roleMap .Values.roleMap.existingConfigMapName }}
{{- .Values.roleMap.existingConfigMapName }}
{{- else }}
{{- printf "%s-role-map" (include "graylog-auth-proxy.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Return the image string (repository:tag).
*/}}
{{- define "graylog-auth-proxy.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}
