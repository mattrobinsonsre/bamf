{{/*
Expand the name of the chart.
*/}}
{{- define "bamf.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "bamf.fullname" -}}
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
{{- define "bamf.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "bamf.labels" -}}
helm.sh/chart: {{ include "bamf.chart" . }}
{{ include "bamf.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "bamf.selectorLabels" -}}
app.kubernetes.io/name: {{ include "bamf.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
API selector labels
*/}}
{{- define "bamf.api.selectorLabels" -}}
{{ include "bamf.selectorLabels" . }}
app.kubernetes.io/component: api
{{- end }}

{{/*
Bridge selector labels
*/}}
{{- define "bamf.bridge.selectorLabels" -}}
{{ include "bamf.selectorLabels" . }}
app.kubernetes.io/component: bridge
{{- end }}

{{/*
Web selector labels
*/}}
{{- define "bamf.web.selectorLabels" -}}
{{ include "bamf.selectorLabels" . }}
app.kubernetes.io/component: web
{{- end }}

{{/*
Agent selector labels
*/}}
{{- define "bamf.agent.selectorLabels" -}}
{{ include "bamf.selectorLabels" . }}
app.kubernetes.io/component: agent
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "bamf.serviceAccountName" -}}
{{- if .Values.api.serviceAccount.create }}
{{- default (include "bamf.fullname" .) .Values.api.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.api.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Construct a container image reference with optional global registry prefix.
Usage: {{ include "bamf.image" (dict "imageValues" .Values.api.image "appVersion" .Chart.AppVersion "globalRegistry" .Values.global.imageRegistry) }}

When global.imageRegistry is set (e.g., "123456789.dkr.ecr.us-east-1.amazonaws.com"),
the image becomes "registry/repo:tag" instead of "repo:tag".
*/}}
{{- define "bamf.image" -}}
{{- $tag := default .appVersion .imageValues.tag -}}
{{- $repo := .imageValues.repository -}}
{{- if .globalRegistry -}}
{{- printf "%s/%s:%s" .globalRegistry $repo $tag -}}
{{- else -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}
{{- end }}

{{/*
Component image helpers — convenience wrappers around bamf.image.
*/}}
{{- define "bamf.api.image" -}}
{{- include "bamf.image" (dict "imageValues" .Values.api.image "appVersion" .Chart.AppVersion "globalRegistry" .Values.global.imageRegistry) -}}
{{- end }}

{{- define "bamf.bridge.image" -}}
{{- include "bamf.image" (dict "imageValues" .Values.bridge.image "appVersion" .Chart.AppVersion "globalRegistry" .Values.global.imageRegistry) -}}
{{- end }}

{{- define "bamf.web.image" -}}
{{- include "bamf.image" (dict "imageValues" .Values.web.image "appVersion" .Chart.AppVersion "globalRegistry" .Values.global.imageRegistry) -}}
{{- end }}

{{- define "bamf.agent.image" -}}
{{- include "bamf.image" (dict "imageValues" .Values.agent.image "appVersion" .Chart.AppVersion "globalRegistry" .Values.global.imageRegistry) -}}
{{- end }}

{{- define "bamf.proxy.image" -}}
{{- include "bamf.image" (dict "imageValues" .Values.proxy.image "appVersion" .Chart.AppVersion "globalRegistry" .Values.global.imageRegistry) -}}
{{- end }}

{{/*
Proxy selector labels
*/}}
{{- define "bamf.proxy.selectorLabels" -}}
{{ include "bamf.selectorLabels" . }}
app.kubernetes.io/component: proxy
{{- end }}

{{/*
Database URL construction
*/}}
{{- define "bamf.databaseUrl" -}}
{{- if .Values.postgresql.bundled.enabled -}}
postgresql+asyncpg://{{ .Values.postgresql.bundled.auth.username }}:$(DATABASE_PASSWORD)@{{ include "bamf.fullname" . }}-postgresql:5432/{{ .Values.postgresql.bundled.auth.database }}?ssl=disable
{{- else if .Values.postgresql.external.enabled -}}
postgresql+asyncpg://{{ .Values.postgresql.external.username }}:$(DATABASE_PASSWORD)@{{ .Values.postgresql.external.host }}:{{ .Values.postgresql.external.port }}/{{ .Values.postgresql.external.database }}?sslmode={{ .Values.postgresql.external.sslmode }}
{{- else -}}
{{- fail "Either postgresql.bundled.enabled or postgresql.external.enabled must be true" -}}
{{- end -}}
{{- end }}

{{/*
Database read replica URL construction.
Falls back to primary if no read replica is configured.
*/}}
{{- define "bamf.databaseReadUrl" -}}
{{- if and .Values.postgresql.external.enabled .Values.postgresql.external.readReplica.enabled -}}
postgresql+asyncpg://{{ default .Values.postgresql.external.username .Values.postgresql.external.readReplica.username }}:$(DATABASE_READ_PASSWORD)@{{ .Values.postgresql.external.readReplica.host }}:{{ default .Values.postgresql.external.port .Values.postgresql.external.readReplica.port }}/{{ default .Values.postgresql.external.database .Values.postgresql.external.readReplica.database }}?sslmode={{ default .Values.postgresql.external.sslmode .Values.postgresql.external.readReplica.sslmode }}
{{- end -}}
{{- end }}

{{/*
Database read replica secret name.
Falls back to primary secret if read replica doesn't have its own.
*/}}
{{- define "bamf.databaseReadSecretName" -}}
{{- if .Values.postgresql.external.readReplica.existingSecret -}}
{{ .Values.postgresql.external.readReplica.existingSecret }}
{{- else if .Values.postgresql.external.readReplica.password -}}
{{ include "bamf.fullname" . }}-database-read-credentials
{{- else -}}
{{ include "bamf.databaseSecretName" . }}
{{- end -}}
{{- end }}

{{/*
Database read replica secret key.
*/}}
{{- define "bamf.databaseReadSecretKey" -}}
{{- if .Values.postgresql.external.readReplica.existingSecret -}}
{{- default "password" .Values.postgresql.external.readReplica.existingSecretKey -}}
{{- else -}}
password
{{- end -}}
{{- end }}

{{/*
Redis URL construction
*/}}
{{- define "bamf.redisUrl" -}}
{{- if .Values.redis.bundled.enabled -}}
redis://{{ include "bamf.fullname" . }}-redis:6379
{{- else if .Values.redis.external.enabled -}}
redis://{{ .Values.redis.external.host }}:{{ .Values.redis.external.port }}
{{- else -}}
{{- fail "Either redis.bundled.enabled or redis.external.enabled must be true" -}}
{{- end -}}
{{- end }}

{{/*
Database secret name
*/}}
{{- define "bamf.databaseSecretName" -}}
{{- if .Values.postgresql.bundled.enabled -}}
{{ include "bamf.fullname" . }}-postgresql
{{- else if .Values.postgresql.external.enabled -}}
{{- if .Values.postgresql.external.existingSecret -}}
{{ .Values.postgresql.external.existingSecret }}
{{- else if .Values.postgresql.external.externalSecret.enabled -}}
{{ include "bamf.fullname" . }}-database-credentials
{{- else -}}
{{ include "bamf.fullname" . }}-database-credentials
{{- end -}}
{{- end -}}
{{- end }}

{{/*
Database secret key
*/}}
{{- define "bamf.databaseSecretKey" -}}
{{- if .Values.postgresql.bundled.enabled -}}
password
{{- else if .Values.postgresql.external.enabled -}}
{{- default "password" .Values.postgresql.external.existingSecretKey -}}
{{- end -}}
{{- end }}

{{/*
Validate configuration
*/}}
{{- define "bamf.validateConfig" -}}
{{- if and .Values.postgresql.bundled.enabled .Values.postgresql.external.enabled -}}
{{- fail "Cannot enable both postgresql.bundled and postgresql.external" -}}
{{- end -}}
{{- if and (not .Values.postgresql.bundled.enabled) (not .Values.postgresql.external.enabled) -}}
{{- fail "Either postgresql.bundled.enabled or postgresql.external.enabled must be true" -}}
{{- end -}}
{{- if and .Values.redis.bundled.enabled .Values.redis.external.enabled -}}
{{- fail "Cannot enable both redis.bundled and redis.external" -}}
{{- end -}}
{{- if and (not .Values.redis.bundled.enabled) (not .Values.redis.external.enabled) -}}
{{- fail "Either redis.bundled.enabled or redis.external.enabled must be true" -}}
{{- end -}}
{{- include "bamf.validateSatellite" . -}}
{{- end -}}

{{/*
Bridge StatefulSet name
*/}}
{{- define "bamf.bridge.statefulsetName" -}}
{{ include "bamf.fullname" . }}-bridge
{{- end }}

{{/*
Bridge pod name for a given ordinal
Usage: {{ include "bamf.bridge.podName" (dict "root" . "ordinal" 0) }}
*/}}
{{- define "bamf.bridge.podName" -}}
{{ include "bamf.fullname" .root }}-bridge-{{ .ordinal }}
{{- end }}

{{/*
Bridge SNI hostname for a given ordinal.
gateway.tunnelDomain already includes "tunnel." (e.g., "tunnel.bamf.example.com").
When satellite.name is set:
  {ordinal}.bridge.{satellite}.{tunnelDomain}
Otherwise (backward compat):
  {ordinal}.bridge.{tunnelDomain}
Usage: {{ include "bamf.bridge.sniHostname" (dict "root" . "ordinal" 0) }}
*/}}
{{- define "bamf.bridge.sniHostname" -}}
{{- if .root.Values.satellite.name -}}
{{ .ordinal }}.bridge.{{ .root.Values.satellite.name }}.{{ .root.Values.gateway.tunnelDomain }}
{{- else -}}
{{ .ordinal }}.bridge.{{ .root.Values.gateway.tunnelDomain }}
{{- end -}}
{{- end }}

{{/*
Satellite tunnel domain — the base domain for this satellite's proxy.
gateway.tunnelDomain already includes "tunnel." (e.g., "tunnel.bamf.example.com").
When satellite.name is set: {satellite}.{tunnelDomain}
Otherwise: {tunnelDomain} (unchanged)
*/}}
{{- define "bamf.satellite.tunnelDomain" -}}
{{- if .Values.satellite.name -}}
{{ .Values.satellite.name }}.{{ .Values.gateway.tunnelDomain }}
{{- else -}}
{{ .Values.gateway.tunnelDomain }}
{{- end -}}
{{- end }}

{{/*
Validate satellite configuration.
Called from deployment templates to fail early on misconfiguration.
*/}}
{{- define "bamf.validateSatellite" -}}
{{- if .Values.satellite.enabled -}}
  {{- if not .Values.satellite.name -}}
    {{- fail "satellite.name is required when satellite.enabled=true" -}}
  {{- end -}}
  {{- if not (regexMatch "^[a-z][a-z0-9-]*$" .Values.satellite.name) -}}
    {{- fail "satellite.name must match [a-z][a-z0-9-]* (DNS label)" -}}
  {{- end -}}
{{- end -}}
{{- end -}}
