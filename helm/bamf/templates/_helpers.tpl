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
{{- if .Values.core.api.serviceAccount.create }}
{{- default (include "bamf.fullname" .) .Values.core.api.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.core.api.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Construct a container image reference with optional global registry prefix.
Usage: {{ include "bamf.image" (dict "imageValues" .Values.core.api.image "appVersion" .Chart.AppVersion "globalRegistry" .Values.global.imageRegistry) }}

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
{{- include "bamf.image" (dict "imageValues" .Values.core.api.image "appVersion" .Chart.AppVersion "globalRegistry" .Values.global.imageRegistry) -}}
{{- end }}

{{- define "bamf.bridge.image" -}}
{{- include "bamf.image" (dict "imageValues" .Values.outpost.bridge.image "appVersion" .Chart.AppVersion "globalRegistry" .Values.global.imageRegistry) -}}
{{- end }}

{{- define "bamf.web.image" -}}
{{- include "bamf.image" (dict "imageValues" .Values.core.web.image "appVersion" .Chart.AppVersion "globalRegistry" .Values.global.imageRegistry) -}}
{{- end }}

{{- define "bamf.agent.image" -}}
{{- include "bamf.image" (dict "imageValues" .Values.agent.image "appVersion" .Chart.AppVersion "globalRegistry" .Values.global.imageRegistry) -}}
{{- end }}

{{- define "bamf.proxy.image" -}}
{{- include "bamf.image" (dict "imageValues" .Values.outpost.proxy.image "appVersion" .Chart.AppVersion "globalRegistry" .Values.global.imageRegistry) -}}
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
{{- if .Values.core.postgresql.bundled.enabled -}}
postgresql+asyncpg://{{ .Values.core.postgresql.bundled.auth.username }}:$(DATABASE_PASSWORD)@{{ include "bamf.fullname" . }}-postgresql:5432/{{ .Values.core.postgresql.bundled.auth.database }}?ssl=disable
{{- else if .Values.core.postgresql.external.enabled -}}
postgresql+asyncpg://{{ .Values.core.postgresql.external.username }}:$(DATABASE_PASSWORD)@{{ .Values.core.postgresql.external.host }}:{{ .Values.core.postgresql.external.port }}/{{ .Values.core.postgresql.external.database }}?sslmode={{ .Values.core.postgresql.external.sslmode }}
{{- else -}}
{{- fail "Either core.postgresql.bundled.enabled or core.postgresql.external.enabled must be true" -}}
{{- end -}}
{{- end }}

{{/*
Database read replica URL construction.
Falls back to primary if no read replica is configured.
*/}}
{{- define "bamf.databaseReadUrl" -}}
{{- if and .Values.core.postgresql.external.enabled .Values.core.postgresql.external.readReplica.enabled -}}
postgresql+asyncpg://{{ default .Values.core.postgresql.external.username .Values.core.postgresql.external.readReplica.username }}:$(DATABASE_READ_PASSWORD)@{{ .Values.core.postgresql.external.readReplica.host }}:{{ default .Values.core.postgresql.external.port .Values.core.postgresql.external.readReplica.port }}/{{ default .Values.core.postgresql.external.database .Values.core.postgresql.external.readReplica.database }}?sslmode={{ default .Values.core.postgresql.external.sslmode .Values.core.postgresql.external.readReplica.sslmode }}
{{- end -}}
{{- end }}

{{/*
Database read replica secret name.
Falls back to primary secret if read replica doesn't have its own.
*/}}
{{- define "bamf.databaseReadSecretName" -}}
{{- if .Values.core.postgresql.external.readReplica.existingSecret -}}
{{ .Values.core.postgresql.external.readReplica.existingSecret }}
{{- else if .Values.core.postgresql.external.readReplica.password -}}
{{ include "bamf.fullname" . }}-database-read-credentials
{{- else -}}
{{ include "bamf.databaseSecretName" . }}
{{- end -}}
{{- end }}

{{/*
Database read replica secret key.
*/}}
{{- define "bamf.databaseReadSecretKey" -}}
{{- if .Values.core.postgresql.external.readReplica.existingSecret -}}
{{- default "password" .Values.core.postgresql.external.readReplica.existingSecretKey -}}
{{- else -}}
password
{{- end -}}
{{- end }}

{{/*
Redis URL construction
*/}}
{{- define "bamf.redisUrl" -}}
{{- if .Values.core.redis.bundled.enabled -}}
redis://{{ include "bamf.fullname" . }}-redis:6379
{{- else if .Values.core.redis.external.enabled -}}
redis://{{ .Values.core.redis.external.host }}:{{ .Values.core.redis.external.port }}
{{- else -}}
{{- fail "Either core.redis.bundled.enabled or core.redis.external.enabled must be true" -}}
{{- end -}}
{{- end }}

{{/*
Database secret name
*/}}
{{- define "bamf.databaseSecretName" -}}
{{- if .Values.core.postgresql.bundled.enabled -}}
{{ include "bamf.fullname" . }}-postgresql
{{- else if .Values.core.postgresql.external.enabled -}}
{{- if .Values.core.postgresql.external.existingSecret -}}
{{ .Values.core.postgresql.external.existingSecret }}
{{- else if .Values.core.postgresql.external.externalSecret.enabled -}}
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
{{- if .Values.core.postgresql.bundled.enabled -}}
password
{{- else if .Values.core.postgresql.external.enabled -}}
{{- default "password" .Values.core.postgresql.external.existingSecretKey -}}
{{- end -}}
{{- end }}

{{/*
Validate configuration
*/}}
{{- define "bamf.validateConfig" -}}
{{- if .Values.core.enabled -}}
{{- if and .Values.core.postgresql.bundled.enabled .Values.core.postgresql.external.enabled -}}
{{- fail "Cannot enable both core.postgresql.bundled and core.postgresql.external" -}}
{{- end -}}
{{- if and (not .Values.core.postgresql.bundled.enabled) (not .Values.core.postgresql.external.enabled) -}}
{{- fail "Either core.postgresql.bundled.enabled or core.postgresql.external.enabled must be true" -}}
{{- end -}}
{{- if and .Values.core.redis.bundled.enabled .Values.core.redis.external.enabled -}}
{{- fail "Cannot enable both core.redis.bundled and core.redis.external" -}}
{{- end -}}
{{- if and (not .Values.core.redis.bundled.enabled) (not .Values.core.redis.external.enabled) -}}
{{- fail "Either core.redis.bundled.enabled or core.redis.external.enabled must be true" -}}
{{- end -}}
{{- end -}}
{{- include "bamf.validateOutpost" . -}}
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
When outpost.name is set:
  {ordinal}.bridge.{outpost}.{tunnelDomain}
Otherwise (backward compat):
  {ordinal}.bridge.{tunnelDomain}
Usage: {{ include "bamf.bridge.sniHostname" (dict "root" . "ordinal" 0) }}
*/}}
{{- define "bamf.bridge.sniHostname" -}}
{{- if .root.Values.outpost.name -}}
{{ .ordinal }}.bridge.{{ .root.Values.outpost.name }}.{{ .root.Values.gateway.tunnelDomain }}
{{- else -}}
{{ .ordinal }}.bridge.{{ .root.Values.gateway.tunnelDomain }}
{{- end -}}
{{- end }}

{{/*
Outpost tunnel domain — the base domain for this outpost's proxy.
gateway.tunnelDomain already includes "tunnel." (e.g., "tunnel.bamf.example.com").
When outpost.name is set: {outpost}.{tunnelDomain}
Otherwise: {tunnelDomain} (unchanged)
*/}}
{{- define "bamf.outpost.tunnelDomain" -}}
{{- if .Values.outpost.name -}}
{{ .Values.outpost.name }}.{{ .Values.gateway.tunnelDomain }}
{{- else -}}
{{ .Values.gateway.tunnelDomain }}
{{- end -}}
{{- end }}

{{/*
Validate outpost configuration.
Called from deployment templates to fail early on misconfiguration.
*/}}
{{- define "bamf.validateOutpost" -}}
{{- if .Values.outpost.enabled -}}
  {{- if not .Values.outpost.name -}}
    {{- fail "outpost.name is required when outpost.enabled=true" -}}
  {{- end -}}
  {{- if not (regexMatch "^[a-z][a-z0-9-]*$" .Values.outpost.name) -}}
    {{- fail "outpost.name must match [a-z][a-z0-9-]* (DNS label)" -}}
  {{- end -}}
{{- end -}}
{{- end -}}
