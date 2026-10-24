{{- define "oncache.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "oncache.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "oncache.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "oncache.labels" -}}
app.kubernetes.io/name: {{ include "oncache.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "oncache.validateHTTPPort" -}}
{{- $address := required "config.server.listenAddress is required" .Values.config.server.listenAddress | toString -}}
{{- $port := regexFind ":[0-9]+$" $address | trimPrefix ":" -}}
{{- if eq $port "" -}}
{{- fail (printf "config.server.listenAddress %q must end with a numeric port" $address) -}}
{{- end -}}
{{- if ne (atoi $port) (int .Values.metrics.port) -}}
{{- fail (printf "config.server.listenAddress port %s must match metrics.port %v" $port .Values.metrics.port) -}}
{{- end -}}
{{- end -}}

{{- define "oncache.selectorLabels" -}}
app.kubernetes.io/name: {{ include "oncache.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "oncache.serviceAccountName" -}}
{{- default (include "oncache.fullname" .) .Values.rbac.serviceAccountName -}}
{{- end -}}
