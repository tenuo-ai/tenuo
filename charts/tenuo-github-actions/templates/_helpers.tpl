{{- define "tenuo-github-actions.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "tenuo-github-actions.fullname" -}}
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

{{- define "tenuo-github-actions.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "tenuo-github-actions.labels" -}}
helm.sh/chart: {{ include "tenuo-github-actions.chart" . }}
{{ include "tenuo-github-actions.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "tenuo-github-actions.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tenuo-github-actions.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "tenuo-github-actions.exchangeSelectorLabels" -}}
{{ include "tenuo-github-actions.selectorLabels" . }}
app.kubernetes.io/component: exchange
{{- end }}

{{- define "tenuo-github-actions.gatewaySelectorLabels" -}}
{{ include "tenuo-github-actions.selectorLabels" . }}
app.kubernetes.io/component: gateway
{{- end }}

{{- define "tenuo-github-actions.image" -}}
{{- $registry := .Values.image.registry -}}
{{- $repo := .Values.image.repository -}}
{{- $ref := "" -}}
{{- if .Values.image.digest }}
{{- $ref = printf "@%s" .Values.image.digest -}}
{{- else }}
{{- $ref = printf ":%s" (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end }}
{{- if $registry }}
{{- printf "%s/%s%s" $registry $repo $ref }}
{{- else }}
{{- printf "%s%s" $repo $ref }}
{{- end }}
{{- end }}

{{- define "tenuo-github-actions.exchangeName" -}}
{{- printf "%s-exchange" (include "tenuo-github-actions.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "tenuo-github-actions.gatewayName" -}}
{{- printf "%s-gateway" (include "tenuo-github-actions.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "tenuo-github-actions.exchangeServiceAccountName" -}}
{{- if .Values.exchange.serviceAccount.create }}
{{- default (include "tenuo-github-actions.exchangeName" .) .Values.exchange.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.exchange.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "tenuo-github-actions.gatewayServiceAccountName" -}}
{{- if .Values.gateway.serviceAccount.create }}
{{- default (include "tenuo-github-actions.gatewayName" .) .Values.gateway.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.gateway.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "tenuo-github-actions.validate" -}}
{{- if ne .Values.signing.profile "secret" }}
{{- fail "signing.profile must be secret. kms is not implemented in this image yet." }}
{{- end }}
{{- if not .Values.trust.rootPublicKeys }}
{{- fail "trust.rootPublicKeys is required" }}
{{- end }}
{{- if not .Values.exchange.audience }}
{{- fail "exchange.audience is required" }}
{{- end }}
{{- if not .Values.exchange.secrets.existingSecret }}
{{- fail "exchange.secrets.existingSecret is required (issuer.pem)" }}
{{- end }}
{{- if not .Values.gateway.secrets.existingSecret }}
{{- fail "gateway.secrets.existingSecret is required (receipt.pem and app.pem)" }}
{{- end }}
{{- if eq .Values.exchange.secrets.existingSecret .Values.gateway.secrets.existingSecret }}
{{- fail "exchange and gateway cannot share a key Secret" }}
{{- end }}
{{- if not .Values.github.appId }}
{{- fail "github.appId is required" }}
{{- end }}
{{- end }}
