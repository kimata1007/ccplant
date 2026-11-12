{{/*
Expand the name of the chart.
*/}}
{{- define "agentapi-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Environment variables for application KV value encryption. */}}
{{- define "agentapi-proxy.kvEncryptionEnv" -}}
{{- $encryption := .encryption | default dict -}}
{{- $prefix := .prefix | default "AGENTAPI_KV_ENCRYPTION" -}}
{{- $provider := dig "provider" "local" $encryption -}}
{{- $activeKeyID := dig "activeKeyId" "" $encryption -}}
{{- $secretName := dig "keysSecretRef" "name" "" $encryption -}}
{{- $kmsKeys := dig "kmsKeys" (dict) $encryption -}}
{{- $kmsKeyIDSecretName := dig "kmsKeyIdSecretRef" "name" "" $encryption -}}
{{- $kmsRegionSecretName := dig "kmsRegionSecretRef" "name" "" $encryption -}}
{{- if or $activeKeyID $secretName $kmsKeys $kmsKeyIDSecretName -}}
- name: {{ printf "%s_PROVIDER" $prefix }}
  value: {{ $provider | quote }}
- name: {{ printf "%s_ACTIVE_KEY_ID" $prefix }}
  value: {{ required "kvStore.encryption.activeKeyId is required when KV encryption is configured" $activeKeyID | quote }}
{{- if or (eq $provider "aws-kms") (eq $provider "aws-kms-branch") (eq $provider "aws-kms-branch-scoped") }}
- name: {{ printf "%s_KMS_REGION" $prefix }}
{{- if $kmsRegionSecretName }}
  valueFrom:
    secretKeyRef:
      name: {{ $kmsRegionSecretName | quote }}
      key: {{ dig "kmsRegionSecretRef" "key" "kms-region" $encryption | quote }}
{{- else }}
  value: {{ required "kvStore.encryption.kmsRegion is required for an AWS KMS provider" (dig "kmsRegion" "" $encryption) | quote }}
{{- end }}
{{- end }}
{{- if or (eq $provider "aws-kms") (eq $provider "aws-kms-branch") (eq $provider "aws-kms-branch-scoped") (eq $provider "cloud-kms-branch") (eq $provider "cloud-kms-branch-scoped") }}
{{- if $kmsKeyIDSecretName }}
- name: {{ printf "%s_KMS_KEY_ID" $prefix }}
  valueFrom:
    secretKeyRef:
      name: {{ $kmsKeyIDSecretName | quote }}
      key: {{ dig "kmsKeyIdSecretRef" "key" "kms-key-id" $encryption | quote }}
{{- else }}
- name: {{ printf "%s_KEYS" $prefix }}
  value: {{ toJson $kmsKeys | quote }}
{{- end }}
{{- if or (eq $provider "aws-kms-branch") (eq $provider "aws-kms-branch-scoped") (eq $provider "cloud-kms-branch") (eq $provider "cloud-kms-branch-scoped") }}
- name: {{ printf "%s_BRANCH_CACHE_TTL_SECONDS" $prefix }}
  value: {{ dig "branchCacheTTLSeconds" 900 $encryption | quote }}
- name: {{ printf "%s_BRANCH_CACHE_MAX_ENTRIES" $prefix }}
  value: {{ dig "branchCacheMaxEntries" 128 $encryption | quote }}
{{- end }}
{{- else }}
- name: {{ printf "%s_KEYS" $prefix }}
  valueFrom:
    secretKeyRef:
      name: {{ required "kvStore.encryption.keysSecretRef.name is required when KV encryption is configured" $secretName | quote }}
      key: {{ dig "keysSecretRef" "key" "keys.json" $encryption | quote }}
{{- end }}
{{- end -}}
{{- end }}

{{/* Static AWS credentials sourced from Kubernetes Secrets. */}}
{{- define "agentapi-proxy.awsCredentialsEnv" -}}
{{- $credentials := . | default dict -}}
{{- $accessKeyRef := dig "accessKeyIdSecretRef" (dict) $credentials -}}
{{- if (dig "name" "" $accessKeyRef) }}
- name: AWS_ACCESS_KEY_ID
  valueFrom:
    secretKeyRef:
      name: {{ dig "name" "" $accessKeyRef | quote }}
      key: {{ dig "key" "AWS_ACCESS_KEY_ID" $accessKeyRef | quote }}
{{- end }}
{{- $secretKeyRef := dig "secretAccessKeySecretRef" (dict) $credentials -}}
{{- if (dig "name" "" $secretKeyRef) }}
- name: AWS_SECRET_ACCESS_KEY
  valueFrom:
    secretKeyRef:
      name: {{ dig "name" "" $secretKeyRef | quote }}
      key: {{ dig "key" "AWS_SECRET_ACCESS_KEY" $secretKeyRef | quote }}
{{- end }}
{{- $sessionTokenRef := dig "sessionTokenSecretRef" (dict) $credentials -}}
{{- if (dig "name" "" $sessionTokenRef) }}
- name: AWS_SESSION_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ dig "name" "" $sessionTokenRef | quote }}
      key: {{ dig "key" "AWS_SESSION_TOKEN" $sessionTokenRef | quote }}
{{- end }}
{{- end }}

{{/* Role-specific image helpers. Empty role values preserve the legacy root image. */}}
{{- define "agentapi-proxy.apiImage" -}}
{{- $api := .Values.api | default dict -}}
{{- $image := $api.image | default dict -}}
{{- $repository := $image.repository | default .Values.image.repository -}}
{{- printf "%s:%s" $repository .Chart.AppVersion -}}
{{- end }}

{{- define "agentapi-proxy.workerImage" -}}
{{- $worker := .Values.worker | default dict -}}
{{- $image := $worker.image | default dict -}}
{{- $repository := $image.repository | default .Values.image.repository -}}
{{- printf "%s:%s" $repository .Chart.AppVersion -}}
{{- end }}

{{- define "agentapi-proxy.sessionManagerImage" -}}
{{- $manager := .Values.sessionManager | default dict -}}
{{- $image := $manager.image | default dict -}}
{{- $repository := $image.repository | default .Values.image.repository -}}
{{- printf "%s:%s" $repository .Chart.AppVersion -}}
{{- end }}

{{- define "agentapi-proxy.apiServiceAccountName" -}}
{{- $api := .Values.api | default dict -}}
{{- $sa := $api.serviceAccount | default .Values.serviceAccount -}}
{{- if $sa.create -}}
{{- default (include "agentapi-proxy.fullname" .) $sa.name -}}
{{- else -}}
{{- default "default" $sa.name -}}
{{- end -}}
{{- end }}

{{- define "agentapi-proxy.workerServiceAccountName" -}}
{{- $worker := .Values.worker | default dict -}}
{{- $sa := $worker.serviceAccount | default dict -}}
{{- if $sa.create -}}
{{- default (printf "%s-worker" (include "agentapi-proxy.fullname" .)) $sa.name -}}
{{- else -}}
{{- default "default" $sa.name -}}
{{- end -}}
{{- end }}

{{- define "agentapi-proxy.sessionManagerServiceAccountName" -}}
{{- $manager := .Values.sessionManager | default dict -}}
{{- $sa := $manager.serviceAccount | default dict -}}
{{- if $sa.create -}}
{{- default (printf "%s-session-manager" (include "agentapi-proxy.fullname" .)) $sa.name -}}
{{- else -}}
{{- default "default" $sa.name -}}
{{- end -}}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "agentapi-proxy.fullname" -}}
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
{{- define "agentapi-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "agentapi-proxy.labels" -}}
helm.sh/chart: {{ include "agentapi-proxy.chart" . }}
{{ include "agentapi-proxy.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "agentapi-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agentapi-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "agentapi-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "agentapi-proxy.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
scia OAuth broker resource names.
*/}}
{{- define "agentapi-proxy.sciaName" -}}
{{- printf "%s-scia-oauth" (include "agentapi-proxy.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "agentapi-proxy.sciaServiceName" -}}
scia-oauth
{{- end }}

{{- define "agentapi-proxy.sciaSecretName" -}}
{{- $scia := .Values.scia | default dict }}
{{- $oauth := $scia.oauth | default dict }}
{{- $google := $oauth.google | default dict }}
{{- $secret := $google.secret | default dict }}
{{- default (include "agentapi-proxy.sciaName" .) $secret.existingSecret }}
{{- end }}

{{- define "agentapi-proxy.sciaTodoistSecretName" -}}
{{- $scia := .Values.scia | default dict }}
{{- $oauth := $scia.oauth | default dict }}
{{- $todoist := $oauth.todoist | default dict }}
{{- $secret := $todoist.secret | default dict }}
{{- default (printf "%s-todoist" (include "agentapi-proxy.sciaName" .) | trunc 63 | trimSuffix "-") $secret.existingSecret }}
{{- end }}

{{- define "agentapi-proxy.taskQueueEnv" -}}
{{- $queue := .Values.taskQueue | default dict }}
{{- if (dig "enabled" false $queue) }}
- name: AGENTAPI_TASK_QUEUE_ENABLED
  value: "true"
{{- range $name, $env := dict "maxStartingGlobal" "MAX_STARTING_GLOBAL" "maxStartingPerUser" "MAX_STARTING_PER_USER" "maxStartingPerTeam" "MAX_STARTING_PER_TEAM" "maxLiveSessionsPerUser" "MAX_LIVE_SESSIONS_PER_USER" "maxLiveSessionsPerTeam" "MAX_LIVE_SESSIONS_PER_TEAM" "maxPending" "MAX_PENDING" "retentionDays" "RETENTION_DAYS" "teamRetentionDays" "TEAM_RETENTION_DAYS" }}
{{- if hasKey $queue $name }}
- name: AGENTAPI_TASK_QUEUE_{{ $env }}
  value: {{ index $queue $name | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
