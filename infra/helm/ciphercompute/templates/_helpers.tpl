{{- define "cc.name" -}}{{ .Release.Name }}{{- end -}}

{{- define "cc.labels" -}}
app.kubernetes.io/name: ciphercompute
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "cc.selector" -}}
app.kubernetes.io/name: ciphercompute
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "cc.image" -}}
{{ .root.Values.global.imageRegistry }}/{{ .image.repository }}:{{ .image.tag }}
{{- end -}}

{{/* Pod-level hardening shared by every workload (TM:E-3). */}}
{{- define "cc.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ .Values.podSecurity.runAsUser }}
runAsGroup: {{ .Values.podSecurity.runAsUser }}
fsGroup: {{ .Values.podSecurity.fsGroup }}
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "cc.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
privileged: false
capabilities:
  drop: ["ALL"]
{{- end -}}

{{- define "cc.envFrom" -}}
- configMapRef:
    name: {{ include "cc.name" . }}-config
- secretRef:
    name: {{ include "cc.name" . }}-secrets
{{- end -}}
