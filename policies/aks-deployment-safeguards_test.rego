package containerization.aks_safeguards

# ==============================================================================
# AKS Deployment Safeguards Policy Tests
# ==============================================================================
#
# Run with: opa test policies/
#
# Verifies that the AKS deployment safeguards policy detects the same
# violations the AKS Automatic admission controller would reject, and allows
# compliant manifests.
#
# ==============================================================================

# ------------------------------------------------------------------------------
# Test Input Constants
# ------------------------------------------------------------------------------

k8s_compliant_deployment := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  labels:
    app.kubernetes.io/name: myapp
spec:
  replicas: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: myapp
  template:
    metadata:
      labels:
        app.kubernetes.io/name: myapp
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              topologyKey: kubernetes.io/hostname
      containers:
      - name: app
        image: myapp:1.0.0
        resources:
          requests:
            cpu: 250m
            memory: 256Mi
          limits:
            cpu: 500m
            memory: 512Mi
        readinessProbe:
          httpGet:
            path: /health
            port: http
        livenessProbe:
          httpGet:
            path: /health
            port: http
`

k8s_no_requests := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: app
        image: myapp:1.0.0
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
`

k8s_latest_tag := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: app
        image: nginx:latest
        resources:
          requests:
            cpu: 250m
            memory: 256Mi
        readinessProbe:
          tcpSocket:
            port: 80
        livenessProbe:
          tcpSocket:
            port: 80
`

k8s_reserved_label := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  labels:
    kubernetes.azure.com/mode: user
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: app
        image: myapp:1.0.0
        resources:
          requests:
            cpu: 250m
            memory: 256Mi
        readinessProbe:
          tcpSocket:
            port: 80
        livenessProbe:
          tcpSocket:
            port: 80
`

k8s_privileged := `
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
  - name: app
    image: myapp:1.0.0
    securityContext:
      privileged: true
    resources:
      requests:
        cpu: 250m
        memory: 256Mi
    readinessProbe:
      tcpSocket:
        port: 80
    livenessProbe:
      tcpSocket:
        port: 80
`

k8s_host_pid := `
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  hostPID: true
  containers:
  - name: app
    image: myapp:1.0.0
    resources:
      requests:
        cpu: 250m
        memory: 256Mi
    readinessProbe:
      tcpSocket:
        port: 80
    livenessProbe:
      tcpSocket:
        port: 80
`

storageclass_intree := `
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: managed
provisioner: kubernetes.io/azure-disk
`

storageclass_csi := `
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: managed-csi
provisioner: disk.csi.azure.com
`

k8s_missing_probes := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: app
        image: myapp:1.0.0
        resources:
          requests:
            cpu: 250m
            memory: 256Mi
`

k8s_multi_replica_no_affinity := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: app
        image: myapp:1.0.0
        resources:
          requests:
            cpu: 250m
            memory: 256Mi
        readinessProbe:
          tcpSocket:
            port: 80
        livenessProbe:
          tcpSocket:
            port: 80
`

# ------------------------------------------------------------------------------
# container-requests
# ------------------------------------------------------------------------------

test_block_missing_requests if {
	some v in result.violations with input as {"content": k8s_no_requests}
	v.rule == "safeguard-container-requests"
}

test_allow_with_requests if {
	r := result with input as {"content": k8s_compliant_deployment}
	count([v | some v in r.violations; v.rule == "safeguard-container-requests"]) == 0
}

# ------------------------------------------------------------------------------
# no-latest-image
# ------------------------------------------------------------------------------

test_block_latest_tag if {
	some v in result.violations with input as {"content": k8s_latest_tag}
	v.rule == "safeguard-no-latest-tag"
}

test_allow_versioned_tag if {
	r := result with input as {"content": k8s_compliant_deployment}
	count([v | some v in r.violations; v.rule == "safeguard-no-latest-tag"]) == 0
}

# ------------------------------------------------------------------------------
# restricted-labels
# ------------------------------------------------------------------------------

test_block_reserved_label if {
	some v in result.violations with input as {"content": k8s_reserved_label}
	v.rule == "safeguard-restricted-labels"
}

test_allow_normal_labels if {
	r := result with input as {"content": k8s_compliant_deployment}
	count([v | some v in r.violations; v.rule == "safeguard-restricted-labels"]) == 0
}

# ------------------------------------------------------------------------------
# no-privileged
# ------------------------------------------------------------------------------

test_block_privileged if {
	some v in result.violations with input as {"content": k8s_privileged}
	v.rule == "safeguard-no-privileged"
}

# ------------------------------------------------------------------------------
# host-namespaces
# ------------------------------------------------------------------------------

test_block_host_pid if {
	some v in result.violations with input as {"content": k8s_host_pid}
	v.rule == "safeguard-host-namespaces"
}

# ------------------------------------------------------------------------------
# csi-driver
# ------------------------------------------------------------------------------

test_block_intree_provisioner if {
	some v in result.violations with input as {"content": storageclass_intree}
	v.rule == "safeguard-csi-driver"
}

test_allow_csi_provisioner if {
	result.allow with input as {"content": storageclass_csi}
}

# ------------------------------------------------------------------------------
# enforce-probes
# ------------------------------------------------------------------------------

test_warn_missing_probes if {
	some w in result.warnings with input as {"content": k8s_missing_probes}
	w.rule == "safeguard-enforce-probes"
}

# ------------------------------------------------------------------------------
# anti-affinity
# ------------------------------------------------------------------------------

test_warn_multi_replica_no_affinity if {
	some w in result.warnings with input as {"content": k8s_multi_replica_no_affinity}
	w.rule == "safeguard-anti-affinity"
}

test_no_affinity_warning_when_set if {
	r := result with input as {"content": k8s_compliant_deployment}
	count([w | some w in r.warnings; w.rule == "safeguard-anti-affinity"]) == 0
}

# ------------------------------------------------------------------------------
# INTEGRATION
# ------------------------------------------------------------------------------

test_compliant_manifest_allowed if {
	result.allow with input as {"content": k8s_compliant_deployment}
}

test_noncompliant_manifest_blocked if {
	not result.allow with input as {"content": k8s_latest_tag}
}
