package containerization.aks_safeguards

# ==============================================================================
# AKS Deployment Safeguards Policy
# ==============================================================================
#
# Mirrors the Azure Kubernetes Service (AKS) Deployment Safeguards that AKS
# Automatic enables in `Enforce` mode by default. The intent is to catch, at
# manifest-authoring time (inside Containerization Assist), the same violations
# that the cluster's Gatekeeper/Azure Policy admission controller would reject
# at deploy time — so a `generate-k8s-manifests` / `deploy-to-aks` run produces
# manifests that pass on AKS Automatic on the first try.
#
# Source of truth: the AKS Gatekeeper constraint templates
#   (k8sazurev1antiaffinityrules, k8sazurev1containerrequests,
#    k8sazurev1enforcecsidriver, k8sazurev1restrictedlabels,
#    k8sazurev2containerenforceprobes, k8sazurev2containernolatestimage,
#    k8sazurev2noprivilege, k8sazurev3blockhostnamespace, ...)
#   https://aka.ms/aks/deployment-safeguards
#
# NOTE ON EVALUATION MODEL:
#   Containerization Assist evaluates policies against `{ "content": <raw YAML
#   string> }` via the pre-compiled WASM bundle (see security-baseline.rego).
#   These rules therefore use regex matching on the raw manifest text, matching
#   the existing built-in policy convention. The structural, parsed equivalents
#   of these safeguards live in the TypeScript validator
#   (src/validation/kubernetes-validator.ts, COMPLIANCE category), which mirrors
#   the upstream Gatekeeper rego logic field-for-field.
#
# Two upstream safeguards operate on Node objects at admission time and cannot
# be evaluated against a workload manifest, so they are intentionally omitted
# here (documented in docs/aks-deployment-safeguards.md):
#   - Cannot Edit Individual Nodes (k8sazurev1restrictednodeedits)
#   - Reserved System Pool Taints  (k8sazurev1reservedtaints)
#
# ==============================================================================

# Metadata
policy_name := "AKS Deployment Safeguards"

policy_version := "1.0"

policy_category := "compliance"

# Default enforcement level (AKS Automatic runs these in Enforce mode)
default enforcement := "strict"

# ==============================================================================
# INPUT TYPE DETECTION
# ==============================================================================

# Detect if input is a Kubernetes manifest
is_kubernetes if {
	contains(input.content, "apiVersion:")
}

is_kubernetes if {
	contains(input.content, "kind:")
}

# Detect a StorageClass manifest
is_storageclass if {
	regex.match(`(?m)^kind:\s*StorageClass\s*$`, input.content)
}

# Detect a workload manifest (has a pod template / containers)
is_workload if {
	is_kubernetes
	regex.match(`(?m)^\s*containers:\s*$`, input.content)
}

# ==============================================================================
# SAFEGUARD: Container CPU and memory resource requests must be defined
# Upstream: k8sazurev1containerrequests
# ==============================================================================

violations contains result if {
	is_workload
	not regex.match(`(?m)^\s*requests:\s*$`, input.content)

	result := {
		"rule": "safeguard-container-requests",
		"category": "compliance",
		"priority": 90,
		"severity": "block",
		"message": "Containers must define CPU and memory resource requests. AKS Deployment Safeguards rejects workloads without resource requests. See https://aka.ms/aks/deployment-safeguards",
		"description": "AKS safeguard: containers must define resource requests",
		"safeguard": "container-requests",
	}
}

# ==============================================================================
# SAFEGUARD: Container images should not use the :latest tag (or be untagged)
# Upstream: k8sazurev2containernolatestimage
# ==============================================================================

violations contains result if {
	is_kubernetes
	regex.match(`(?m)^\s*image:\s*\S+:latest\s*$`, input.content)

	result := {
		"rule": "safeguard-no-latest-tag",
		"category": "compliance",
		"priority": 85,
		"severity": "block",
		"message": "Container images must use an explicit, versioned tag instead of ':latest'. AKS Deployment Safeguards blocks the 'latest' tag. See https://aka.ms/aks/deployment-safeguards",
		"description": "AKS safeguard: no ':latest' image tag",
		"safeguard": "no-latest-image",
	}
}

# Untagged image (no ':' after the repository, ignoring digests handled separately)
violations contains result if {
	is_kubernetes
	regex.match(`(?m)^\s*image:\s*[^:@\s]+\s*$`, input.content)

	result := {
		"rule": "safeguard-no-latest-tag",
		"category": "compliance",
		"priority": 85,
		"severity": "block",
		"message": "Container images must specify an explicit version tag (an untagged image defaults to ':latest'). AKS Deployment Safeguards blocks the 'latest' tag. See https://aka.ms/aks/deployment-safeguards",
		"description": "AKS safeguard: no ':latest' image tag",
		"safeguard": "no-latest-image",
	}
}

# ==============================================================================
# SAFEGUARD: No AKS-reserved labels (kubernetes.azure.com/*)
# Upstream: k8sazurev1restrictedlabels
# ==============================================================================

violations contains result if {
	is_kubernetes
	regex.match(`kubernetes\.azure\.com/`, input.content)

	result := {
		"rule": "safeguard-restricted-labels",
		"category": "compliance",
		"priority": 80,
		"severity": "block",
		"message": "Labels under 'kubernetes.azure.com/' are reserved for AKS use only. Remove them from your workload. See https://aka.ms/aks/deployment-safeguards",
		"description": "AKS safeguard: no AKS-reserved labels",
		"safeguard": "restricted-labels",
	}
}

# ==============================================================================
# SAFEGUARD: No privileged containers
# Upstream: k8sazurev2noprivilege
# ==============================================================================

violations contains result if {
	is_kubernetes
	regex.match(`(?m)privileged:\s*true`, input.content)

	result := {
		"rule": "safeguard-no-privileged",
		"category": "compliance",
		"priority": 95,
		"severity": "block",
		"message": "Privileged containers are not allowed. Remove 'securityContext.privileged: true'. See https://aka.ms/aks/deployment-safeguards",
		"description": "AKS safeguard: no privileged containers",
		"safeguard": "no-privileged",
	}
}

# ==============================================================================
# SAFEGUARD: Host namespaces are disallowed (baseline Pod Security Standard)
# Upstream: k8sazurev3blockhostnamespace
# ==============================================================================

violations contains result if {
	is_kubernetes
	regex.match(`(?m)host(Network|PID|IPC):\s*true`, input.content)

	result := {
		"rule": "safeguard-host-namespaces",
		"category": "compliance",
		"priority": 90,
		"severity": "block",
		"message": "Host namespaces (hostNetwork, hostPID, hostIPC) are disallowed under the baseline Pod Security Standard enforced by AKS. Set them to false or remove them. See https://aka.ms/aks/deployment-safeguards",
		"description": "AKS safeguard: no host namespaces",
		"safeguard": "host-namespaces",
	}
}

# ==============================================================================
# SAFEGUARD: StorageClass must use a CSI driver (no in-tree provisioner)
# Upstream: k8sazurev1enforcecsidriver
# ==============================================================================

violations contains result if {
	is_storageclass
	regex.match(`(?m)^\s*provisioner:\s*kubernetes\.io/azure-(disk|file)\s*$`, input.content)

	result := {
		"rule": "safeguard-csi-driver",
		"category": "compliance",
		"priority": 85,
		"severity": "block",
		"message": "StorageClass must use a CSI driver (disk.csi.azure.com or file.csi.azure.com). In-tree provisioners (kubernetes.io/azure-disk, kubernetes.io/azure-file) are not allowed. See https://aka.ms/aks/deployment-safeguards",
		"description": "AKS safeguard: use CSI driver StorageClass",
		"safeguard": "csi-driver",
	}
}

# ==============================================================================
# SAFEGUARD: Readiness and liveness probes should be configured
# Upstream: k8sazurev2containerenforceprobes
# ==============================================================================

warnings contains result if {
	is_workload
	not regex.match(`(?m)readinessProbe:`, input.content)

	result := {
		"rule": "safeguard-enforce-probes",
		"category": "compliance",
		"priority": 70,
		"severity": "warn",
		"message": "Containers should define a readinessProbe. AKS Deployment Safeguards can enforce readiness/liveness probes. See https://aka.ms/aks/deployment-safeguards",
		"description": "AKS safeguard: enforce readiness/liveness probes",
		"safeguard": "enforce-probes",
	}
}

warnings contains result if {
	is_workload
	not regex.match(`(?m)livenessProbe:`, input.content)

	result := {
		"rule": "safeguard-enforce-probes",
		"category": "compliance",
		"priority": 70,
		"severity": "warn",
		"message": "Containers should define a livenessProbe. AKS Deployment Safeguards can enforce readiness/liveness probes. See https://aka.ms/aks/deployment-safeguards",
		"description": "AKS safeguard: enforce readiness/liveness probes",
		"safeguard": "enforce-probes",
	}
}

# ==============================================================================
# SAFEGUARD: Anti-affinity or topology spread when replicas > 1
# Upstream: k8sazurev1antiaffinityrules
# ==============================================================================

warnings contains result if {
	is_workload
	regex.match(`(?m)^\s*replicas:\s*([2-9]|[1-9][0-9]+)\s*$`, input.content)
	not regex.match(`podAntiAffinity`, input.content)
	not regex.match(`topologySpreadConstraints`, input.content)

	result := {
		"rule": "safeguard-anti-affinity",
		"category": "compliance",
		"priority": 65,
		"severity": "warn",
		"message": "Workloads with more than one replica should set podAntiAffinity or topologySpreadConstraints to avoid disruptions when nodes crash. See https://aka.ms/aks/deployment-safeguards",
		"description": "AKS safeguard: anti-affinity or topology spread for multi-replica workloads",
		"safeguard": "anti-affinity",
	}
}

# ==============================================================================
# POLICY DECISION
# ==============================================================================

# Allow if no blocking violations
default allow := false

allow if {
	count(violations) == 0
}

# Suggestions set (reserved for future advisory safeguards)
suggestions := set()

# Final result structure
result := {
	"allow": allow,
	"violations": violations,
	"warnings": warnings,
	"suggestions": suggestions,
	"summary": {
		"total_violations": count(violations),
		"total_warnings": count(warnings),
		"total_suggestions": count(suggestions),
	},
}
