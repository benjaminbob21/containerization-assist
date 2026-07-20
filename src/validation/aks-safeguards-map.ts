/**
 * AKS Deployment Safeguards coverage map
 *
 * A single, programmatic source of truth that maps each AKS Deployment
 * Safeguard to:
 *   - the upstream Gatekeeper/Azure Policy constraint template that enforces it
 *     at admission time on the cluster, and
 *   - where Containerization Assist (CA) covers it at authoring time: the
 *     skill(s) that generate compliant manifests, the built-in Rego policy
 *     rule (evaluated by MCP tools via the WASM bundle), and the structural
 *     TypeScript validator rule (src/validation/kubernetes-validator.ts).
 *
 * See docs/aks-deployment-safeguards.md for the rendered table and rationale.
 * Reference: https://aka.ms/aks/deployment-safeguards
 */

export type SafeguardEnforcementPoint = 'authoring' | 'runtime-only';

export interface SafeguardCoverage {
  /** Stable identifier used across the Rego policy and TS validator. */
  id: string;
  /** Human-readable safeguard name (as it appears in AKS docs). */
  safeguard: string;
  /** Upstream AKS Gatekeeper constraint template kind. */
  constraintTemplate: string;
  /** Where CA can enforce this: at manifest authoring time, or only at cluster admission. */
  enforcementPoint: SafeguardEnforcementPoint;
  /** CA skills whose generated output satisfies this safeguard. */
  skills: string[];
  /** Built-in Rego policy rule id (containerization.aks_safeguards), if covered. */
  regoRule: string | null;
  /** Structural TypeScript validator rule id, if covered. */
  validatorRule: string | null;
  /** Short note on scope or limitations. */
  notes: string;
}

export const AKS_SAFEGUARDS: SafeguardCoverage[] = [
  {
    id: 'container-requests',
    safeguard: 'Containers CPU and memory resource requests must be defined',
    constraintTemplate: 'K8sAzureV1ContainerRequests',
    enforcementPoint: 'authoring',
    skills: ['generate-k8s-manifests', 'deploy-to-aks'],
    regoRule: 'safeguard-container-requests',
    validatorRule: 'aks-safeguard-resource-requests',
    notes: 'generate-k8s-manifests always emits requests and limits for production.',
  },
  {
    id: 'no-latest-image',
    safeguard: 'Container images should not include the latest image tag',
    constraintTemplate: 'K8sAzureV2ContainerNoLatestImage',
    enforcementPoint: 'authoring',
    skills: ['generate-k8s-manifests', 'deploy-to-aks'],
    regoRule: 'safeguard-no-latest-tag',
    validatorRule: 'aks-safeguard-no-latest-image',
    notes: 'Also covers untagged images, which default to :latest.',
  },
  {
    id: 'anti-affinity',
    safeguard: 'Must have anti-affinity rules or topologySpreadConstraints set',
    constraintTemplate: 'K8sAzureV1AntiAffinityRules',
    enforcementPoint: 'authoring',
    skills: ['generate-k8s-manifests'],
    regoRule: 'safeguard-anti-affinity',
    validatorRule: 'aks-safeguard-anti-affinity',
    notes: 'Only applies when replicas > 1.',
  },
  {
    id: 'enforce-probes',
    safeguard: 'Ensure cluster containers have readiness or liveness probes configured',
    constraintTemplate: 'K8sAzureV2ContainerEnforceProbes',
    enforcementPoint: 'authoring',
    skills: ['generate-k8s-manifests'],
    regoRule: 'safeguard-enforce-probes',
    validatorRule: 'aks-safeguard-enforce-probes',
    notes: 'Warning severity; generate-k8s-manifests omits probes only in development.',
  },
  {
    id: 'restricted-labels',
    safeguard: 'No AKS specific labels (kubernetes.azure.com/*)',
    constraintTemplate: 'K8sAzureV1RestrictedLabels',
    enforcementPoint: 'authoring',
    skills: ['generate-k8s-manifests'],
    regoRule: 'safeguard-restricted-labels',
    validatorRule: 'aks-safeguard-restricted-labels',
    notes: 'Checks both resource labels and pod-template labels.',
  },
  {
    id: 'csi-driver',
    safeguard: 'Clusters should use Container Storage Interface (CSI) driver StorageClass',
    constraintTemplate: 'K8sAzureV1EnforceCSIDriver',
    enforcementPoint: 'authoring',
    skills: ['generate-k8s-manifests'],
    regoRule: 'safeguard-csi-driver',
    validatorRule: 'aks-safeguard-csi-storageclass',
    notes: 'Blocks in-tree kubernetes.io/azure-disk and kubernetes.io/azure-file provisioners.',
  },
  {
    id: 'unique-service-selector',
    safeguard: 'Services should use unique selectors',
    constraintTemplate: 'K8sAzureV1UniqueServiceSelector',
    enforcementPoint: 'authoring',
    skills: ['generate-k8s-manifests'],
    regoRule: null,
    validatorRule: 'aks-safeguard-unique-service-selector',
    notes:
      'Cross-document check in the validator (needs all manifests). The runtime constraint also compares against existing cluster inventory.',
  },
  {
    id: 'no-privileged',
    safeguard: 'Privileged containers are disallowed (baseline Pod Security Standard)',
    constraintTemplate: 'K8sAzureV2NoPrivilege',
    enforcementPoint: 'authoring',
    skills: ['generate-k8s-manifests', 'deploy-to-aks'],
    regoRule: 'safeguard-no-privileged',
    validatorRule: 'no-privileged-containers',
    notes: 'Reuses the existing no-privileged-containers validator rule.',
  },
  {
    id: 'host-namespaces',
    safeguard: 'Host namespaces are disallowed (baseline Pod Security Standard)',
    constraintTemplate: 'K8sAzureV3BlockHostNamespace',
    enforcementPoint: 'authoring',
    skills: ['generate-k8s-manifests'],
    regoRule: 'safeguard-host-namespaces',
    validatorRule: 'aks-safeguard-host-namespaces',
    notes: 'Covers hostNetwork, hostPID, and hostIPC.',
  },
  {
    id: 'allowed-images',
    safeguard: 'Containers should only use allowed images',
    constraintTemplate: 'K8sAzureV*AllowedImages',
    enforcementPoint: 'authoring',
    skills: ['generate-dockerfile', 'fix-dockerfile'],
    regoRule: 'require-microsoft-images',
    validatorRule: null,
    notes:
      'Cluster-specific allow list. CA base-images.rego requires Microsoft Container Registry images at the Dockerfile layer.',
  },
  {
    id: 'restricted-node-edits',
    safeguard: 'Cannot edit individual nodes',
    constraintTemplate: 'K8sAzureV1RestrictedNodeEdits',
    enforcementPoint: 'runtime-only',
    skills: [],
    regoRule: null,
    validatorRule: null,
    notes:
      'Operates on Node objects and userInfo at admission time. Not expressible against a workload manifest; enforced by the cluster.',
  },
  {
    id: 'reserved-taints',
    safeguard: 'Reserved system pool taints',
    constraintTemplate: 'K8sAzureV1ReservedTaints',
    enforcementPoint: 'runtime-only',
    skills: [],
    regoRule: null,
    validatorRule: null,
    notes:
      'Operates on Node objects at admission time. Not expressible against a workload manifest; enforced by the cluster.',
  },
];

/** Safeguards that Containerization Assist can validate at manifest-authoring time. */
export const AUTHORING_SAFEGUARDS = AKS_SAFEGUARDS.filter(
  (s) => s.enforcementPoint === 'authoring',
);
