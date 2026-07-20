/**
 * Kubernetes validation using YAML parser (Functional)
 *
 * Invariant: All validation rules maintain backwards compatibility
 * Trade-off: Runtime YAML parsing cost over build-time validation for flexibility
 */

import { parse as parseYaml, parseAllDocuments } from 'yaml';
import { extractErrorMessage } from '@/lib/errors';
import {
  KubernetesValidationRule,
  KubernetesManifest,
  ValidationResult,
  ValidationReport,
  ValidationSeverity,
  ValidationCategory,
  ValidationGrade,
} from './core-types';

// Type definitions for Kubernetes resources
interface PodSpec {
  containers?: Container[];
  initContainers?: Container[];
  volumes?: Volume[];
  securityContext?: SecurityContext;
  hostNetwork?: boolean;
  hostPID?: boolean;
  hostIPC?: boolean;
  affinity?: {
    podAntiAffinity?: unknown;
  };
  topologySpreadConstraints?: unknown[];
}

interface Container {
  name?: string;
  resources?: {
    limits?: Record<string, string>;
    requests?: Record<string, string>;
  };
  securityContext?: SecurityContext;
  image?: string;
  imagePullPolicy?: string;
  livenessProbe?: Probe;
  readinessProbe?: Probe;
}

interface SecurityContext {
  runAsNonRoot?: boolean;
  readOnlyRootFilesystem?: boolean;
  capabilities?: {
    drop?: string[];
  };
  privileged?: boolean;
  runAsUser?: number;
  fsGroup?: number;
}

interface Volume {
  emptyDir?: Record<string, unknown>;
  [key: string]: unknown;
}

interface Probe {
  httpGet?: unknown;
  tcpSocket?: unknown;
  exec?: unknown;
}

interface WorkloadSpec {
  replicas?: number;
  template?: {
    metadata?: {
      labels?: Record<string, string>;
    };
    spec?: PodSpec;
  };
  jobTemplate?: {
    spec?: {
      template?: {
        spec?: PodSpec;
      };
    };
  };
  strategy?: {
    type?: string;
  };
}

export interface KubernetesValidatorInstance {
  validate(yamlContent: string): ValidationReport;
  getRules(): KubernetesValidationRule[];
  getCategory(category: ValidationCategory): KubernetesValidationRule[];
}

/**
 * Check if manifest is a workload type
 */
const isWorkload = (manifest: KubernetesManifest): boolean => {
  const workloadKinds = ['Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'Pod'];
  return manifest.kind ? workloadKinds.includes(manifest.kind) : false;
};

/**
 * Get pod spec from different workload types
 */
const getPodSpec = (manifest: KubernetesManifest): PodSpec | undefined => {
  if (manifest.kind === 'Pod') {
    return manifest.spec as PodSpec;
  }
  if (manifest.kind === 'Job' || manifest.kind === 'CronJob') {
    const spec = manifest.spec as WorkloadSpec;
    return spec?.jobTemplate?.spec?.template?.spec || spec?.template?.spec;
  }
  return (manifest.spec as WorkloadSpec)?.template?.spec;
};

/**
 * Get all containers from manifest
 */
const getContainers = (manifest: KubernetesManifest): Container[] => {
  const podSpec = getPodSpec(manifest);
  return [...(podSpec?.containers || []), ...(podSpec?.initContainers || [])];
};

/**
 * Get workload (non-init) containers only.
 * AKS probe enforcement (k8sazurev2containerenforceprobes) applies to
 * spec.containers and excludes initContainers.
 */
const getMainContainers = (manifest: KubernetesManifest): Container[] => {
  const podSpec = getPodSpec(manifest);
  return podSpec?.containers || [];
};

/**
 * Get the desired replica count for a workload, defaulting to 1.
 * Used by the anti-affinity safeguard (k8sazurev1antiaffinityrules), which
 * only fires when replicas > 1.
 */
const getReplicas = (manifest: KubernetesManifest): number => {
  const replicas = (manifest.spec as { replicas?: number })?.replicas;
  return typeof replicas === 'number' ? replicas : 1;
};

/**
 * Detect an image reference that resolves to the mutable ':latest' tag,
 * either explicitly (`repo:latest`) or implicitly (no tag / no digest).
 * Mirrors k8sazurev2containernolatestimage.
 */
const usesLatestImage = (image: string | undefined): boolean => {
  if (!image) return false;
  // A digest-pinned image (repo@sha256:...) is always explicit.
  if (image.includes('@sha256:')) return false;
  // Split off any registry-with-port (host:5000/repo) before checking the tag.
  const lastSlash = image.lastIndexOf('/');
  const nameAndTag = lastSlash >= 0 ? image.slice(lastSlash + 1) : image;
  const colon = nameAndTag.lastIndexOf(':');
  if (colon < 0) {
    // No tag at all -> defaults to :latest.
    return true;
  }
  const tag = nameAndTag.slice(colon + 1);
  return tag === 'latest';
};

/**
 * Kubernetes validation rules
 */
const KUBERNETES_RULES: KubernetesValidationRule[] = [
  {
    id: 'has-resource-limits',
    name: 'Resource limits defined',
    description: 'Containers must have CPU and memory limits defined',
    check: (manifest: KubernetesManifest) => {
      if (!isWorkload(manifest)) return true;

      const containers = getContainers(manifest);
      return containers.every((container) => {
        const resources = container.resources;
        return resources?.limits?.cpu && resources?.limits?.memory;
      });
    },
    message: 'Define CPU and memory limits for all containers',
    severity: ValidationSeverity.ERROR,
    fix: 'Add resources.limits.cpu and resources.limits.memory',
    category: ValidationCategory.BEST_PRACTICE,
  },

  {
    id: 'has-resource-requests',
    name: 'Resource requests defined',
    description: 'Containers should have resource requests for proper scheduling',
    check: (manifest: KubernetesManifest) => {
      if (!isWorkload(manifest)) return true;

      const containers = getContainers(manifest);
      return containers.every((container) => {
        const resources = container.resources;
        return resources?.requests?.cpu && resources?.requests?.memory;
      });
    },
    message: 'Define CPU and memory requests for proper scheduling',
    severity: ValidationSeverity.WARNING,
    fix: 'Add resources.requests.cpu and resources.requests.memory',
    category: ValidationCategory.BEST_PRACTICE,
  },

  {
    id: 'has-readiness-probe',
    name: 'Readiness probe configured',
    description: 'Containers should have readiness probes for traffic management',
    check: (manifest: KubernetesManifest) => {
      if (!isWorkload(manifest)) return true;

      const containers = getContainers(manifest);
      return containers.every((container) => container.readinessProbe);
    },
    message: 'Add readiness probe for traffic management',
    severity: ValidationSeverity.WARNING,
    fix: 'Add readinessProbe with httpGet, tcpSocket, or exec',
    category: ValidationCategory.BEST_PRACTICE,
  },

  {
    id: 'has-liveness-probe',
    name: 'Liveness probe configured',
    description: 'Containers should have liveness probes for auto-restart',
    check: (manifest: KubernetesManifest) => {
      if (!isWorkload(manifest)) return true;

      const containers = getContainers(manifest);
      // Liveness probes prevent zombie containers in production workloads
      return containers.some((container) => container.livenessProbe);
    },
    message: 'Consider adding liveness probe for auto-restart',
    severity: ValidationSeverity.INFO,
    fix: 'Add livenessProbe with httpGet, tcpSocket, or exec',
    category: ValidationCategory.BEST_PRACTICE,
  },

  {
    id: 'no-privileged-containers',
    name: 'No privileged containers',
    description: 'Containers should not run in privileged mode',
    check: (manifest: KubernetesManifest) => {
      if (!isWorkload(manifest)) return true;

      const containers = getContainers(manifest);
      return containers.every((container) => {
        const securityContext = container.securityContext;
        return !securityContext?.privileged;
      });
    },
    message: 'Containers should not run in privileged mode',
    severity: ValidationSeverity.ERROR,
    fix: 'Remove privileged: true or set to false',
    category: ValidationCategory.SECURITY,
  },

  {
    id: 'security-context-defined',
    name: 'Security context configured',
    description: 'Pods should define appropriate security context',
    check: (manifest: KubernetesManifest) => {
      if (!isWorkload(manifest)) return true;

      const podSpec = getPodSpec(manifest);
      const securityContext = podSpec?.securityContext;

      return !!(
        securityContext?.runAsNonRoot ||
        securityContext?.runAsUser ||
        securityContext?.fsGroup
      );
    },
    message: 'Define pod security context for better security',
    severity: ValidationSeverity.WARNING,
    fix: 'Add securityContext with runAsNonRoot: true and runAsUser',
    category: ValidationCategory.SECURITY,
  },

  {
    id: 'has-labels',
    name: 'Proper labeling',
    description: 'Resources should have meaningful labels',
    check: (manifest: KubernetesManifest) => {
      const labels = manifest.metadata?.labels;
      const hasAppLabel = labels?.app || labels?.['app.kubernetes.io/name'];
      return !!hasAppLabel;
    },
    message: 'Add meaningful labels for resource organization',
    severity: ValidationSeverity.INFO,
    fix: 'Add labels like app, version, component under metadata.labels',
    category: ValidationCategory.BEST_PRACTICE,
  },

  {
    id: 'image-pull-policy',
    name: 'Appropriate image pull policy',
    description: 'Image pull policy should match image tag strategy',
    check: (manifest: KubernetesManifest) => {
      if (!isWorkload(manifest)) return true;

      const containers = getContainers(manifest);
      return containers.every((container) => {
        const c = container;
        // :latest tags change content, requiring Always pull policy
        if (c.image?.includes(':latest')) {
          return c.imagePullPolicy === 'Always';
        }
        // Immutable tags don't need Always, reducing network overhead
        return true;
      });
    },
    message: 'Set appropriate imagePullPolicy for image tag strategy',
    severity: ValidationSeverity.INFO,
    fix: 'Use imagePullPolicy: Always for :latest, IfNotPresent for specific tags',
    category: ValidationCategory.BEST_PRACTICE,
  },

  {
    id: 'no-host-network',
    name: 'Avoid host networking',
    description: 'Pods should not use host networking unless necessary',
    check: (manifest: KubernetesManifest) => {
      if (!isWorkload(manifest)) return true;

      const podSpec = getPodSpec(manifest);
      return !podSpec?.hostNetwork;
    },
    message: 'Avoid hostNetwork unless absolutely necessary',
    severity: ValidationSeverity.WARNING,
    fix: 'Remove hostNetwork: true or use proper service exposure',
    category: ValidationCategory.SECURITY,
  },

  {
    id: 'no-host-path-volumes',
    name: 'Avoid hostPath volumes',
    description: 'Avoid mounting host directories unless necessary',
    check: (manifest: KubernetesManifest) => {
      if (!isWorkload(manifest)) return true;

      const podSpec = getPodSpec(manifest);
      const volumes = podSpec?.volumes || [];

      return !volumes.some((volume: Record<string, unknown>) => volume.hostPath);
    },
    message: 'Avoid hostPath volumes for better security',
    severity: ValidationSeverity.WARNING,
    fix: 'Use configMaps, secrets, or persistent volumes instead',
    category: ValidationCategory.SECURITY,
  },

  {
    id: 'service-has-selector',
    name: 'Service has proper selector',
    description: 'Services should have selectors to target pods',
    check: (manifest: KubernetesManifest) => {
      if (manifest.kind !== 'Service') return true;

      return !!(manifest.spec?.selector && Object.keys(manifest.spec.selector).length > 0);
    },
    message: 'Service should have selector to target pods',
    severity: ValidationSeverity.ERROR,
    fix: 'Add spec.selector with labels matching your pods',
    category: ValidationCategory.BEST_PRACTICE,
  },

  {
    id: 'deployment-has-strategy',
    name: 'Deployment strategy defined',
    description: 'Deployments should define update strategy',
    check: (manifest: KubernetesManifest) => {
      if (manifest.kind !== 'Deployment') return true;

      return !!(manifest.spec as WorkloadSpec)?.strategy?.type;
    },
    message: 'Define deployment strategy for updates',
    severity: ValidationSeverity.INFO,
    fix: 'Add strategy.type (RollingUpdate or Recreate)',
    category: ValidationCategory.BEST_PRACTICE,
  },

  // ===========================================================================
  // AKS DEPLOYMENT SAFEGUARDS
  //
  // These rules mirror the AKS Gatekeeper constraint templates that AKS
  // Automatic enforces by default (Enforce mode). Catching them here means a
  // generated manifest passes AKS Automatic admission on the first deploy.
  // See docs/aks-deployment-safeguards.md and https://aka.ms/aks/deployment-safeguards
  // ===========================================================================

  {
    // Upstream: k8sazurev1containerrequests
    id: 'aks-safeguard-resource-requests',
    name: 'AKS safeguard: container resource requests',
    description: 'Every container must define CPU and memory resource requests',
    check: (manifest: KubernetesManifest) => {
      if (!isWorkload(manifest)) return true;

      const containers = getContainers(manifest);
      if (containers.length === 0) return true;
      return containers.every((container) => {
        const requests = container.resources?.requests;
        return !!(requests?.cpu && requests?.memory);
      });
    },
    message: 'Define CPU and memory requests on every container (AKS Deployment Safeguards)',
    severity: ValidationSeverity.ERROR,
    fix: 'Add resources.requests.cpu and resources.requests.memory to each container',
    category: ValidationCategory.COMPLIANCE,
  },

  {
    // Upstream: k8sazurev2containernolatestimage
    id: 'aks-safeguard-no-latest-image',
    name: 'AKS safeguard: no ":latest" image tag',
    description: 'Container images must use an explicit version tag, not :latest or untagged',
    check: (manifest: KubernetesManifest) => {
      if (!isWorkload(manifest)) return true;

      const containers = getContainers(manifest);
      return containers.every((container) => !usesLatestImage(container.image));
    },
    message: 'Use an explicit, versioned image tag instead of :latest (AKS Deployment Safeguards)',
    severity: ValidationSeverity.ERROR,
    fix: 'Pin each container image to an explicit version tag, e.g. myapp:1.2.3',
    category: ValidationCategory.COMPLIANCE,
  },

  {
    // Upstream: k8sazurev1antiaffinityrules
    id: 'aks-safeguard-anti-affinity',
    name: 'AKS safeguard: anti-affinity or topology spread',
    description:
      'Multi-replica workloads must set podAntiAffinity or topologySpreadConstraints to survive node failures',
    check: (manifest: KubernetesManifest) => {
      if (!isWorkload(manifest)) return true;
      if (getReplicas(manifest) <= 1) return true;

      const podSpec = getPodSpec(manifest);
      const hasAntiAffinity = !!podSpec?.affinity?.podAntiAffinity;
      const hasTopologySpread =
        Array.isArray(podSpec?.topologySpreadConstraints) &&
        podSpec.topologySpreadConstraints.length > 0;
      return hasAntiAffinity || hasTopologySpread;
    },
    message:
      'Set podAntiAffinity or topologySpreadConstraints on workloads with more than one replica (AKS Deployment Safeguards)',
    severity: ValidationSeverity.ERROR,
    fix: 'Add spec.template.spec.affinity.podAntiAffinity or spec.template.spec.topologySpreadConstraints',
    category: ValidationCategory.COMPLIANCE,
  },

  {
    // Upstream: k8sazurev2containerenforceprobes
    id: 'aks-safeguard-enforce-probes',
    name: 'AKS safeguard: readiness and liveness probes',
    description: 'Every workload container should define readiness and liveness probes',
    check: (manifest: KubernetesManifest) => {
      if (!isWorkload(manifest)) return true;

      const containers = getMainContainers(manifest);
      if (containers.length === 0) return true;
      return containers.every(
        (container) => !!container.readinessProbe && !!container.livenessProbe,
      );
    },
    message: 'Add readinessProbe and livenessProbe to every container (AKS Deployment Safeguards)',
    severity: ValidationSeverity.WARNING,
    fix: 'Define readinessProbe and livenessProbe (httpGet, tcpSocket, or exec) on each container',
    category: ValidationCategory.COMPLIANCE,
  },

  {
    // Upstream: k8sazurev1restrictedlabels
    id: 'aks-safeguard-restricted-labels',
    name: 'AKS safeguard: no AKS-reserved labels',
    description: 'Labels under kubernetes.azure.com/ are reserved for AKS and must not be set',
    check: (manifest: KubernetesManifest) => {
      const reserved = (labels?: Record<string, string>): boolean =>
        !!labels && Object.keys(labels).some((key) => key.startsWith('kubernetes.azure.com/'));

      const podTemplateLabels = (manifest.spec as WorkloadSpec)?.template?.metadata?.labels;
      return !reserved(manifest.metadata?.labels) && !reserved(podTemplateLabels);
    },
    message: 'Remove labels under kubernetes.azure.com/ — they are reserved for AKS use only',
    severity: ValidationSeverity.ERROR,
    fix: 'Delete any kubernetes.azure.com/* labels from metadata.labels and pod template labels',
    category: ValidationCategory.COMPLIANCE,
  },

  {
    // Upstream: k8sazurev3blockhostnamespace (baseline Pod Security Standard)
    id: 'aks-safeguard-host-namespaces',
    name: 'AKS safeguard: no host namespaces',
    description: 'hostNetwork, hostPID, and hostIPC are disallowed under the baseline PSS',
    check: (manifest: KubernetesManifest) => {
      if (!isWorkload(manifest)) return true;

      const podSpec = getPodSpec(manifest);
      return !podSpec?.hostNetwork && !podSpec?.hostPID && !podSpec?.hostIPC;
    },
    message: 'Do not set hostNetwork, hostPID, or hostIPC to true (AKS Deployment Safeguards)',
    severity: ValidationSeverity.ERROR,
    fix: 'Remove hostNetwork/hostPID/hostIPC or set them to false',
    category: ValidationCategory.COMPLIANCE,
  },

  {
    // Upstream: k8sazurev1enforcecsidriver
    id: 'aks-safeguard-csi-storageclass',
    name: 'AKS safeguard: CSI driver StorageClass',
    description: 'StorageClasses must use a CSI provisioner, not an in-tree Azure provisioner',
    check: (manifest: KubernetesManifest) => {
      if (manifest.kind !== 'StorageClass') return true;

      const provisioner = (manifest as { provisioner?: string }).provisioner;
      const inTree = ['kubernetes.io/azure-disk', 'kubernetes.io/azure-file'];
      return !provisioner || !inTree.includes(provisioner);
    },
    message:
      'Use a CSI StorageClass provisioner (disk.csi.azure.com or file.csi.azure.com), not an in-tree provisioner (AKS Deployment Safeguards)',
    severity: ValidationSeverity.ERROR,
    fix: 'Set provisioner to disk.csi.azure.com or file.csi.azure.com',
    category: ValidationCategory.COMPLIANCE,
  },
];

/**
 * Parse YAML documents from content
 */
const parseDocuments = (yamlContent: string): KubernetesManifest[] => {
  // YAML allows multiple K8s resources separated by ---
  const parts = yamlContent.split(/^---\s*$/m);
  const documents: KubernetesManifest[] = [];

  for (const part of parts) {
    const trimmed = part.trim();
    if (trimmed) {
      try {
        const doc = parseYaml(trimmed);
        if (doc && typeof doc === 'object') {
          documents.push(doc);
        }
      } catch {
        // Ignore parsing errors for individual documents
      }
    }
  }

  return documents;
};

/**
 * Calculate validation grade from score
 */
const calculateGrade = (score: number): ValidationGrade => {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
};

/**
 * Create validation report from results
 */
const createReport = (results: ValidationResult[]): ValidationReport => {
  const errors = results.filter(
    (r) => !r.passed && r.metadata?.severity === ValidationSeverity.ERROR,
  ).length;
  const warnings = results.filter(
    (r) => !r.passed && r.metadata?.severity === ValidationSeverity.WARNING,
  ).length;
  const info = results.filter(
    (r) => !r.passed && r.metadata?.severity === ValidationSeverity.INFO,
  ).length;
  const passed = results.filter((r) => r.passed).length;
  const total = results.length;

  // Weighted scoring prioritizes security and correctness over style
  const score = Math.max(0, 100 - errors * 15 - warnings * 5 - info * 2);
  const grade = calculateGrade(score);

  return {
    results,
    score,
    grade,
    passed,
    failed: total - passed,
    errors,
    warnings,
    info,
    timestamp: new Date().toISOString(),
  };
};

/**
 * Cross-document AKS safeguard: unique Service selectors.
 * Mirrors k8sazurev1uniqueserviceselector — flags Services in the same
 * namespace that share an identical selector.
 */
const checkUniqueServiceSelectors = (documents: KubernetesManifest[]): ValidationResult[] => {
  const results: ValidationResult[] = [];
  const services = documents.filter(
    (doc) => doc.kind === 'Service' && doc.spec?.selector && typeof doc.spec.selector === 'object',
  );

  const flatten = (selector: Record<string, unknown>): string =>
    Object.keys(selector)
      .sort()
      .map((key) => `${key}:${String(selector[key])}`)
      .join(',');

  for (const service of services) {
    const namespace = service.metadata?.namespace || 'default';
    const name = service.metadata?.name || 'Service';
    const selector = flatten(service.spec?.selector as Record<string, unknown>);

    const collision = services.find(
      (other) =>
        other !== service &&
        (other.metadata?.namespace || 'default') === namespace &&
        flatten(other.spec?.selector as Record<string, unknown>) === selector,
    );

    const passed = !collision;
    results.push({
      ruleId: `${name}-aks-safeguard-unique-service-selector`,
      isValid: passed,
      passed,
      errors: passed
        ? []
        : [
            `[${name}] AKS safeguard: unique Service selector: shares selector with Service ${collision?.metadata?.name} in namespace ${namespace}`,
          ],
      warnings: [],
      message: passed
        ? `✓ [${name}] AKS safeguard: unique Service selector`
        : `✗ [${name}] AKS safeguard: unique Service selector: collides with ${collision?.metadata?.name}`,
      suggestions: passed ? [] : ['Give each Service a unique spec.selector within its namespace'],
      metadata: {
        severity: ValidationSeverity.ERROR,
        location: `Service/${name}`,
      },
    });
  }

  return results;
};

/**
 * Validate Kubernetes YAML content
 */
const validateKubernetesContent = (yamlContent: string): ValidationReport => {
  try {
    try {
      // Use parseAllDocuments so multi-document manifests (resources separated
      // by `---`) are treated as valid syntax rather than throwing. parse()
      // rejects multi-document input, which real K8s manifest sets routinely use.
      const parsedDocs = parseAllDocuments(yamlContent);
      const fatal = parsedDocs.flatMap((doc) => doc.errors);
      if (fatal.length > 0 && fatal[0]) {
        throw fatal[0];
      }
    } catch (parseError) {
      return {
        results: [
          {
            ruleId: 'parse-error',
            isValid: false,
            passed: false,
            errors: [`Failed to parse YAML: ${extractErrorMessage(parseError)}`],
            warnings: [],
            message: `Failed to parse YAML: ${extractErrorMessage(parseError)}`,
            metadata: {
              severity: ValidationSeverity.ERROR,
            },
          },
        ],
        score: 0,
        grade: 'F',
        passed: 0,
        failed: 1,
        errors: 1,
        warnings: 0,
        info: 0,
        timestamp: new Date().toISOString(),
      };
    }

    // Extract all K8s resources from potentially multi-document YAML
    const documents = parseDocuments(yamlContent);

    if (documents.length === 0) {
      return {
        results: [
          {
            ruleId: 'no-documents',
            isValid: false,
            passed: false,
            errors: ['No valid Kubernetes documents found'],
            warnings: [],
            message: 'No valid Kubernetes documents found',
            metadata: {
              severity: ValidationSeverity.ERROR,
            },
          },
        ],
        score: 0,
        grade: 'F',
        passed: 0,
        failed: 1,
        errors: 1,
        warnings: 0,
        info: 0,
        timestamp: new Date().toISOString(),
      };
    }

    const allResults: ValidationResult[] = [];
    let validDocumentCount = 0;

    for (const doc of documents) {
      if (!doc.apiVersion || !doc.kind) continue;

      validDocumentCount++;

      for (const rule of KUBERNETES_RULES) {
        const passed = rule.check(doc);
        const resourceName = doc.metadata?.name || doc.kind;

        allResults.push({
          ruleId: `${resourceName}-${rule.id}`,
          isValid: passed,
          passed,
          errors: passed ? [] : [`[${resourceName}] ${rule.name}: ${rule.message}`],
          warnings: [],
          message: passed
            ? `✓ [${resourceName}] ${rule.name}`
            : `✗ [${resourceName}] ${rule.name}: ${rule.message}`,
          suggestions: !passed && rule.fix ? [rule.fix] : [],
          metadata: {
            severity: rule.severity,
            location: `${doc.kind}/${resourceName}`,
          },
        });
      }
    }

    // Cross-document AKS safeguard: unique Service selectors
    // (k8sazurev1uniqueserviceselector). Two Services in the same namespace
    // with identical selectors collide at admission time.
    for (const result of checkUniqueServiceSelectors(documents)) {
      allResults.push(result);
    }

    // Fail-fast if content parses as YAML but contains no K8s resources
    if (validDocumentCount === 0) {
      return {
        results: [
          {
            ruleId: 'no-documents',
            isValid: false,
            passed: false,
            errors: ['No valid Kubernetes documents found'],
            warnings: [],
            message: 'No valid Kubernetes documents found',
            metadata: {
              severity: ValidationSeverity.ERROR,
            },
          },
        ],
        score: 0,
        grade: 'F',
        passed: 0,
        failed: 1,
        errors: 1,
        warnings: 0,
        info: 0,
        timestamp: new Date().toISOString(),
      };
    }

    return createReport(allResults);
  } catch (error) {
    return {
      results: [
        {
          ruleId: 'parse-error',
          isValid: false,
          passed: false,
          errors: [`Failed to parse YAML: ${extractErrorMessage(error)}`],
          warnings: [],
          message: `Failed to parse YAML: ${extractErrorMessage(error)}`,
          metadata: {
            severity: ValidationSeverity.ERROR,
          },
        },
      ],
      score: 0,
      grade: 'F',
      passed: 0,
      failed: 1,
      errors: 1,
      warnings: 0,
      info: 0,
      timestamp: new Date().toISOString(),
    };
  }
};

/**
 * Get all Kubernetes validation rules
 */
const getKubernetesRules = (): KubernetesValidationRule[] => {
  return [...KUBERNETES_RULES];
};

/**
 * Get Kubernetes rules by category
 */
const getKubernetesRulesByCategory = (category: ValidationCategory): KubernetesValidationRule[] => {
  return KUBERNETES_RULES.filter((rule) => rule.category === category);
};

/**
 * Create a Kubernetes validator factory
 */
export const createKubernetesValidator = (): KubernetesValidatorInstance => {
  return {
    validate: validateKubernetesContent,
    getRules: getKubernetesRules,
    getCategory: getKubernetesRulesByCategory,
  };
};

/**
 * Standalone validation function for simple use cases
 */
