/**
 * Validation module exports - Functional API with Result<T> pattern
 */

export * from './core-types';

export {
  createKubernetesValidator,
  type KubernetesValidatorInstance,
} from './kubernetes-validator';
export {
  AKS_SAFEGUARDS,
  AUTHORING_SAFEGUARDS,
  type SafeguardCoverage,
  type SafeguardEnforcementPoint,
} from './aks-safeguards-map';
export type {
  ValidationResult,
  ValidationReport,
  ValidationSeverity,
  ValidationCategory,
  ValidationGrade,
  DockerfileValidationRule,
  KubernetesValidationRule,
} from './core-types';
