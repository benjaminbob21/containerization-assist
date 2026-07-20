# AKS Deployment Safeguards in Containerization Assist

[AKS Deployment Safeguards](https://learn.microsoft.com/en-us/azure/aks/deployment-safeguards)
enforce Kubernetes best practices through Azure Policy / Gatekeeper admission
control. On **AKS Automatic** clusters they are enabled in **Enforce** mode by
default, so a manifest that violates a safeguard is **rejected at deploy time**.

Containerization Assist (CA) moves these checks **left**: it validates manifests
at authoring time so that `generate-k8s-manifests` and `deploy-to-aks` output
passes AKS Automatic admission on the first try, instead of failing after
`kubectl apply`.

## How the checks are implemented

Each safeguard is covered in up to three places:

1. **Rego policy** — `policies/aks-deployment-safeguards.rego`
   (package `containerization.aks_safeguards`). Compiled into the WASM bundle and
   evaluated by MCP tools alongside the other built-in policies. Uses the same
   raw-content evaluation model as `security-baseline.rego`.
2. **TypeScript validator** — `src/validation/kubernetes-validator.ts`
   (`ValidationCategory.COMPLIANCE`). Parses the YAML and mirrors the upstream
   **AKS Gatekeeper constraint templates** field-for-field, so the logic matches
   what the cluster actually enforces.
3. **Skills** — `generate-k8s-manifests` produces manifests that satisfy the
   safeguards by construction; `deploy-to-aks` performs AKS Automatic hardening
   before applying.

The programmatic source of truth for this mapping is
[`src/validation/aks-safeguards-map.ts`](../src/validation/aks-safeguards-map.ts).

## Coverage map

| Safeguard | Upstream constraint template | Enforcement point | Skills | Rego rule | Validator rule |
|---|---|---|---|---|---|
| Containers CPU/memory requests defined | `K8sAzureV1ContainerRequests` | authoring | generate-k8s-manifests, deploy-to-aks | `safeguard-container-requests` | `aks-safeguard-resource-requests` |
| No `:latest` image tag | `K8sAzureV2ContainerNoLatestImage` | authoring | generate-k8s-manifests, deploy-to-aks | `safeguard-no-latest-tag` | `aks-safeguard-no-latest-image` |
| Anti-affinity or topology spread | `K8sAzureV1AntiAffinityRules` | authoring | generate-k8s-manifests | `safeguard-anti-affinity` | `aks-safeguard-anti-affinity` |
| Readiness/liveness probes | `K8sAzureV2ContainerEnforceProbes` | authoring | generate-k8s-manifests | `safeguard-enforce-probes` | `aks-safeguard-enforce-probes` |
| No AKS-reserved labels (`kubernetes.azure.com/*`) | `K8sAzureV1RestrictedLabels` | authoring | generate-k8s-manifests | `safeguard-restricted-labels` | `aks-safeguard-restricted-labels` |
| CSI driver StorageClass | `K8sAzureV1EnforceCSIDriver` | authoring | generate-k8s-manifests | `safeguard-csi-driver` | `aks-safeguard-csi-storageclass` |
| Unique Service selectors | `K8sAzureV1UniqueServiceSelector` | authoring | generate-k8s-manifests | — | `aks-safeguard-unique-service-selector` |
| No privileged containers (baseline PSS) | `K8sAzureV2NoPrivilege` | authoring | generate-k8s-manifests, deploy-to-aks | `safeguard-no-privileged` | `no-privileged-containers` |
| No host namespaces (baseline PSS) | `K8sAzureV3BlockHostNamespace` | authoring | generate-k8s-manifests | `safeguard-host-namespaces` | `aks-safeguard-host-namespaces` |
| Allowed images only | `K8sAzureV*AllowedImages` | authoring | generate-dockerfile, fix-dockerfile | `require-microsoft-images` | — |
| Cannot edit individual nodes | `K8sAzureV1RestrictedNodeEdits` | runtime-only | — | — | — |
| Reserved system pool taints | `K8sAzureV1ReservedTaints` | runtime-only | — | — | — |

### Runtime-only safeguards

Two safeguards evaluate `Node` objects (and the requesting `userInfo`) at
admission time. They are not expressible against an application manifest, so CA
does not attempt to validate them — they remain enforced by the cluster. They
are listed here for completeness.

## Running the compliance suite

The suite runs the validator against compliant and non-compliant manifest
fixtures and reports a compliance score, demonstrating that safeguard-aware
manifests pass while naive ones fail:

```sh
npm run safeguards:report
```

Fixtures live in `test/fixtures/aks-safeguards/` (`compliant/` and
`noncompliant/`). Unit coverage for the individual rules is in
`test/unit/validation/kubernetes-validator.test.ts`.

## Reference

- AKS docs: <https://learn.microsoft.com/en-us/azure/aks/deployment-safeguards>
- Short link: <https://aka.ms/aks/deployment-safeguards>
