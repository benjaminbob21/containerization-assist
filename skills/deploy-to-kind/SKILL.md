---
name: deploy-to-kind
description: End-to-end orchestrator that takes a source repository through analysis → Dockerfile → image build → security scan → local Kind cluster prep → local registry push → Kubernetes manifests → deploy → verify on a **local Kind cluster** (no Azure required). Use when the user says "deploy to kind", "test locally", "spin up a local cluster", "kind dev loop", "containerize and run locally", or otherwise asks for a complete repo-to-running-pod workflow that does NOT need AKS or ACR. No Azure inputs required. Optional: namespace, image name.
---

# Deploy to Kind

> **STOP — read this entire file before doing anything else.**
>
> 1. Before running **any** step, always come back to read this SKILL.md from top to bottom. Do not skim. Do not start from a section title.
> 2. Before executing each numbered step, re-read that step's full text (including its sub-bullets and the "Skill / tool catalog" row for that step at the bottom of this file). The catalog tells you exactly **which skill or which tool** to invoke — do **not** guess from the step heading alone.
> 3. Several skills (`analyze-repo`, `generate-dockerfile`, `fix-dockerfile`, `generate-k8s-manifests`) share a name with an MCP tool. When a step says "invoke the **X** skill", you MUST read `skills/X/SKILL.md` and follow that skill's procedure — do **not** call the MCP tool of the same name. The skills wrap the tools with user-confirmation, monorepo-selection, retry, and chaining logic this loop depends on; the bare tools skip all of that.
> 4. If you have not read the step's text in this turn, do not call any tool. Re-read first.

You are driving a **full repository → running pod on a local Kind cluster** iteration loop. This skill **orchestrates** other skills and tools — it does not duplicate their logic. Invoke each downstream piece by name and pass results forward.

This is the local-only counterpart to `deploy-to-aks`. Use it for fast iteration without needing Azure credentials, an ACR, or a remote AKS cluster.

## Inputs

Collect (ask the user once if any are missing):

- `namespace` (optional) — defaults to a unique name like `dev-<short-hash>`
- `imageName` (optional) — defaults to the repo directory name
- `repoPath` — the **current working directory** (confirm with user)
- `targetPlatform` — detect the **local system architecture** automatically (`uname -m` → `linux/amd64` or `linux/arm64`)
- `environment` — fixed `development`

After collection, **echo back the resolved values** in one block and ask the user to confirm before running Step 1.

## Prerequisites

Before Step 1, verify the local toolchain is available:

- `docker --version` — must succeed; if not, tell the user to install Docker Desktop / Docker Engine. STOP.
- `kind --version` — must succeed; if not, point them to https://kind.sigs.k8s.io/docs/user/quick-start/#installation. STOP.
- `kubectl version --client` — must succeed; if not, install kubectl. STOP.

## Workflow

Run the steps strictly in order. **Retry each step up to 2 times** before halting. Keep the user informed after every step.

### Step 1 — Validate the kubeconfig context targets the Kind cluster

1. Run `kubectl config current-context` to read the active context.
2. The expected context for a containerization-assist Kind cluster is `kind-containerization-assist`.
3. If the active context does **not** match:
   - Run `kind get clusters` to check whether the `containerization-assist` cluster exists.
   - If it exists, switch context: `kubectl config use-context kind-containerization-assist`.
   - If it does not exist, note that — Step 6 (`prepare-cluster`) will create it.
4. If the active context already matches, verify connectivity: `kubectl get nodes --no-headers`.
   - If this fails, the cluster may be stopped or deleted — Step 6 will recreate it.

### Step 2 — Analyze the repository

> **Required action:** open `skills/analyze-repo/SKILL.md` with your file-read tool and execute its procedure. **The `analyze-repo` skill is the only permitted way to perform this step** — do not call the `analyze-repo` MCP tool directly, do not improvise your own analysis, do not skip ahead.

- Confirm the detected language, framework, modules, existing Dockerfiles, `detectedDatabases`, and `detectedEnvVars` with the user.
- For monorepos, list independently deployable modules and ask which one(s) to target.
- Forward the full analysis JSON to every later step that needs it.

### Step 3 — Generate or remediate the Dockerfile

For each target module:

- If **no Dockerfile exists**:
  > **Required action:** open `skills/generate-dockerfile/SKILL.md` with your file-read tool and execute its procedure with the analysis context, environment `development`, and the local system platform. **The `generate-dockerfile` skill is the only permitted way to author the Dockerfile**.
- If **a Dockerfile exists**:
  > **Required action:** open `skills/fix-dockerfile/SKILL.md` with your file-read tool and execute its procedure against the existing Dockerfile. **The `fix-dockerfile` skill is the only permitted way to remediate Dockerfiles** — do not call the `fix-dockerfile` MCP tool directly and do not hand-edit the Dockerfile.

Retry up to 2 times if generation/remediation fails.

### Step 4 — Build the image

1. Detect platform once: parse `uname -m` (`x86_64` → `linux/amd64`, `aarch64` / `arm64` → `linux/arm64`).
2. Call the **`build-image-context`** tool with:
   - `path` = repo (or module) path
   - `imageName` = `<imageName>:latest` (or a derived tag)
   - `platform` = the detected local platform (do **NOT** force `linux/amd64`)
3. Execute the returned build command to produce the local Docker image.
4. On failure:
   - If the failure looks Dockerfile-related (syntax, missing files, base image not found, dependency error): open `skills/fix-dockerfile/SKILL.md` with your file-read tool and execute its procedure against the current Dockerfile, then retry. **The `fix-dockerfile` skill is the only permitted remediation path** — do not hand-edit the Dockerfile or call the MCP tool of the same name directly.
   - Otherwise retry the build directly.
   - Maximum **2 retries** per failure mode.

### Step 5 — Scan the image

1. Call the **`scan-image`** tool with the built image ID.
2. Review vulnerabilities.
3. If any **critical** or **high** issues are reported: open `skills/fix-dockerfile/SKILL.md` with your file-read tool and execute its procedure using the scan results as context, then rebuild (Step 4) and rescan. **The `fix-dockerfile` skill is the only permitted remediation path** — do not hand-edit the Dockerfile or call the MCP tool of the same name directly. Loop **up to 2 times**.
4. For local Kind development, the user may choose to accept high findings to keep iterating — surface them clearly but do not block unless they ask you to.

### Step 6 — Prepare the Kind cluster

1. Call the **`prepare-cluster`** tool with:
   - `clusterType: "kind"` (creates a local Kind cluster with a local container registry sidecar)
   - `namespace`: `<namespace>`
   - `targetPlatform`: the local system architecture from Step 4
2. **Capture the local registry address** from the tool's result (e.g. `localhost:5000` or `localhost:6XXX`). Hold onto it as `localRegistry` — Steps 7, 8, and 9 all need it.
3. Retry up to 2 times on failure.
4. Sanity-check after prepare: `kubectl get nodes --no-headers` should list at least one Kind node.

### Step 7 — Tag the image for the local registry

1. Call the **`tag-image`** tool to produce `<localRegistry>/<imageName>:<tag>` (use the exact `localRegistry` returned by Step 6 — do not invent or hard-code a different address).
2. Retry up to 2 times.

### Step 8 — Push the image to the local registry

1. Call the **`push-image`** tool to push the tagged image to `<localRegistry>` (same address as Step 7).
2. Retry up to 2 times.
3. Local registries don't require auth, so any "unauthorized" error means the registry is unreachable — verify it's running with `docker ps | grep registry` before retrying.

### Step 9 — Generate Kubernetes manifests (if missing)

If no manifests exist for the target module(s):

> **Required action:** open `skills/generate-k8s-manifests/SKILL.md` with your file-read tool and execute its procedure with the parameters listed below. **The `generate-k8s-manifests` skill is the only permitted way to produce manifests for this step** — do not call the `generate-k8s-manifests` MCP tool directly and do not template YAML by hand.

1. Parameters to pass to the skill:
   - `modulePath` = target module path
   - `namespace` = `<namespace>`
   - `environment` = `development`
   - `image` = `<localRegistry>/<imageName>:<tag>` (use the **local registry address from Step 6**, not a placeholder)
   - `detectedDatabases` and `detectedEnvVars` from Step 2
2. The skill writes one YAML file per resource to `<modulePath>/k8s/`.
3. Because `environment == development`, the skill will skip liveness/readiness probes by default. That's fine for local iteration. If the user wants probes locally, ask them to re-run with `environment: production`.

### Step 10 — Deploy

1. Ensure the namespace exists (idempotent): `kubectl create namespace <namespace> --dry-run=client -o yaml | kubectl apply -f -`.
2. Apply manifests: `kubectl apply -f <modulePath>/k8s/ --namespace <namespace>`.
3. Retry up to 2 times.

### Step 11 — Verify

1. Call the **`verify-deploy`** tool with `<namespace>` to check pod status, readiness, and events.
2. On failure: inspect pod logs and events, fix the underlying issue (re-run an earlier step if needed), redeploy. Retry up to 2 times.
3. Report how the user can access the service locally:
   - `kubectl port-forward -n <namespace> svc/<appName> 8080:80` for ClusterIP services.
   - Note the NodePort if one was emitted.

## Tool / skill catalog used by this loop

| Step | Component | Kind |
| --- | --- | --- |
| 2 | `analyze-repo` | skill |
| 3 (gen) | `generate-dockerfile` | skill |
| 3 (fix), 4 (on-fail), 5 (on-vuln) | `fix-dockerfile` | skill |
| 4 | `build-image-context` | tool |
| 5 | `scan-image` | tool |
| 6 | `prepare-cluster` | tool |
| 7 | `tag-image` | tool |
| 8 | `push-image` | tool |
| 9 | `generate-k8s-manifests` | skill |
| 11 | `verify-deploy` | tool |

## Rules

- **Skill steps are exclusive.** Steps 2, 3, 4 (on-fail), 5 (on-vuln), and 9 require a named skill. For each of these you MUST (a) open that skill's `SKILL.md` with your file-read tool in the current turn and (b) execute its procedure. Calling the MCP tool of the same name, improvising your own implementation, or hand-editing artifacts is not permitted.
- **Always retry a failed step up to 2 times** before halting and reporting.
- After every step, send a short status line to the user (`✅ Step N — <heading>`).
- Use the **local system architecture** for every platform parameter — do not force `linux/amd64`.
- Always use the exact `localRegistry` address returned by Step 6 in Steps 7, 8, and 9. Never invent or assume a port.
- Local Kind has no Azure dependencies — do **NOT** run `az`, `az aks`, `az acr`, or any RBAC checks.
- If a tool or skill returns chain hints / next-step suggestions, follow them.
- When using `vscode_askQuestions` for pickers, always include a free-text input fallback.
- Do not invent commands or registry addresses. If something is unclear, ask.

## Final report

After Step 11 passes, summarize:

1. Kind cluster name, namespace, local registry address, image reference.
2. Deployed resources (deployment, service, configmap, secret, etc. as applicable).
3. How to access the service (port-forward command).
4. How to tear it all down when done:
   - `kubectl delete namespace <namespace>` — removes the app.
   - `kind delete cluster --name containerization-assist` — removes the entire local cluster.
