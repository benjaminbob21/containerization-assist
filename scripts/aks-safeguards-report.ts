#!/usr/bin/env tsx
/**
 * AKS Deployment Safeguards Compliance Report
 *
 * Runs the Kubernetes validator against the compliant and non-compliant
 * manifest fixtures in test/fixtures/aks-safeguards/ and prints a per-manifest
 * and aggregate compliance report focused on the AKS Deployment Safeguards.
 *
 * The point of the report is to demonstrate — with numbers — that
 * safeguard-aware manifests (what `generate-k8s-manifests` produces) pass the
 * safeguards, while naive manifests fail. Run it with:
 *
 *   npm run safeguards:report
 *
 * See docs/guides/aks-deployment-safeguards.md.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createKubernetesValidator } from '../src/validation/kubernetes-validator';
import { AKS_SAFEGUARDS } from '../src/validation/aks-safeguards-map';
import type { ValidationResult } from '../src/validation/core-types';

const FIXTURES_DIR = join(process.cwd(), 'test', 'fixtures', 'aks-safeguards');

/** Validator rule ids that correspond to an AKS Deployment Safeguard. */
const SAFEGUARD_RULE_IDS = AKS_SAFEGUARDS.map((s) => s.validatorRule).filter(
  (id): id is string => id !== null,
);

interface ManifestReport {
  file: string;
  score: number;
  grade: string;
  safeguardChecks: number;
  safeguardFailures: number;
  failedSafeguards: string[];
}

/** True when a validation result belongs to an AKS safeguard rule. */
const isSafeguardResult = (result: ValidationResult): boolean =>
  SAFEGUARD_RULE_IDS.some((id) => result.ruleId?.endsWith(id));

function evaluateFixture(file: string, content: string): ManifestReport {
  const validator = createKubernetesValidator();
  const report = validator.validate(content);

  const safeguardResults = report.results.filter(isSafeguardResult);
  const failures = safeguardResults.filter((r) => !r.passed);

  return {
    file,
    score: report.score,
    grade: report.grade,
    safeguardChecks: safeguardResults.length,
    safeguardFailures: failures.length,
    failedSafeguards: [...new Set(failures.map((r) => r.ruleId ?? 'unknown'))],
  };
}

function readFixtures(dir: string): ManifestReport[] {
  const full = join(FIXTURES_DIR, dir);
  let files: string[] = [];
  try {
    files = readdirSync(full).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));
  } catch {
    return [];
  }
  return files.map((f) => evaluateFixture(`${dir}/${f}`, readFileSync(join(full, f), 'utf8')));
}

function pct(passed: number, total: number): number {
  return total === 0 ? 100 : Math.round((passed / total) * 100);
}

function printGroup(title: string, reports: ManifestReport[]): void {
  console.log(`\n${title}`);
  console.log('-'.repeat(78));
  for (const r of reports) {
    const passedChecks = r.safeguardChecks - r.safeguardFailures;
    const status = r.safeguardFailures === 0 ? '✅ PASS' : '❌ FAIL';
    console.log(
      `${status}  ${r.file.padEnd(46)} safeguards ${passedChecks}/${r.safeguardChecks}  score ${r.score} (${r.grade})`,
    );
    if (r.failedSafeguards.length > 0) {
      for (const failed of r.failedSafeguards) {
        console.log(`         ↳ ${failed}`);
      }
    }
  }
}

function aggregate(reports: ManifestReport[]): { checks: number; failures: number } {
  return reports.reduce(
    (acc, r) => ({
      checks: acc.checks + r.safeguardChecks,
      failures: acc.failures + r.safeguardFailures,
    }),
    { checks: 0, failures: 0 },
  );
}

function main(): void {
  console.log('='.repeat(78));
  console.log('🛡️  AKS Deployment Safeguards — Compliance Report');
  console.log('='.repeat(78));
  console.log(
    `Safeguards validated at authoring time: ${SAFEGUARD_RULE_IDS.length}` +
      ` (of ${AKS_SAFEGUARDS.length} total; 2 are runtime-only, 1 Dockerfile-layer).`,
  );

  const compliant = readFixtures('compliant');
  const noncompliant = readFixtures('noncompliant');

  if (compliant.length === 0 && noncompliant.length === 0) {
    console.error('\n❌ No fixtures found under test/fixtures/aks-safeguards/');
    process.exit(1);
  }

  printGroup('BEFORE — naive manifests (non-compliant fixtures)', noncompliant);
  printGroup('AFTER — safeguard-aware manifests (generate-k8s-manifests style)', compliant);

  const before = aggregate(noncompliant);
  const after = aggregate(compliant);
  const beforePct = pct(before.checks - before.failures, before.checks);
  const afterPct = pct(after.checks - after.failures, after.checks);

  console.log(`\n${'='.repeat(78)}`);
  console.log('📈 Compliance summary');
  console.log('-'.repeat(78));
  console.log(`  Naive manifests:            ${beforePct}% of safeguard checks pass`);
  console.log(`  Safeguard-aware manifests:  ${afterPct}% of safeguard checks pass`);
  console.log(`  Improvement:                +${afterPct - beforePct} percentage points`);
  console.log('='.repeat(78));

  // The suite is a demonstration, not a gate: exit non-zero only if the
  // safeguard-aware fixtures unexpectedly fail (i.e. a regression in the checks
  // or in what "compliant" means).
  if (after.failures > 0) {
    console.error('\n❌ A compliant fixture failed a safeguard check — investigate a regression.');
    process.exit(1);
  }
  console.log('\n✅ All safeguard-aware fixtures pass every safeguard check.');
}

main();
