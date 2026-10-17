/**
 * Judges the ZAP reports in reports/zap (written by scripts/scan.ts):
 *
 * 1. The hardened build may only have alerts that zap/rules.tsv marks IGNORE (with a reason).
 * 2. In the vulnerable build, every planted defect that ZAP is responsible for (tests/detections.ts) must appear
 *    as its expected alert. A full-scan defect counts as "not checked" when only the baseline scan ran.
 *
 * Prints a Markdown summary (also into the GitHub Actions job summary) and exits 1 on any problem.
 *   npm run verify            after npm run scan or scan:full
 *   npm run verify -- --full  also fail when the full-scan reports are missing
 */
import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { DEFECTS } from '../app/defects.ts';
import { DETECTIONS } from '../tests/detections.ts';
import { describeAlert, parseReport, parseRules, unexpected, type Alert } from './zap-results.ts';

const DIR = join('reports', 'zap');
const rules = parseRules(readFileSync(join('zap', 'rules.tsv'), 'utf8'));

function report(name: string): Alert[] | undefined {
  const file = join(DIR, `${name}.json`);
  return existsSync(file) ? parseReport(readFileSync(file, 'utf8')) : undefined;
}

const scans = {
  hardenedBaseline: report('hardened-baseline'),
  hardenedFull: report('hardened-full'),
  vulnerableBaseline: report('vulnerable-baseline'),
  vulnerableFull: report('vulnerable-full'),
};
const requireFull = process.argv.includes('--full');
const problems: string[] = [];
const lines = ['## OWASP ZAP results', ''];

if (!scans.hardenedBaseline || !scans.vulnerableBaseline) {
  console.error(`No baseline reports in ${DIR}. Run npm run scan first.`);
  process.exit(1);
}
if (requireFull && (!scans.hardenedFull || !scans.vulnerableFull)) problems.push('full-scan reports are missing');

// 1. The hardened build.
lines.push('### Hardened build: only IGNORE alerts allowed', '', '| Scan | Alerts | Not allowed |', '|---|---:|---|');
for (const [scan, alerts] of [
  ['baseline', scans.hardenedBaseline],
  ['full', scans.hardenedFull],
] as const) {
  if (!alerts) {
    lines.push(`| ${scan} | not run | |`);
    continue;
  }
  const bad = unexpected(alerts, rules);
  problems.push(...bad.map((a) => `hardened ${scan}: ${describeAlert(a, rules)}`));
  lines.push(`| ${scan} | ${alerts.length} | ${bad.map((a) => describeAlert(a, rules)).join('<br>') || 'none'} |`);
}

// 2. The vulnerable build: every planted defect caught by the tool named for it.
lines.push('', '### Vulnerable build: every planted defect must be caught', '');
lines.push('| Defect | OWASP | Caught by | Result |', '|---|---|---|---|');
for (const defect of DEFECTS) {
  const detection = DETECTIONS[defect.id];
  let caughtBy: string;
  let result: string;
  if (detection.tool === 'api-test') {
    caughtBy = 'API test (npm test)';
    result = 'checked in tests/security.test.ts';
  } else {
    caughtBy = `ZAP ${detection.tool === 'zap-baseline' ? 'baseline' : 'full'} [${detection.ruleId}] ${detection.rule}`;
    const alerts = detection.tool === 'zap-baseline' ? scans.vulnerableBaseline : scans.vulnerableFull;
    const hit = alerts?.find((a) => a.ruleId === detection.ruleId);
    if (!alerts) result = 'not checked (run npm run scan:full)';
    else if (hit) result = `caught (${hit.count}x)`;
    else {
      result = '**missed**';
      problems.push(`vulnerable: ${defect.id} was not reported as [${detection.ruleId}]`);
    }
  }
  lines.push(`| ${defect.id} | ${defect.owasp} | ${caughtBy} | ${result} |`);
}

lines.push('', problems.length ? `**${problems.length} problem(s):**` : '**All checks passed.**', '');
lines.push(...problems.map((p) => `- ${p}`));
const markdown = lines.join('\n') + '\n';
console.log(markdown);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown);
process.exit(problems.length ? 1 : 0);
