/**
 * Scans both builds of NoteVault with OWASP ZAP, on a private Docker network: the deliberately vulnerable build is
 * never reachable from the host or the LAN.
 *
 *   npm run scan          ZAP baseline scan (passive: spider + look at every response) of both builds
 *   npm run scan:full     also the full scan (active attacks such as cross-site scripting) of both builds
 *   ... -- --build vulnerable   only one build (CI scans each build in its own job)
 *
 * Reports land in reports/zap/<build>-<scan>.json and .html; then scripts/verify.ts judges them.
 */
import { spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, mkdirSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { Build } from '../app/defects.ts';

const ZAP_IMAGE = 'ghcr.io/zaproxy/zaproxy:2.17.0';
const NODE_IMAGE = 'node:24.22.0-alpine';
const NETWORK = 'notevault-scan';
const REPORTS = resolve('reports', 'zap');
const ALL_BUILDS: { build: Build; port: number }[] = [
  { build: 'hardened', port: 4320 },
  { build: 'vulnerable', port: 4321 },
];
const only = process.argv[process.argv.indexOf('--build') + 1];
const BUILDS = process.argv.includes('--build') ? ALL_BUILDS.filter((b) => b.build === only) : ALL_BUILDS;
if (BUILDS.length === 0) throw new Error('--build must be hardened or vulnerable');

/** Runs docker with the given arguments; returns the exit code. Output goes to the console unless quiet. */
function docker(args: string[], quiet = false): number {
  const result = spawnSync('docker', args, { stdio: quiet ? 'ignore' : 'inherit', encoding: 'utf8' });
  if (result.error) throw new Error(`Could not run docker: ${result.error.message}`);
  return result.status ?? 1;
}

function containerName(build: Build): string {
  return `notevault-${build}`;
}

function startApps(): void {
  docker(['network', 'create', NETWORK], true); // fails harmlessly if it already exists
  for (const { build, port } of BUILDS) {
    docker(['rm', '-f', containerName(build)], true);
    const code = docker(
      [
        'run',
        '-d',
        '--rm',
        '--name',
        containerName(build),
        '--network',
        NETWORK,
        '-v',
        `${process.cwd()}:/app:ro`,
        '-w',
        '/app',
        NODE_IMAGE,
        'node',
        'app/server.ts',
        '--host',
        '0.0.0.0',
        '--port',
        String(port),
        '--build',
        build,
      ],
      true,
    );
    if (code !== 0) throw new Error(`Could not start ${containerName(build)}`);
  }
  // Wait until both answer (busybox wget is part of the Alpine image).
  for (const { build, port } of BUILDS) {
    const deadline = Date.now() + 30_000;
    while (docker(['exec', containerName(build), 'wget', '-q', '-O', '/dev/null', `http://127.0.0.1:${port}/`], true)) {
      if (Date.now() > deadline) throw new Error(`${containerName(build)} did not start`);
      spawnSync(process.execPath, ['-e', 'setTimeout(() => {}, 500)']);
    }
  }
}

function stopApps(): void {
  for (const { build } of BUILDS) docker(['rm', '-f', containerName(build)], true);
  docker(['network', 'rm', NETWORK], true);
}

/** One ZAP scan of one build. ZAP's own exit code only says pass/warn/fail; verify.ts makes the decision. */
function zapScan(script: 'zap-baseline.py' | 'zap-full-scan.py', build: Build, port: number): void {
  const name = `${build}-${script === 'zap-baseline.py' ? 'baseline' : 'full'}`;
  console.log(`\n=== ${name}: ${script} against ${containerName(build)} ===`);
  const code = docker([
    'run',
    '--rm',
    '--network',
    NETWORK,
    '-v',
    `${REPORTS}:/zap/wrk:rw`,
    ZAP_IMAGE,
    script,
    '-t',
    `http://${containerName(build)}:${port}`,
    '-c',
    'rules.tsv', // read from /zap/wrk, where it was copied
    '-J',
    `${name}.json`,
    '-r',
    `${name}.html`,
    '-m',
    '1', // spider for at most one minute: the app is small
    '-s', // short output: no list of passed rules
  ]);
  // 0 = no warnings, 1 = at least one FAIL, 2 = warnings only; 3 and above = ZAP itself had a problem.
  if (code > 2) throw new Error(`ZAP failed on ${name} (exit code ${code})`);
}

const full = process.argv.includes('--full');
// Keep the other build's reports when only one build is scanned.
for (const { build } of BUILDS) {
  for (const file of ['baseline.json', 'baseline.html', 'full.json', 'full.html']) {
    rmSync(join(REPORTS, `${build}-${file}`), { force: true });
  }
}
mkdirSync(REPORTS, { recursive: true });
chmodSync(REPORTS, 0o777); // ZAP runs as user "zap" (uid 1000) and must be able to write here on Linux
copyFileSync(join('zap', 'rules.tsv'), join(REPORTS, 'rules.tsv'));

try {
  startApps();
  for (const { build, port } of BUILDS) {
    zapScan('zap-baseline.py', build, port);
    if (full) zapScan('zap-full-scan.py', build, port);
  }
} finally {
  stopApps();
}
console.log(`\nReports in ${REPORTS}. Next: npm run verify`);
