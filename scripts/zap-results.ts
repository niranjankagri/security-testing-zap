/**
 * Reading ZAP's JSON reports and the rules file, and judging them. Pure functions: unit-tested in tests/unit.test.ts.
 */

export type Action = 'FAIL' | 'WARN' | 'IGNORE' | 'INFO';

export interface Alert {
  ruleId: string;
  name: string;
  /** ZAP's risk: Informational, Low, Medium, High. */
  risk: string;
  /** How many requests showed it. */
  count: number;
  /** Up to three example URLs. */
  examples: string[];
}

interface ZapJson {
  site?: { alerts?: { pluginid: string; name: string; riskdesc: string; instances?: { uri?: string }[] }[] }[];
}

/** All alerts of a ZAP JSON report (zap-baseline.py -J / zap-full-scan.py -J). */
export function parseReport(json: string): Alert[] {
  const report = JSON.parse(json) as ZapJson;
  return (report.site ?? []).flatMap((site) =>
    (site.alerts ?? []).map((alert) => ({
      ruleId: alert.pluginid,
      name: alert.name,
      risk: alert.riskdesc.split(' ')[0] ?? alert.riskdesc,
      count: alert.instances?.length ?? 0,
      examples: (alert.instances ?? []).slice(0, 3).map((i) => i.uri ?? ''),
    })),
  );
}

/** Rule id to action, from zap/rules.tsv. Lines starting with # are comments. */
export function parseRules(tsv: string): Map<string, Action> {
  const rules = new Map<string, Action>();
  for (const line of tsv.split('\n')) {
    if (!line.trim() || line.startsWith('#')) continue;
    const [id, action] = line.split('\t');
    if (!id || !/^\d+$/.test(id) || !['FAIL', 'WARN', 'IGNORE', 'INFO'].includes(action ?? '')) {
      throw new Error(`Bad line in rules.tsv: ${line}`);
    }
    rules.set(id, action as Action);
  }
  return rules;
}

/**
 * Alerts the hardened build must not have: every FAIL alert, and every WARN alert with a risk above Informational.
 * A warning on the hardened build is either a new problem or a rule that needs a decision (fix it, or IGNORE it with
 * a reason in rules.tsv), and neither should pass silently. Informational alerts are notes, not problems (ZAP does
 * not count them as warnings either), unless their rule is marked FAIL.
 */
export function unexpected(alerts: Alert[], rules: Map<string, Action>): Alert[] {
  return alerts.filter((alert) => {
    const action = rules.get(alert.ruleId) ?? 'WARN';
    if (action === 'FAIL') return true;
    return action === 'WARN' && alert.risk !== 'Informational';
  });
}

/** One line per alert, for messages and summaries. */
export function describeAlert(alert: Alert, rules?: Map<string, Action>): string {
  const action = rules ? ` ${rules.get(alert.ruleId) ?? 'WARN'}` : '';
  return `[${alert.ruleId}]${action} ${alert.name} (${alert.risk}, ${alert.count}x)`;
}
