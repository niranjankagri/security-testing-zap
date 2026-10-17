// Unit tests for the report logic and the defect catalogue (node:test, no Docker): npm test
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { DEFECTS, defectsOf } from '../app/defects.ts';
import { describeAlert, parseReport, parseRules, unexpected } from '../scripts/zap-results.ts';
import { DETECTIONS } from './detections.ts';

const REPORT = JSON.stringify({
  site: [
    {
      alerts: [
        { pluginid: '10038', name: 'CSP Header Not Set', riskdesc: 'Medium (High)', instances: [{ uri: 'http://a/' }] },
        { pluginid: '10049', name: 'Non-Storable Content', riskdesc: 'Informational (Medium)', instances: [] },
      ],
    },
  ],
});

describe('parseReport', () => {
  it('reads rule id, name, risk, count and examples', () => {
    assert.deepEqual(parseReport(REPORT)[0], {
      ruleId: '10038',
      name: 'CSP Header Not Set',
      risk: 'Medium',
      count: 1,
      examples: ['http://a/'],
    });
  });

  it('copes with a report without alerts', () => {
    assert.deepEqual(parseReport('{"site":[{"alerts":[]}]}'), []);
  });
});

describe('parseRules', () => {
  it('reads the rules file of this repository', () => {
    const rules = parseRules(readFileSync('zap/rules.tsv', 'utf8'));
    assert.equal(rules.get('10038'), 'FAIL');
    assert.equal(rules.get('10049'), 'IGNORE');
  });

  it('rejects an unknown action, so a typo cannot switch a rule off', () => {
    assert.throws(() => parseRules('10038\tIGNOR\t(CSP)'), /Bad line in rules.tsv/);
  });
});

describe('unexpected', () => {
  const rules = parseRules('10038\tFAIL\t(CSP)\n10049\tIGNORE\t(Non-Storable)\n');

  it('lets IGNORE alerts through and flags everything else', () => {
    assert.deepEqual(
      unexpected(parseReport(REPORT), rules).map((a) => a.ruleId),
      ['10038'],
    );
  });

  it('treats a rule that is not in the file as WARN, which is not allowed either', () => {
    const report = JSON.stringify({ site: [{ alerts: [{ pluginid: '99999', name: 'New rule', riskdesc: 'Low' }] }] });
    assert.equal(unexpected(parseReport(report), rules).length, 1);
  });

  it('lets informational WARN alerts through, but not informational FAIL alerts', () => {
    const report = JSON.stringify({
      site: [
        {
          alerts: [
            { pluginid: '10104', name: 'User Agent Fuzzer', riskdesc: 'Informational (Medium)' },
            { pluginid: '10038', name: 'CSP', riskdesc: 'Informational (Low)' },
          ],
        },
      ],
    });
    assert.deepEqual(
      unexpected(parseReport(report), rules).map((a) => a.ruleId),
      ['10038'],
    );
  });

  it('describes an alert with its action', () => {
    assert.equal(describeAlert(parseReport(REPORT)[0]!, rules), '[10038] FAIL CSP Header Not Set (Medium, 1x)');
  });
});

describe('the defect catalogue', () => {
  const server = readFileSync('app/server.ts', 'utf8');

  it('has unique ids', () => {
    assert.equal(new Set(DEFECTS.map((d) => d.id)).size, DEFECTS.length);
  });

  // Each defect must still be planted somewhere: otherwise the vulnerable build quietly loses it and the
  // check that should catch it would prove nothing.
  for (const defect of DEFECTS) {
    it(`${defect.id} is planted in app/server.ts and has a detection`, () => {
      assert.ok(server.includes(`has('${defect.id}')`), `has('${defect.id}') not found in app/server.ts`);
      assert.ok(DETECTIONS[defect.id]);
    });
  }

  it('has every ZAP detection marked FAIL in the rules file', () => {
    const rules = parseRules(readFileSync('zap/rules.tsv', 'utf8'));
    for (const detection of Object.values(DETECTIONS)) {
      if (detection.tool !== 'api-test') assert.equal(rules.get(detection.ruleId), 'FAIL', detection.ruleId);
    }
  });

  it('is empty for the hardened build and complete for the vulnerable one', () => {
    assert.equal(defectsOf('hardened').size, 0);
    assert.equal(defectsOf('vulnerable').size, DEFECTS.length);
  });
});
