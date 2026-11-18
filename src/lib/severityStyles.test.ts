import test from 'node:test';
import assert from 'node:assert/strict';
import { getSeverityStyle, SEVERITY_ORDER } from './severityStyles';

test('getSeverityStyle provides distinct color-coded badge classes for all severities', () => {
  const high = getSeverityStyle('High');
  const medium = getSeverityStyle('Medium');
  const low = getSeverityStyle('Low');
  const critical = getSeverityStyle('Critical');

  assert.match(high.badgeClass, /\bred-/);
  assert.match(high.cardAccentClass, /\bred-/);
  assert.match(medium.badgeClass, /\bamber-/);
  assert.match(medium.cardAccentClass, /\bamber-/);
  assert.match(low.badgeClass, /\bblue-/);
  assert.match(low.cardAccentClass, /\bblue-/);
  assert.match(critical.badgeClass, /\bpurple-/);

  const hexSet = new Set(SEVERITY_ORDER.map((level) => getSeverityStyle(level).hex));
  assert.equal(hexSet.size, SEVERITY_ORDER.length);
});
