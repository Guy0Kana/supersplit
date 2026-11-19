'use strict';

const BANDS = [['Low', 20], ['Guarded', 40], ['Elevated', 60], ['High', 80], ['Severe', 100]];

function percentile(values, p) {
  if (!values.length) return 0;
  const s = values.slice().sort((a, b) => a - b);
  const idx = Math.min(s.length - 1, Math.max(0, Math.ceil(p * s.length) - 1));
  return s[idx];
}

/** score = 100 * sum(weight * min(1, x / p90)) */
function computeScore(signals) {
  const total = signals.reduce((acc, s) => acc + s.w * Math.min(1, s.p90 > 0 ? s.x / s.p90 : 0), 0);
  return Math.round(100 * total);
}

function bandOf(score) {
  for (const [name, max] of BANDS) if (score <= max) return name;
  return 'Severe';
}

module.exports = { BANDS, percentile, computeScore, bandOf };
