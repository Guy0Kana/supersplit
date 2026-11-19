'use strict';
const path = require('path');
const DOMAINS = require(path.join(__dirname, '..', '..', 'data', 'quiz.json'));

const VAL = { y: 2, p: 1, n: 0, u: 0 };

function questionKeys() {
  const keys = [];
  DOMAINS.forEach((d) => d.qs.forEach((_, i) => keys.push(d.id + i)));
  return keys;
}

/** answers must contain exactly one valid code for every question key. */
function validateAnswers(answers) {
  if (!answers || typeof answers !== 'object' || Array.isArray(answers)) return false;
  const keys = questionKeys();
  if (Object.keys(answers).length !== keys.length) return false;
  return keys.every((k) => Object.prototype.hasOwnProperty.call(VAL, answers[k]));
}

function bandOf(pct) {
  return pct < 40 ? 'Foundational' : pct < 70 ? 'Developing' : pct < 90 ? 'Solid' : 'Audit-ready';
}

function scoreAnswers(answers) {
  let total = 0;
  const domains = DOMAINS.map((d) => {
    let s = 0;
    d.qs.forEach((_, i) => { s += VAL[answers[d.id + i]]; });
    total += s;
    return { id: d.id, name: d.name, pct: Math.round((s / (d.qs.length * 2)) * 100) };
  });
  const max = DOMAINS.reduce((a, d) => a + d.qs.length * 2, 0);
  const overall = Math.round((total / max) * 100);
  return { overall, band: bandOf(overall), domains };
}

module.exports = { DOMAINS, validateAnswers, scoreAnswers, bandOf, questionKeys };
