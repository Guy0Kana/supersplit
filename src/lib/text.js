'use strict';

const SEV_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3 };

function severityFromCvss(score, kev) {
  if (typeof score !== 'number' || Number.isNaN(score)) return kev ? 'High' : 'Medium';
  if (score >= 9) return 'Critical';
  if (score >= 7) return 'High';
  if (score >= 4) return 'Medium';
  return 'Low';
}

function stripTags(s) {
  return String(s == null ? '' : s)
    .replace(/<[^>]*>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;/g, "'")
    .replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ')
    .trim();
}

function truncate(s, max) {
  s = String(s || '');
  if (s.length <= max) return s;
  const cut = s.slice(0, max - 1);
  const sp = cut.lastIndexOf(' ');
  return (sp > max * 0.6 ? cut.slice(0, sp) : cut) + '…';
}

function firstSentence(s, max) {
  s = stripTags(s);
  const m = s.match(/^(.+?[.!?])(\s|$)/);
  return truncate(m ? m[1] : s, max || 140);
}

/** Clean model output: plain text only, no links, no markup, bounded length. */
function sanitizeSummary(text, max) {
  let t = String(text || '');
  t = t.replace(/<[^>]*>/g, ' ');
  t = t.replace(/\[([^\]]*)\]\([^)]*\)/g, '$1');
  t = t.replace(/\b(?:https?:\/\/|www\.)\S+/gi, '');
  t = t.replace(/[*_`#>|]/g, '');
  t = t.replace(/\s+/g, ' ').trim();
  return truncate(t, max || 420);
}

function compileIndustryMap(list) {
  return list.map((e) => ({ industry: e.industry, re: new RegExp(e.pattern, 'i') }));
}

function tagIndustry(text, compiled, fallback) {
  for (const e of compiled) if (e.re.test(text)) return e.industry;
  return fallback || 'General';
}

const BREACH_RE = /\b(breach(?:ed|es)?|ransomware|data leak|leaked|exposed|stolen|hacked|cyber ?attack|compromis(?:ed|e)|unauthori[sz]ed access)\b/i;
const PATCH_RE = /\b(patch(?:es|ed)?|security update|updates?|fix(?:es|ed)?|hotfix|advisory)\b/i;

function isBreachHeadline(title, desc) {
  return BREACH_RE.test(`${title} ${desc || ''}`);
}
function isPatchHeadline(title, desc) {
  return PATCH_RE.test(`${title} ${desc || ''}`);
}
function newsSeverity(title) {
  return /\b(ransomware|millions?|critical infrastructure|zero-?day|actively exploited)\b/i.test(title) ? 'High' : 'Medium';
}

module.exports = {
  SEV_RANK, severityFromCvss, stripTags, truncate, firstSentence, sanitizeSummary,
  compileIndustryMap, tagIndustry, isBreachHeadline, isPatchHeadline, newsSeverity,
};
