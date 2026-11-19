'use strict';
const { truncate } = require('./text');

const ACTIVITY = 'COALESCE(kev_date, published)';
const SEV_ORDER = "CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END";

function toApi(r) {
  return {
    id: r.id,
    type: r.type,
    severity: r.severity,
    cvss: r.cvss,
    kev: !!r.kev,
    vendor: r.vendor,
    product: r.product,
    industry: r.industry,
    title: r.title,
    summary: r.summary || truncate(r.description || '', 320),
    ai: !!r.summary,
    source: { name: r.source_name, url: r.source_url },
    published: r.published,
    activity: r.kev_date || r.published,
  };
}

module.exports = { ACTIVITY, SEV_ORDER, toApi };
