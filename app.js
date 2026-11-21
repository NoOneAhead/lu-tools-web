(() => {
  // Wire config URLs
  const cfg = window.LUTOOLS_CONFIG || {};
  const setHref = (id, url) => { const el = document.getElementById(id); if (el && url) el.href = url; };
  setHref('nav-apify', cfg.apifyProfileUrl);
  setHref('nav-github', cfg.githubStarterUrl);
  setHref('cta-domain-apify', cfg.actors?.domainPreflight);
  setHref('cta-domain-n8n', cfg.githubStarterUrl);
  setHref('cta-diff-apify', cfg.actors?.pricingDiff);
  setHref('cta-diff-n8n', cfg.n8nAffiliateUrl);
  setHref('cta-oss-apify', cfg.actors?.ossAuditor);
  setHref('cta-oss-github', cfg.githubStarterUrl);

  // Tabs
  document.querySelectorAll('.tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach((t) => { t.classList.remove('active'); t.setAttribute('aria-selected', 'false'); });
      document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));
      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');
      document.getElementById(`panel-${btn.dataset.tab}`).classList.add('active');
    });
  });

  const escapeHtml = (str) => String(str).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // =========================================================================
  // TOOL 1: B2B Domain Email Deliverability & SPF/DMARC Auditor (Google DoH)
  // =========================================================================
  const FREE_DOMAINS = new Set(['gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'icloud.com', 'qq.com', '163.com', 'proton.me', 'live.com']);
  const DISPOSABLE = new Set(['mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com', 'yopmail.com', 'trashmail.com', 'sharklasers.com']);

  function normalizeDomain(raw) {
    let s = (raw || '').trim().toLowerCase();
    if (!s) return null;
    if (s.includes('@') && !s.includes('://')) s = s.split('@').pop();
    if (s.includes('://')) { try { s = new URL(s).hostname; } catch { return null; } }
    else s = s.split(/[/?#:]/)[0];
    s = s.replace(/^www\./, '').replace(/\.$/, '');
    return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(s) ? s : null;
  }

  async function dohQuery(name, type) {
    const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`);
    if (!res.ok) return [];
    const data = await res.json();
    return Array.isArray(data.Answer) ? data.Answer : [];
  }

  function stripQuotes(txt) {
    return txt.replace(/^"|"$/g, '').replace(/"\s*"/g, '');
  }

  async function resolveSpfRecursive(domain, visited = new Set(), depth = 0) {
    if (depth > 4 || visited.has(domain)) return { record: null, lookups: 0 };
    visited.add(domain);
    const answers = await dohQuery(domain, 'TXT');
    const spf = answers.map((a) => stripQuotes(a.data || '')).find((t) => t.toLowerCase().startsWith('v=spf1'));
    if (!spf) return { record: null, lookups: 0 };
    const tokens = spf.split(/\s+/);
    let lookups = 0;
    const includes = [];
    for (const rawTok of tokens) {
      const tok = rawTok.replace(/^[+\-~?]/, '').toLowerCase();
      if (tok.startsWith('include:')) { lookups++; includes.push(tok.slice(8)); }
      else if (tok.startsWith('redirect=')) { lookups++; includes.push(tok.slice(9)); }
      else if (tok === 'a' || tok.startsWith('a:') || tok === 'mx' || tok.startsWith('mx:') || tok.startsWith('exists:')) lookups++;
    }
    const children = await Promise.all(includes.slice(0, 10).map((inc) => resolveSpfRecursive(inc, visited, depth + 1)));
    for (const c of children) lookups += c.lookups;
    return { record: spf, lookups };
  }

  function detectProvider(mxList) {
    const joined = mxList.join(' ').toLowerCase();
    if (!joined) return 'None';
    if (joined.includes('google')) return 'Google Workspace';
    if (joined.includes('outlook.com')) return 'Microsoft 365';
    if (joined.includes('mimecast')) return 'Mimecast';
    if (joined.includes('proofpoint') || joined.includes('pphosted')) return 'Proofpoint';
    if (joined.includes('protonmail')) return 'Proton Mail';
    if (joined.includes('zoho')) return 'Zoho Mail';
    if (joined.includes('qq.com')) return 'Tencent Exmail';
    return 'Custom / Self-Hosted';
  }

  async function runDomainAudit(rawInput) {
    const box = document.getElementById('domain-result');
    const domain = normalizeDomain(rawInput);
    box.classList.remove('hidden');
    if (!domain) {
      box.innerHTML = `<span class="badge badge-red">INVALID</span> Please enter a valid public domain, URL, or email.`;
      return;
    }
    box.innerHTML = `<p class="hint" style="margin:0">Running live DNS/MX/SPF/DMARC/DKIM probes for <strong>${escapeHtml(domain)}</strong>…</p>`;

    try {
      const [mxAns, spfRes, dmarcAns, mtaAns, ...dkimAns] = await Promise.all([
        dohQuery(domain, 'MX'),
        resolveSpfRecursive(domain),
        dohQuery(`_dmarc.${domain}`, 'TXT'),
        dohQuery(`_mta-sts.${domain}`, 'TXT'),
        ...['google', 'selector1', 'selector2', 'k1', 's1', 'default'].map(async (sel) => {
          const ans = await dohQuery(`${sel}._domainkey.${domain}`, 'TXT');
          return ans.length > 0 ? sel : null;
        }),
      ]);

      const mxHosts = mxAns.map((a) => String(a.data || '')).filter(Boolean);
      const provider = detectProvider(mxHosts);
      const dmarcRec = dmarcAns.map((a) => stripQuotes(a.data || '')).find((t) => t.toLowerCase().startsWith('v=dmarc1')) || null;
      const dmarcPolicy = dmarcRec ? ((dmarcRec.match(/;\s*p=([a-z]+)/i)?.[1] || dmarcRec.match(/\bp=([a-z]+)/i)?.[1] || 'none').toLowerCase()) : 'missing';
      const dkimMatched = dkimAns.filter(Boolean);
      const hasMtaSts = mtaAns.some((a) => stripQuotes(a.data || '').toLowerCase().startsWith('v=stsv1'));
      const isFree = FREE_DOMAINS.has(domain);
      const isDisp = DISPOSABLE.has(domain);

      let score = 0;
      const flags = [];
      const good = [];
      if (mxHosts.length) { score += 35; if (!isFree && !isDisp && ['Google Workspace', 'Microsoft 365'].includes(provider)) { score += 10; good.push(provider); } }
      else flags.push('NO_MX_RECORD');
      if (spfRes.record) { score += 20; if (spfRes.lookups > 10) { score -= 12; flags.push('SPF_OVER_10_LOOKUPS'); } else good.push(`SPF_OK (${spfRes.lookups}/10)`); }
      else flags.push('SPF_MISSING');
      if (dmarcPolicy === 'reject') { score += 25; good.push('DMARC_REJECT'); }
      else if (dmarcPolicy === 'quarantine') { score += 20; good.push('DMARC_QUARANTINE'); }
      else if (dmarcPolicy === 'none') { score += 10; flags.push('DMARC_NOT_ENFORCED'); }
      else flags.push('DMARC_MISSING');
      if (dkimMatched.length) { score += 10; good.push(`DKIM (${dkimMatched.join(', ')})`); }
      if (hasMtaSts) good.push('MTA-STS');
      if (isFree) { score = Math.min(score, 40); flags.push('FREE_WEBMAIL'); }
      if (isDisp) { score = Math.min(score, 10); flags.push('DISPOSABLE_EMAIL'); }

      score = Math.max(0, Math.min(100, score));
      const verdict = (isDisp || !mxHosts.length || score < 45) ? 'REJECT' : (isFree || spfRes.lookups > 10 || score < 70) ? 'CAUTION' : 'READY';
      const badgeClass = verdict === 'READY' ? 'badge-green' : verdict === 'CAUTION' ? 'badge-yellow' : 'badge-red';

      box.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
          <div><strong style="font-size:17px">${escapeHtml(domain)}</strong> &nbsp;<span class="badge ${badgeClass}">${verdict}</span></div>
          <div>Deliverability Score: <strong>${score}/100</strong></div>
        </div>
        <div class="metrics-grid">
          <div class="metric"><div class="metric-label">Email Provider</div><div class="metric-val">${escapeHtml(provider)}</div></div>
          <div class="metric"><div class="metric-label">SPF Lookups</div><div class="metric-val">${spfRes.lookups} / 10</div></div>
          <div class="metric"><div class="metric-label">DMARC Policy</div><div class="metric-val">${escapeHtml(dmarcPolicy)}</div></div>
          <div class="metric"><div class="metric-label">DKIM Selectors</div><div class="metric-val">${dkimMatched.length ? escapeHtml(dkimMatched.join(', ')) : 'None probed'}</div></div>
        </div>
        <div class="tag-list">
          ${good.map((g) => `<span class="tag tag-good">✓ ${escapeHtml(g)}</span>`).join('')}
          ${flags.map((f) => `<span class="tag tag-danger">⚠ ${escapeHtml(f)}</span>`).join('')}
        </div>
        ${spfRes.record ? `<pre>SPF: ${escapeHtml(spfRes.record)}${dmarcRec ? `\nDMARC: ${escapeHtml(dmarcRec)}` : ''}</pre>` : ''}
      `;
    } catch (err) {
      box.innerHTML = `<span class="badge badge-red">ERROR</span> Could not reach DNS-over-HTTPS resolver: ${escapeHtml(err.message)}`;
    }
  }

  document.getElementById('btn-run-domain').addEventListener('click', () => runDomainAudit(document.getElementById('domain-input').value));
  document.getElementById('domain-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') runDomainAudit(e.target.value); });
  document.querySelectorAll('.pill').forEach((p) => p.addEventListener('click', () => {
    document.getElementById('domain-input').value = p.dataset.domain;
    runDomainAudit(p.dataset.domain);
  }));

  // =========================================================================
  // TOOL 2: OpenAPI Breaking-Change Diff Inspector (100% Client-Side)
  // =========================================================================
  const DEMO_PREV = JSON.stringify({
    openapi: '3.0.3',
    info: { title: 'Payments API', version: '1.2.0' },
    paths: {
      '/v1/charges': { get: { parameters: [{ name: 'limit', in: 'query', required: false }], responses: { '200': { description: 'OK' } } } },
      '/v1/legacy-tokens': { delete: { responses: { '204': { description: 'Deleted' } } } },
    },
  }, null, 2);

  const DEMO_CURR = JSON.stringify({
    openapi: '3.0.3',
    info: { title: 'Payments API', version: '2.0.0' },
    paths: {
      '/v1/charges': {
        get: {
          parameters: [
            { name: 'limit', in: 'query', required: false },
            { name: 'idempotency_key', in: 'header', required: true },
          ],
          responses: { '200': { description: 'OK' } },
        },
      },
      '/v2/agent-intents': { post: { responses: { '201': { description: 'Created' } } } },
    },
  }, null, 2);

  document.getElementById('openapi-prev').value = DEMO_PREV;
  document.getElementById('openapi-curr').value = DEMO_CURR;
  document.getElementById('btn-demo-openapi').addEventListener('click', () => {
    document.getElementById('openapi-prev').value = DEMO_PREV;
    document.getElementById('openapi-curr').value = DEMO_CURR;
  });

  function extractOps(doc) {
    const methods = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options']);
    const map = new Map();
    for (const [p, item] of Object.entries(doc.paths || {})) {
      if (!item || typeof item !== 'object') continue;
      for (const [m, op] of Object.entries(item)) {
        if (!methods.has(m.toLowerCase()) || !op || typeof op !== 'object') continue;
        const reqParams = (op.parameters || []).filter((x) => x?.required).map((x) => `${x.in || 'param'}:${x.name}`);
        map.set(`${m.toUpperCase()} ${p}`, {
          reqParams: new Set(reqParams),
          reqBody: Boolean(op.requestBody?.required),
          codes2xx: Object.keys(op.responses || {}).filter((c) => c.startsWith('2')),
        });
      }
    }
    return map;
  }

  document.getElementById('btn-run-openapi').addEventListener('click', () => {
    const box = document.getElementById('openapi-result');
    box.classList.remove('hidden');
    try {
      const prev = JSON.parse(document.getElementById('openapi-prev').value);
      const curr = JSON.parse(document.getElementById('openapi-curr').value);
      const pOps = extractOps(prev);
      const cOps = extractOps(curr);
      const breaking = [], added = [], removed = [];

      for (const [k] of pOps) {
        if (!cOps.has(k)) { breaking.push(`Endpoint removed: ${k}`); removed.push(k); }
      }
      for (const [k] of cOps) {
        if (!pOps.has(k)) added.push(`Endpoint added: ${k}`);
      }
      for (const [k, co] of cOps) {
        const po = pOps.get(k);
        if (!po) continue;
        for (const rp of co.reqParams) {
          if (!po.reqParams.has(rp)) breaking.push(`New required param on ${k}: ${rp}`);
        }
        if (!po.reqBody && co.reqBody) breaking.push(`Request body became required on ${k}`);
        for (const c2 of po.codes2xx) {
          if (!co.codes2xx.includes(c2)) breaking.push(`2xx response ${c2} removed on ${k}`);
        }
      }

      const severity = breaking.length ? 'BREAKING' : (added.length || prev.info?.version !== curr.info?.version) ? 'MAJOR' : 'UNCHANGED';
      const badgeClass = severity === 'BREAKING' ? 'badge-red' : severity === 'MAJOR' ? 'badge-yellow' : 'badge-green';
      box.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
          <div>Diff Severity: <span class="badge ${badgeClass}">${severity}</span></div>
          <div>Version: <strong>${escapeHtml(prev.info?.version || 'n/a')} → ${escapeHtml(curr.info?.version || 'n/a')}</strong></div>
        </div>
        <div class="tag-list">
          ${breaking.map((b) => `<span class="tag tag-danger">⛔ ${escapeHtml(b)}</span>`).join('')}
          ${added.map((a) => `<span class="tag tag-good">+ ${escapeHtml(a)}</span>`).join('')}
          ${!breaking.length && !added.length ? `<span class="tag tag-good">✓ No breaking or endpoint changes detected</span>` : ''}
        </div>
      `;
    } catch (err) {
      box.innerHTML = `<span class="badge badge-red">JSON ERROR</span> ${escapeHtml(err.message)}`;
    }
  });

  // =========================================================================
  // TOOL 3: OSS CVE & Copyleft License Gate (OSV.dev + npm / PyPI)
  // =========================================================================
  function classifyLic(raw) {
    if (!raw) return 'UNKNOWN';
    if (/\bOR\b/.test(raw) && /\b(MIT|APACHE|BSD|ISC)\b/i.test(raw)) return 'PERMISSIVE';
    if (/\b(SSPL|BSL|BUSL|ELASTIC-?2)\b/i.test(raw)) return 'SOURCE_AVAILABLE';
    if (/\b(LGPL|MPL)\b/i.test(raw)) return 'WEAK_COPYLEFT';
    if (/\b(AGPL|GPL-?2|GPL-?3|GPLv2|GPLv3)\b/i.test(raw)) return 'STRONG_COPYLEFT';
    if (/\b(MIT|APACHE|BSD|ISC|0BSD|PSF)\b/i.test(raw)) return 'PERMISSIVE';
    return 'UNKNOWN';
  }

  async function runOssAudit(eco, rawPkg) {
    const box = document.getElementById('oss-result');
    box.classList.remove('hidden');
    const trimmed = (rawPkg || '').trim();
    if (!trimmed) { box.innerHTML = `<span class="badge badge-red">INVALID</span> Enter a package name.`; return; }

    let name = trimmed, version = null;
    if (eco === 'pypi' && trimmed.includes('==')) { [name, version] = trimmed.split('=='); }
    else {
      const idx = trimmed.startsWith('@') ? trimmed.indexOf('@', 1) : trimmed.indexOf('@');
      if (idx > 0) { name = trimmed.slice(0, idx); version = trimmed.slice(idx + 1); }
    }

    box.innerHTML = `<p class="hint" style="margin:0">Querying live ${escapeHtml(eco)} registry &amp; OSV.dev for <strong>${escapeHtml(name)}</strong>…</p>`;
    try {
      let resolvedVer = version, license = 'UNKNOWN', deprecated = false;
      if (eco === 'npm') {
        const reg = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
        if (!reg.ok) throw new Error(`Package "${name}" not found on npm`);
        const d = await reg.json();
        resolvedVer = version || d['dist-tags']?.latest;
        const vo = d.versions?.[resolvedVer] || {};
        license = typeof vo.license === 'string' ? vo.license : (vo.license?.type || d.license || 'UNKNOWN');
        deprecated = Boolean(vo.deprecated);
      } else {
        const url = version ? `https://pypi.org/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json` : `https://pypi.org/pypi/${encodeURIComponent(name)}/json`;
        const reg = await fetch(url);
        if (!reg.ok) throw new Error(`Package "${name}" not found on PyPI`);
        const d = await reg.json();
        resolvedVer = d.info?.version || version;
        license = d.info?.license_expression || (d.info?.license && d.info.license.length < 60 ? d.info.license : null) ||
          (d.info?.classifiers || []).filter((c) => c.startsWith('License ::')).map((c) => c.split('::').pop().trim()).join(' OR ') || 'UNKNOWN';
        deprecated = Boolean(d.info?.yanked);
      }

      const osvRes = await fetch('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ package: { name, ecosystem: eco === 'npm' ? 'npm' : 'PyPI' }, ...(resolvedVer ? { version: resolvedVer } : {}) }),
      });
      const osvData = osvRes.ok ? await osvRes.json() : { vulns: [] };
      const vulns = Array.isArray(osvData.vulns) ? osvData.vulns : [];
      const licCat = classifyLic(license);

      const verdict = (vulns.length > 0 || deprecated || licCat === 'STRONG_COPYLEFT' || licCat === 'SOURCE_AVAILABLE')
        ? 'BLOCKED'
        : (licCat === 'UNKNOWN' || licCat === 'WEAK_COPYLEFT') ? 'REVIEW' : 'APPROVED';
      const badgeClass = verdict === 'APPROVED' ? 'badge-green' : verdict === 'REVIEW' ? 'badge-yellow' : 'badge-red';

      box.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
          <div><strong>${escapeHtml(eco)}:${escapeHtml(name)}@${escapeHtml(resolvedVer || 'latest')}</strong> &nbsp;<span class="badge ${badgeClass}">${verdict}</span></div>
          <div>Known OSV CVEs: <strong>${vulns.length}</strong></div>
        </div>
        <div class="metrics-grid">
          <div class="metric"><div class="metric-label">License</div><div class="metric-val">${escapeHtml(license)}</div></div>
          <div class="metric"><div class="metric-label">License Tier</div><div class="metric-val">${escapeHtml(licCat)}</div></div>
          <div class="metric"><div class="metric-label">Deprecated / Yanked</div><div class="metric-val">${deprecated ? 'YES' : 'No'}</div></div>
        </div>
        ${vulns.length ? `<pre>${vulns.slice(0, 6).map((v) => `• ${v.id}: ${v.summary || 'Vulnerability reported'}`).join('\n')}</pre>` : `<div class="tag-list"><span class="tag tag-good">✓ Zero known OSV vulnerabilities for v${escapeHtml(resolvedVer || '')}</span></div>`}
      `;
    } catch (err) {
      box.innerHTML = `<span class="badge badge-red">ERROR</span> ${escapeHtml(err.message)}`;
    }
  }

  document.getElementById('btn-run-oss').addEventListener('click', () => runOssAudit(document.getElementById('oss-eco').value, document.getElementById('oss-pkg').value));
  document.querySelectorAll('.pill-oss').forEach((p) => p.addEventListener('click', () => {
    document.getElementById('oss-eco').value = p.dataset.eco;
    document.getElementById('oss-pkg').value = p.dataset.pkg;
    runOssAudit(p.dataset.eco, p.dataset.pkg);
  }));
})();
