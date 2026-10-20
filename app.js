/* =============================================================
   StratDeck — Strategy Console (no build, no dependencies)
   Fetch -> decrypt (WebCrypto) -> render. Hash-routed SPA.
   ============================================================= */
'use strict';

/* ------------------------------------------------------------------ *
 * Config
 * ------------------------------------------------------------------ */
const DATA_URL = 'https://ss-strat-dash-8f21.s3.eu-west-1.amazonaws.com/data/dashboard_data.enc';
const HKDF_INFO = 'strat-dashboard-v1';
// Login password + the recipient private key are embedded in this static site so
// operators only need to remember a single password. NOTE: because the key ships
// with the page, anyone who can load the site can also decrypt the ciphertext.
const LOGIN_PASSWORD = 'silverstream2026!';
const PRIVATE_KEY = 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgBB1QM5ezUnTsH+zOv0NCZj2ayyifvY/+Co2AKoAEqAKhRANCAATtstn7N3w6wfgJBvEEUx9rOKmWWxA7+oRc+WTZCV6LHjgBNM+ijEemoNio7RWH76xelzJ7MRMFdlrnM+4nFmSs';

// Freshness / auto-refresh. The prod server publishes a new encrypted snapshot to
// S3 every 5 minutes; once the current snapshot passes that age we poll S3 and swap
// in the new data automatically (no page reload or logout needed).
const PUBLISH_INTERVAL_MS = 5 * 60 * 1000;
const AUTO_REFRESH_AFTER_MS = PUBLISH_INTERVAL_MS + 5 * 1000;   // trigger at ~5:05
const TICK_MS = 30 * 1000;                                      // badge/refresh cadence
const STALE_MS = 15 * 60 * 1000;                                // badge turns red past this

// Optional local/serve override:      index.html?data=/test.enc
// Honoured ONLY on localhost (never on the deployed Pages origin), so a link to the
// live site can never point the fetch at a third-party host.
const _isLocalhost = /^localhost$/i.test(location.hostname) || /^127\.\d+\.\d+\.\d+$/.test(location.hostname) || location.hostname === '[::1]';
const DATA_OVERRIDE = _isLocalhost ? new URLSearchParams(location.search).get('data') : null;

// Canonical nav order: MM1, MM2, JIC, ctabinTEST, CTABIN1. The strategy list,
// names and every AUM figure (including initial_aum) come straight from the S3
// payload — nothing is hardcoded or corrected client-side.
const STRATEGY_ORDER = ['mm', 'mm2', 'jic', 'ctabin_test', 'ctabin1'];

/* ------------------------------------------------------------------ *
 * Tiny DOM / escape helpers
 * ------------------------------------------------------------------ */
const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => Array.from(el.querySelectorAll(sel));

function esc(v) {
  return String(v == null ? '' : v).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

/* ------------------------------------------------------------------ *
 * Formatting
 * ------------------------------------------------------------------ */
function fmtUsd(v, compact) {
  if (v === null || v === undefined || isNaN(v)) return '—';
  const sign = v < 0 ? '-' : '';
  const a = Math.abs(v);
  let body;
  if (compact) {
    body = a >= 1e9 ? (a / 1e9).toFixed(2) + 'B'
         : a >= 1e6 ? (a / 1e6).toFixed(2) + 'M'
         : a >= 1e3 ? Math.round(a / 1e3) + 'K'
         : a.toFixed(0);
  } else {
    body = a.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }
  return sign + '$' + body;
}
// Signed, for PnL deltas: "+$1.23" / "-$4.56" / "$0.00"
function fmtSignedUsd(v) {
  if (v === null || v === undefined || isNaN(v)) return '—';
  const s = Math.abs(v).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  return (v > 0 ? '+' : v < 0 ? '-' : '') + '$' + s;
}
function fmtPct(v) {
  if (v === null || v === undefined || isNaN(v)) return '—';
  return (v > 0 ? '+' : '') + v.toFixed(2) + '%';
}
function fmtInt(v) { return (v == null || isNaN(v)) ? '—' : Math.round(v).toLocaleString('en-US'); }

function toneClass(v) { // for a signed money value
  return v > 0 ? 'pos' : v < 0 ? 'neg' : 'flat';
}
function deltaBadge(v, prefix = '') {
  return '<span class="delta ' + toneClass(v) + '">' + prefix + esc(fmtSignedUsd(v)) + '</span>';
}

/* ------------------------------------------------------------------ *
 * Crypto (reuses the proven envelope scheme from the handover)
 * ------------------------------------------------------------------ */
function b64ToBytes(text) {
  const clean = String(text).replace(/-----BEGIN[^-]+-----/g, '').replace(/-----END[^-]+-----/g, '').replace(/\s+/g, '');
  const bin = atob(clean);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function decryptEnvelope(env, keyText) {
  const subtle = crypto.subtle;
  let der;
  try {
    der = b64ToBytes(keyText);
  } catch (e) {
    throw new Error('invalid key text');
  }

  let priv;
  try {
    priv = await subtle.importKey('pkcs8', der, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  } catch (e) {
    throw new Error('not a valid P-256 private key (need PKCS#8)');
  }

  if (env[0] !== 1) throw new Error('unsupported envelope version: ' + env[0]);
  const eph = env.subarray(1, 66);
  const salt = env.subarray(66, 82);
  const nonce = env.subarray(82, 94);
  const ct = env.subarray(94);

  const ephPub = await subtle.importKey('raw', eph, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = await subtle.deriveBits({ name: 'ECDH', public: ephPub }, priv, 256);
  const hk = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: salt, info: new TextEncoder().encode(HKDF_INFO) }, hk, 256);
  const aes = await subtle.importKey('raw', bits, 'AES-GCM', false, ['decrypt']);
  const plain = await subtle.decrypt({ name: 'AES-GCM', iv: nonce }, aes, ct);
  return JSON.parse(new TextDecoder().decode(plain));
}

/* ------------------------------------------------------------------ *
 * State
 * ------------------------------------------------------------------ */
const state = {
  data: null,
  fetchedAt: null,
  refreshing: false,
  loggingIn: false,
  lastAttemptAt: 0,
  epoch: 0,
};

/* ------------------------------------------------------------------ *
 * Payload normalisation (in-memory only — never republished)
 * Every figure comes from the S3 payload; we only put strategies into the
 * canonical nav order and recompute portfolio totals from those same rows.
 * ------------------------------------------------------------------ */
function normalizePayload(data) {
  data.strategies = Array.isArray(data.strategies) ? data.strategies : [];
  const order = Object.fromEntries(STRATEGY_ORDER.map((k, i) => [k, i]));
  for (const s of data.strategies) {
    // Only derive pnl_initial when the payload omits it. initial_aum itself is
    // always the server value — never hardcoded or corrected here.
    if (s.pnl_initial == null && s.aum != null && s.initial_aum != null) {
      s.pnl_initial = +(s.aum - s.initial_aum).toFixed(2);
    }
    if (!Array.isArray(s.positions)) s.positions = [];
    if (!Array.isArray(s.aum_history)) s.aum_history = [];
  }
  // Stable canonical order (falls back to alphabetical for unknown keys).
  data.strategies.sort((a, b) =>
    ((order[a.key] ?? 1e6) - (order[b.key] ?? 1e6)) || (a.key < b.key ? -1 : 1));

  // Recompute portfolio totals from the published strategy rows.
  const initial = data.strategies.reduce((t, s) => t + (s.initial_aum || 0), 0);
  const aum = data.strategies.reduce((t, s) => t + (s.aum || 0), 0);
  const positions = data.strategies.reduce((t, s) =>
    t + ((s.positions && s.positions.length) || s.positions_count || 0), 0);
  data.totals = Object.assign({}, data.totals, {
    aum: +aum.toFixed(2),
    initial_aum: +initial.toFixed(2),
    pnl_initial: +(aum - initial).toFixed(2),
    positions: positions,
  });
  return data;
}

/* ------------------------------------------------------------------ *
 * ALL aggregate (computed client-side)
 * ------------------------------------------------------------------ */
function strategySequences(strats) {
  return strats.map(st => {
    const m = new Map();
    for (const p of (st.aum_history || [])) m.set(p[0], +p[1]);
    return Array.from(m.entries()).sort((a, b) => (a[0] < b[0] ? -1 : 1));
  });
}
function combinedHistory(strats) {
  const seqs = strategySequences(strats);
  const dates = Array.from(new Set(strats.flatMap(st => (st.aum_history || []).map(p => p[0])))).sort();
  const ptr = seqs.map(() => 0);
  const cur = seqs.map(() => 0);
  const out = [];
  for (const d of dates) {
    let sum = 0;
    for (let i = 0; i < seqs.length; i++) {
      const s = seqs[i];
      if (!s.length) continue;
      while (ptr[i] < s.length && s[ptr[i]][0] <= d) { cur[i] = s[ptr[i]][1]; ptr[i]++; }
      if (ptr[i] > 0) sum += cur[i];
    }
    out.push([d, +sum.toFixed(2)]);
  }
  return out;
}

function buildAll(data) {
  const strats = data.strategies;
  const s = {
    key: 'all', name: 'ALL', account_type: 'aggregate', as_of: data.as_of,
    aum: 0, initial_aum: 0, pnl_initial: 0, pnl_1d: 0, pnl_tod: 0,
    risk_budget: 0, risk_utilised: 0, risk_long: 0, risk_short: 0, risk_net: 0,
    drawdown_limit: 0, drawdown_utilised: 0, daily_drawdown_limit: 0, daily_drawdown_utilised: 0,
    positions: [], positions_count: 0, aum_history: [], _isAll: true,
  };
  const add = k => strats.reduce((t, st) => t + (st[k] || 0), 0);
  s.aum = add('aum'); s.initial_aum = add('initial_aum');
  s.pnl_initial = s.aum - s.initial_aum;
  s.pnl_1d = add('pnl_1d'); s.pnl_tod = add('pnl_tod');
  s.risk_budget = add('risk_budget'); s.risk_utilised = add('risk_utilised');
  s.risk_long = add('risk_long'); s.risk_short = add('risk_short'); s.risk_net = add('risk_net');
  s.drawdown_limit = add('drawdown_limit'); s.drawdown_utilised = add('drawdown_utilised');
  s.daily_drawdown_limit = add('daily_drawdown_limit'); s.daily_drawdown_utilised = add('daily_drawdown_utilised');
  s.positions = strats.flatMap(st => (st.positions || []).map(p => Object.assign({ _strat: st.name }, p)));
  s.positions_count = s.positions.length;
  s.aum_history = combinedHistory(strats);
  return s;
}

/* ------------------------------------------------------------------ *
 * Routing (hash)
 * ------------------------------------------------------------------ */
function routeFromHash() {
  const raw = location.hash.replace(/^#\/?/, '').toLowerCase() || 'all';
  const keys = ['all'].concat((state.data?.strategies || []).map(s => s.key));
  return keys.includes(raw) ? raw : 'all';
}
function viewForRoute(route) {
  if (route === 'all') return buildAll(state.data);
  return state.data.strategies.find(s => s.key === route) || buildAll(state.data);
}

/* ------------------------------------------------------------------ *
 * Render: nav
 * ------------------------------------------------------------------ */
function renderNav(activeKey) {
  const nav = $('#nav');
  const items = [buildAll(state.data)].concat(state.data.strategies);
  nav.innerHTML = items.map(s => {
    const flat = Math.abs(s.pnl_initial) < 0.005;
    const tick = flat ? 'flat' : (s.pnl_initial > 0 ? 'pos' : 'neg');
    return '<button class="nav-tab' + (s.key === activeKey ? ' active' : '') + '" data-key="' + esc(s.key) + '">' +
      '<span class="tick ' + tick + '"></span>' + esc(s.name) + '</button>';
  }).join('');
  $$('.nav-tab', nav).forEach(b => {
    b.addEventListener('click', () => { location.hash = '#/' + b.dataset.key; });
  });
}

/* ------------------------------------------------------------------ *
 * Render: AUM line chart (inline SVG, no deps)
 * ------------------------------------------------------------------ */
function renderChart(container, history, initialAum) {
  const W = container.clientWidth || 860;
  const H = 300;
  const M = { l: 66, r: 18, t: 18, b: 30 };

  const pts = (history || [])
    .map(([d, v]) => ({ t: Date.parse(String(d) + 'T00:00:00Z'), v: +v }))
    .filter(p => isFinite(p.t) && isFinite(p.v));

  if (!pts.length) {
    container.innerHTML = '<div class="empty-state">No AUM history available.</div>';
    return;
  }

  const xs = pts.map(p => p.t);
  const x0 = Math.min.apply(null, xs), x1 = Math.max.apply(null, xs);
  const vals = pts.map(p => p.v);
  let yLo = Math.min.apply(null, vals.concat(initialAum == null ? [] : [initialAum]));
  let yHi = Math.max.apply(null, vals.concat(initialAum == null ? [] : [initialAum]));
  const pad = (yHi - yLo) || Math.abs(yHi) * 0.05 || 100;
  yLo -= pad * 0.1; yHi += pad * 0.1;

  const iw = W - M.l - M.r, ih = H - M.t - M.b;
  const sx = t => M.l + (x1 === x0 ? iw / 2 : ((t - x0) / (x1 - x0)) * iw);
  const sy = v => M.t + ih - ((v - yLo) / (yHi - yLo)) * ih;

  const line = pts.map((p, i) => (i ? 'L' : 'M') + sx(p.t).toFixed(2) + ' ' + sy(p.v).toFixed(2)).join(' ');
  const area = line + 'L' + sx(x1).toFixed(2) + ' ' + (M.t + ih) + 'L' + sx(x0).toFixed(2) + ' ' + (M.t + ih) + 'Z';

  const last = pts[pts.length - 1];
  const upDown = last.v >= (initialAum == null ? last.v : initialAum);
  const stroke = upDown ? '#34d399' : '#fb7185';

  // grid + y labels (5 bands)
  let grid = '', yLabels = '';
  const BANDS = 5;
  for (let i = 0; i <= BANDS; i++) {
    const v = yLo + ((yHi - yLo) * i / BANDS);
    const y = sy(v).toFixed(2);
    grid += '<line x1="' + M.l + '" y1="' + y + '" x2="' + (W - M.r) + '" y2="' + y +
      '" stroke="rgba(148,163,184,.10)" stroke-width="1"/>';
    yLabels += '<text x="' + (M.l - 8) + '" y="' + (sy(v) + 3.5) + '" text-anchor="end">' + esc(fmtUsd(v, true)) + '</text>';
  }

  // x labels (up to 5 ticks)
  let xLabels = '';
  const nTick = Math.min(5, pts.length);
  const tickIdx = new Set();
  for (let i = 0; i < nTick; i++) tickIdx.add(Math.round(i * (pts.length - 1) / (nTick - 1 || 1)));
  tickIdx.forEach(i => {
    const d = new Date(pts[i].t);
    const lab = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    xLabels += '<text x="' + sx(pts[i].t).toFixed(2) + '" y="' + (H - 9) + '" text-anchor="middle">' + esc(lab) + '</text>';
  });

  let baselineSvg = '';
  if (initialAum != null) {
    const by = sy(initialAum).toFixed(2);
    baselineSvg =
      '<line x1="' + M.l + '" y1="' + by + '" x2="' + (W - M.r) + '" y2="' + by +
      '" stroke="' + stroke + '" stroke-width="1.2" stroke-dasharray="5 5" opacity=".55"/>' +
      '<text x="' + M.l + '" y="' + (sy(initialAum) - 6) + '" class="chart-labels" opacity=".8">initial</text>';
  }

  container.innerHTML =
    '<svg class="chart" viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="xMidYMid meet" role="img" aria-label="AUM history">' +
      '<defs>' +
        '<linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">' +
          '<stop offset="0" stop-color="' + stroke + '" stop-opacity=".28"/>' +
          '<stop offset="1" stop-color="' + stroke + '" stop-opacity="0"/>' +
        '</linearGradient>' +
      '</defs>' +
      '<g>' + grid + '</g>' +
      '<g class="chart-labels">' + yLabels + '</g>' +
      '<g class="chart-labels" fill="' + '#5d6878' + '">' + xLabels + '</g>' +
      baselineSvg +
      '<path d="' + area + '" fill="url(#areaGrad)" stroke="none"/>' +
      '<path d="' + line + '" fill="none" stroke="' + stroke + '" stroke-width="2.4" stroke-linejoin="round" stroke-linecap="round"/>' +
      // current marker
      '<line x1="' + sx(last.t).toFixed(2) + '" y1="' + sy(last.v).toFixed(2) + '" x2="' + sx(last.t).toFixed(2) + '" y2="' + (M.t + ih) + '" stroke="' + stroke + '" stroke-width="1" opacity=".35"/>' +
      '<circle cx="' + sx(last.t).toFixed(2) + '" cy="' + sy(last.v).toFixed(2) + '" r="9" fill="' + stroke + '" opacity=".18"/>' +
      '<circle cx="' + sx(last.t).toFixed(2) + '" cy="' + sy(last.v).toFixed(2) + '" r="4" fill="' + stroke + '" stroke="#07090f" stroke-width="1.6"/>' +
      // hover layers
      '<line id="crossX" x1="0" y1="' + M.t + '" x2="0" y2="' + (M.t + ih) + '" stroke="rgba(232,237,244,.25)" stroke-width="1" stroke-dasharray="3 3" opacity="0"/>' +
      '<circle id="crossDot" r="4" fill="#e8edf4" opacity="0"/>' +
      '<rect x="' + M.l + '" y="' + M.t + '" width="' + iw + '" height="' + ih + '" fill="transparent" id="hoverRect"/>' +
    '</svg>' +
    '<div class="chart-tip" id="chartTip"></div>';

  // hover interactivity
  const svg = container.querySelector('svg');
  const tip = container.querySelector('#chartTip');
  const crossX = container.querySelector('#crossX');
  const crossDot = container.querySelector('#crossDot');
  const rect = svg.getBoundingClientRect();
  const scale = W / rect.width;

  svg.addEventListener('mousemove', ev => {
    const r = svg.getBoundingClientRect();
    const mx = (ev.clientX - r.left) * scale;
    if (mx < M.l || mx > W - M.r) { tip.style.opacity = 0; crossX.setAttribute('opacity', 0); crossDot.setAttribute('opacity', 0); return; }
    let bi = 0, bd = Infinity;
    for (let i = 0; i < pts.length; i++) {
      const d = Math.abs(sx(pts[i].t) - mx);
      if (d < bd) { bd = d; bi = i; }
    }
    const p = pts[bi];
    const px = sx(p.t), py = sy(p.v);
    crossX.setAttribute('x1', px); crossX.setAttribute('x2', px); crossX.setAttribute('opacity', 1);
    crossDot.setAttribute('cx', px); crossDot.setAttribute('cy', py); crossDot.setAttribute('opacity', 1);
    const d = new Date(p.t);
    const deltaVsInit = initialAum != null ? ((p.v - initialAum) / initialAum) * 100 : null;
    tip.innerHTML =
      '<div class="tip-date">' + esc(d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })) + '</div>' +
      '<b style="color:' + stroke + '">' + esc(fmtUsd(p.v)) + '</b>' +
      (deltaVsInit != null ? '<span style="color:#98a3b4"> &nbsp;' + esc(fmtPct(deltaVsInit)) + '</span>' : '');
    tip.style.left = px + 'px';
    tip.style.top = (py - 12) + 'px';
    tip.style.opacity = 1;
  });
  svg.addEventListener('mouseleave', () => { tip.style.opacity = 0; crossX.setAttribute('opacity', 0); crossDot.setAttribute('opacity', 0); });
}

/* ------------------------------------------------------------------ *
 * Render: risk / drawdown gauges
 * ------------------------------------------------------------------ */
function riskTone(ratio) {
  if (ratio >= 0.85) return 'tone-hot';
  if (ratio >= 0.6) return 'tone-warn';
  return 'tone-ok';
}
function gauge(name, display, used, limit, opts) {
  const ratio = limit > 0 ? used / limit : 0;
  const pct = Math.min(100, Math.max(0, ratio * 100));
  return '<div class="gauge">' +
    '<div class="g-top">' +
      '<span class="g-name">' + esc(name) + '</span>' +
      '<span class="g-val">' + esc(fmtUsd(display)) + '<span class="g-pct"> / ' + esc(fmtUsd(limit)) + '</span></span>' +
    '</div>' +
    '<div class="bar"><div class="fill ' + opts.tone + '" data-fill="' + pct.toFixed(1) + '"></div></div>' +
  '</div>';
}

/* ------------------------------------------------------------------ *
 * Render: strategy dashboard
 * ------------------------------------------------------------------ */
function renderDashboard(view) {
  const s = view;
  const isAll = s._isAll;
  const pnlPct = s.initial_aum ? (s.pnl_initial / s.initial_aum) * 100 : 0;

  // KPI cards
  const kpis =
    '<section class="kpis" aria-label="Key metrics">' +
      kpiCard('Assets (AUM)', s.aum, fmtUsd,
        '<span class="k-hint">initial ' + esc(fmtUsd(s.initial_aum)) + '</span>', '') +
      kpiCard('PnL — inception', s.pnl_initial, fmtSignedUsd,
        '<span class="delta ' + toneClass(s.pnl_initial) + '">' + esc(fmtPct(pnlPct)) + '</span>',
        toneClass(s.pnl_initial)) +
      kpiCard('PnL — 1 day', s.pnl_1d, fmtSignedUsd,
        '<span class="k-hint">last 24h</span>', toneClass(s.pnl_1d)) +
      kpiCard('PnL — today', s.pnl_tod, fmtSignedUsd,
        '<span class="k-hint">since 00:00 UTC</span>', toneClass(s.pnl_tod)) +
    '</section>';

  // Chart card
  const chart =
    '<div class="card card-chart">' +
      '<h3>AUM history <span class="hint">daily · dashed = initial</span></h3>' +
      '<div class="chart-wrap" id="chartWrap"></div>' +
    '</div>';

  // Risk card
  const riskUtilRatio = s.risk_budget > 0 ? s.risk_utilised / s.risk_budget : 0;
  const risk =
    '<div class="card">' +
      '<h3>Risk exposure <span class="hint">notional ' + esc(fmtUsd(s.risk_utilised)) + '</span></h3>' +
      gauge('Utilised budget', s.risk_utilised, s.risk_utilised, s.risk_budget, { tone: riskTone(riskUtilRatio) }) +
      '<div class="breakdown">' +
        '<div class="b-cell"><div class="b-label">Long</div><div class="b-val" style="color:var(--pos)">' + esc(fmtUsd(s.risk_long, true)) + '</div></div>' +
        '<div class="b-cell"><div class="b-label">Short</div><div class="b-val" style="color:var(--neg)">' + esc(fmtUsd(s.risk_short, true)) + '</div></div>' +
        '<div class="b-cell"><div class="b-label">Net</div><div class="b-val">' + esc(fmtUsd(s.risk_net, true)) + '</div></div>' +
      '</div>' +
    '</div>';

  // Drawdown card
  const usedDD = Math.max(0, -s.drawdown_utilised);
  const ddRatio = s.drawdown_limit > 0 ? usedDD / s.drawdown_limit : 0;
  const usedDDd = Math.max(0, -s.daily_drawdown_utilised);
  const dddRatio = s.daily_drawdown_limit > 0 ? usedDDd / s.daily_drawdown_limit : 0;
  const ddTone = s.drawdown_utilised >= 0 ? 'tone-ok' : riskTone(ddRatio);
  const dddTone = s.daily_drawdown_utilised >= 0 ? 'tone-ok' : riskTone(dddRatio);
  const ddState = s.drawdown_utilised >= 0 ? ' (above high-water)' : ' (in drawdown)';
  const drawdown =
    '<div class="card">' +
      '<h3>Drawdown</h3>' +
      gauge('Lifetime' + ddState, s.drawdown_utilised, usedDD, s.drawdown_limit, { tone: ddTone }) +
      gauge('Daily', s.daily_drawdown_utilised, usedDDd, s.daily_drawdown_limit, { tone: dddTone }) +
    '</div>';

  // Positions table
  const posRows = (s.positions || []).map(p => {
    const side = String(p.side || '').toUpperCase();
    return '<tr>' +
      (isAll ? '<td>' + esc(p._strat) + '</td>' : '') +
      '<td>' + esc(p.symbol) + '</td>' +
      '<td><span class="side-badge ' + (side === 'LONG' ? 'long' : 'short') + '">' + esc(side) + '</span></td>' +
      '<td>' + esc(fmtUsd(p.size)) + '</td>' +
      '<td>' + esc((+p.entry_price).toLocaleString('en-US', { maximumFractionDigits: 2 })) + '</td>' +
      '<td style="color:' + (+p.unrealized_pnl >= 0 ? 'var(--pos)' : 'var(--neg)') + '">' + esc(fmtSignedUsd(p.unrealized_pnl)) + '</td>' +
    '</tr>';
  }).join('');
  const positions =
    '<div class="card card-positions">' +
      '<h3>Open positions <span class="hint">' + s.positions_count + '</span></h3>' +
      (s.positions_count
        ? '<div class="table-scroll"><table class="positions"><thead><tr>' +
            (isAll ? '<th>Strategy</th>' : '') +
            '<th>Symbol</th><th>Side</th><th>Size (notional)</th><th>Entry price</th><th>Unrealized PnL</th>' +
          '</tr></thead><tbody>' + posRows + '</tbody></table></div>'
        : '<div class="empty-state">No open positions.</div>') +
    '</div>';

  $('#content').innerHTML =
    '<div class="page-head">' +
      '<div>' +
        '<h1 class="page-title">' + esc(s.name) + '<span class="account-tag">' + esc(s.account_type || '') + '</span></h1>' +
        '<div class="page-sub">' + esc(s.aum_history.length) + ' daily history points' +
          (isAll ? ' &middot; forward-filled across ' + state.data.strategies.length + ' strategies' : '') +
        '</div>' +
      '</div>' +
    '</div>' +
    kpis + chart + '<div class="card-side">' + risk + drawdown + '</div>' + positions;

  // set bar widths (CSSOM — CSP-safe)
  $$('.bar .fill', $('#content')).forEach(f => {
    f.style.width = f.dataset.fill + '%';
  });

  // animate KPI values
  $$('.kpi .k-value', $('#content')).forEach(el => {
    const fmtName = el.dataset.fmt;
    const formatter = fmtName === 'signed' ? fmtSignedUsd : fmtUsd;
    const target = parseFloat(el.dataset.raw);
    if (isNaN(target)) return;
    animateNumber(el, target, formatter);
  });

  renderChart($('#chartWrap'), s.aum_history, s.initial_aum);
}

function kpiCard(label, value, formatter, subHtml, valueClass) {
  const fmtName = formatter === fmtSignedUsd ? 'signed' : 'plain';
  const display = value === null || value === undefined || isNaN(value) ? '—' : formatter(value);
  return '<div class="kpi ' + (valueClass === 'pos' ? 'raised' : valueClass === 'neg' ? 'red' : '') + '">' +
    '<div class="k-label">' + esc(label) + '</div>' +
    '<div class="k-value" data-raw="' + value + '" data-fmt="' + fmtName + '">' + esc(display) + '</div>' +
    (subHtml ? '<div class="k-sub">' + subHtml + '</div>' : '') +
  '</div>';
}

/* ------------------------------------------------------------------ *
 * Status bar / stale badge
 * ------------------------------------------------------------------ */
function renderMeta() {
  const d = state.data;
  const total = d.totals;
  $('#portfolioSummary').innerHTML =
    'Portfolio AUM <b>' + esc(fmtUsd(total.aum)) + '</b> &middot; ' +
    d.strategies.length + ' strategies &middot; ' +
    (total.positions || 0) + ' open ' + ((total.positions === 1) ? 'position' : 'positions');

  $('#asOfBadge').textContent = 'snapshot ' + d.as_of + ' UTC';

  const gen = Date.parse(d.generated_at);
  const staleBadge = $('#staleBadge');
  if (Number.isFinite(gen)) {
    const age = Date.now() - gen;
    if (age > STALE_MS) {
      staleBadge.className = 'badge stale';
      staleBadge.textContent = 'data stale · ' + relTime(gen);
    } else if (age > STALE_MS * 0.6) {
      staleBadge.className = 'badge warn';
      staleBadge.textContent = 'refreshing soon · ' + relTime(gen);
    } else {
      staleBadge.className = 'badge fresh';
      staleBadge.textContent = 'live · ' + relTime(gen);
    }
  }

  $('#generatedAt').textContent = 'published ' +
    (Number.isFinite(gen) ? new Date(gen).toLocaleString('en-US', { hour12: false }) + ' UTC' : (d.generated_at || '—'));

  // show fetch time in refresh button tooltip
  $('#refreshBtn').title = 'Re-fetch and re-decrypt' + (state.fetchedAt ? ' · last ' + new Date(state.fetchedAt).toLocaleTimeString() : '');
}

function relTime(t) {
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return s + 's ago';
  const m = Math.round(s / 60);
  if (m < 60) return m + 'm ago';
  const h = Math.round(m / 60);
  return h + 'h ago';
}

/* ------------------------------------------------------------------ *
 * Number count-up animation
 * ------------------------------------------------------------------ */
function animateNumber(el, target, formatter, dur = 750) {
  const start = performance.now();
  function tick(now) {
    const t = Math.min(1, (now - start) / dur);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = formatter(target * eased);
    if (t < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

/* ------------------------------------------------------------------ *
 * Login / lock / data refresh
 * ------------------------------------------------------------------ */
function showLogin() { $('#login').hidden = false; $('#app').hidden = true; }
function showApp() { $('#login').hidden = true; $('#app').hidden = false; }

function setLoginStatus(msg, cls) {
  const el = $('#loginStatus');
  el.textContent = msg || '';
  el.className = 'login-status' + (cls ? ' ' + cls : '');
}

async function fetchEnvelope(url) {
  const res = await fetch(url + (url.includes('?') ? '&' : '?') + 't=' + Date.now(), { cache: 'no-store' });
  if (!res.ok) throw new Error('data fetch failed (HTTP ' + res.status + ')');
  const text = (await res.text()).trim();
  return b64ToBytes(text);
}

async function fetchAndDecrypt() {
  const env = await fetchEnvelope(DATA_OVERRIDE || DATA_URL);
  return normalizePayload(await decryptEnvelope(env, PRIVATE_KEY));
}

// Hand the credentials to the browser password manager (Chrome/Edge support the
// Credential Management API) so it offers to save and autofill them next time.
// Elsewhere this is a no-op and the form's autocomplete attributes take over.
async function saveCredential(password) {
  try {
    if (!window.PasswordCredential || !navigator.credentials || !navigator.credentials.store) return;
    const user = ($('#username') && $('#username').value) || 'strategist';
    await navigator.credentials.store(new PasswordCredential({ id: user, password: password, name: 'StratDeck' }));
  } catch (e) { /* user dismissed the prompt, or API unavailable */ }
}

async function login() {
  if (state.loggingIn) return;
  const pwInput = $('#passwordInput');
  const btn = $('#unlockBtn');
  const password = pwInput ? pwInput.value : '';

  if (!crypto.subtle) {
    setLoginStatus('WebCrypto unavailable — open over https:// or http://localhost (not file://).', 'err');
    return;
  }
  if (!password) { setLoginStatus('Enter your password to continue.', 'err'); return; }
  if (password !== LOGIN_PASSWORD) { setLoginStatus('Incorrect password. Try again.', 'err'); return; }

  state.loggingIn = true;
  btn.disabled = true; btn.classList.add('working');
  setLoginStatus('Fetching encrypted data…', 'busy');
  try {
    const data = await fetchAndDecrypt();
    state.data = data;
    state.fetchedAt = Date.now();
    state.lastAttemptAt = state.fetchedAt;

    setLoginStatus('', '');
    if (pwInput) pwInput.value = '';
    saveCredential(password);   // fire-and-forget: let the password manager save it
    showApp();
    if (!location.hash) location.hash = '#/all';
    renderRoute();
    startTicker();
  } catch (e) {
    const msg = String(e && e.message || e);
    const friendly = msg.includes('decrypt') || msg.includes('OperationError')
      ? 'Could not decrypt the latest snapshot.'
      : msg;
    setLoginStatus('Failed to log in. ' + friendly, 'err');
  } finally {
    state.loggingIn = false;
    btn.disabled = false; btn.classList.remove('working');
  }
}

function lock() {
  state.epoch++;
  state.data = null;
  state.refreshing = false;
  stopTicker();
  showLogin();
  const pw = $('#passwordInput');
  if (pw) { pw.value = ''; pw.focus(); }
  setLoginStatus('Locked. Enter your password to unlock again.', '');
}

// Re-fetch + re-decrypt the S3 snapshot. Returns true when the snapshot changed.
async function refresh(opts) {
  if (state.refreshing) return false;
  const manual = !!(opts && opts.manual);
  const epoch = state.epoch;
  const btn = $('#refreshBtn');
  state.refreshing = true;
  state.lastAttemptAt = Date.now();
  if (manual) btn.disabled = true;
  try {
    const data = await fetchAndDecrypt();
    // The user locked (or a new session started) while we were fetching — drop it.
    if (epoch !== state.epoch) return false;
    const prev = state.data;
    state.data = data;
    state.fetchedAt = Date.now();
    const changed = !prev || prev.generated_at !== data.generated_at || prev.as_of !== data.as_of;
    if (changed) renderRoute(); else renderMeta();
    return changed;
  } catch (e) {
    console.error('refresh failed', e);
    return false;
  } finally {
    state.refreshing = false;
    if (manual) btn.disabled = false;
  }
}

/* ------------------------------------------------------------------ *
 * Route rendering + ticker
 * ------------------------------------------------------------------ */
function renderRoute() {
  if (!state.data) { showLogin(); return; }
  const route = routeFromHash();
  renderNav(route);
  renderDashboard(viewForRoute(route));
  renderMeta();
}

let _ticker = null;

// Age of the currently displayed snapshot, based on the publisher timestamp
// (falling back to the monitor timestamp, then to when we fetched it).
function snapshotAgeMs() {
  const gen = Date.parse(state.data && state.data.generated_at);
  if (Number.isFinite(gen)) return Date.now() - gen;
  const asOfRaw = state.data && state.data.as_of;
  const asOf = Date.parse(String(asOfRaw || '').replace(' ', 'T') + 'Z');
  if (Number.isFinite(asOf)) return Date.now() - asOf;
  return state.fetchedAt ? Date.now() - state.fetchedAt : Infinity;
}

async function tick() {
  if (!state.data) return;
  renderMeta();
  // Once the displayed snapshot passes the 5-minute publish cadence, fetch the
  // next one from S3 automatically — no page refresh or logout required.
  if (state.refreshing) return;
  if (snapshotAgeMs() < AUTO_REFRESH_AFTER_MS) return;
  if (Date.now() - state.lastAttemptAt < TICK_MS - 1000) return;
  await refresh();
}

function startTicker() {
  stopTicker();
  _ticker = setInterval(tick, TICK_MS);
}
function stopTicker() { if (_ticker) { clearInterval(_ticker); _ticker = null; } }

/* ------------------------------------------------------------------ *
 * Boot
 * ------------------------------------------------------------------ */
window.addEventListener('hashchange', renderRoute);

document.addEventListener('DOMContentLoaded', () => {
  const form = $('#loginForm');
  if (form) {
    // Submit is the standard signal password managers watch for; we intercept it
    // so no navigation happens (CSP also blocks form-action) and log in in-place.
    form.addEventListener('submit', e => { e.preventDefault(); login(); });
  } else {
    $('#unlockBtn').addEventListener('click', login);
  }
  $('#lockBtn').addEventListener('click', lock);
  $('#refreshBtn').addEventListener('click', () => refresh({ manual: true }));

  showLogin();
  const pw = $('#passwordInput');
  if (pw) pw.focus();
});