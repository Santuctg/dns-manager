import {
  $, $$, api, escapeHtml, icon, t, toast, fmtBytes, fmtDate,
  poll, createChart, healthChip, badge,
} from '../core.js';

const state = {
  mappings: [],
  backends: [],
  certificates: [],
  pending: { count: 0, domains: [] },
  status: null,
  metrics: null,
  ufw: null,
  events: [],
  net: null,
};

const charts = {};

// Each card renders as soon as its own request finishes instead of waiting for
// the slowest endpoint (backend probes can take seconds on a real host).
const loaded = {
  status: false,
  mappings: false,
  backends: false,
  pending: false,
  certificates: false,
};

function setText(name, value) {
  const node = $(`[data-${name}]`);
  if (node) node.textContent = value;
}

function servicesSummary() {
  const services = state.metrics?.services || {};
  const names = ['dns-manager', 'dns-manager-helper.service', 'nginx', 'dnsmasq'];
  const active = names.filter((name) => String(services[name] || '').toLowerCase() === 'active').length;
  if (Object.keys(services).length) {
    return { active, total: names.length };
  }
  const fallback = [state.status?.database === 'ok', state.status?.dnsmasq === 'active', state.status?.nginx === 'active'];
  return { active: fallback.filter(Boolean).length + 1, total: 4 };
}

function renderSummary() {
  if (loaded.status || state.metrics) {
    const { active, total } = servicesSummary();
    setText('summary-services', `${active} / ${total}`);
    setText('summary-services-detail', t('dashboard.services_active', { active, total }));
  }

  if (loaded.mappings || loaded.backends) {
    const total = state.mappings.length || state.backends.length;
    setText('summary-mappings', String(total));
    if (loaded.backends) {
      const up = state.backends.filter((row) => row.status === 'UP').length;
      const down = state.backends.filter((row) => ['DOWN', 'HTTP_ERROR', 'TLS_ERROR', 'TIMEOUT'].includes(row.status)).length;
      setText('summary-mappings-detail', t('dashboard.mappings_breakdown', { total, up, down }));
    } else {
      setText('summary-mappings-detail', t('dashboard.mappings_total', { total }));
    }
  }

  if (loaded.pending) {
    setText('summary-pending', String(state.pending.count || 0));
    const pendingCard = $('[data-summary-card-pending]');
    if (pendingCard) pendingCard.classList.toggle('attention', Number(state.pending.count) > 0);
  }

  if (loaded.certificates) {
    const expiring = state.certificates.filter((cert) => {
      if (!cert.expires_at) return false;
      const days = Math.ceil((new Date(cert.expires_at).getTime() - Date.now()) / 86400000);
      return days <= 30;
    }).length;
    setText('summary-certificates', String(expiring));
    setText('summary-certificates-detail', t('dashboard.expiring', { count: expiring }));
  }
}

function attentionItems() {
  const items = [];
  const down = state.backends.filter((row) => ['DOWN', 'HTTP_ERROR', 'TLS_ERROR', 'TIMEOUT'].includes(row.status));
  if (down.length) {
    items.push({
      title: t('dashboard.down_backends', { count: down.length }),
      detail: down.slice(0, 3).map((row) => `${row.domain} · ${row.status}`).join(', '),
      href: '/app/mappings',
      icon: 'alert',
      tone: 'critical',
    });
  }
  const expiring = state.certificates.filter((cert) => {
    if (!cert.expires_at) return false;
    const days = Math.ceil((new Date(cert.expires_at).getTime() - Date.now()) / 86400000);
    return days <= 30;
  });
  if (expiring.length) {
    items.push({
      title: t('dashboard.expiring', { count: expiring.length }),
      detail: expiring.slice(0, 3).map((cert) => cert.domain).join(', '),
      href: '/app/ssl',
      icon: 'ssl',
      tone: 'warning',
    });
  }
  if (state.ufw && state.ufw.active === false) {
    items.push({
      title: t('dashboard.ufw_inactive'),
      detail: state.ufw.installed === false ? t('common.not_available') : '',
      href: '/app/firewall',
      icon: 'firewall',
      tone: 'critical',
    });
  }
  if (Number(state.pending.count) > 0) {
    items.push({
      title: t('dashboard.pending_item', { count: state.pending.count }),
      detail: (state.pending.domains || []).slice(0, 3).join(', '),
      href: '/app/mappings',
      icon: 'mappings',
      tone: 'warning',
    });
  }
  return items;
}

function renderAttention() {
  const list = $('[data-attention-list]');
  if (!list) return;
  list.setAttribute('aria-busy', 'false');
  const items = attentionItems();
  if (!items.length) {
    list.innerHTML = `<p class="muted small">${escapeHtml(t('dashboard.attention_empty'))}</p>`;
    return;
  }
  list.innerHTML = items.map((item) => `
    <a class="attention-item" href="${item.href}">
      <span class="status-dot ${item.tone}" aria-hidden="true"></span>
      <span class="attention-copy">
        <strong>${escapeHtml(item.title)}</strong>
        ${item.detail ? `<span class="muted small">${escapeHtml(item.detail)}</span>` : ''}
      </span>
      ${icon('arrow-right', 'icon icon-sm')}
    </a>`).join('');
}

function renderEvents() {
  const list = $('[data-recent-events]');
  if (!list) return;
  list.setAttribute('aria-busy', 'false');
  if (!state.events.length) {
    list.innerHTML = `<p class="muted small">${escapeHtml(t('dashboard.no_events'))}</p>`;
    return;
  }
  list.innerHTML = state.events.map((event) => `
    <div class="event-item">
      <div class="event-main">
        <strong>${escapeHtml(event.action)}</strong>
        <div>${escapeHtml(event.username || '—')} · ${escapeHtml(fmtDate(event.created_at))}</div>
      </div>
      ${badge(event.status || 'success', event.status || 'success')}
    </div>`).join('');
}

function renderMetrics() {
  const metrics = state.metrics;
  if (!metrics) return;
  const cpu = metrics.cpu || {};
  const memory = metrics.memory || {};

  charts.cpuMemory?.push('cpu', cpu.usage_percent);
  charts.cpuMemory?.push('memory', memory.usage_percent);

  const interfaces = metrics.network?.interfaces || [];
  const rx = interfaces.reduce((sum, row) => sum + Number(row.rx_bytes || 0), 0);
  const tx = interfaces.reduce((sum, row) => sum + Number(row.tx_bytes || 0), 0);
  const now = Number(metrics.sampled_at_ms) || Date.now();
  if (state.net && state.net.rx <= rx && state.net.tx <= tx) {
    const seconds = Math.max((now - state.net.time) / 1000, 0.001);
    const rxRate = (rx - state.net.rx) / seconds;
    const txRate = (tx - state.net.tx) / seconds;
    charts.network?.push('input', rxRate);
    charts.network?.push('output', txRate);
  }
  state.net = { rx, tx, time: now };
  const sample = $('[data-dashboard-sample]');
  if (sample) {
    sample.textContent = new Date(now).toLocaleTimeString();
  }
  renderSummary();
}

async function refreshMetrics() {
  try {
    state.metrics = await api('/api/v1/system/metrics');
    renderMetrics();
  } catch (error) {
    const sample = $('[data-dashboard-sample]');
    if (sample) sample.textContent = t('status.unavailable');
    // Let poll() see the failure so it backs off instead of hammering a
    // metrics endpoint that is permanently unavailable (e.g. no /proc).
    throw error;
  }
}

async function loadDashboard() {
  const apply = (promise, done) => promise.then((value) => {
    done(value);
    renderSummary();
    renderAttention();
  });
  const results = await Promise.allSettled([
    apply(api('/api/v1/system/status'), (value) => { state.status = value; loaded.status = true; }),
    apply(api('/api/v1/mappings'), (value) => { state.mappings = value; loaded.mappings = true; }),
    apply(api('/api/v1/system/backends'), (value) => { state.backends = value; loaded.backends = true; }),
    apply(api('/api/v1/config/pending'), (value) => { state.pending = value; loaded.pending = true; }),
    apply(api('/api/v1/ssl/certificates'), (value) => { state.certificates = value; loaded.certificates = true; }),
    // Firewall state only feeds the attention list, no summary counter.
    apply(api('/api/v1/firewall/status'), (value) => { state.ufw = value; }),
    api('/api/v1/audit?limit=10').then((value) => {
      state.events = value.slice(0, 10);
      renderEvents();
    }),
  ]);
  if (results.every((result) => result.status === 'rejected')) {
    const reason = results.find((result) => result.status === 'rejected')?.reason;
    throw reason instanceof Error ? reason : new Error(t('common.error'));
  }
}

// Seed the charts from the server-recorded history (~1 h window). The server
// is the source of truth so any device sees the same timeline; localStorage is
// only a fallback. A failed history fetch must never break live sampling.
async function hydrateChartsFromHistory() {
  let rows;
  try {
    rows = await api('/api/v1/system/metrics/history');
  } catch {
    return; // fall back to whatever localStorage restored at chart creation
  }
  if (!Array.isArray(rows) || rows.length === 0) return;
  const cpuPoints = rows
    .filter((row) => Number.isFinite(Number(row.cpu)) || Number.isFinite(Number(row.mem)))
    .map((row) => ({ t: Number(row.t), cpu: Number(row.cpu), memory: Number(row.mem) }));
  const netPoints = rows
    .filter((row) => Number.isFinite(Number(row.input)) || Number.isFinite(Number(row.output)))
    .map((row) => ({ t: Number(row.t), input: Number(row.input), output: Number(row.output) }));
  // reset() drops the localStorage copy so the server timeline is authoritative.
  if (cpuPoints.length) {
    charts.cpuMemory?.reset();
    charts.cpuMemory?.replay(cpuPoints);
  }
  if (netPoints.length) {
    charts.network?.reset();
    charts.network?.replay(netPoints);
  }
}

export async function init() {
  charts.cpuMemory = createChart($('[data-chart="cpu-memory"]'), {
    series: [
      { key: 'cpu', toneName: 'accent', label: t('dashboard.cpu') },
      { key: 'memory', toneName: 'info', label: t('dashboard.ram') },
    ],
    yMax: 100,
    minIntervalMs: 5000,
    capacity: 720,
    storageKey: 'dns-manager:chart:cpu-memory',
    formatValue: (value) => `${Number(value).toFixed(1)}%`,
    xLabels: ['-60m', '-30m', t('dashboard.now')],
  });
  charts.network = createChart($('[data-chart="network"]'), {
    series: [
      { key: 'input', toneName: 'accent', label: t('dashboard.input') },
      { key: 'output', toneName: 'info', label: t('dashboard.output') },
    ],
    minIntervalMs: 5000,
    capacity: 720,
    storageKey: 'dns-manager:chart:network',
    formatValue: (value) => `${fmtBytes(value)}/s`,
    xLabels: ['-60m', '-30m', t('dashboard.now')],
  });

  // Seed charts from the recorded history before live polling so the graph is
  // populated on first paint instead of starting empty.
  await hydrateChartsFromHistory();

  // Metrics are independent of the summary endpoints, so they start first and
  // keep their own retry/backoff loop.
  poll(refreshMetrics, 1000);

  try {
    await loadDashboard();
  } catch (error) {
    toast(error.message, 'critical');
  }

  $('[data-dashboard-refresh]')?.addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      const [summary] = await Promise.allSettled([loadDashboard(), refreshMetrics()]);
      if (summary.status === 'rejected') throw summary.reason;
      toast(t('common.success'), 'good');
    } catch (error) {
      toast(error.message, 'critical');
    } finally {
      button.disabled = false;
    }
  });

  document.addEventListener('dns:pending-refreshed', (event) => {
    state.pending = event.detail || state.pending;
    loaded.pending = true;
    renderSummary();
    renderAttention();
  });
}
