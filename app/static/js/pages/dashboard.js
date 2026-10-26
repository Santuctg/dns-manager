import {
  $, $$, api, escapeHtml, icon, t, toast, fmtBytes, fmtDate,
  poll, createSparkline, healthChip, badge,
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

const sparks = {};

function setText(name, value) {
  const node = $(`[data-${name}]`);
  if (node) node.textContent = value;
}

function setSpark(kind, key, value) {
  const node = $(`[data-spark-${kind}="${key}"]`);
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
  const { active, total } = servicesSummary();
  setText('summary-services', `${active} / ${total}`);
  setText('summary-services-detail', t('dashboard.services_active', { active, total }));

  const up = state.backends.filter((row) => row.status === 'UP').length;
  const down = state.backends.filter((row) => ['DOWN', 'HTTP_ERROR', 'TLS_ERROR', 'TIMEOUT'].includes(row.status)).length;
  setText('summary-mappings', String(state.mappings.length || state.backends.length));
  setText('summary-mappings-detail', t('dashboard.mappings_breakdown', {
    total: state.mappings.length || state.backends.length,
    up,
    down,
  }));

  setText('summary-pending', String(state.pending.count || 0));
  const pendingCard = $('[data-summary-card-pending]');
  if (pendingCard) pendingCard.classList.toggle('attention', Number(state.pending.count) > 0);

  const expiring = state.certificates.filter((cert) => {
    if (!cert.expires_at) return false;
    const days = Math.ceil((new Date(cert.expires_at).getTime() - Date.now()) / 86400000);
    return days <= 30;
  }).length;
  setText('summary-certificates', String(expiring));
  setText('summary-certificates-detail', t('dashboard.expiring', { count: expiring }));
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
  setSpark('value', 'cpu', Number.isFinite(Number(cpu.usage_percent)) ? `${Number(cpu.usage_percent).toFixed(1)}%` : '—');
  setSpark('detail', 'cpu', Number.isFinite(Number(cpu.load_1)) ? `load ${cpu.load_1}` : t('common.not_available'));
  setSpark('value', 'memory', Number.isFinite(Number(memory.usage_percent)) ? `${Number(memory.usage_percent).toFixed(1)}%` : '—');
  setSpark('detail', 'memory', memory.total_bytes
    ? `${fmtBytes(memory.used_bytes)} / ${fmtBytes(memory.total_bytes)}`
    : t('common.not_available'));

  sparks.cpu?.push(cpu.usage_percent);
  sparks.memory?.push(memory.usage_percent);

  const interfaces = metrics.network?.interfaces || [];
  const rx = interfaces.reduce((sum, row) => sum + Number(row.rx_bytes || 0), 0);
  const tx = interfaces.reduce((sum, row) => sum + Number(row.tx_bytes || 0), 0);
  const now = Number(metrics.sampled_at_ms) || Date.now();
  if (state.net && state.net.rx <= rx && state.net.tx <= tx) {
    const seconds = Math.max((now - state.net.time) / 1000, 0.001);
    const rxRate = (rx - state.net.rx) / seconds;
    const txRate = (tx - state.net.tx) / seconds;
    sparks.rx?.push(rxRate);
    sparks.tx?.push(txRate);
    setSpark('value', 'network', `${fmtBytes(rxRate)}/s`);
    setSpark('detail', 'network', `RX ${fmtBytes(rxRate)}/s · TX ${fmtBytes(txRate)}/s`);
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
  } catch {
    const sample = $('[data-dashboard-sample]');
    if (sample) sample.textContent = t('status.unavailable');
    for (const key of ['cpu', 'memory', 'network']) {
      setSpark('value', key, '—');
      setSpark('detail', key, t('common.not_available'));
    }
  }
}

async function loadDashboard() {
  const [status, mappings, backends, pending, certificates, ufw, events] = await Promise.allSettled([
    api('/api/v1/system/status'),
    api('/api/v1/mappings'),
    api('/api/v1/system/backends'),
    api('/api/v1/config/pending'),
    api('/api/v1/ssl/certificates'),
    api('/api/v1/firewall/status'),
    api('/api/v1/audit?limit=10'),
  ]);
  if (status.status === 'fulfilled') state.status = status.value;
  if (mappings.status === 'fulfilled') state.mappings = mappings.value;
  if (backends.status === 'fulfilled') state.backends = backends.value;
  if (pending.status === 'fulfilled') state.pending = pending.value;
  if (certificates.status === 'fulfilled') state.certificates = certificates.value;
  if (ufw.status === 'fulfilled') state.ufw = ufw.value;
  if (events.status === 'fulfilled') state.events = events.value.slice(0, 10);
  renderSummary();
  renderAttention();
  renderEvents();
  await refreshMetrics();
}

export async function init() {
  sparks.cpu = createSparkline($('[data-sparkline="cpu"]'), { toneName: 'accent' });
  sparks.memory = createSparkline($('[data-sparkline="memory"]'), { toneName: 'info' });
  sparks.rx = createSparkline($('[data-sparkline="rx"]'), { toneName: 'good' });
  sparks.tx = createSparkline($('[data-sparkline="tx"]'), { toneName: 'warning' });

  try {
    await loadDashboard();
  } catch (error) {
    toast(error.message, 'critical');
  }

  poll(refreshMetrics, 1000);

  $('[data-dashboard-refresh]')?.addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      await loadDashboard();
      toast(t('common.success'), 'good');
    } catch (error) {
      toast(error.message, 'critical');
    } finally {
      button.disabled = false;
    }
  });

  document.addEventListener('dns:pending-refreshed', (event) => {
    state.pending = event.detail || state.pending;
    renderSummary();
    renderAttention();
  });
}
