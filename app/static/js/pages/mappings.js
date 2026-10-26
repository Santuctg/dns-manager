import {
  $, $$, api, escapeHtml, icon, t, toast, healthChip, tone, statusLabel,
  openPanel, closePanel, wirePanel, runAction, showResult, showLoading,
  closeModal, refreshPending,
} from '../core.js';

const state = {
  mappings: [],
  health: new Map(),
  healthAt: 0,
  pending: new Set(),
  filter: 'all',
  search: '',
  preview: null,
  previewError: null,
};

const FAILING = ['DOWN', 'HTTP_ERROR', 'TLS_ERROR', 'TIMEOUT'];

const can = (name) => document.body.dataset[name] === 'true';
const canCreate = () => can('canMappingCreate');
const canUpdate = () => can('canMappingUpdate');
const canDelete = () => can('canMappingDelete');
const canPreview = () => can('canApply');

function upstream(mapping) {
  return `${mapping.upstream_scheme}://${mapping.upstream_host}:${mapping.upstream_port}`;
}

function sslIssued(mapping) {
  return ['ISSUED', 'EXPIRING'].includes(String(mapping.ssl_status || '').toUpperCase());
}

function isDown(status) {
  return FAILING.includes(String(status || '').toUpperCase());
}

function healthOf(mapping) {
  return state.health.get(mapping.id) || null;
}

function healthTone(mapping) {
  if (!mapping.enabled) return 'info';
  const status = healthOf(mapping)?.status;
  return status ? tone(status) : 'warning';
}

function rowMatches(mapping) {
  const health = state.health.get(mapping.id)?.status || 'UNKNOWN';
  if (state.filter === 'up' && health !== 'UP') return false;
  if (state.filter === 'down' && !isDown(health)) return false;
  if (state.filter === 'disabled' && mapping.enabled) return false;
  if (state.filter === 'pending' && !state.pending.has(mapping.domain)) return false;
  if (!state.search) return true;
  const haystack = [
    mapping.domain,
    mapping.upstream_host,
    mapping.upstream_scheme,
    mapping.upstream_port,
    mapping.description || '',
  ].join(' ').toLowerCase();
  return haystack.includes(state.search);
}

function flagChips(mapping) {
  const flag = (on, toneName, key, offTitle) => {
    const label = t(key);
    if (on) return `<span class="chip chip-${toneName}">${escapeHtml(label)}</span>`;
    return `<span class="chip chip-off" title="${escapeHtml(offTitle)}">${escapeHtml(label)}</span>`;
  };
  const flags = [
    flag(sslIssued(mapping), 'good', 'mappings.flag.https', t('mappings.flag.https_off')),
    flag(Boolean(mapping.websocket_enabled), 'info', 'mappings.flag.ws', t('mappings.flag.ws_off')),
    flag(Boolean(mapping.preserve_host), 'accent', 'mappings.flag.host', t('mappings.flag.host_off')),
  ];
  if (!mapping.enabled) flags.push(`<span class="chip chip-off">${escapeHtml(t('common.disabled'))}</span>`);
  return `<div class="flag-list" aria-label="${escapeHtml(t('mappings.col.flags'))}">${flags.join('')}</div>`;
}

function healthCell(mapping) {
  if (!mapping.enabled) return `<span class="chip chip-off">${escapeHtml(t('common.disabled'))}</span>`;
  const health = healthOf(mapping);
  if (!health) return `<span class="health"><span class="status-dot warning" aria-hidden="true"></span><span class="health-label">${escapeHtml(t('common.loading'))}</span></span>`;
  const latency = latencyText(health);
  return `<div class="health-stack">${healthChip(health.status)}${latency ? `<span class="health-latency">${escapeHtml(latency)}</span>` : ''}</div>`;
}

function latencyText(health) {
  if (health?.latency_ms === null || health?.latency_ms === undefined) return '';
  if (!Number.isFinite(Number(health.latency_ms))) return '';
  return t('mappings.latency', { value: Number(health.latency_ms).toFixed(0) });
}

function actionsCell(mapping) {
  const actions = [
    `<button class="btn btn-ghost btn-sm" type="button" data-mapping-detail="${mapping.id}">${icon('search', 'icon icon-sm')}${escapeHtml(t('common.details'))}</button>`,
  ];
  if (canUpdate()) {
    actions.push(`<button class="btn btn-ghost btn-sm" type="button" data-mapping-edit="${mapping.id}">${icon('edit', 'icon icon-sm')}${escapeHtml(t('common.edit'))}</button>`);
  }
  if (canDelete()) {
    actions.push(`<button class="btn btn-ghost btn-sm btn-danger" type="button" data-mapping-delete="${mapping.id}">${icon('trash', 'icon icon-sm')}${escapeHtml(t('common.delete'))}</button>`);
  }
  return `<div class="row-actions">${actions.join('')}</div>`;
}

function renderTable() {
  const table = $('[data-mappings-table]');
  if (!table) return;
  const rows = state.mappings.filter(rowMatches);
  if (!rows.length) {
    table.innerHTML = `<tr><td colspan="5" class="muted">${escapeHtml(state.mappings.length ? t('mappings.no_results') : t('mappings.empty'))}</td></tr>`;
    return;
  }
  table.innerHTML = rows.map((mapping) => `<tr class="mapping-row${mapping.enabled ? '' : ' is-disabled'}">
    <td data-label="${escapeHtml(t('mappings.col.domain'))}">
      <div class="cell-primary mapping-domain">
        <span class="status-dot ${healthTone(mapping)}" aria-hidden="true"></span>
        <button class="mapping-domain-link" type="button" data-mapping-detail="${mapping.id}">
          <span class="domain-name">${escapeHtml(mapping.domain)}</span>
        </button>
        ${state.pending.has(mapping.domain) ? `<span class="chip chip-warning">${escapeHtml(t('mappings.chip.pending'))}</span>` : ''}
        ${mapping.description ? `<span class="domain-desc">${escapeHtml(mapping.description)}</span>` : ''}
      </div>
    </td>
    <td data-label="${escapeHtml(t('mappings.col.upstream'))}"><code>${escapeHtml(upstream(mapping))}</code></td>
    <td data-label="${escapeHtml(t('mappings.col.flags'))}">${flagChips(mapping)}</td>
    <td data-label="${escapeHtml(t('mappings.col.health'))}">${healthCell(mapping)}</td>
    <td data-label="${escapeHtml(t('mappings.col.actions'))}">${actionsCell(mapping)}</td>
  </tr>`).join('');
}

async function loadMappings() {
  const mappingsPromise = api('/api/v1/mappings');
  const pendingPromise = api('/api/v1/config/pending');
  const healthPromise = api('/api/v1/system/backends');

  const [mappings, pending] = await Promise.allSettled([mappingsPromise, pendingPromise]);
  if (mappings.status === 'rejected') {
    healthPromise.catch(() => {});
    throw mappings.reason;
  }
  state.mappings = mappings.value;
  state.pending = new Set(pending.status === 'fulfilled' ? (pending.value.domains || []) : []);
  state.preview = null;
  state.previewError = null;
  renderTable();

  try {
    const rows = await healthPromise;
    state.health = new Map((rows || []).map((row) => [row.mapping_id, row]));
    state.healthAt = Date.now();
  } catch (error) {
    state.health = new Map();
    state.healthAt = 0;
    if (error?.status === 403) state.previewError = t('common.permission_denied');
  }
  renderTable();
}

// ---------------------------------------------------------------- side panels
function openMappingPanel(mapping, trigger) {
  const panel = $('[data-mapping-panel]');
  const form = $('[data-mapping-form]');
  if (!panel || !form) return;
  form.reset();
  form.elements.id.value = mapping?.id || '';
  form.elements.version.value = mapping?.version || '';
  form.elements.domain.value = mapping?.domain || '';
  form.elements.upstream_scheme.value = mapping?.upstream_scheme || 'http';
  form.elements.upstream_host.value = mapping?.upstream_host || '';
  form.elements.upstream_port.value = mapping?.upstream_port ?? '';
  form.elements.custom_timeout.value = mapping?.custom_timeout ?? '';
  form.elements.description.value = mapping?.description || '';
  form.elements.enabled.checked = mapping ? Boolean(mapping.enabled) : true;
  form.elements.websocket_enabled.checked = mapping ? Boolean(mapping.websocket_enabled) : true;
  form.elements.preserve_host.checked = mapping ? Boolean(mapping.preserve_host) : true;
  form.elements.tls_verify.checked = mapping ? Boolean(mapping.tls_verify) : true;
  const title = $('[data-mapping-panel-title]', panel);
  if (title) title.textContent = mapping ? t('mappings.edit_title') : t('mappings.create_title');
  openPanel(panel, trigger, '#mapping-domain');
}

function serverBlocks(text, domain) {
  if (!text) return [];
  const blocks = [];
  const lines = String(text).split('\n');
  let depth = 0;
  let start = -1;
  lines.forEach((line, index) => {
    if (depth === 0 && /^\s*server\s*\{/.test(line)) start = index;
    depth += (line.match(/\{/g) || []).length;
    depth -= (line.match(/\}/g) || []).length;
    if (start >= 0 && depth === 0) {
      const block = lines.slice(start, index + 1);
      if (block.some((row) => row.includes(`server_name ${domain}`))) blocks.push(block.join('\n'));
      start = -1;
    }
  });
  return blocks;
}

function healthDetail(mapping) {
  const health = healthOf(mapping);
  if (!health) return `<p class="muted small">${escapeHtml(t('mappings.health_unavailable'))}</p>`;
  const parts = [];
  if (health.http_status != null) parts.push(`HTTP ${escapeHtml(health.http_status)}`);
  const latency = latencyText(health);
  if (latency) parts.push(escapeHtml(latency));
  if (state.healthAt) {
    parts.push(escapeHtml(t('mappings.checked_at', { time: new Date(state.healthAt).toLocaleTimeString() })));
  }
  return `<div class="stack">
    <div class="health-stack">${healthChip(health.status)}${parts.map((row) => `<span class="health-latency">${row}</span>`).join('')}</div>
    ${health.detail ? `<p class="muted small">${escapeHtml(health.detail)}</p>` : ''}
  </div>`;
}

function configBlock(mapping) {
  if (state.previewError) {
    return `<p class="muted small">${escapeHtml(t('mappings.preview_permission'))}</p>`;
  }
  const blocks = serverBlocks(state.preview?.nginx_config, mapping.domain);
  const https = state.preview?.ssl_vhosts?.[mapping.domain] || '';
  const httpSection = blocks.length
    ? `<pre><code>${escapeHtml(blocks[0])}</code></pre>`
    : `<p class="muted small">${escapeHtml(mapping.enabled ? t('mappings.no_http_block') : t('common.disabled'))}</p>`;
  const httpsSection = https
    ? `<pre><code>${escapeHtml(https)}</code></pre>`
    : `<p class="muted small">${escapeHtml(mapping.enabled ? t('mappings.no_https_block') : t('common.disabled'))}</p>`;
  return `<div class="stack">
    <div class="panel-section">
      <h3>${escapeHtml(t('mappings.http_block'))}</h3>
      ${httpSection}
    </div>
    <div class="panel-section">
      <h3>${escapeHtml(t('mappings.https_block'))}</h3>
      ${httpsSection}
    </div>
  </div>`;
}

async function openDetailPanel(mapping, trigger) {
  const panel = $('[data-mapping-detail-panel]');
  const body = $('[data-mapping-detail-body]', panel);
  const title = $('[data-mapping-detail-title]', panel);
  if (!panel || !body) return;
  if (title) title.textContent = mapping.domain;
  const failing = isDown(healthOf(mapping)?.status);
  const route = `<div class="route-line">
    <span class="route-hop">${escapeHtml(mapping.domain)}</span>
    <span class="route-arrow" aria-hidden="true">→</span>
    <span class="route-hop">${escapeHtml(t('mappings.route_nginx'))}</span>
    <span class="route-arrow" aria-hidden="true">→</span>
    <span class="route-hop ${failing ? 'failing' : ''}">${escapeHtml(upstream(mapping))}</span>
  </div>`;
  body.innerHTML = `<div class="stack">
    <div class="panel-section">
      <h3>${escapeHtml(t('mappings.route'))}</h3>
      ${route}
      ${mapping.description ? `<p class="muted small">${escapeHtml(mapping.description)}</p>` : ''}
      ${flagChips(mapping)}
    </div>
    <div class="panel-section">
      <h3>${escapeHtml(t('mappings.last_health'))}</h3>
      ${healthDetail(mapping)}
    </div>
    <div class="panel-section">
      <h3>${escapeHtml(t('mappings.generated_config'))}</h3>
      <p class="muted small">${escapeHtml(t('mappings.detail_help'))}</p>
      <div data-mapping-config><p class="muted small">${escapeHtml(t('common.loading'))}</p></div>
    </div>
  </div>`;
  openPanel(panel, trigger);
  if (!canPreview()) {
    $('[data-mapping-config]', body).innerHTML = `<p class="muted small">${escapeHtml(t('mappings.preview_permission'))}</p>`;
    return;
  }
  try {
    const preview = await api('/api/v1/config/preview');
    state.preview = preview;
    state.previewError = null;
    const target = $('[data-mapping-config]', body);
    if (target && panel.open) target.innerHTML = configBlock(mapping);
  } catch (error) {
    state.previewError = error.message;
    const target = $('[data-mapping-config]', body);
    if (target && panel.open) target.innerHTML = `<p class="muted small">${escapeHtml(error.message)}</p>`;
  }
}

async function deleteMapping(mapping, trigger) {
  return runAction({
    key: `mapping-delete:${mapping.id}`,
    title: t('mappings.delete_title'),
    confirm: {
      title: t('mappings.delete_title'),
      message: t('mappings.delete_message', { domain: mapping.domain }),
      confirmLabel: t('common.delete'),
      danger: true,
    },
    trigger,
    request: () => api(`/api/v1/mappings/${mapping.id}`, { method: 'DELETE' }),
    onSuccess: async () => {
      await loadMappings();
      await refreshPending().catch(() => {});
      document.dispatchEvent(new CustomEvent('dns:pending-refreshed', { detail: { count: state.pending.size, domains: [...state.pending] } }));
    },
    successMessage: t('mappings.deleted'),
  });
}

export async function init() {
  const panel = $('[data-mapping-panel]');
  const detailPanel = $('[data-mapping-detail-panel]');
  const form = $('[data-mapping-form]');
  wirePanel(panel);
  wirePanel(detailPanel);

  if (canCreate()) {
    $('[data-mapping-create]')?.addEventListener('click', (event) => openMappingPanel(null, event.currentTarget));
  }

  $('[data-mapping-search]')?.addEventListener('input', (event) => {
    state.search = String(event.currentTarget.value || '').trim().toLowerCase();
    renderTable();
  });

  $$('[data-mapping-filter]').forEach((button) => {
    button.addEventListener('click', () => {
      state.filter = button.dataset.mappingFilter || 'all';
      $$('[data-mapping-filter]').forEach((chip) => {
        chip.setAttribute('aria-pressed', String(chip === button));
      });
      renderTable();
    });
  });

  $('[data-mapping-refresh]')?.addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      await loadMappings();
      await refreshPending().catch(() => {});
      toast(t('common.success'), 'good', 2200);
    } catch (error) {
      toast(error.message, 'critical');
    } finally {
      button.disabled = false;
    }
  });

  $('[data-mappings-table]')?.addEventListener('click', async (event) => {
    const detail = event.target.closest('[data-mapping-detail]');
    if (detail) {
      const mapping = state.mappings.find((row) => String(row.id) === String(detail.dataset.mappingDetail));
      if (mapping) await openDetailPanel(mapping, detail);
      return;
    }
    const edit = event.target.closest('[data-mapping-edit]');
    if (edit) {
      const mapping = state.mappings.find((row) => String(row.id) === String(edit.dataset.mappingEdit));
      if (mapping) openMappingPanel(mapping, edit);
      return;
    }
    const remove = event.target.closest('[data-mapping-delete]');
    if (!remove) return;
    const mapping = state.mappings.find((row) => String(row.id) === String(remove.dataset.mappingDelete));
    if (mapping) await deleteMapping(mapping, remove);
  });

  form?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const id = data.get('id');
    const payload = {
      domain: String(data.get('domain') || '').trim(),
      upstream_scheme: String(data.get('upstream_scheme') || 'http'),
      upstream_host: String(data.get('upstream_host') || '').trim(),
      upstream_port: Number(data.get('upstream_port')),
      enabled: form.elements.enabled.checked,
      websocket_enabled: form.elements.websocket_enabled.checked,
      preserve_host: form.elements.preserve_host.checked,
      tls_verify: form.elements.tls_verify.checked,
      custom_timeout: data.get('custom_timeout') ? Number(data.get('custom_timeout')) : null,
      description: String(data.get('description') || '').trim() || null,
    };
    if (id) payload.version = Number(data.get('version'));
    await runAction({
      key: `mapping-save:${id || payload.domain}`,
      title: id ? t('mappings.edit_title') : t('mappings.create_title'),
      message: payload.domain,
      trigger: event.submitter || form,
      request: () => api(id ? `/api/v1/mappings/${id}` : '/api/v1/mappings', {
        method: id ? 'PUT' : 'POST',
        json: payload,
      }),
      onSuccess: async () => {
        closePanel(panel);
        await loadMappings();
        await refreshPending().catch(() => {});
      },
      successMessage: t('toast.saved_pending'),
    });
  });

  document.addEventListener('dns:pending-refreshed', (event) => {
    const detail = event.detail || {};
    state.pending = new Set(detail.domains || []);
    renderTable();
  });

  try {
    await loadMappings();
  } catch (error) {
    toast(error.message, 'critical');
  }
}
