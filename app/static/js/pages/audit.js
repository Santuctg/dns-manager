import {
  $, $$, api, escapeHtml, t, toast, fmtDate, statusChip,
} from '../core.js';

const PAGE = 50;
const state = { rows: [], offset: 0, filters: {}, loading: false };

function queryString() {
  const params = new URLSearchParams();
  Object.entries(state.filters).forEach(([key, value]) => {
    if (value) params.set(key, value);
  });
  params.set('limit', String(PAGE));
  params.set('offset', String(state.offset));
  return params.toString();
}

function rowHtml(row) {
  const status = String(row.status || 'success').toLowerCase();
  const chipTone = status === 'success' ? 'good' : status === 'failed' ? 'critical' : status === 'error' ? 'critical' : 'warning';
  const object = row.object_type
    ? `${escapeHtml(row.object_type)}${row.object_id != null ? ` <span class="muted">#${escapeHtml(row.object_id)}</span>` : ''}`
    : '—';
  return `<tr>
    <td data-label="${escapeHtml(t('audit.time'))}" class="nowrap">${escapeHtml(fmtDate(row.created_at))}</td>
    <td data-label="${escapeHtml(t('audit.user'))}">${escapeHtml(row.username || '—')}</td>
    <td data-label="${escapeHtml(t('audit.action'))}">
      <strong class="mono">${escapeHtml(row.action)}</strong>
      ${row.error_message ? `<div class="muted tiny">${escapeHtml(row.error_message)}</div>` : ''}
    </td>
    <td data-label="${escapeHtml(t('audit.object'))}">${object}</td>
    <td data-label="${escapeHtml(t('audit.ip'))}" class="cell-mono">${escapeHtml(row.source_ip || '—')}</td>
    <td data-label="${escapeHtml(t('common.status'))}"><span class="chip chip-${chipTone}">${escapeHtml(row.status || 'success')}</span></td>
  </tr>`;
}

function render({ append = false } = {}) {
  const table = $('[data-audit-table]');
  if (!table) return;
  if (!state.rows.length) {
    table.innerHTML = `<tr><td colspan="6" class="muted">${escapeHtml(t('audit.empty'))}</td></tr>`;
  } else if (append) {
    table.insertAdjacentHTML('beforeend', state.rows.slice(-PAGE).map(rowHtml).join(''));
  } else {
    table.innerHTML = state.rows.map(rowHtml).join('');
  }
  const summary = $('[data-audit-summary]');
  if (summary) summary.textContent = `${state.rows.length} ${t('audit.title').toLowerCase()}`;
  const count = $('[data-audit-count]');
  if (count) count.textContent = String(state.rows.length);
  const range = $('[data-audit-range]');
  if (range) {
    range.textContent = state.rows.length
      ? `${state.rows.length - Math.min(state.rows.length, PAGE) + 1}–${state.rows.length}`
      : '';
  }
  const more = $('[data-audit-more]');
  if (more) more.hidden = state.rows.length < PAGE || state.rows.length % PAGE !== 0;
}

async function load({ append = false } = {}) {
  if (state.loading) return;
  state.loading = true;
  try {
    if (!append) state.offset = 0;
    const rows = await api(`/api/v1/audit?${queryString()}`);
    if (append) {
      const seen = new Set(state.rows.map((row) => row.id));
      const fresh = rows.filter((row) => !seen.has(row.id));
      state.rows = [...state.rows, ...fresh];
    } else {
      state.rows = rows;
    }
    state.offset = state.rows.length;
    render({ append });
  } finally {
    state.loading = false;
  }
}

function readFilters() {
  const form = $('[data-audit-filters]');
  if (!form) return {};
  const data = new FormData(form);
  return {
    username: String(data.get('username') || '').trim(),
    action: String(data.get('action') || '').trim(),
    object_type: String(data.get('object_type') || '').trim(),
    status: String(data.get('status') || '').trim(),
    source_ip: String(data.get('source_ip') || '').trim(),
  };
}

export async function init() {
  $('[data-audit-filters]')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    state.filters = readFilters();
    try {
      await load();
    } catch (error) {
      toast(error.message, 'critical');
    }
  });

  $('[data-audit-clear]')?.addEventListener('click', async () => {
    $('[data-audit-filters]')?.reset();
    state.filters = {};
    try {
      await load();
    } catch (error) {
      toast(error.message, 'critical');
    }
  });

  $('[data-audit-refresh]')?.addEventListener('click', async () => {
    try {
      state.filters = readFilters();
      await load();
    } catch (error) {
      toast(error.message, 'critical');
    }
  });

  $('[data-audit-more]')?.addEventListener('click', async () => {
    try {
      await load({ append: true });
    } catch (error) {
      toast(error.message, 'critical');
    }
  });

  try {
    await load();
  } catch (error) {
    toast(error.message, 'critical');
  }
}
