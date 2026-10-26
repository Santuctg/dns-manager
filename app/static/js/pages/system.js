import {
  $, $$, api, escapeHtml, icon, t, toast, fmtBytes, fmtDate, fmtDuration, fmtPercent,
  poll, runAction, applyPending, badge, tone,
} from '../core.js';

const state = {
  status: null,
  metrics: null,
  preview: null,
  revisions: { items: [], total: 0, page: 1, per_page: 50 },
};

const SERVICE_ROWS = [
  ['system.service.database', (status) => (status?.database === 'ok' ? 'active' : status?.database || 'unknown')],
  ['system.service.dns_manager', (status, metrics) => metrics?.services?.['dns-manager'] || 'unknown'],
  ['system.service.helper', (status, metrics) => metrics?.services?.['dns-manager-helper.service'] || 'unknown'],
  ['system.service.nginx', (status, metrics) => status?.nginx || metrics?.services?.nginx || 'unknown'],
  ['system.service.dnsmasq', (status, metrics) => status?.dnsmasq || metrics?.services?.dnsmasq || 'unknown'],
];

function renderDnsSafety() {
  const safety = state.status?.dns_safety;
  const badgeNode = $('[data-system="dns_safety"]');
  if (badgeNode) {
    if (!safety) {
      badgeNode.innerHTML = badge('UNKNOWN');
    } else {
      const label = safety.safe ? 'SAFE' : 'UNSAFE';
      badgeNode.innerHTML = badge(label, label);
    }
  }
  const bind = $('[data-system="dns_bind"]');
  if (bind) bind.textContent = safety?.expected_ip || safety?.bind_ip || '—';
}

function renderServices() {
  const grid = $('[data-services-grid]');
  if (!grid) return;
  const rows = SERVICE_ROWS.map(([key, read]) => {
    const value = read(state.status, state.metrics);
    return `<article class="service-card">
      <span>${escapeHtml(t(key))}</span>
      ${badge(value, value)}
    </article>`;
  });
  grid.innerHTML = rows.join('');
  const sample = $('[data-system-sample]');
  if (sample) {
    const stamp = Number(state.metrics?.sampled_at_ms);
    sample.textContent = Number.isFinite(stamp) ? new Date(stamp).toLocaleTimeString() : t('common.live');
  }
}

function renderMetrics() {
  const metrics = state.metrics;
  if (!metrics) return;
  const cpu = metrics.cpu || {};
  const memory = metrics.memory || {};
  const uptime = metrics.uptime || {};
  const set = (name, value) => {
    const node = $(`[data-monitor="${name}"]`);
    if (node) node.textContent = value;
  };
  set('cpu', fmtPercent(cpu.usage_percent));
  set('load', Number.isFinite(Number(cpu.load_1)) ? `${t('dashboard.cpu')} load ${cpu.load_1}` : '—');
  set('memory', fmtPercent(memory.usage_percent));
  set('memory-detail', memory.total_bytes ? `${fmtBytes(memory.used_bytes)} / ${fmtBytes(memory.total_bytes)}` : '—');
  set('uptime', fmtDuration(uptime.seconds));
  set('boot', uptime.boot_time_ms ? fmtDate(uptime.boot_time_ms) : '—');

  const cpuProgress = $('[data-monitor-progress="cpu"]');
  if (cpuProgress) cpuProgress.value = Number(cpu.usage_percent) || 0;
  const memoryProgress = $('[data-monitor-progress="memory"]');
  if (memoryProgress) memoryProgress.value = Number(memory.usage_percent) || 0;

  const interfaces = $('[data-monitor-interfaces]');
  if (interfaces) {
    const rows = metrics.network?.interfaces || [];
    interfaces.innerHTML = rows.length ? rows.map((row) => {
      const up = String(row.operstate || '').toLowerCase() === 'up';
      return `<tr>
        <td data-label="${escapeHtml(t('system.interface'))}"><code>${escapeHtml(row.name)}</code></td>
        <td data-label="${escapeHtml(t('common.status'))}"><span class="chip chip-${up ? 'good' : 'critical'}">${escapeHtml(row.operstate || '—')}</span></td>
        <td data-label="RX" class="cell-mono">${escapeHtml(fmtBytes(row.rx_bytes))}</td>
        <td data-label="TX" class="cell-mono">${escapeHtml(fmtBytes(row.tx_bytes))}</td>
      </tr>`;
    }).join('') : `<tr><td colspan="4" class="muted">${escapeHtml(t('common.no_data'))}</td></tr>`;
  }

  const disks = $('[data-monitor-disks]');
  if (disks) {
    const rows = metrics.disks || [];
    disks.innerHTML = rows.length ? rows.map((row) => `<div class="monitor-meter">
      <div class="row spread">
        <span class="mono small">${escapeHtml(row.mount)}</span>
        <span class="muted tiny">${escapeHtml(fmtBytes(row.used_bytes))} / ${escapeHtml(fmtBytes(row.total_bytes))}</span>
      </div>
      <progress class="progress" value="${Number(row.usage_percent) || 0}" max="100" aria-label="${escapeHtml(row.mount)}"></progress>
      <span class="muted tiny">${escapeHtml(fmtPercent(row.usage_percent))}</span>
    </div>`).join('') : `<p class="muted small">${escapeHtml(t('system.no_filesystems'))}</p>`;
  }

  const services = $('[data-monitor-services]');
  if (services) {
    services.innerHTML = SERVICE_ROWS.map(([key, read]) => {
      const value = read(state.status, metrics);
      return `<div class="row spread">
        <span class="mono small">${escapeHtml(t(key))}</span>
        ${badge(value, value)}
      </div>`;
    }).join('');
  }

  const status = $('[data-monitor-status]');
  if (status) {
    status.textContent = metrics.warnings?.length
      ? metrics.warnings.join(' · ')
      : t('system.monitoring_help');
  }

  renderServices();
}

function renderMetricsUnavailable() {
  const status = $('[data-monitor-status]');
  if (status) status.textContent = t('status.unavailable');
  const stamp = $('[data-monitor-time]');
  if (stamp) stamp.textContent = t('status.unavailable');

  const interfaces = $('[data-monitor-interfaces]');
  if (interfaces) {
    interfaces.innerHTML = `<tr><td colspan="4" class="muted">${escapeHtml(t('common.no_data'))}</td></tr>`;
  }
  const disks = $('[data-monitor-disks]');
  if (disks) {
    disks.innerHTML = `<p class="muted small">${escapeHtml(t('common.not_available'))}</p>`;
  }
  const services = $('[data-monitor-services]');
  if (services) {
    services.innerHTML = SERVICE_ROWS.map(([key, read]) => {
      const value = read(state.status, state.metrics || {});
      return `<div class="row spread">
        <span class="mono small">${escapeHtml(t(key))}</span>
        ${badge(value, value)}
      </div>`;
    }).join('');
  }
}

function splitLines(text) {
  return String(text ?? '').replace(/\r\n/g, '\n').split('\n');
}

function diffLines(before, after) {
  const oldLines = splitLines(before);
  const newLines = splitLines(after);
  let prefix = 0;
  while (prefix < oldLines.length && prefix < newLines.length && oldLines[prefix] === newLines[prefix]) prefix += 1;
  let suffix = 0;
  while (
    suffix < oldLines.length - prefix
    && suffix < newLines.length - prefix
    && oldLines[oldLines.length - 1 - suffix] === newLines[newLines.length - 1 - suffix]
  ) suffix += 1;

  const result = [];
  for (let index = 0; index < prefix; index += 1) {
    result.push({ type: 'same', text: oldLines[index], num: index + 1 });
  }

  const oldMiddle = oldLines.slice(prefix, oldLines.length - suffix);
  const newMiddle = newLines.slice(prefix, newLines.length - suffix);
  const product = oldMiddle.length * newMiddle.length;
  if (product > 500000) {
    oldMiddle.forEach((text, index) => result.push({ type: 'remove', text, num: prefix + index + 1 }));
    newMiddle.forEach((text, index) => result.push({ type: 'add', text, num: prefix + index + 1 }));
  } else {
    const rows = oldMiddle.length + 1;
    const cols = newMiddle.length + 1;
    const table = Array.from({ length: rows }, () => new Uint32Array(cols));
    for (let i = oldMiddle.length - 1; i >= 0; i -= 1) {
      for (let j = newMiddle.length - 1; j >= 0; j -= 1) {
        table[i][j] = oldMiddle[i] === newMiddle[j]
          ? table[i + 1][j + 1] + 1
          : Math.max(table[i + 1][j], table[i][j + 1]);
      }
    }
    let i = 0;
    let j = 0;
    while (i < oldMiddle.length && j < newMiddle.length) {
      if (oldMiddle[i] === newMiddle[j]) {
        result.push({ type: 'same', text: oldMiddle[i], num: prefix + i + 1 });
        i += 1;
        j += 1;
      } else if (table[i + 1][j] >= table[i][j + 1]) {
        result.push({ type: 'remove', text: oldMiddle[i], num: prefix + i + 1 });
        i += 1;
      } else {
        result.push({ type: 'add', text: newMiddle[j], num: prefix + j + 1 });
        j += 1;
      }
    }
    while (i < oldMiddle.length) {
      result.push({ type: 'remove', text: oldMiddle[i], num: prefix + i + 1 });
      i += 1;
    }
    while (j < newMiddle.length) {
      result.push({ type: 'add', text: newMiddle[j], num: prefix + j + 1 });
      j += 1;
    }
  }

  for (let index = 0; index < suffix; index += 1) {
    const oldIndex = oldLines.length - suffix + index;
    result.push({ type: 'same', text: oldLines[oldIndex], num: oldIndex + 1 });
  }
  return result;
}

function renderDiff(target, before, after, { active }) {
  if (!target) return;
  const lines = active === null ? splitLines(after).map((text, index) => ({ type: 'same', text, num: index + 1 })) : diffLines(before, after);
  const changed = lines.some((line) => line.type !== 'same');
  if (active !== null && !changed) {
    target.innerHTML = `<p class="muted small diff-empty">${escapeHtml(t('system.no_changes'))}</p>`;
    return;
  }
  target.innerHTML = lines.map((line) => `<div class="diff-line${line.type === 'same' ? '' : ` ${line.type}`}">
    <span class="diff-num">${line.num}</span>
    <span class="diff-code">${escapeHtml(line.text) || ' '}</span>
  </div>`).join('');
  if (active === null) {
    target.insertAdjacentHTML('afterbegin', `<p class="muted small diff-empty">${escapeHtml(t('system.no_active_revision'))}</p>`);
  }
}

function renderPreview() {
  const preview = state.preview;
  if (!preview) return;
  const status = $('[data-config-status]');
  if (status) {
    const active = preview.active_revision;
    status.textContent = active
      ? `${t('system.col.revision')} #${active} · ${t('pending.title', { count: preview.pending_change_count || 0 })}`
      : t('system.no_active_revision');
  }
  renderDiff($('[data-diff-dnsmasq]'), preview.active_dnsmasq_config ?? '', preview.dnsmasq_config ?? '', {
    active: preview.active_revision ? (preview.active_dnsmasq_config ?? '') : null,
  });
  renderDiff($('[data-diff-nginx]'), preview.active_nginx_config ?? '', preview.nginx_config ?? '', {
    active: preview.active_revision ? (preview.active_nginx_config ?? '') : null,
  });
}

async function loadPreview() {
  if (!$('[data-configuration]')) return;
  state.preview = await api('/api/v1/config/preview');
  renderPreview();
}

function revisionRows() {
  const table = $('[data-revisions-table]');
  if (!table) return;
  const page = state.revisions;
  if (!page.items.length) {
    table.innerHTML = `<tr><td colspan="5" class="muted">${escapeHtml(t('system.revisions_empty'))}</td></tr>`;
  } else {
    table.innerHTML = page.items.map((row) => `<tr>
      <td data-label="${escapeHtml(t('system.col.revision'))}"><strong class="mono">${escapeHtml(row.revision)}</strong></td>
      <td data-label="${escapeHtml(t('system.col.created'))}" class="nowrap">${escapeHtml(fmtDate(row.created_at))}</td>
      <td data-label="${escapeHtml(t('system.col.created_by'))}">${escapeHtml(row.created_by_username || '—')}</td>
      <td data-label="${escapeHtml(t('system.col.status'))}">${badge(row.status, row.status)}</td>
      <td data-label="">
        ${row.status === 'active' ? '' : `<button class="btn btn-ghost btn-sm" type="button" data-revision-rollback="${row.id}" data-revision-label="${escapeHtml(row.revision)}">${icon('undo', 'icon icon-sm')}${escapeHtml(t('system.rollback'))}</button>`}
      </td>
    </tr>`).join('');
  }
  const pages = Math.max(1, Math.ceil(page.total / page.per_page));
  const range = $('[data-revisions-range]');
  if (range) {
    range.textContent = page.total
      ? `${(page.page - 1) * page.per_page + 1}–${Math.min(page.page * page.per_page, page.total)} / ${page.total}`
      : '0';
  }
  const prev = $('[data-revisions-prev]');
  const next = $('[data-revisions-next]');
  if (prev) prev.disabled = page.page <= 1;
  if (next) next.disabled = page.page >= pages;
}

async function loadRevisions(desiredPage = null) {
  if (!$('[data-revisions]')) return;
  const page = desiredPage ?? state.revisions.page ?? 1;
  state.revisions = await api(`/api/v1/config/revisions?page=${encodeURIComponent(page)}`);
  revisionRows();
}

async function loadSystem() {
  const [status, metrics] = await Promise.allSettled([
    api('/api/v1/system/status'),
    api('/api/v1/system/metrics'),
  ]);
  if (status.status === 'fulfilled') state.status = status.value;
  if (metrics.status === 'fulfilled') state.metrics = metrics.value;
  renderDnsSafety();
  renderServices();
  if (state.metrics) renderMetrics();
  else renderMetricsUnavailable();
}

async function refreshMetrics() {
  try {
    state.metrics = await api('/api/v1/system/metrics');
    renderMetrics();
  } catch {
    renderMetricsUnavailable();
  }
}

async function rollback(revisionId, label, trigger) {
  const result = await runAction({
    key: `config-rollback:${revisionId}`,
    title: t('system.rollback_title'),
    message: t('system.rollback_message', { revision: label }),
    confirm: {
      title: t('system.rollback_title'),
      message: t('system.rollback_message', { revision: label }),
      confirmLabel: t('system.rollback'),
      danger: true,
    },
    trigger,
    request: () => api(`/api/v1/config/rollback/${revisionId}`, { method: 'POST' }),
    onSuccess: async () => {
      await Promise.all([loadPreview().catch(() => {}), loadRevisions(1).catch(() => {}), loadSystem()]);
    },
    successMessage: t('system.rollback_done'),
  });
  return result;
}

export async function init() {
  try {
    await loadSystem();
  } catch (error) {
    toast(error.message, 'critical');
  }

  poll(refreshMetrics, 1000);

  if ($('[data-configuration]')) {
    try {
      await loadPreview();
    } catch (error) {
      const status = $('[data-config-status]');
      if (status) status.textContent = error.message;
      toast(error.message, 'critical');
    }

    $('[data-config-validate]')?.addEventListener('click', async (event) => {
      const result = await runAction({
        key: 'config-validate',
        title: t('system.validate'),
        message: t('system.diff_help'),
        trigger: event.currentTarget,
        request: () => api('/api/v1/config/validate', { method: 'POST' }),
        successMessage: t('system.validated'),
      });
      if (result) {
        await Promise.all([loadPreview().catch(() => {}), loadRevisions(1).catch(() => {})]);
        await loadSystem();
      }
    });

    $('[data-config-apply]')?.addEventListener('click', async (event) => {
      const result = await applyPending(event.currentTarget);
      if (result) {
        await Promise.all([loadPreview().catch(() => {}), loadRevisions(1).catch(() => {}), loadSystem()]);
      }
    });
  }

  if ($('[data-revisions]')) {
    try {
      await loadRevisions(1);
    } catch (error) {
      toast(error.message, 'critical');
    }

    $('[data-revisions-prev]')?.addEventListener('click', async () => {
      try {
        await loadRevisions(Math.max(1, state.revisions.page - 1));
      } catch (error) {
        toast(error.message, 'critical');
      }
    });

    $('[data-revisions-next]')?.addEventListener('click', async () => {
      try {
        await loadRevisions(state.revisions.page + 1);
      } catch (error) {
        toast(error.message, 'critical');
      }
    });

    $('[data-revisions-table]')?.addEventListener('click', async (event) => {
      const button = event.target.closest('[data-revision-rollback]');
      if (!button) return;
      await rollback(button.dataset.revisionRollback, button.dataset.revisionLabel || button.dataset.revisionRollback, button);
    });
  }

  $('[data-system-refresh]')?.addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      await loadSystem();
      await Promise.all([
        loadPreview().catch(() => {}),
        loadRevisions().catch(() => {}),
      ]);
      toast(t('common.success'), 'good', 2200);
    } catch (error) {
      toast(error.message, 'critical');
    } finally {
      button.disabled = false;
    }
  });
}
