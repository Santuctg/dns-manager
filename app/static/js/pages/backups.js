import {
  $, $$, api, escapeHtml, icon, t, toast, fmtBytes, fmtDate,
  openPanel, closePanel, wirePanel, runAction,
} from '../core.js';

const state = { backups: [], selected: null };
const canRestore = () => document.body.dataset.canBackupRestore === 'true';
const canCreate = () => document.body.dataset.canBackupCreate === 'true';

function renderTable() {
  const table = $('[data-backups-table]');
  if (!table) return;
  const rows = state.backups;
  const summary = $('[data-backups-summary]');
  if (summary) summary.textContent = `${rows.length} · ${fmtBytes(rows.reduce((sum, row) => sum + Number(row.size_bytes || 0), 0))}`;
  if (!rows.length) {
    table.innerHTML = `<tr><td colspan="6" class="muted">${escapeHtml(t('backups.empty'))}</td></tr>`;
    return;
  }
  table.innerHTML = rows.map((row) => `
    <tr>
      <td data-label="${escapeHtml(t('backups.created'))}" class="nowrap">${escapeHtml(fmtDate(row.created_at))}</td>
      <td data-label="${escapeHtml(t('backups.id'))}"><code class="backup-id">${escapeHtml(row.backup_id)}</code></td>
      <td data-label="${escapeHtml(t('backups.label'))}">${escapeHtml(row.label || '—')}</td>
      <td data-label="${escapeHtml(t('backups.schema'))}" class="cell-mono">${escapeHtml(row.alembic_version || '—')}</td>
      <td data-label="${escapeHtml(t('backups.size'))}" class="cell-mono">${escapeHtml(fmtBytes(row.size_bytes))}</td>
      <td data-label="">
        <div class="row-actions">
          <a class="btn btn-ghost btn-sm" href="/api/v1/backups/${encodeURIComponent(row.backup_id)}/download">
            ${icon('download', 'icon icon-sm')}${escapeHtml(t('common.download'))}
          </a>
          ${canRestore() ? `
          <button class="btn btn-ghost btn-sm" type="button" data-backup-restore="${escapeHtml(row.backup_id)}">
            ${icon('undo', 'icon icon-sm')}${escapeHtml(t('backups.restore'))}
          </button>
          <button class="btn btn-ghost btn-sm btn-danger" type="button" data-backup-delete="${escapeHtml(row.backup_id)}">
            ${icon('trash', 'icon icon-sm')}${escapeHtml(t('backups.delete'))}
          </button>` : ''}
        </div>
      </td>
    </tr>`).join('');
}

async function loadBackups() {
  state.backups = await api('/api/v1/backups');
  renderTable();
}

function openRestore(row, trigger) {
  const panel = $('[data-backup-restore-panel]');
  if (!panel) return;
  state.selected = row;
  $('[data-backup-restore-id]', panel).textContent = row.backup_id;
  $('[data-backup-restore-created]', panel).textContent = fmtDate(row.created_at);
  const input = $('#backup-restore-confirm', panel);
  const button = $('[data-backup-restore-confirm]', panel);
  const error = $('[data-backup-restore-error]', panel);
  input.value = '';
  button.disabled = true;
  if (error) error.hidden = true;
  input.oninput = () => {
    button.disabled = input.value.trim() !== row.backup_id;
  };
  openPanel(panel, trigger, '#backup-restore-confirm');
}

async function restoreSelected(trigger) {
  const panel = $('[data-backup-restore-panel]');
  const row = state.selected;
  const input = $('#backup-restore-confirm', panel);
  if (!panel || !row) return;
  if (input.value.trim() !== row.backup_id) {
    const error = $('[data-backup-restore-error]', panel);
    if (error) {
      error.textContent = t('backups.type_to_confirm');
      error.hidden = false;
    }
    return;
  }
  const result = await runAction({
    key: `backup-restore:${row.backup_id}`,
    title: t('backups.restore'),
    message: t('backups.restore_help'),
    trigger,
    request: () => api(`/api/v1/backups/${encodeURIComponent(row.backup_id)}/restore`, { method: 'POST' }),
    silentSuccess: true,
  });
  if (result) {
    closePanel(panel);
    toast(t('backups.restored'), 'good', 8000);
    setTimeout(() => location.assign('/login'), 1200);
  }
}

export async function init() {
  const panel = $('[data-backup-restore-panel]');
  const uploadDialog = $('[data-backup-upload-dialog]');
  wirePanel(panel);
  $$('[data-dialog-close]', uploadDialog).forEach((button) => button.addEventListener('click', () => uploadDialog.close()));

  $('[data-backup-refresh]')?.addEventListener('click', (event) => runAction({
    key: 'backup-refresh',
    title: t('common.refresh'),
    trigger: event.currentTarget,
    request: loadBackups,
    successMessage: t('common.success'),
  }));

  $('[data-backup-create]')?.addEventListener('click', (event) => {
    if (!canCreate()) return;
    return runAction({
      key: 'backup-create',
      title: t('backups.create'),
      message: t('backups.subtitle'),
      trigger: event.currentTarget,
      request: () => api('/api/v1/backups', { method: 'POST' }),
      onSuccess: loadBackups,
      successMessage: (row) => t('backups.created_toast', { id: row.backup_id }),
    });
  });

  $('[data-backup-upload]')?.addEventListener('click', () => {
    const form = $('[data-backup-upload-form]');
    form?.reset();
    uploadDialog?.showModal();
  });

  $('[data-backup-upload-form]')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const file = form.elements.backup?.files?.[0];
    if (!file) return;
    const result = await runAction({
      key: `backup-upload:${file.name}`,
      title: t('backups.upload'),
      message: file.name,
      trigger: event.submitter || form,
      request: () => api('/api/v1/backups/upload', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/gzip',
          'X-Backup-Filename': file.name,
        },
        body: file,
      }),
      onSuccess: async () => {
        uploadDialog?.close();
        form.reset();
        await loadBackups();
      },
      successMessage: (row) => t('backups.uploaded', { id: row.backup_id }),
    });
    return result;
  });

  $('[data-backups-table]')?.addEventListener('click', (event) => {
    const restore = event.target.closest('[data-backup-restore]');
    if (restore) {
      const row = state.backups.find((item) => item.backup_id === restore.dataset.backupRestore);
      if (row) openRestore(row, restore);
      return;
    }
    const remove = event.target.closest('[data-backup-delete]');
    if (!remove) return;
    const id = remove.dataset.backupDelete;
    runAction({
      key: `backup-delete:${id}`,
      title: t('backups.delete_title'),
      confirm: {
        title: t('backups.delete_title'),
        message: t('backups.delete_message', { id }),
        confirmLabel: t('common.delete'),
        danger: true,
      },
      trigger: remove,
      request: () => api(`/api/v1/backups/${encodeURIComponent(id)}`, { method: 'DELETE' }),
      onSuccess: loadBackups,
      successMessage: t('toast.deleted'),
    });
  });

  $('[data-backup-restore-confirm]')?.addEventListener('click', (event) => restoreSelected(event.currentTarget));

  try {
    await loadBackups();
  } catch (error) {
    toast(error.message, 'critical');
  }
}
