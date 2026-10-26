import {
  $, $$, api, escapeHtml, icon, t, toast, fmtDate,
  openPanel, closePanel, wirePanel, runAction, promptAction, showResult,
} from '../core.js';

const state = { users: [], roles: [] };
const can = (name) => document.body.dataset[name] === 'true';

function roleOptions(selected) {
  return state.roles.map((role) => `<option value="${role.id}" ${String(role.id) === String(selected) ? 'selected' : ''}>${escapeHtml(role.name)}</option>`).join('');
}

function statusCell(user) {
  const locked = user.locked_until && new Date(user.locked_until).getTime() > Date.now();
  if (locked) return `<span class="chip chip-warning">${escapeHtml(t('common.warning'))}</span>`;
  return user.is_active
    ? `<span class="chip chip-good">${escapeHtml(t('common.enabled'))}</span>`
    : `<span class="chip chip-off">${escapeHtml(t('common.disabled'))}</span>`;
}

function renderTable() {
  const table = $('[data-users-table]');
  if (!table) return;
  const summary = $('[data-users-summary]');
  if (summary) {
    const active = state.users.filter((user) => user.is_active).length;
    summary.textContent = `${state.users.length} · ${active} ${t('common.enabled').toLowerCase()}`;
  }
  if (!state.users.length) {
    table.innerHTML = `<tr><td colspan="5" class="muted">${escapeHtml(t('common.no_data'))}</td></tr>`;
    return;
  }
  table.innerHTML = state.users.map((user) => {
    const actions = [];
    if (can('canUserUpdate')) actions.push(`<button class="btn btn-ghost btn-sm" type="button" data-user-edit="${user.id}">${icon('edit', 'icon icon-sm')}${escapeHtml(t('common.edit'))}</button>`);
    if (can('canUserUpdate')) actions.push(`<button class="btn btn-ghost btn-sm" type="button" data-user-reset="${user.id}">${escapeHtml(t('users.reset'))}</button>`);
    if (can('canUserDelete') && user.is_active) actions.push(`<button class="btn btn-ghost btn-sm btn-danger" type="button" data-user-disable="${user.id}">${escapeHtml(t('users.disable'))}</button>`);
    return `<tr class="${user.is_active ? '' : 'muted'}">
      <td data-label="${escapeHtml(t('users.username'))}" class="cell-primary">
        <strong>${escapeHtml(user.username)}</strong>
        <div class="muted tiny">${escapeHtml(user.email || '—')}</div>
      </td>
      <td data-label="${escapeHtml(t('users.role'))}">${escapeHtml(user.role?.name || '—')}</td>
      <td data-label="${escapeHtml(t('common.status'))}">${statusCell(user)}</td>
      <td data-label="${escapeHtml(t('users.last_login'))}" class="nowrap">${escapeHtml(fmtDate(user.last_login_at, t('common.never')))}</td>
      <td data-label=""><div class="row-actions">${actions.join('')}</div></td>
    </tr>`;
  }).join('');
}

async function loadUsers() {
  state.users = await api('/api/v1/users');
  renderTable();
}

function openUserPanel(user, trigger) {
  const panel = $('[data-user-panel]');
  const form = $('[data-user-form]');
  if (!panel || !form) return;
  form.reset();
  form.elements.id.value = user?.id || '';
  form.elements.username.value = user?.username || '';
  form.elements.email.value = user?.email || '';
  form.elements.role_id.innerHTML = roleOptions(user?.role?.id);
  form.elements.role_id.value = String(user?.role?.id || state.roles[0]?.id || '');
  form.elements.is_active.checked = user ? Boolean(user.is_active) : true;
  const passwordField = $('[data-user-password-field]', panel);
  const activeField = $('[data-user-active-field]', panel);
  if (passwordField) passwordField.hidden = Boolean(user);
  if (activeField) activeField.hidden = !user;
  form.elements.password.required = !user;
  const title = $('[data-user-panel-title]', panel);
  if (title) title.textContent = user ? t('users.edit') : t('users.add');
  openPanel(panel, trigger, '#user-username');
}

async function resetPassword(user, trigger) {
  const password = await promptAction({
    title: t('users.reset_title'),
    message: t('users.reset_message', { username: user.username }),
    inputLabel: t('users.password'),
    inputType: 'password',
    required: true,
    confirmLabel: t('users.reset'),
    trigger,
  });
  if (password === null) return;
  if (password.length < 12) {
    showResult('error', { title: t('users.reset_title'), message: t('common.required'), trigger });
    return;
  }
  await runAction({
    key: `user-reset:${user.id}`,
    title: t('users.reset'),
    message: user.username,
    trigger,
    request: () => api(`/api/v1/users/${user.id}/reset-password`, { method: 'POST', json: { password } }),
    successMessage: t('users.reset_done'),
  });
}

export async function init() {
  const panel = $('[data-user-panel]');
  wirePanel(panel);

  try {
    state.roles = await api('/api/v1/roles');
  } catch {
    state.roles = [];
  }

  $('[data-user-add]')?.addEventListener('click', (event) => {
    if (!state.roles.length) {
      toast(t('common.not_available'), 'warning');
      return;
    }
    openUserPanel(null, event.currentTarget);
  });

  $('[data-users-refresh]')?.addEventListener('click', (event) => runAction({
    key: 'users-refresh',
    title: t('common.refresh'),
    trigger: event.currentTarget,
    request: loadUsers,
    successMessage: t('common.success'),
  }));

  $('[data-users-table]')?.addEventListener('click', (event) => {
    const edit = event.target.closest('[data-user-edit]');
    if (edit) {
      const user = state.users.find((row) => String(row.id) === String(edit.dataset.userEdit));
      if (user) openUserPanel(user, edit);
      return;
    }
    const reset = event.target.closest('[data-user-reset]');
    if (reset) {
      const user = state.users.find((row) => String(row.id) === String(reset.dataset.userReset));
      if (user) resetPassword(user, reset);
      return;
    }
    const disable = event.target.closest('[data-user-disable]');
    if (!disable) return;
    const user = state.users.find((row) => String(row.id) === String(disable.dataset.userDisable));
    if (!user) return;
    runAction({
      key: `user-disable:${user.id}`,
      title: t('users.disable_title'),
      confirm: {
        title: t('users.disable_title'),
        message: t('users.disable_message', { username: user.username }),
        confirmLabel: t('users.disable'),
        danger: true,
      },
      trigger: disable,
      request: () => api(`/api/v1/users/${user.id}`, { method: 'DELETE' }),
      onSuccess: loadUsers,
      successMessage: t('toast.updated'),
    });
  });

  $('[data-user-form]')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const id = data.get('id');
    const payload = {
      username: String(data.get('username') || '').trim(),
      email: String(data.get('email') || '').trim() || null,
      role_id: Number(data.get('role_id')),
      is_active: form.elements.is_active.checked,
    };
    if (!id) {
      payload.password = String(data.get('password') || '');
    }
    await runAction({
      key: `user-save:${id || 'new'}`,
      title: t('common.save'),
      message: payload.username,
      trigger: event.submitter || form,
      request: () => api(id ? `/api/v1/users/${id}` : '/api/v1/users', {
        method: id ? 'PUT' : 'POST',
        json: payload,
      }),
      onSuccess: async () => {
        closePanel(panel);
        await loadUsers();
      },
      successMessage: t('users.saved'),
    });
  });

  try {
    await loadUsers();
  } catch (error) {
    toast(error.message, 'critical');
  }
}
