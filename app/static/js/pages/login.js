import { $, t } from '../core.js';

function setError(message) {
  const error = $('[data-login-error]');
  if (!error) return;
  error.textContent = message;
  error.hidden = !message;
}

async function fetchCsrf() {
  const response = await fetch('/api/v1/auth/csrf', { credentials: 'same-origin' });
  if (!response.ok) throw new Error(t('login.failed'));
  const body = await response.json();
  return body.csrf_token;
}

async function errorDetail(response) {
  try {
    const body = await response.json();
    if (typeof body.detail === 'string') return body.detail;
    if (body.detail) return JSON.stringify(body.detail);
    return t('login.failed');
  } catch {
    return t('login.failed');
  }
}

export function init() {
  const form = $('[data-login-form]');
  if (!form) return;
  const button = $('[data-login-submit]', form);
  const username = form.elements.username;
  username?.focus();

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    setError('');
    const data = Object.fromEntries(new FormData(form));
    const name = String(data.username || '').trim();
    const password = String(data.password || '');
    if (!name || !password) {
      setError(t('common.required'));
      (name ? form.elements.password : username)?.focus();
      return;
    }
    if (button) {
      button.disabled = true;
      button.dataset.label = button.textContent;
      button.textContent = t('login.working');
    }
    try {
      const token = await fetchCsrf();
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': token,
        },
        body: JSON.stringify({ username: name, password }),
      });
      if (!response.ok) throw new Error(await errorDetail(response));
      const next = form.dataset.next || '/app/dashboard';
      location.assign(next.startsWith('/app/') ? next : '/app/dashboard');
    } catch (error) {
      setError(error?.message || t('login.failed'));
      if (button) {
        button.disabled = false;
        button.textContent = button.dataset.label || t('login.submit');
      }
      form.elements.password?.focus();
    }
  });
}
