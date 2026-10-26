# API reference and testing

The interactive OpenAPI schema is served at `/openapi.json`. Use it as the definitive version-specific request/response contract; the list below is an operator overview, not a promise of stable external API compatibility.

| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | GET | Process/database health |
| `/ready` | GET | Environment readiness |
| `/api/v1/system/status` | GET | System state, `system.view` |
| `/api/v1/system/metrics` | GET | Host metrics, `system.view`, `no-store` |
| `/api/v1/system/backends` | GET | Upstream checks, `system.view` |
| `/api/v1/mappings` | GET/POST | List/create mappings |
| `/api/v1/mappings/{id}` | GET/PUT/DELETE | Read/edit/remove mapping |
| `/api/v1/config/preview` | GET | Render draft DNS/Nginx configs |
| `/api/v1/config/validate` | POST | Validate draft deployment |
| `/api/v1/config/apply` | POST | Apply desired configuration |
| `/api/v1/firewall/policy` | GET/PUT | Desired UFW policy |
| `/api/v1/firewall/rules` | POST | Create logical firewall rule |
| `/api/v1/firewall/preview` | POST | Preview proposed firewall operations |
| `/api/v1/firewall/validate` | POST | Check firewall safety |
| `/api/v1/firewall/apply` | POST | Apply firewall policy |
| `/api/v1/firewall/confirm` | POST | Keep applied firewall rules |
| `/api/v1/firewall/rollback` | POST | Restore prior firewall policy |

Authenticated browser sessions and RBAC are required for operational endpoints. Mutating calls may require a matching CSRF cookie and `X-CSRF-Token` header. Avoid using privileged endpoints from scripts without understanding their safety workflow.

## Development checks

```bash
python3 -m pytest -q
python3 -m compileall -q app privileged
bash -n packaging/install.sh
for f in app/static/js/core.js app/static/js/pages/*.js; do node --input-type=module --check < "$f"; done
```

Tests should run in an isolated test environment rather than the production host. Do not run production-impacting integration tests against live firewall services.

### Optional browser smoke test

The console smoke test renders the sign-in page and every console page at 1440 px and 390 px in both themes and both languages. It fails on horizontal overflow, visible elements escaping the viewport outside a scroll container, closed dialogs that are still rendered, missing bundled fonts, raw translation keys and console errors.

The test is marked `browser` and skips automatically when Playwright or Chromium is not installed, so it is not part of the runtime requirements. Install it only on a development machine:

```bash
python3 -m pip install "playwright>=1.40,<2"
python3 -m playwright install chromium
python3 -m pytest -m browser -q
```

The test starts its own uvicorn server with a temporary SQLite database and seeded accounts, so it does not touch the production database or host services. The expected `503` from `/api/v1/system/metrics` on hosts without `/proc` is ignored.
