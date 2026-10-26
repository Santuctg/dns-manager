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

Tests should run in an isolated test environment rather than the production host. Do not run production-impacting integration tests against live firewall services. The GitHub packaging archive was reconstructed from the 0.6.11 source and the documentation additions; documentation authoring is not a new software version.
