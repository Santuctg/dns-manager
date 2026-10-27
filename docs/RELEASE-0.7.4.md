# DNS Manager v0.7.4 — release notes

Fixes form fields that appeared unstyled when their HTML omitted the `type`
attribute. Browsers treat these as text inputs, but earlier CSS targeted only
explicit `type="text"` fields. Username and other implicit text inputs now
share the normal input styling. Password and checkbox behavior is unchanged.

No database migration is added. Upgrade using the existing
`DNS_MANAGER_INTERNAL_PROXY_IP`, then hard-reload the browser.

Verification includes a browser regression test comparing username and password
styles, the browser suite, and the non-browser suite in a Linux container. A
container test is not a substitute for validating an installed Linux host.
