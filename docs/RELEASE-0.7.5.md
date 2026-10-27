# DNS Manager v0.7.5 — release notes

Fixes icons on dynamically generated buttons. The JavaScript icon renderer
previously referenced SVG symbols without their `icon-` prefix, leaving the
SSL more-actions control and other action icons blank even though the controls
could still be clicked. The renderer now references the existing sprite IDs.

No database migration is added. Upgrade with the existing
`DNS_MANAGER_INTERNAL_PROXY_IP` and hard-reload the browser afterwards.
