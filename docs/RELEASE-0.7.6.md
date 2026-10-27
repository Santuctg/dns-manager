# DNS Manager v0.7.6 — release notes

- Keep the sidebar show/hide control inside the scrollable sidebar so it is
  fully visible and clickable in expanded and collapsed modes.
- Make the UFW Policy incoming and outgoing fields wider and consistent on
  desktop, and stack them on narrow screens. The firewall policy behavior,
  validation and apply workflow are unchanged.

No database migration is added. Upgrade with the existing
`DNS_MANAGER_INTERNAL_PROXY_IP` and hard-reload the browser afterwards.
