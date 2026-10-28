# DNS Manager v0.7.7 — release notes

Refines the UFW Policy form layout: desktop dropdowns have a consistent,
bounded width and the Enable UFW checkbox and Save policy button align with
them. On narrow screens the fields remain stacked.

This is a visual-only change: firewall policy behavior and the validation and
apply workflow are unchanged. No database migration is added. Upgrade with
the existing `DNS_MANAGER_INTERNAL_PROXY_IP` and hard-reload the browser.
