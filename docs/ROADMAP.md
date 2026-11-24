# Upgrades that would help organisations

1. **Multi-tenant orgs**: organisation IDs, per-org install tokens and dashboards, SSO (OIDC/SAML), SCIM user provisioning.
2. **Managed deployment**: Chrome Enterprise policy (force-install, locked server URL via managed storage) so staff cannot disable protection.
3. **Shared allow/block lists** pushed from the admin console; org-wide "report phishing" button feeding an analyst queue.
4. **Real training data pipeline**: scheduled retraining from OpenPhish/PhishTank/URLhaus + Tranco, model versioning, drift and false-positive tracking.
5. **Content-based detection**: server-side page fetch (already SSRF-safe) for brand logo / form similarity, with consent.
6. **Alerting**: email/Slack/SIEM (syslog, Splunk, Sentinel) webhooks, daily digest, incident status workflow.
7. **Hardening**: Postgres, Redis rate limits, cookie sessions + CSRF, TOTP MFA for admins, signed audit-log export, pen test.
8. **Awareness training**: simulated-phish campaigns and a "why was this blocked" explainer for staff.
