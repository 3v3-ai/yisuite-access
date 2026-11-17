# Changelog

## 0.1.0 (2026-11-17)
- One token verifier, folded from the six app copies (dark-factory, invoice_extraction,
  yinvoice_free, project_mm_invoice, Yi.Flow, yingdom): `EnvVerifier`, `EveClaims`
  (user_id, email, name, org_id, org_role, tid, ent), `bearer`, `looks_like_rs256`,
  `EVE_TOKEN_MODE` off|both|v2, own User-Agent on the JWKS fetch.
- `EveClient`: `publish_catalog`, `notify`, `report_usage`, `read_usage`, `health_event`;
  timeouts, retries, idempotency keys, no-op without a secret. `report_workspace` removed.
- `token_conformance`: pytest suite apps run in CI.
- Flask and FastAPI adapters, decision model, decision conformance unchanged.
