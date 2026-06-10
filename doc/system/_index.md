# FOCSYSTEM.md - ForgeCustomer Canonical System Reference

**Document version:** 1.0 (bootstrap)
**Document date:** 2026-06-10
**Protocol:** Forge Documentation Protocol v1
**Documentation structure class:** `system`

This `doc/system/` tree is the canonical authored source for the ForgeCustomer system
reference. The assembled artifact is generated and should not be edited directly.

Assembly contract:

- Command: `bash doc/system/BUILD.sh`
- Validation: `bash doc/system/validate_snapshots.sh doc/FOCSYSTEM.md`
- Primary output: `doc/FOCSYSTEM.md`
- Generated artifact rule: edit `doc/system/*.md`, then rebuild.

Supporting reference material remains in `docs/`, `contracts/`, `supabase/migrations/`,
and the Rust API crate. When those sources disagree, the live implementation and this
generated canonical reference must be reconciled in the same change.

| Part | File | Contents |
| --- | --- | --- |
| 1 | `00-overview.md` | Mission, current readiness, and repository ownership. |
| 2 | `01-authority-boundaries.md` | Data authority, source-of-truth rules, and out-of-scope data. |
| 3 | `02-architecture-runtime.md` | Runtime components, request lifecycle, and process behavior. |
| 4 | `03-api-contract.md` | HTTP routes, auth boundaries, errors, and correlation behavior. |
| 5 | `04-data-model.md` | Supabase/Postgres schema domains and RLS posture. |
| 6 | `05-domain-subsystems.md` | Commerce, licensing, entitlement, usage, privacy, and admin semantics. |
| 7 | `06-integrations-events.md` | Stripe, DataForge outbox, contracts, and event hygiene. |
| 8 | `07-security-privacy.md` | Token validation, secret handling, signing, PII, and fail-closed rules. |
| 9 | `08-configuration-operations.md` | Environment variables, deployment, migrations, and runbook notes. |
| 10 | `09-verification-status.md` | Tests, CI gates, runnable proof, and known MVP gaps. |
| 11 | `90-governance-change-control.md` | Change-control rules for keeping the system document current. |

## Quick Assembly

```bash
bash doc/system/BUILD.sh
```
