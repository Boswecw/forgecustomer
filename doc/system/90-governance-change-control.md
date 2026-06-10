## 11. Governance and Change Control

This repository treats documentation as part of the system contract. Changes that alter
customer/commercial behavior must update this canonical source tree and any supporting
contract files in the same change.

### Canonical doc workflow

1. Edit the relevant file under `doc/system/`.
2. Rebuild with `bash doc/system/BUILD.sh`.
3. Review `doc/FOCSYSTEM.md`.
4. Run the relevant Rust, migration, and contract checks.

Do not edit `doc/FOCSYSTEM.md` directly except as a generated output from the build
script.

### Supporting docs

The existing `docs/` tree remains useful for domain detail. It is not the generated
canonical artifact. When domain docs and `doc/FOCSYSTEM.md` diverge, update both or
record why the domain doc is stale.

### Change boundaries

Any change that does one of the following requires a documentation update:

- Adds or removes an API route.
- Changes auth, admin, customer, RLS, or token validation behavior.
- Adds a table, migration, event type, schema, or outbox payload field.
- Changes Stripe, DataForge, Supabase, signing, privacy, or deletion behavior.
- Marks a `NOT_IMPLEMENTED` route as implemented.
- Changes local-access/offline entitlement doctrine.

### Review checklist

- Authority matrix still has no overlap.
- Secrets remain server-side only.
- DataForge remains a sanitized sink.
- Usage and audit state remain append-only.
- Creative content remains out of scope.
- CI and local proof match the claims in this document.
