# Retained legacy backend source

Owner: publication. Official publication grant authority, listener custody and operator configuration.

Legacy source only, not a current supported import path or command. Original cross-package namespaces, private imports, target paths, key/account custody, host/network/process actions and fixtures must be ported deliberately before use. Do not add sys.path shims, privileged globals, fake storage or automatic service/firewall actions to make it run. No old module/driver is imported or executed by this extraction; no active backend or minimum dependency changes.

## Source and history

Desktop snapshot `4f72ea86928666189b32f6f05c2c697a37341d06`; exact source baseline `f5440391cf3d83e1700b5efe8867056c4ab2353c`; separate mechanical merge `13124fbb41f45bf516c08490bc527d33e2e0e59a`. Private phase41 retains original/earlier paths, copy-boundary notes and commit/ref maps. No active package/module/test body changed.

| Original path | Retained path |
|---|---|
| `active-system/origin_service/official_authority.py` | `legacy/backend/origin_service/official_authority.py` |
| `active-system/origin_service/official_backend_custody.py` | `legacy/backend/origin_service/official_backend_custody.py` |
| `active-system/origin_service/official_management.py` | `legacy/backend/origin_service/official_management.py` |

These sources remain outside supported package/build/test entrypoints. Existing source baseline failures remain separate; syntax/history checks do not establish old protocol or current application compatibility. Preserve native signed-worker/authorization checks during a real public-interface port. External publication is not authorized by this source retention.
