# Required interface port

The source is organized; its legacy composition is not the new backend contract.

| Legacy dependency | Owner / required work | Gate |
|---|---|---|
| `.protocol` signed-root/catalog/channel verification, including `_proof` | Rendezvous retains original protocol source; expose the actual shared proof operation through a tested public interface in its correct engine, without private imports or wrappers | OPEN |
| `room_service.contract` request/identity/principal validation | Legacy Rooms preserves this source; determine the reusable public wire boundary deliberately. The old room worker remains unused and disabled | OPEN |
| `origin_service.official_authority` confirmation profile | Accounts owns live identity, but the experimental issuer module is not yet ported. Define the public resource-bound admission contract; it grants no content/storage permission by itself | OPEN |
| `gateway_service.http.offload` asynchronous I/O | Replace the private gateway helper import with the correct tested public runtime/storage I/O interface | OPEN |
| Python `chess`, aiohttp, cryptography | Verify exact required dependency pins/graph before providing an install/build interface | OPEN |
| Own `.official_*` / `.system_*` imports | Owned inside this component; retain real domain state and replay, not a second simulated model | source retained |

Production key custody, durable registry and history persistence, root/controller recovery, authorization, signed replay, stale writes, jobs after view close, lifecycle cleanup, and actual browser/agent operations require qualification. Source AST validity and the unsigned reconstruction fixture are not those gates. No server or operator scripts are enabled here.
