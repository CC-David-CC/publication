# Publication source — interface port pending

Owns32 former steward publication modules: signed Chat/Chess history validation, registry, writers/moderation, HTTP readers/submission, recovery journals and SYSTEM publication/key-custody source. It is separate from peer discovery/signaling at platform/rendezvous and from the Chat/Chess UIs. The source has one repository owner and retained history; it is not an enabled backend or a completed fresh-system implementation.

All32 implementation files are byte-identical to the verified original baseline. The original structural reconstruction fixture is retained under tests/fixtures; a separate source-layout commit changes only its import/setup paths and adds metadata. The fixture uses unsigned synthetic content and verifies reconstruction/tampering/bounds only. It does not establish signatures, accepted history, account permissions, server storage, human/agent operations or application readiness.

The old private import boundaries remain explicit porting work. There is no supported full build/install or server entrypoint yet. PORTING.md lists the required interfaces. Do not add path shims into the old workspace, merge two components into the same Python namespace, expose signing keys, or assume package presence authorizes an operation. New generic fixes belong in the appropriate engine/interface with tests; final host-facing operations must share the human/agent domain path.

This component is not a minimum-system dependency. No publisher, reader, operator, network listener, timer, root migration or deployment is started by this extraction. Historical assets and old account data are not prerequisites for rebuilding the fresh product.

Run the isolated structural fixture with `python tests/fixtures/history-reconstruct.py`. Full-module imports and operational acceptance remain OPEN.
