# ZChat for iOS

Native iOS client (Swift, SwiftUI) of [ZChat](https://github.com/decentrathai/zchat-android), the private
messenger on Zcash: no phone number, email or account; your Zcash address is your identity. It speaks the
same ZMSG protocol as the Android app and is kept in step with it through a shared parity registry.

**Status: early development, not usable yet.** No release exists. The first parts being built are the
platform-independent core in `Packages/ZChatCore` (message format, crypto, Nostr, wallet logic), tested
against the Android app's behaviour.

## Layout

- `Packages/ZChatCore` — the Swift package with the core logic and its tests (builds on macOS and Linux)
- `parity/` — the pin to the shared parity registry
- `tools/qa`, `.claude`, `AGENTS.md` — the development harness (tests, commit hooks, agent rules)

## Licence

MIT, see [LICENSE](LICENSE).
