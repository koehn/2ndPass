# Repository working notes

## macOS sandbox and validation

Swift/Xcode validation in the Codex filesystem sandbox has known environmental
failures. Account for these before interpreting failures as regressions:

- SwiftPM's default Clang module cache (`~/.cache/clang/ModuleCache`) may be
  unwritable. Use `CLANG_MODULE_CACHE_PATH=/tmp/mop-clang-cache` and
  `SWIFTPM_MODULECACHE_OVERRIDE=/tmp/mop-swift-cache` for sandboxed Swift commands.
- SwiftPM manifest sandboxing can also fail inside the outer sandbox. Use
  `swift test --disable-sandbox` or `swift build --disable-sandbox`; this disables
  SwiftPM's nested manifest sandbox, not Codex's access restrictions.
- Direct `swiftc` compilation of SwiftUI views can also fail when its macro
  plugin launches a nested sandbox (`sandbox_apply: Operation not permitted`,
  followed by missing `SwiftUIMacros.StateMacro` errors). Run that compilation
  with `require_escalated`; these messages do not establish a source-code error.
- The full test suite needs local Unix sockets, process inspection, child
  processes, and macOS test pasteboards. Run it with the execution tool's
  `require_escalated` permission mode when available. Under the restricted
  sandbox, SSH-agent socket/process tests and `SecretClipboardTests` can fail,
  and some asynchronous tests can stall. Do not change the product or weaken
  tests to make these environmental failures pass.
- Xcode builds and simulator tests need access to Apple build/simulator services
  and package caches. Request `require_escalated` for `xcodebuild` when the
  sandbox denies those services. Use `-clonedSourcePackagesDirPath .build` to
  reuse the repository's existing package checkout cache, plus a distinct
  `-derivedDataPath .build/<purpose>`.
- A running `swift test` owns SwiftPM's `.build` lock until tests finish. Do not
  start another SwiftPM invocation while it is running. If it stalls because of
  sandbox restrictions, terminate only that known task-owned runner before
  rerunning with the required access. A denied `kill` may itself need escalation.
- Some Xcode simulator runs can finish or abort test execution but hang while
  collecting diagnostics, leaving an incomplete `.xcresult` without `Info.plist`.
  Inspect test-case output separately from the final runner status. Verify that a
  task-owned runner actually exited before retrying; SIGINT was ignored in this
  environment, so SIGTERM was needed for the known stalled PIDs. Do not leave
  concurrent runners targeting the same simulator. For a retry,
  `-collect-test-diagnostics never` avoids lengthy sysdiagnose collection after
  failures; retain normal test assertions and inspect their actual results.
- Read actual tool outcomes. Escalation is subject to approval; if denied, report
  the limitation instead of claiming tests passed. Simulator/software tests do
  not validate real Secure Enclave, iCloud synchronization, recovery, or
  cross-account permissions.

Observed 2026-10-01: the full suite passed with the required access after
sandbox-only socket, process, pasteboard, and module-cache failures. Relevant
commands:

```sh
CLANG_MODULE_CACHE_PATH=/tmp/mop-clang-cache \
SWIFTPM_MODULECACHE_OVERRIDE=/tmp/mop-swift-cache \
swift test --disable-sandbox

xcodebuild -project Apple/Mop.xcodeproj -scheme MopAutoFill \
  -configuration Debug -destination 'generic/platform=macOS' \
  -derivedDataPath .build/credential-autofill \
  -clonedSourcePackagesDirPath .build CODE_SIGNING_ALLOWED=NO build
```
