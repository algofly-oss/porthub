# Local native release builds

Run this on each explicitly authorized build host, in a clean checkout at the
same full commit. It does not provision hosts, register runners, deploy, install
services, or publish. SSH/staging remains a separate explicit operator action.

```
python3 scripts/build-local-native.py --source-revision FULL40SHA --output /owned/new/component-builds --tool core
```

The default prints a plan without invoking Cargo or downloading terminal sources.
Add `--execute` to build. On Windows use `python` and a Windows-owned output path.
Omit `--tool core` to build all configured independent components. Each component
gets a separate Cargo invocation, preventing optional-helper feature unification.
`--previous` accepts an existing verified component-build index for safe reuse.

Prerequisites are the existing shipping workflow's native toolchain/dependencies:
Rust from rust-toolchain.toml, Python 3.11+, Git; Linux matching musl-gcc, terminal
builder prerequisites and readelf; Windows MSVC/Windows SDK; macOS Xcode command
line tools and target SDK. Media helper native dependencies still apply when
selecting all tools. This entry point installs none of them and does not elevate.

Linux x86_64/arm64 chooses the shipping musl target and builds the existing pinned
terminal bundle. macOS/Windows select the matching architecture only. Unsupported
hosts fail closed. Shipping compiler inputs come from component-platforms.toml;
conflicting inherited settings are rejected, not erased. Full source pin and
clean-tree checks bracket the existing build orchestration. Cargo uses --locked
and the configured release recipe. index.json references build-receipt.json files
with actual dependency/input closure and raw binary SHA/size; all emitted binaries
are verified again through previous_builds/verify_reuse before success.

This establishes artifact/input integrity, not native service, audio, network,
signing/notarization, or all-platform release acceptance. Existing hosted native
checks, prepare-release/assemble-client-release and publication verification remain
separate. On nitin-mbp, the arm64 core build at commit
`e33e3e5f179c7dd5113384cde2f13ae307ca831e` completed in 92 seconds.
The local build command verified the artifact receipt and the executable
reported `porthub 1.11.42` when run on the Mac.
