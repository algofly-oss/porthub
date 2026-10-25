# Bundled Wintun runtime

PortHub embeds the official signed Wintun 0.14.1 DLLs downloaded from
https://www.wintun.net/builds/wintun-0.14.1.zip. The ZIP SHA-256 was verified as
`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`.

The DLLs are extracted on Windows to the ACL-protected `%ProgramData%\\PortHub\\drivers`
directory because the Wintun API loads a platform-specific DLL. The included
`LICENSE.txt` applies to these unmodified binaries. The Rust agent uses only
the published Wintun API through `tun-rs`.
