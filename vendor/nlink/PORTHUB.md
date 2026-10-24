# Upstream provenance

nlink 0.33.0, crates.io source from upstream commit
`35f90a67bc4772212b4b37b7226073c2f8655b74` in
https://github.com/p13marc/nlink (crates/nlink).
Dual MIT / Apache-2.0; upstream licenses are included alongside this file.

PortHub vendors this dependency because its namespace helpers did not compile
on 32-bit Linux. Two changes widen libc's architecture-dependent syscall result
and inode number to the existing i64/u64 API types. Their values and behavior
are unchanged on 64-bit Linux. Registry-only marker/lock files are omitted.
All other upstream library source, examples and tests are retained.
