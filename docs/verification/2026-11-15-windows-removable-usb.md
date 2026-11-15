# Native Windows removable-drive USB validation — 2026-11-15

The actual **agent 1.11.28 CLI** completed a Windows → Linux removable-drive
forwarding cycle. This used the installed Windows executable with SHA-256
`cfcded6790fb66588a4c750e8ece907e3b198aefbd4e89e4674ee309ec4251c5`,
from source `bd631c096ff1666b5bdf0d323c295966161590e6`. The preparation and
restoration operations were Rust CLI commands, not the earlier C# API prototype.

The selected source was Aero's SanDisk USB device `0781:55a9`, bus `1-14`, native
disk serial `04013171d3e655479e33`, disk size **123,060,879,360 bytes**. Its NTFS
volume initially had drive letter D:, online/read-write state and 32 root directory
entries. Its full USB instance serial and physical ancestry were checked before
each ownership change. There were no existing SanDisk server forwards or saved
local USB jobs.

## Completed cycle

1. Installed a temporary Luna udev rule matching only this vendor, product and
   full USB serial before attachment. It suppressed UDisks automounting and set
   the matching whole block device and partitions read-only.
2. Ran `porthub usb prepare 1-14` on Aero. The command succeeded, produced its
   private identity-bound recovery journal and left D: inaccessible/offline.
3. Started an actual detached PortHub USB forward from Aero to Luna. Luna
   enumerated the exact device on VHCI, with one NTFS partition. The whole disk
   and partition both had kernel read-only state, and `UDISKS_IGNORE=1` was active.
4. Mounted only that partition with
   `ro,norecover,nodev,noexec,nosuid`. Verified the active mount flags and original
   disk size/USB identity again. Counted and statted root directory entries:
   **32 entries**, matching Windows. No filenames or user-file contents were
   printed or read, and no user-data writes were performed.
5. Unmounted normally, without force or lazy unmount, before stopping the owned
   detached forward. No filesystem repair, journal replay or formatting was used.
6. Waited for the original Windows device to return unshared, then ran
   `porthub usb restore 1-14`. It succeeded and removed its preparation journal.
7. Verified D: was online/read-write again with its original 32 root entries,
   and Aero had no saved USB forwards. Verified Luna's imported device and owned
   mount were absent, then removed the exact temporary protection rule.

The normal lock operation flushes Windows' preexisting filesystem cache before
unmounting. The test did not create/delete files on the drive or perform raw
writes. Directory counts are metadata evidence, not a claim of a full file-content
or bitwise comparison. The sensitive Samsung T7 was neither selected nor tested.

## Scope

This proves the new typed prepare/forward/read-only-mount/restore workflow for
this SanDisk NTFS removable drive and these enrolled machines. It does not claim
Windows destination storage compatibility, write benchmarks, every filesystem,
or automatic unmounting from the server. Preparation remains an explicit local
administrator operation and refuses unsafe/open/unknown volume states.
