# Read-only USB NVMe health

Linux physical-drive health now recognizes a narrow set of ASMedia USB-to-NVMe bridges. The current IDs are ASMedia `174c:2362`, `174c:2364`, `174c:2463`, Samsung T9 `04e8:61fd`, and the physically verified Samsung T7 `04e8:4001`. Unknown USB IDs never receive vendor-specific probes. Known identity alone is insufficient for a health result: a valid NVMe Identify Controller response and a complete SMART/Health log are both required.

The native Rust implementation is deliberately not a general pass-through interface. Its only commands are 4 KiB Identify Controller and the 512-byte SMART/Health Get Log Page 2. Both use the ASMedia read-only vendor CDB and Linux SG_IO with a two-second command timeout. No self-test, firmware, namespace, filesystem, or data-write operation is exposed. The file is opened read-only with O_NOFOLLOW; transfer direction is always device-to-host. Partial transfers and any non-success SCSI/host/driver status are rejected.

Before and after each query, the probe binds the held block-device file descriptor's major/minor to sysfs and revalidates the USB ancestor, VID/PID/serial, model, capacity, and existing inventory identity. Exported USB devices and runtime-suspended drives are skipped. Correcting the report protocol to `nvme_usb` retains the existing physical-drive ID, preserving prior unavailable readings and history. Hyper-V/WSL VMBus virtual disks are excluded using kernel bus/driver ancestry, rather than pretending their virtual SCSI device exposes the host's physical SMART controller.

Protocol facts were checked against the [smartmontools ASMedia protocol documentation](https://www.smartmontools.org/static/doxygen/scsinvme_8cpp_source.html) and [documented bridge identities](https://github.com/smartmontools/smartmontools/blob/main/drivedb/drivedb.h). The bounded Rust encoder is independently written. NVMe fields are interpreted by the shared parser using [libnvme's SMART definitions](https://github.com/linux-nvme/libnvme/blob/master/src/nvme/types.h). Lifetime read/write counters are reported in thousands of 512-byte units, rounded up; zero means unreported. Converted byte values are approximate, and unsupported or overflowing values remain unavailable.

## Physical validation

A read-only probe of the existing Luna Samsung T7 matched the independently collected smartctl ASMedia reference: approximately 31°C, 6,517 power-on hours, 100% available spare, 0% rated endurance used, 445 unsafe shutdowns, and zero media/data integrity errors. Approximate lifetime reads were 4,398,008,832,000 bytes and writes 1,751,504,896,000 bytes, matching reference raw counters multiplied by 512,000.

The probe used the exact known hardware identity and capacity, a read-only device mapping, no network, and an automatically removed helper container. It read no filesystem or user-file contents and issued no self-tests or writes. This is native source-probe proof; it does not claim that an agent release containing the change has been deployed.

Five actual agent unit tests pass: exact bridge allowlist, fixed read-only wire commands, rejection of partial/error transport, positive Identify validation, and virtual-bus exclusion without model-name heuristics.
