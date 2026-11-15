# SMART parameter validation

The November 2026 investigation compared PortHub's native read-only collector with drive-reported SMART data. No filesystem contents were read or written, no self-test was started, no disk was repaired, and no mount state was changed. SMART reference queries used `smartctl -j -i -H -A -n standby`; the standby option avoids waking sleeping disks. Reference binaries are diagnostic tools, not an agent runtime dependency.

| Machine / physical drive | Actual supported readings | Finding |
| --- | --- | --- |
| Luna / WD 8 TB SATA HDD | Temperature, power-on hours/cycles, reallocated/pending/offline-uncorrectable sectors and ATA normalized thresholds | Native readings agree with the reference. NVMe spare/endurance fields do not apply. |
| Luna / Samsung 980 PRO NVMe | Temperature, endurance used, spare/threshold, power-on hours/cycles, unsafe shutdowns, media errors, lifetime host data units | Native log agrees with the reference. Lifetime host bytes were previously omitted. |
| Luna / WD SN570 NVMe | Same NVMe fields | Native log agrees with the reference. Error-log entries alone are not equivalent to media errors. |
| Luna / Samsung T7 USB SSD | Full NVMe health through its ASMedia bridge | The previous ATA-only USB transport reported unavailable despite supported SMART. Read-only NVMe bridge support is needed; unsupported transport must never fabricate healthy zeros. |
| Miro / Toshiba SATA HDD | Temperature, hours/cycles, reallocated/pending sectors, normalized thresholds, historical reported-uncorrectable events | Attribute 187 reports two historical command-error events with normalized value 98. This warrants attention and trend inspection, not a prediction of imminent failure. Attribute 198 is absent, so offline-uncorrectable sectors remain unknown. |
| Miro / XPG NVMe | Full standard NVMe health and lifetime host data units | Native readings agree with the reference. |
| Aero / Samsung internal NVMe | Actual Windows storage-protocol query returns temperature, endurance, spare, hours/cycles, unsafe shutdowns, media errors and lifetime data units | Native query succeeds. A zero supported endurance/media-error counter is a real zero. |
| Aero / SanDisk USB flash drive | Neither the native NVMe protocol query nor legacy ATA SMART query succeeds | Windows returns invalid-parameter (87) and not-supported (50), respectively. StorageReliabilityCounter zero placeholders do not prove supported SMART; those fields remain unavailable. |
| WSL / Microsoft virtual disks | Virtual disks only; host physical SMART is not exposed | Host physical health must be obtained from the Windows agent, not inferred from virtual block devices. |
| MacBook | Machine unreachable during this investigation | No new hardware claim. Existing OS-level SMART status does not provide detailed ATA/NVMe attributes. |

Raw diagnostic receipts are kept locally with restricted permissions, including the device-to-result mapping. Hardware serials and raw user data are not included in this document or uploaded in metrics; drive identities remain hashed.

## Parameter semantics

NVMe lifetime host reads/writes are approximate: the drive reports 128-bit, rounded-up thousands of 512-byte units. PortHub multiplies by 512,000 with checked arithmetic, displays an approximation marker, and treats an unreported zero or an out-of-range result as unknown. It does not saturate an overflowing lifetime value and present it as an exact reading. See the [libnvme primary definitions](https://github.com/linux-nvme/libnvme/blob/master/src/nvme/types.h).

ATA reported-uncorrectable **events** (187), pending sectors (197), and offline-uncorrectable **sectors** (198) remain distinct. A historical event count creates a warning. A valid drive-specific normalized threshold failure remains critical. Vendor-specific counters are not interpreted as universal unsafe-shutdown or lifetime-write totals.

A checksum-valid ATA page without usable attributes is unavailable, not healthy. Optional corrupt threshold/self-test sectors are ignored rather than producing a false threshold failure or failed test.

## Rolling compatibility

New optional health fields are stripped on schema rejection before retrying older gateways, preserving existing health and CPU/RAM/disk readings. Database storage keeps strict legacy samples and SMART history snapshots unchanged; new details live beside them. Latest details are bound to both the physical drive identity and its exact observation time, preventing another drive or an older observation from inheriting counters. Ordinary utilization history does not duplicate the low-frequency SMART details.
