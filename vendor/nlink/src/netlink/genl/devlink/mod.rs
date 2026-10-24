//! Devlink Generic Netlink support for hardware device management.
//!
//! This module provides a typed API for querying devlink devices, ports,
//! firmware info, health reporters, and device parameters via Generic Netlink.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Devlink};
//!
//! let conn = Connection::<Devlink>::new_async().await?;
//!
//! // List all devlink devices
//! let devices = conn.get_devices().await?;
//! for dev in &devices {
//!     println!("{}", dev.path());
//! }
//!
//! // Get firmware info
//! let info = conn.get_device_info("pci", "0000:03:00.0").await?;
//! println!("Driver: {}", info.driver);
//! for v in &info.versions_running {
//!     println!("  {}: {}", v.name, v.value);
//! }
//! # Ok(())
//! # }
//! ```

pub mod connection;
pub mod types;

pub use types::*;

/// Devlink GENL family name.
pub const DEVLINK_GENL_NAME: &str = "devlink";

/// Devlink GENL version.
pub const DEVLINK_GENL_VERSION: u8 = 1;

// Commands
pub const DEVLINK_CMD_GET: u8 = 1;
pub const DEVLINK_CMD_PORT_GET: u8 = 5;
/// Set port attributes, including the `DEVLINK_ATTR_PORT_FUNCTION` nest.
pub const DEVLINK_CMD_PORT_SET: u8 = 6;
pub const DEVLINK_CMD_PORT_SPLIT: u8 = 9;
pub const DEVLINK_CMD_PORT_UNSPLIT: u8 = 10;
pub const DEVLINK_CMD_RELOAD: u8 = 37;
pub const DEVLINK_CMD_PARAM_GET: u8 = 38;
pub const DEVLINK_CMD_PARAM_SET: u8 = 39;
pub const DEVLINK_CMD_INFO_GET: u8 = 51;
pub const DEVLINK_CMD_HEALTH_REPORTER_GET: u8 = 52;
pub const DEVLINK_CMD_HEALTH_REPORTER_SET: u8 = 53;
pub const DEVLINK_CMD_HEALTH_REPORTER_RECOVER: u8 = 54;
pub const DEVLINK_CMD_FLASH_UPDATE: u8 = 58;

// Shared-buffer / resource / region / trap read commands. Values from
// `enum devlink_command` in include/uapi/linux/devlink.h. SB_GET,
// REGION_GET, TRAP_GET and TRAP_GROUP_GET are dumpit-capable; while
// RESOURCE_DUMP is a per-device doit requiring bus+device.
pub const DEVLINK_CMD_SB_GET: u8 = 11;
pub const DEVLINK_CMD_RESOURCE_DUMP: u8 = 36;
pub const DEVLINK_CMD_REGION_GET: u8 = 42;
pub const DEVLINK_CMD_TRAP_GET: u8 = 61;

// Shared-buffer attributes (`DEVLINK_ATTR_SB_*`).
pub const DEVLINK_ATTR_SB_INDEX: u16 = 11;
pub const DEVLINK_ATTR_SB_SIZE: u16 = 12;
pub const DEVLINK_ATTR_SB_INGRESS_POOL_COUNT: u16 = 13;
pub const DEVLINK_ATTR_SB_EGRESS_POOL_COUNT: u16 = 14;
pub const DEVLINK_ATTR_SB_INGRESS_TC_COUNT: u16 = 15;
pub const DEVLINK_ATTR_SB_EGRESS_TC_COUNT: u16 = 16;

// Resource attributes (`DEVLINK_ATTR_RESOURCE_*`).
pub const DEVLINK_ATTR_RESOURCE_LIST: u16 = 63;
pub const DEVLINK_ATTR_RESOURCE: u16 = 64;
pub const DEVLINK_ATTR_RESOURCE_NAME: u16 = 65;
pub const DEVLINK_ATTR_RESOURCE_ID: u16 = 66;
pub const DEVLINK_ATTR_RESOURCE_SIZE: u16 = 67;
pub const DEVLINK_ATTR_RESOURCE_SIZE_VALID: u16 = 69;
pub const DEVLINK_ATTR_RESOURCE_UNIT: u16 = 73;
pub const DEVLINK_ATTR_RESOURCE_OCC: u16 = 74;

// Region attributes (`DEVLINK_ATTR_REGION_*`).
pub const DEVLINK_ATTR_REGION_NAME: u16 = 88;
pub const DEVLINK_ATTR_REGION_SIZE: u16 = 89;
pub const DEVLINK_ATTR_REGION_SNAPSHOTS: u16 = 90;

// Trap attributes (`DEVLINK_ATTR_TRAP_*`).
pub const DEVLINK_ATTR_TRAP_NAME: u16 = 130;
pub const DEVLINK_ATTR_TRAP_ACTION: u16 = 131;
pub const DEVLINK_ATTR_TRAP_TYPE: u16 = 132;
pub const DEVLINK_ATTR_TRAP_GENERIC: u16 = 133;
pub const DEVLINK_ATTR_TRAP_GROUP_NAME: u16 = 135;

// Trap actions (`DEVLINK_TRAP_ACTION_*`).
pub const DEVLINK_TRAP_ACTION_DROP: u8 = 0;
pub const DEVLINK_TRAP_ACTION_TRAP: u8 = 1;
pub const DEVLINK_TRAP_ACTION_MIRROR: u8 = 2;

// Trap types (`DEVLINK_TRAP_TYPE_*`).
pub const DEVLINK_TRAP_TYPE_DROP: u8 = 0;
pub const DEVLINK_TRAP_TYPE_EXCEPTION: u8 = 1;
pub const DEVLINK_TRAP_TYPE_CONTROL: u8 = 2;

// Rate + port-function commands (Plan 153.2).
pub const DEVLINK_CMD_RATE_GET: u8 = 74;
pub const DEVLINK_CMD_RATE_SET: u8 = 75;
pub const DEVLINK_CMD_RATE_NEW: u8 = 76;
pub const DEVLINK_CMD_RATE_DEL: u8 = 77;

// Device/Port attributes
pub const DEVLINK_ATTR_BUS_NAME: u16 = 1;
pub const DEVLINK_ATTR_DEV_NAME: u16 = 2;
pub const DEVLINK_ATTR_PORT_INDEX: u16 = 3;
pub const DEVLINK_ATTR_PORT_TYPE: u16 = 4;
pub const DEVLINK_ATTR_PORT_NETDEV_IFINDEX: u16 = 6;
pub const DEVLINK_ATTR_PORT_NETDEV_NAME: u16 = 7;
pub const DEVLINK_ATTR_PORT_IBDEV_NAME: u16 = 8;
pub const DEVLINK_ATTR_PORT_SPLIT_COUNT: u16 = 9;
pub const DEVLINK_ATTR_PORT_SPLIT_GROUP: u16 = 10;
pub const DEVLINK_ATTR_PORT_FLAVOUR: u16 = 77;
pub const DEVLINK_ATTR_PORT_NUMBER: u16 = 78;
pub const DEVLINK_ATTR_PORT_SPLIT_SUBPORT_NUMBER: u16 = 79;
pub const DEVLINK_ATTR_PORT_PCI_PF_NUMBER: u16 = 127;
pub const DEVLINK_ATTR_PORT_CONTROLLER_NUMBER: u16 = 150;
pub const DEVLINK_ATTR_PORT_PCI_SF_NUMBER: u16 = 164;
pub const DEVLINK_ATTR_PORT_PCI_VF_NUMBER: u16 = 128;

// Info attributes
pub const DEVLINK_ATTR_INFO_DRIVER_NAME: u16 = 98;
pub const DEVLINK_ATTR_INFO_SERIAL_NUMBER: u16 = 99;
pub const DEVLINK_ATTR_INFO_VERSION_FIXED: u16 = 100;
pub const DEVLINK_ATTR_INFO_VERSION_RUNNING: u16 = 101;
pub const DEVLINK_ATTR_INFO_VERSION_STORED: u16 = 102;
pub const DEVLINK_ATTR_INFO_VERSION_NAME: u16 = 103;
pub const DEVLINK_ATTR_INFO_VERSION_VALUE: u16 = 104;
pub const DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER: u16 = 146;

// Health reporter attributes
pub const DEVLINK_ATTR_HEALTH_REPORTER: u16 = 114;
pub const DEVLINK_ATTR_HEALTH_REPORTER_NAME: u16 = 115;
pub const DEVLINK_ATTR_HEALTH_REPORTER_STATE: u16 = 116;
pub const DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT: u16 = 117;
pub const DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT: u16 = 118;
pub const DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS: u16 = 119;
pub const DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD: u16 = 120;
pub const DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER: u16 = 121;
pub const DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP: u16 = 141;

// Flash update attributes
pub const DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME: u16 = 122;
pub const DEVLINK_ATTR_FLASH_UPDATE_COMPONENT: u16 = 123;
pub const DEVLINK_ATTR_FLASH_UPDATE_STATUS_MSG: u16 = 124;
pub const DEVLINK_ATTR_FLASH_UPDATE_STATUS_DONE: u16 = 125;
pub const DEVLINK_ATTR_FLASH_UPDATE_STATUS_TOTAL: u16 = 126;

// Reload attributes
pub const DEVLINK_ATTR_RELOAD_ACTION: u16 = 153;

// Parameter attributes
pub const DEVLINK_ATTR_PARAM: u16 = 80;
pub const DEVLINK_ATTR_PARAM_NAME: u16 = 81;
pub const DEVLINK_ATTR_PARAM_GENERIC: u16 = 82;
pub const DEVLINK_ATTR_PARAM_TYPE: u16 = 83;
pub const DEVLINK_ATTR_PARAM_VALUES_LIST: u16 = 84;
pub const DEVLINK_ATTR_PARAM_VALUE: u16 = 85;
pub const DEVLINK_ATTR_PARAM_VALUE_DATA: u16 = 86;
pub const DEVLINK_ATTR_PARAM_VALUE_CMODE: u16 = 87;

// Notification commands (received via multicast)
pub const DEVLINK_CMD_PORT_NEW: u8 = 7;
pub const DEVLINK_CMD_PORT_DEL: u8 = 8;
pub const DEVLINK_CMD_FLASH_UPDATE_STATUS: u8 = 60;

// Rate + port-function attributes (Plan 153.2). Values from
// include/uapi/linux/devlink.h — stable ABI, must not drift.
pub const DEVLINK_ATTR_RATE_TYPE: u16 = 165;
pub const DEVLINK_ATTR_RATE_TX_SHARE: u16 = 166;
pub const DEVLINK_ATTR_RATE_TX_MAX: u16 = 167;
pub const DEVLINK_ATTR_RATE_NODE_NAME: u16 = 168;
pub const DEVLINK_ATTR_RATE_PARENT_NODE_NAME: u16 = 169;
pub const DEVLINK_ATTR_PORT_FUNCTION: u16 = 145;

// Attributes carried INSIDE the `DEVLINK_ATTR_PORT_FUNCTION` nest
// live in their own namespace, defined by
// `enum devlink_port_function_attr` in `include/uapi/linux/devlink.h`:
//
//   DEVLINK_PORT_FUNCTION_ATTR_UNSPEC   = 0,
//   DEVLINK_PORT_FUNCTION_ATTR_HW_ADDR  = 1,
//   DEVLINK_PORT_FN_ATTR_STATE          = 2,  // u8 — DEVLINK_PORT_FN_STATE_*
//   DEVLINK_PORT_FN_ATTR_OPSTATE        = 3,  // u8
//   DEVLINK_PORT_FN_ATTR_CAPS           = 4,  // bitfield32
//
// NOT to be confused with the outer-namespace attribute IDs.
pub const DEVLINK_PORT_FN_ATTR_STATE: u16 = 2;

// Rate types — `DEVLINK_RATE_TYPE_*` from devlink.h.
pub const DEVLINK_RATE_TYPE_LEAF: u16 = 0;
pub const DEVLINK_RATE_TYPE_NODE: u16 = 1;

// Port-function state — `DEVLINK_PORT_FN_STATE_*` from devlink.h.
pub const DEVLINK_PORT_FN_STATE_INACTIVE: u8 = 0;
pub const DEVLINK_PORT_FN_STATE_ACTIVE: u8 = 1;

/// Devlink multicast group name — matches the kernel's
/// `DEVLINK_GENL_MCGRP_CONFIG_NAME` (literally `"config"`) from
/// `include/uapi/linux/devlink.h`.
///
/// Pre-0.19 this was `"devlink"`, which is not a name the kernel
/// registers in its CTRL_ATTR_MCAST_GROUPS table. Every
/// `Connection::<Devlink>::subscribe()` call returned
/// a GENL-family-not-found error for `devlink::devlink` — the
/// documented devlink event API was entirely non-functional on
/// every kernel version. Plan 204 C4.
pub const DEVLINK_MCGRP_NAME: &str = "config";
