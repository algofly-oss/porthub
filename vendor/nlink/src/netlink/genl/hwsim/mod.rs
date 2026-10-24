//! `mac80211_hwsim`: simulated Wi-Fi radios, made and removed at run time
//! (#530).
//!
//! The `MAC80211_HWSIM` generic-netlink family creates and deletes radios
//! without reloading the module — `modprobe mac80211_hwsim radios=N`
//! fixes the count for the whole host, and changing it takes every other
//! user's radios down. A radio made over netlink belongs to the network
//! namespace of the socket that made it, and is seen only by radios of the
//! same netgroup — by default, the same namespace.
//!
//! **Unverified on a live kernel**: the machine this was written on has
//! no wireless stack. The command and attribute numbers come from the
//! driver's private header (`drivers/net/wireless/virtual/mac80211_hwsim.h`,
//! not in the UAPI, so the UAPI audit cannot check them) and are pinned by
//! unit tests.
//!
//! ```no_run
//! # async fn example() -> nlink::Result<()> {
//! use nlink::netlink::{Connection, Hwsim, Nl80211, Route};
//! use nlink::netlink::genl::hwsim::NewRadio;
//! use nlink::netlink::genl::nl80211::InterfaceType;
//!
//! let hwsim = Connection::<Hwsim>::new_async().await?;
//! let nl80211 = Connection::<Nl80211>::new_async().await?;
//! let route = Connection::<Route>::new()?;
//!
//! // A radio with no interface, then a mesh point on it.
//! let id = hwsim.new_radio(NewRadio::new().name("lab-r1").no_vif()).await?;
//! let phy = nl80211.get_phy_by_name("lab-r1").await?.expect("the radio's wiphy");
//! let mesh0 = nl80211.new_interface(phy.index, "mesh0", InterfaceType::MeshPoint).await?;
//! route.set_link_up_by_index(mesh0).await?;
//! nl80211.join_mesh_by_index(mesh0, b"lab", 2412).await?;
//!
//! for radio in hwsim.get_radios().await? {
//!     println!("{}: {:?}", radio.id, radio.name);
//! }
//! hwsim.del_radio(id).await?;
//! # Ok(())
//! # }
//! ```

mod connection;

pub use connection::{HwsimRadio, NewRadio};

/// The generic-netlink family name.
pub const HWSIM_GENL_NAME: &str = "MAC80211_HWSIM";

/// `HWSIM_CMD_NEW_RADIO`: create a radio; the ACK carries its id.
pub const HWSIM_CMD_NEW_RADIO: u8 = 4;
/// `HWSIM_CMD_DEL_RADIO`: delete a radio by id or name.
pub const HWSIM_CMD_DEL_RADIO: u8 = 5;
/// `HWSIM_CMD_GET_RADIO`: one radio, or all of them as a dump.
pub const HWSIM_CMD_GET_RADIO: u8 = 6;

/// `HWSIM_ATTR_CHANNELS`: concurrent channels (u32).
pub const HWSIM_ATTR_CHANNELS: u16 = 9;
/// `HWSIM_ATTR_RADIO_ID`: the radio's id (u32).
pub const HWSIM_ATTR_RADIO_ID: u16 = 10;
/// `HWSIM_ATTR_REG_HINT_ALPHA2`: a regulatory hint, two letters.
pub const HWSIM_ATTR_REG_HINT_ALPHA2: u16 = 11;
/// `HWSIM_ATTR_SUPPORT_P2P_DEVICE`: flag.
pub const HWSIM_ATTR_SUPPORT_P2P_DEVICE: u16 = 14;
/// `HWSIM_ATTR_USE_CHANCTX`: flag.
pub const HWSIM_ATTR_USE_CHANCTX: u16 = 15;
/// `HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE`: flag — the radio goes with the
/// socket that made it.
pub const HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE: u16 = 16;
/// `HWSIM_ATTR_RADIO_NAME`: the radio's name (its wiphy's).
pub const HWSIM_ATTR_RADIO_NAME: u16 = 17;
/// `HWSIM_ATTR_NO_VIF`: flag — no default interface.
pub const HWSIM_ATTR_NO_VIF: u16 = 18;
/// `HWSIM_ATTR_PERM_ADDR`: the radio's permanent MAC address.
pub const HWSIM_ATTR_PERM_ADDR: u16 = 22;
