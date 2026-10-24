//! TUN/TAP device implementation.

use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    mem::MaybeUninit,
    os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
};

use super::{
    TUN_DEVICE_PATH,
    error::{Error, Result},
};

// TUN/TAP ioctl constants
const TUNSETIFF: libc::c_ulong = 0x400454ca;
const TUNSETOWNER: libc::c_ulong = 0x400454cc;
const TUNSETGROUP: libc::c_ulong = 0x400454ce;
const TUNSETPERSIST: libc::c_ulong = 0x400454cb;
const TUNSETOFFLOAD: libc::c_ulong = 0x400454d0;
const TUNSETVNETHDRSZ: libc::c_ulong = 0x400454d8;

// TUN/TAP flags (from linux/if_tun.h)
/// TUN device (Layer 3).
const IFF_TUN: libc::c_short = 0x0001;
/// TAP device (Layer 2).
const IFF_TAP: libc::c_short = 0x0002;
/// No protocol information.
const IFF_NO_PI: libc::c_short = 0x1000;
/// Single queue.
const IFF_ONE_QUEUE: libc::c_short = 0x2000;
/// VNET header support.
const IFF_VNET_HDR: libc::c_short = 0x4000;
/// Multi-queue support.
const IFF_MULTI_QUEUE: libc::c_short = 0x0100;
/// Exclusive open (prevent re-open).
#[allow(dead_code)]
const IFF_TUN_EXCL: libc::c_short = -0x8000; // 0x8000 as signed

/// Device mode (TUN or TAP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// TUN device - operates at Layer 3 (IP packets).
    Tun,
    /// TAP device - operates at Layer 2 (Ethernet frames).
    Tap,
}

impl Mode {
    /// Get the ifreq flag for this mode.
    fn flag(&self) -> libc::c_short {
        match self {
            Mode::Tun => IFF_TUN,
            Mode::Tap => IFF_TAP,
        }
    }

    /// Get the mode name.
    pub fn name(&self) -> &'static str {
        match self {
            Mode::Tun => "tun",
            Mode::Tap => "tap",
        }
    }
}

/// Additional flags for TUN/TAP devices.
#[derive(Debug, Clone, Copy, Default)]
pub struct TunTapFlags {
    /// Don't include protocol info header.
    pub no_pi: bool,
    /// Use single queue (for backwards compatibility).
    pub one_queue: bool,
    /// Enable VNET header for virtio compatibility.
    pub vnet_hdr: bool,
    /// Enable multi-queue support.
    pub multi_queue: bool,
}

impl TunTapFlags {
    /// Create a new flags builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the no_pi flag (don't include protocol info).
    pub fn no_pi(mut self, value: bool) -> Self {
        self.no_pi = value;
        self
    }

    /// Set the one_queue flag.
    pub fn one_queue(mut self, value: bool) -> Self {
        self.one_queue = value;
        self
    }

    /// Set the vnet_hdr flag.
    pub fn vnet_hdr(mut self, value: bool) -> Self {
        self.vnet_hdr = value;
        self
    }

    /// Set the multi_queue flag.
    pub fn multi_queue(mut self, value: bool) -> Self {
        self.multi_queue = value;
        self
    }

    /// Convert to ifreq flags.
    fn as_flags(&self) -> libc::c_short {
        let mut flags: libc::c_short = 0;
        if self.no_pi {
            flags |= IFF_NO_PI;
        }
        if self.one_queue {
            flags |= IFF_ONE_QUEUE;
        }
        if self.vnet_hdr {
            flags |= IFF_VNET_HDR;
        }
        if self.multi_queue {
            flags |= IFF_MULTI_QUEUE;
        }
        flags
    }
}

/// Builder for creating TUN/TAP devices.
#[derive(Debug, Clone)]
pub struct TunTapBuilder {
    name: Option<String>,
    mode: Option<Mode>,
    owner: Option<u32>,
    group: Option<u32>,
    persistent: bool,
    flags: TunTapFlags,
}

impl TunTapBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            name: None,
            mode: None,
            owner: None,
            group: None,
            persistent: false,
            flags: TunTapFlags {
                no_pi: true, // Default to no protocol info
                ..Default::default()
            },
        }
    }

    /// Set the device name.
    ///
    /// If not specified, the kernel will assign a name (tun0, tap0, etc.).
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the device mode (TUN or TAP).
    pub fn mode(mut self, mode: Mode) -> Self {
        self.mode = Some(mode);
        self
    }

    /// Set the owner UID.
    pub fn owner(mut self, uid: u32) -> Self {
        self.owner = Some(uid);
        self
    }

    /// Set the owner by username.
    pub fn owner_name(mut self, name: &str) -> Result<Self> {
        let uid = lookup_user(name)?;
        self.owner = Some(uid);
        Ok(self)
    }

    /// Set the group GID.
    pub fn group(mut self, gid: u32) -> Self {
        self.group = Some(gid);
        self
    }

    /// Set the group by name.
    pub fn group_name(mut self, name: &str) -> Result<Self> {
        let gid = lookup_group(name)?;
        self.group = Some(gid);
        Ok(self)
    }

    /// Make the device persistent (survives close).
    pub fn persistent(mut self, persistent: bool) -> Self {
        self.persistent = persistent;
        self
    }

    /// Don't include protocol info header.
    pub fn no_pi(mut self, value: bool) -> Self {
        self.flags.no_pi = value;
        self
    }

    /// Use single queue (for backwards compatibility).
    pub fn one_queue(mut self, value: bool) -> Self {
        self.flags.one_queue = value;
        self
    }

    /// Enable VNET header for virtio compatibility.
    pub fn vnet_hdr(mut self, value: bool) -> Self {
        self.flags.vnet_hdr = value;
        self
    }

    /// Enable multi-queue support.
    pub fn multi_queue(mut self, value: bool) -> Self {
        self.flags.multi_queue = value;
        self
    }

    /// Set additional flags.
    pub fn flags(mut self, flags: TunTapFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Create the TUN/TAP device.
    pub fn create(self) -> Result<TunTap> {
        let mode = self.mode.ok_or(Error::NoModeSpecified)?;

        // Validate name length
        if let Some(ref name) = self.name
            && name.len() > libc::IFNAMSIZ - 1
        {
            return Err(Error::NameTooLong {
                name: name.clone(),
                len: name.len(),
            });
        }

        // Open the TUN device
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(TUN_DEVICE_PATH)?;

        let fd = file.as_raw_fd();

        // Build ifreq
        // SAFETY: ifreq is a C struct that is safe to zero-initialize.
        // All fields are primitive integers, arrays, or unions of such types.
        let mut ifr = {
            let uninit = MaybeUninit::<libc::ifreq>::zeroed();
            // SAFETY: zeroed is valid for ifreq
            unsafe { uninit.assume_init() }
        };
        ifr.ifr_ifru.ifru_flags = mode.flag() | self.flags.as_flags();

        // Set name if provided
        if let Some(ref name) = self.name {
            let name_bytes = name.as_bytes();
            // SAFETY: ifr_name is a [c_char; IFNAMSIZ] array. Casting to [u8] is safe
            // because c_char and u8 have the same size and alignment on Linux.
            let name_slice =
                unsafe { &mut *(&mut ifr.ifr_name as *mut [libc::c_char] as *mut [u8]) };
            name_slice[..name_bytes.len()].copy_from_slice(name_bytes);
        }

        // Create the interface
        // SAFETY: libc::ioctl with TUNSETIFF is the standard way to create TUN/TAP
        // devices. fd is a valid file descriptor from opening /dev/net/tun, and
        // ifr is a properly initialized ifreq struct.
        let ret = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
        if ret < 0 {
            return Err(Error::ioctl("TUNSETIFF", io::Error::last_os_error()));
        }

        // Set owner if specified
        if let Some(uid) = self.owner {
            // SAFETY: TUNSETOWNER ioctl sets the owner UID of the TUN/TAP device.
            // fd is valid and uid is a valid user ID.
            let ret = unsafe { libc::ioctl(fd, TUNSETOWNER, uid as libc::c_ulong) };
            if ret < 0 {
                return Err(Error::ioctl("TUNSETOWNER", io::Error::last_os_error()));
            }
        }

        // Set group if specified
        if let Some(gid) = self.group {
            // SAFETY: TUNSETGROUP ioctl sets the group GID of the TUN/TAP device.
            // fd is valid and gid is a valid group ID.
            let ret = unsafe { libc::ioctl(fd, TUNSETGROUP, gid as libc::c_ulong) };
            if ret < 0 {
                return Err(Error::ioctl("TUNSETGROUP", io::Error::last_os_error()));
            }
        }

        // Set persistent if requested
        if self.persistent {
            // SAFETY: TUNSETPERSIST ioctl sets the persistent flag on the device.
            // fd is valid, 1 enables persistence.
            let ret = unsafe { libc::ioctl(fd, TUNSETPERSIST, 1 as libc::c_int) };
            if ret < 0 {
                return Err(Error::ioctl("TUNSETPERSIST", io::Error::last_os_error()));
            }
        }

        // Get the actual interface name
        // SAFETY: After TUNSETIFF, the kernel writes the actual interface name
        // back to ifr_name. Casting to [u8] is safe (same size/alignment).
        let name = unsafe {
            let name_slice = &*(&ifr.ifr_name as *const [libc::c_char] as *const [u8]);
            let len = name_slice
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(name_slice.len());
            String::from_utf8_lossy(&name_slice[..len]).to_string()
        };

        Ok(TunTap {
            file,
            name,
            mode,
            persistent: self.persistent,
        })
    }

    /// Create the TUN/TAP device without keeping it open.
    ///
    /// This is useful for creating persistent devices that will be
    /// managed separately.
    pub fn create_persistent(self) -> Result<String> {
        let device = self.persistent(true).create()?;
        let name = device.name.clone();
        // Device will be closed but remains persistent
        Ok(name)
    }
}

impl Default for TunTapBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A TUN/TAP device.
pub struct TunTap {
    file: File,
    name: String,
    mode: Mode,
    persistent: bool,
}

impl TunTap {
    /// Create a new builder.
    pub fn builder() -> TunTapBuilder {
        TunTapBuilder::new()
    }

    /// Get the device name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the device mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Check if the device is persistent.
    pub fn is_persistent(&self) -> bool {
        self.persistent
    }

    /// Get the raw file descriptor.
    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    /// Set the VNET header size (for VNET_HDR mode).
    pub fn set_vnet_hdr_size(&self, size: i32) -> Result<()> {
        // SAFETY: TUNSETVNETHDRSZ ioctl sets the VNET header size.
        // The fd is valid (owned by self.file) and size is a valid i32.
        let ret = unsafe { libc::ioctl(self.file.as_raw_fd(), TUNSETVNETHDRSZ, &size) };
        if ret < 0 {
            return Err(Error::ioctl("TUNSETVNETHDRSZ", io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Set offload flags.
    pub fn set_offload(&self, flags: u32) -> Result<()> {
        // SAFETY: TUNSETOFFLOAD ioctl sets offload flags on the device.
        // The fd is valid and flags is a valid bitmask.
        let ret =
            unsafe { libc::ioctl(self.file.as_raw_fd(), TUNSETOFFLOAD, flags as libc::c_ulong) };
        if ret < 0 {
            return Err(Error::ioctl("TUNSETOFFLOAD", io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Make the device persistent.
    pub fn set_persistent(&mut self, persistent: bool) -> Result<()> {
        let value = if persistent { 1 } else { 0 };
        // SAFETY: TUNSETPERSIST ioctl sets the persistent flag.
        // The fd is valid and value is 0 or 1.
        let ret =
            unsafe { libc::ioctl(self.file.as_raw_fd(), TUNSETPERSIST, value as libc::c_int) };
        if ret < 0 {
            return Err(Error::ioctl("TUNSETPERSIST", io::Error::last_os_error()));
        }
        self.persistent = persistent;
        Ok(())
    }

    /// Delete a persistent device.
    pub fn delete(self) -> Result<()> {
        // SAFETY: TUNSETPERSIST with 0 clears the persistent flag, causing
        // the device to be deleted when closed. The fd is valid.
        let ret = unsafe { libc::ioctl(self.file.as_raw_fd(), TUNSETPERSIST, 0 as libc::c_int) };
        if ret < 0 {
            return Err(Error::ioctl("TUNSETPERSIST", io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Delete a persistent device by name.
    pub fn delete_by_name(name: &str, mode: Mode) -> Result<()> {
        let device = TunTapBuilder::new()
            .name(name)
            .mode(mode)
            .no_pi(true)
            .create()?;
        device.delete()
    }

    /// Read a packet from the device.
    pub fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }

    /// Write a packet to the device.
    pub fn write_packet(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    /// Take ownership of the underlying file.
    pub fn into_file(self) -> File {
        self.file
    }

    /// Get a reference to the underlying file.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Get a mutable reference to the underlying file.
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
}

impl Read for TunTap {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for TunTap {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl AsRawFd for TunTap {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl std::os::fd::AsFd for TunTap {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.file.as_fd()
    }
}

impl IntoRawFd for TunTap {
    fn into_raw_fd(self) -> RawFd {
        self.file.into_raw_fd()
    }
}

impl FromRawFd for TunTap {
    /// Create a TunTap from a raw file descriptor.
    ///
    /// # Safety
    ///
    /// The file descriptor must be a valid TUN/TAP device.
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        TunTap {
            // SAFETY: Caller guarantees fd is a valid TUN/TAP device fd.
            file: unsafe { File::from_raw_fd(fd) },
            name: String::new(), // Unknown
            mode: Mode::Tun,     // Unknown
            persistent: false,
        }
    }
}

/// Look up a user by name and return the UID.
fn lookup_user(name: &str) -> Result<u32> {
    let name_cstr = CString::new(name).map_err(|_| Error::InvalidName(name.to_string()))?;

    // SAFETY: libc::getpwnam is a standard POSIX function. name_cstr.as_ptr()
    // returns a valid null-terminated C string. The returned pointer is valid
    // until the next getpwnam/getpwuid call (we read it immediately).
    unsafe {
        let pwd = libc::getpwnam(name_cstr.as_ptr());
        if pwd.is_null() {
            return Err(Error::UserNotFound(name.to_string()));
        }
        Ok((*pwd).pw_uid)
    }
}

/// Look up a group by name and return the GID.
fn lookup_group(name: &str) -> Result<u32> {
    let name_cstr = CString::new(name).map_err(|_| Error::InvalidName(name.to_string()))?;

    // SAFETY: libc::getgrnam is a standard POSIX function. name_cstr.as_ptr()
    // returns a valid null-terminated C string. The returned pointer is valid
    // until the next getgrnam/getgrgid call (we read it immediately).
    unsafe {
        let grp = libc::getgrnam(name_cstr.as_ptr());
        if grp.is_null() {
            return Err(Error::GroupNotFound(name.to_string()));
        }
        Ok((*grp).gr_gid)
    }
}

/// List existing TUN/TAP devices.
///
/// This reads from /sys/class/net to find devices with the tun driver.
pub fn list_devices() -> Result<Vec<TunTapInfo>> {
    let mut devices = Vec::new();

    let dir = match std::fs::read_dir("/sys/class/net") {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(devices),
        Err(e) => return Err(e.into()),
    };

    for entry in dir {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();

        // Check if this is a tun/tap device
        let tun_flags_path = entry.path().join("tun_flags");
        if tun_flags_path.exists() {
            let flags_str = std::fs::read_to_string(&tun_flags_path)?;
            let flags: u32 = flags_str.trim().parse().unwrap_or(0);

            let mode = if flags & (IFF_TUN as u32) != 0 {
                Mode::Tun
            } else if flags & (IFF_TAP as u32) != 0 {
                Mode::Tap
            } else {
                continue;
            };

            // Get owner/group from /sys/class/net/<dev>/owner and /sys/class/net/<dev>/group
            let owner = std::fs::read_to_string(entry.path().join("owner"))
                .ok()
                .and_then(|s| s.trim().parse().ok());

            let group = std::fs::read_to_string(entry.path().join("group"))
                .ok()
                .and_then(|s| s.trim().parse().ok());

            devices.push(TunTapInfo {
                name,
                mode,
                owner,
                group,
                flags,
            });
        }
    }

    Ok(devices)
}

/// Information about a TUN/TAP device.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TunTapInfo {
    /// Device name.
    pub name: String,
    /// Device mode.
    pub mode: Mode,
    /// Owner UID.
    pub owner: Option<u32>,
    /// Group GID.
    pub group: Option<u32>,
    /// Device flags.
    pub flags: u32,
}

#[allow(dead_code)]
impl TunTapInfo {
    /// Check if the device has no protocol info.
    pub fn no_pi(&self) -> bool {
        self.flags & (IFF_NO_PI as u32) != 0
    }

    /// Check if the device has VNET header support.
    pub fn vnet_hdr(&self) -> bool {
        self.flags & (IFF_VNET_HDR as u32) != 0
    }

    /// Check if the device has multi-queue support.
    pub fn multi_queue(&self) -> bool {
        self.flags & (IFF_MULTI_QUEUE as u32) != 0
    }
}
