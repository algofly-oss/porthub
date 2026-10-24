//! The cgroup half of `ip vrf exec` (#257): a `BPF_PROG_TYPE_CGROUP_SOCK`
//! program, attached to a cgroup v2 directory at
//! `BPF_CGROUP_INET_SOCK_CREATE`, that binds every inet socket a process in
//! the cgroup creates to one device — the VRF's ifindex — as iproute2's
//! `ip vrf exec` does. [`NetnsCommand::vrf`](super::NetnsCommand::vrf) is
//! the way in.

use std::{
    ffi::CString,
    fs::File,
    os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    path::{Path, PathBuf},
};

use crate::netlink::error::{Error, Result};

/// `BPF_PROG_LOAD`, `BPF_PROG_ATTACH` (`enum bpf_cmd`).
const BPF_PROG_LOAD: libc::c_long = 5;
const BPF_PROG_ATTACH: libc::c_long = 8;
/// `BPF_PROG_TYPE_CGROUP_SOCK` (`enum bpf_prog_type`).
const BPF_PROG_TYPE_CGROUP_SOCK: u32 = 9;
/// `BPF_CGROUP_INET_SOCK_CREATE` (`enum bpf_attach_type`).
const BPF_CGROUP_INET_SOCK_CREATE: u32 = 2;

/// `union bpf_attr`'s `BPF_PROG_LOAD` member, as far as it is used. The
/// kernel requires every byte past the last field given to be zero, and
/// takes `expected_attach_type` 0 for a cgroup sock program as
/// `BPF_CGROUP_INET_SOCK_CREATE`.
#[repr(C)]
struct ProgLoad {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
}

/// `union bpf_attr`'s `BPF_PROG_ATTACH` member.
#[repr(C)]
struct ProgAttach {
    target_fd: u32,
    attach_bpf_fd: u32,
    attach_type: u32,
    attach_flags: u32,
    replace_bpf_fd: u32,
}

fn bpf<T>(cmd: libc::c_long, attr: &T) -> std::io::Result<i64> {
    // SAFETY: `attr` is a fully initialized `bpf_attr` prefix of the size
    // passed, and every pointer in it outlives the call.
    let ret = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr as *const T, std::mem::size_of::<T>()) };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // PortHub: libc::c_long is 32 bits on i686 and ARM32 Linux.
        Ok(ret as i64)
    }
}

/// One `struct bpf_insn`: opcode, `dst | src << 4` (the register nibbles
/// in a little-endian byte), offset and immediate.
fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let regs = if cfg!(target_endian = "little") {
        dst | (src << 4)
    } else {
        (dst << 4) | src
    };
    let mut out = [0u8; 8];
    out[0] = code;
    out[1] = regs;
    out[2..4].copy_from_slice(&off.to_ne_bytes());
    out[4..8].copy_from_slice(&imm.to_ne_bytes());
    out
}

/// The program iproute2 loads (`ip/ipvrf.c`): `sk->bound_dev_if =
/// ifindex; return 1`. `bound_dev_if` is the first field of `struct
/// bpf_sock`.
pub(crate) fn program(ifindex: u32) -> [[u8; 8]; 6] {
    const MOV64_REG: u8 = 0xbf; // BPF_ALU64 | BPF_MOV | BPF_X
    const MOV64_IMM: u8 = 0xb7; // BPF_ALU64 | BPF_MOV | BPF_K
    const STX_MEM_W: u8 = 0x63; // BPF_STX | BPF_W | BPF_MEM
    const EXIT: u8 = 0x95; // BPF_JMP | BPF_EXIT
    [
        insn(MOV64_REG, 6, 1, 0, 0),
        insn(MOV64_IMM, 3, 0, 0, ifindex as i32),
        insn(MOV64_IMM, 2, 0, 0, 0),
        insn(STX_MEM_W, 1, 3, 0, 0),
        insn(MOV64_IMM, 0, 0, 0, 1),
        insn(EXIT, 0, 0, 0, 0),
    ]
}

/// Load the program for `ifindex`.
fn load(ifindex: u32) -> Result<OwnedFd> {
    let insns = program(ifindex);
    let license = c"GPL";
    let attr = ProgLoad {
        prog_type: BPF_PROG_TYPE_CGROUP_SOCK,
        insn_cnt: insns.len() as u32,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 0,
        log_size: 0,
        log_buf: 0,
        kern_version: 0,
        prog_flags: 0,
    };
    let fd = bpf(BPF_PROG_LOAD, &attr)
        .map_err(|e| Error::from(e).with_context("vrf exec: load the socket-binding program"))?;
    // SAFETY: the kernel just returned this fd, and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// Bind every inet socket created by a process in the cgroup `dir` to
/// `ifindex`: load the program and attach it. An attach replaces the
/// program a previous one left (no `BPF_F_ALLOW_MULTI`), so doing this
/// again is harmless; the attachment keeps the program once its fd closes.
pub(crate) fn bind_sockets(dir: &Path, ifindex: u32) -> Result<()> {
    let prog = load(ifindex)?;
    let cgroup = File::open(dir)
        .map_err(|e| Error::from(e).with_context(format!("vrf exec: open cgroup {}", dir.display())))?;
    let attr = ProgAttach {
        target_fd: cgroup.as_raw_fd() as u32,
        attach_bpf_fd: prog.as_raw_fd() as u32,
        attach_type: BPF_CGROUP_INET_SOCK_CREATE,
        attach_flags: 0,
        replace_bpf_fd: 0,
    };
    bpf(BPF_PROG_ATTACH, &attr).map_err(|e| {
        Error::from(e).with_context(format!("vrf exec: attach to cgroup {}", dir.display()))
    })?;
    Ok(())
}

/// The ifindex of `name` in the namespace `ns`, asked from a thread that
/// has entered it (`if_nametoindex` opens its socket in the caller's
/// namespace).
pub(crate) fn ifindex_in(ns: BorrowedFd<'_>, name: &str) -> Result<u32> {
    let ns = ns
        .try_clone_to_owned()
        .map_err(|e| Error::from(e).with_context("vrf exec: duplicate the namespace fd"))?;
    let name = CString::new(name).map_err(|_| Error::invalid_message("null byte in a VRF name"))?;
    let shown = name.to_string_lossy().into_owned();
    let index = std::thread::spawn(move || -> std::io::Result<u32> {
        // Leave again before the thread ends (#797): see `ReturnHome`.
        let _home = super::ReturnHome::new();
        // SAFETY: `ns` is an open nsfs fd; the thread is ours.
        if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `name` is a valid C string.
        match unsafe { libc::if_nametoindex(name.as_ptr()) } {
            0 => Err(std::io::Error::last_os_error()),
            index => Ok(index),
        }
    })
    .join()
    .map_err(|_| Error::invalid_message("vrf exec: the lookup thread panicked"))?;
    index.map_err(|e| Error::from(e).with_context(format!("vrf exec: device {shown}")))
}

/// The cgroup a VRF's processes go in by default: `vrf/<netns
/// inode>/<name>` under this process's own cgroup, as iproute2 puts it under
/// `vrf/<name>`. The namespace is part of the path: the program bakes in
/// the ifindex, and two namespaces each with a `red` VRF would replace
/// each other's.
pub(crate) fn default_cgroup(ns: BorrowedFd<'_>, name: &str) -> Result<PathBuf> {
    let dir = cgroup_path(ns, name)?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| Error::from(e).with_context(format!("vrf exec: create cgroup {}", dir.display())))?;
    Ok(dir)
}

/// Where [`default_cgroup`] puts the VRF `name` of the namespace `ns`.
fn cgroup_path(ns: BorrowedFd<'_>, name: &str) -> Result<PathBuf> {
    let mount = cgroup2_mount()?;
    let own = own_cgroup()?;
    let inode = File::from(
        ns.try_clone_to_owned()
            .map_err(|e| Error::from(e).with_context("vrf exec: duplicate the namespace fd"))?,
    )
    .metadata()
    .map_err(|e| Error::from(e).with_context("vrf exec: stat the namespace"))?;
    Ok(mount
        .join(own.trim_start_matches('/'))
        .join("vrf")
        .join(std::os::unix::fs::MetadataExt::ino(&inode).to_string())
        .join(name))
}

/// The cgroup [`NetnsCommand::vrf`](super::NetnsCommand::vrf) puts the
/// processes it runs in the VRF `name` of this process's namespace in by
/// default, if one has been made (#257): what `ip vrf pids` lists.
pub fn vrf_cgroup(name: &str) -> Result<Option<PathBuf>> {
    let ns = File::open("/proc/self/ns/net")
        .map_err(|e| Error::from(e).with_context("vrf exec: open /proc/self/ns/net"))?;
    use std::os::fd::AsFd;
    let dir = cgroup_path(ns.as_fd(), name)?;
    Ok(dir.is_dir().then_some(dir))
}

/// Where cgroup v2 is mounted, from `/proc/self/mountinfo`.
fn cgroup2_mount() -> Result<PathBuf> {
    let info = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|e| Error::from(e).with_context("vrf exec: read /proc/self/mountinfo"))?;
    info.lines()
        .find_map(|line| {
            let (mount, rest) = line.split_once(" - ")?;
            (rest.split_whitespace().next()? == "cgroup2")
                .then(|| mount.split_whitespace().nth(4).map(PathBuf::from))
                .flatten()
        })
        .ok_or_else(|| Error::not_supported("vrf exec: cgroup v2 is not mounted"))
}

/// This process's cgroup v2 path, from `/proc/self/cgroup` (`0::<path>`).
fn own_cgroup() -> Result<String> {
    let cgroups = std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|e| Error::from(e).with_context("vrf exec: read /proc/self/cgroup"))?;
    cgroups
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(str::to_string))
        .ok_or_else(|| Error::not_supported("vrf exec: this process is in no cgroup v2"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The instructions `ip/ipvrf.c` writes (`BPF_MOV64_REG(6, 1)`,
    /// `BPF_MOV64_IMM(3, idx)`, `BPF_MOV64_IMM(2, 0)`, `BPF_STX_MEM(BPF_W,
    /// 1, 3, 0)`, `BPF_MOV64_IMM(0, 1)`, `BPF_EXIT_INSN()`), as a
    /// little-endian host encodes them.
    #[test]
    #[cfg(target_endian = "little")]
    fn the_program_is_iproute2s() {
        let p = program(7);
        assert_eq!(p[0], [0xbf, 0x16, 0, 0, 0, 0, 0, 0]); // r6 = r1
        assert_eq!(p[1], [0xb7, 0x03, 0, 0, 7, 0, 0, 0]); // r3 = 7
        assert_eq!(p[2], [0xb7, 0x02, 0, 0, 0, 0, 0, 0]); // r2 = 0
        assert_eq!(p[3], [0x63, 0x31, 0, 0, 0, 0, 0, 0]); // *(u32 *)(r1 + 0) = r3
        assert_eq!(p[4], [0xb7, 0x00, 0, 0, 1, 0, 0, 0]); // r0 = 1
        assert_eq!(p[5], [0x95, 0, 0, 0, 0, 0, 0, 0]); // exit
    }
}
