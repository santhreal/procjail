//! Raw-syscall helpers for seccomp integration tests when libc omits wrappers.

#![allow(dead_code)]

#[cfg(target_os = "linux")]
pub(crate) const SECCOMP_DATA_NR_OFFSET: u32 = 0;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) const SYS_NICE: libc::c_long = 34;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) const SYS_STIME: libc::c_long = 159;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) const ARCH_GET_FS: libc::c_ulong = 0x1003;

/// Linux capability bit for `CAP_CHOWN` (used in prctl ambient-cap tests).
#[cfg(target_os = "linux")]
pub(crate) const CAP_CHOWN: u32 = 0;

#[cfg(target_os = "linux")]
pub(crate) const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[cfg(target_os = "linux")]
#[repr(C)]
pub(crate) struct CapUserHeader {
    pub version: u32,
    pub pid: i32,
}

#[cfg(target_os = "linux")]
#[derive(Copy, Clone)]
#[repr(C)]
pub(crate) struct CapUserData {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}

#[cfg(target_os = "linux")]
pub(crate) unsafe fn syscall_eventfd2(initval: u32, flags: libc::c_int) -> libc::c_int {
    libc::syscall(libc::SYS_eventfd2, initval, flags) as libc::c_int
}

#[cfg(target_os = "linux")]
pub(crate) unsafe fn syscall_signalfd4(
    fd: libc::c_int,
    mask: *const libc::sigset_t,
    mask_size: libc::size_t,
    flags: libc::c_int,
) -> libc::c_int {
    libc::syscall(libc::SYS_signalfd4, fd, mask, mask_size, flags) as libc::c_int
}

#[cfg(target_os = "linux")]
pub(crate) unsafe fn syscall_exit_group(status: libc::c_int) -> ! {
    libc::syscall(libc::SYS_exit_group, status);
    unreachable!("exit_group does not return")
}

#[cfg(target_os = "linux")]
pub(crate) unsafe fn syscall_set_tid_address(tid: *mut libc::c_int) -> *mut libc::c_int {
    libc::syscall(libc::SYS_set_tid_address, tid) as *mut libc::c_int
}

#[cfg(target_os = "linux")]
pub(crate) unsafe fn syscall_capget(
    hdr: *mut CapUserHeader,
    data: *mut CapUserData,
) -> libc::c_int {
    libc::syscall(libc::SYS_capget, hdr, data) as libc::c_int
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) unsafe fn syscall_arch_prctl(code: libc::c_ulong, addr: *mut libc::c_void) -> libc::c_int {
    libc::syscall(libc::SYS_arch_prctl, code, addr) as libc::c_int
}
