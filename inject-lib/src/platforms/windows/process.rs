use super::macros::{check_ptr, err};
use crate::Result;
use core::fmt::{Display, Formatter};
use once_cell::race::OnceBool;
use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::{GetCurrentProcess, GetCurrentProcessId, OpenProcess};
use winapi::um::winnt::{
    HANDLE, IMAGE_FILE_MACHINE_UNKNOWN, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use winapi::um::wow64apiset::IsWow64Process2;

///Represents a Process.
///Holds various information about the open Process handle, to ensure better function performance.
#[derive(Debug)]
pub struct Process {
    //I save this as usize rather than Handle, because usize is sync.
    proc: usize,
    pid: u32,
    perms: DWORD,
    wow: OnceBool,
}
impl Process {
    pub fn new(pid: u32, perms: DWORD) -> Result<Self> {
        let proc = check_ptr!(OpenProcess(perms, FALSE, pid)) as usize;
        Ok(Self {
            proc,
            pid,
            perms,
            wow: Default::default(),
        })
    }
    ///Creates a process from raw parts
    #[cfg(test)]
    pub(in super::super) unsafe fn from_raw_parts(proc: usize, pid: u32, perms: DWORD) -> Self {
        Self {
            proc,
            pid,
            perms,
            wow: Default::default(),
        }
    }
    ///Constructs a Process, using a pseudo-handle.
    ///That is a special type of handle. It does not actually exists, but just works. (except in ntdll)
    pub fn self_proc() -> Self {
        Process {
            proc: unsafe { GetCurrentProcess() as usize },
            pid: unsafe {GetCurrentProcessId()},
            perms: PROCESS_ALL_ACCESS,
            wow: Default::default(),
        }
    }
    ///Checks, if this process has real handle
    #[must_use]
    #[cfg_attr(not(any(feature = "ntdll", test)), allow(unused))]
    pub fn has_real_handle(&self) -> bool {
        self.get_proc() != unsafe { GetCurrentProcess() }
    }
    ///Returns Error::IO:(ErrorKind::InvalidInput), if the process is ![has_real_handle]
    #[must_use]
    #[cfg_attr(not(feature = "ntdll"), allow(unused))]
    pub fn err_pseudo_handle(&self) -> Result<()> {
        if !self.has_real_handle() {
            return Err(crate::error::CustomError::InvalidInput.into());
        }
        Ok(())
    }
    ///Returns true, if the supplied process-handle is running under WOW, otherwise false.
    ///# Safety
    ///The process handle must have the PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION access right.
    unsafe fn unchecked_impl_is_under_wow(&self) -> Result<bool> {
        let mut process_machine: u16 = 0;
        let mut native_machine: u16 = 0;
        if IsWow64Process2(
            self.proc as HANDLE,
            &mut process_machine as *mut u16,
            &mut native_machine as *mut u16,
        ) == FALSE
        {
            return Err(err("IsWow64Process2 number 1"));
        }
        crate::trace!("proc:{:#x},native:{:#x}", process_machine, native_machine);

        //The value will be IMAGE_FILE_MACHINE_UNKNOWN if the target process is not a WOW64 process; otherwise, it will identify the type of WoW process.
        Ok(process_machine != IMAGE_FILE_MACHINE_UNKNOWN)
    }
    ///Returns true, if the supplied process-handle is running under WOW, otherwise false.
    ///# Safety
    ///The process handle must have the PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION access right.
    pub fn unchecked_is_under_wow(&self) -> Result<bool> {
        self.wow
            .get_or_try_init(|| unsafe { self.unchecked_impl_is_under_wow() })
    }
    ///Returns true, if the supplied process-handle is running under WOW, otherwise false.
    #[must_use]
    //todo: where can we replace Self::self_proc().is_under_wow() with cfg statements? where is it useful?
    pub fn is_under_wow(&self) -> Result<bool> {
        if self.has_perm(PROCESS_QUERY_INFORMATION)
            || self.has_perm(PROCESS_QUERY_LIMITED_INFORMATION)
        {
            self.unchecked_is_under_wow()
        } else {
            Err(crate::error::CustomError::PermissionDenied.into())
        }
    }
    ///Get the contained process Handle
    #[must_use]
    pub fn get_proc(&self) -> HANDLE {
        self.proc as HANDLE
    }
    ///Get the pid, the process Handle represents
    #[must_use]
    pub fn get_pid(&self) -> u32 {
        self.pid
    }
    ///Checks if the process handle has a specific permission.
    #[must_use]
    pub fn has_perm(&self, perm: DWORD) -> bool {
        return self.perms & perm == perm;
    }
}

impl Drop for Process {
    ///Closes the Process Handle properly
    fn drop(&mut self) {
        crate::trace!("Cleaning Process Handle");
        if unsafe { CloseHandle(self.proc as HANDLE) } == FALSE {
            crate::error!("Error during Process Handle cleanup!");
            err("CloseHandle of OpenProcess");
        }
    }
}

impl Display for Process {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "(proc:{:x},pid: {},perms:{:x}, wow:{:#?})",
            self.proc as usize, self.pid, self.perms, self.wow
        )
    }
}

#[cfg(test)]
mod test {
    use crate::Result;
    use winapi::um::winnt::PROCESS_ALL_ACCESS;

    #[test]
    fn new() {
        let r = super::Process::new(std::process::id(), PROCESS_ALL_ACCESS);
        assert!(r.is_ok(), "{}", r.unwrap_err());
    }
    #[test]
    fn has_real_handle() -> Result<()> {
        assert!(!super::Process::self_proc().has_real_handle());
        assert!(super::Process::new(std::process::id(), PROCESS_ALL_ACCESS)?.has_real_handle());
        Ok(())
    }
    #[test]
    fn has_perm() {
        assert!(super::Process::self_proc().has_perm(PROCESS_ALL_ACCESS))
    }
}
