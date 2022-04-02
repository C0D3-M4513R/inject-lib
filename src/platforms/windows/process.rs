use super::macros::{check_ptr, err};
use crate::Result;
use log::{debug, error, info, trace, warn};
use once_cell::sync::OnceCell;
use std::fmt::{Display, Formatter};
use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcess};
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
    wow: OnceCell<bool>,
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
    pub fn self_proc() -> &'static Self {
        static PRC: OnceCell<Process> = OnceCell::new();
        PRC.get_or_init(|| Process {
            proc: unsafe { GetCurrentProcess() as usize },
            pid: std::process::id(),
            perms: PROCESS_ALL_ACCESS,
            wow: Default::default(),
        })
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
        trace!("proc:{:#x},native:{:#x}", process_machine, native_machine);

        //The value will be IMAGE_FILE_MACHINE_UNKNOWN if the target process is not a WOW64 process; otherwise, it will identify the type of WoW process.
        Ok(process_machine != IMAGE_FILE_MACHINE_UNKNOWN)
    }
    ///Returns true, if the supplied process-handle is running under WOW, otherwise false.
    ///# Safety
    ///The process handle must have the PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION access right.
    pub fn unchecked_is_under_wow(&self) -> Result<bool> {
        self.wow
            .get_or_try_init(|| unsafe { self.unchecked_impl_is_under_wow() })
            .copied()
    }
    ///Returns true, if the supplied process-handle is running under WOW, otherwise false.
    pub fn is_under_wow(&self) -> Result<bool> {
        if self.has_perm(PROCESS_QUERY_INFORMATION)
            || self.has_perm(PROCESS_QUERY_LIMITED_INFORMATION)
        {
            self.unchecked_is_under_wow()
        } else {
            Err(crate::error::Error::from(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )))
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
        trace!("Cleaning Process Handle");
        if unsafe { CloseHandle(self.proc as HANDLE) } == FALSE {
            error!("Error during Process Handle cleanup!");
            err::<String>("CloseHandle of ".to_string() + std::stringify!($name));
        }
    }
}

impl Display for Process {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "(proc:{:x},pid: {},perms:{:x}, wow:{:#?})",
            self.proc as usize, self.pid, self.perms, self.wow
        )
    }
}

#[cfg(test)]
mod test {
    use winapi::um::winnt::PROCESS_ALL_ACCESS;

    #[test]
    fn new() {
        let r = super::Process::new(std::process::id(), PROCESS_ALL_ACCESS);
        assert!(r.is_ok(), "{}", r.unwrap_err());
    }

    #[test]
    fn has_perm() {
        assert!(super::Process::self_proc().has_perm(PROCESS_ALL_ACCESS))
    }
}
