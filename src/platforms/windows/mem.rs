use crate::Result;
use std::fmt::{Display, Formatter};
use winapi::shared::minwindef::{FALSE, LPCVOID, LPVOID};

use crate::platforms::platform::macros::{err, void_res};
use crate::platforms::platform::process::Process;
use log::{debug, error, info, trace, warn};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory};
use winapi::um::winnt::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
    PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
};

#[derive(Debug)]
pub struct MemPage<'a> {
    proc: &'a Process,
    addr: LPVOID,
    size: usize,
    exec: bool,
}
impl<'a> MemPage<'a> {
    ///Create a new MemoryPage.
    ///exec specifies, if the contents of the MemoryPage should be able to be executed or not.
    pub fn new(proc: &'a Process, size: usize, exec: bool) -> Result<Self> {
        //https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
        if !proc.has_perm(PROCESS_VM_OPERATION) {
            return Err(crate::error::Error::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )));
        }
        let addr = unsafe {
            VirtualAllocEx(
                proc.get_proc(),
                std::ptr::null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                if exec {
                    PAGE_EXECUTE_READWRITE
                } else {
                    PAGE_READWRITE
                },
            )
        };
        if addr.is_null() {
            return Err(err(format!(
                "VirtualAllocEx failed to allocate {}{} bytes on process {:x}",
                size,
                if exec { " executable" } else { "" },
                proc.get_proc() as usize
            )));
        }
        Ok(MemPage {
            proc,
            addr,
            size,
            exec,
        })
    }
    ///Writes the buffer to the allocated memory page.
    ///
    ///# Panic
    /// This Panics, if the buffer would overflow the size of allocated memory.
    pub fn write(&mut self, buffer: &[u8]) -> Result<usize> {
        //https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
        if !self.proc.has_perm(PROCESS_VM_WRITE) {
            return Err(crate::error::Error::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )));
        }
        let mut n: usize = 0;
        assert!(buffer.len() <= self.size);
        if unsafe {
            WriteProcessMemory(
                self.proc.get_proc(),
                self.addr,
                buffer.as_ptr() as LPCVOID,
                buffer.len(),
                &mut n as *mut usize,
            ) == FALSE
        } {
            return Err(crate::platforms::platform::macros::err(
                "WriteProcessMemory",
            ));
        }
        debug_assert!(n == buffer.len());
        Ok(n)
    }
    ///Get the Address, at which the MemPage as allocated
    #[must_use]
    pub fn get_address(&self) -> LPVOID {
        self.addr
    }
    ///Checks, if the Process, this MemoryPage was allocated in is valid in another Process object.
    #[must_use]
    pub fn check_proc(&self, proc: &Process) -> bool {
        self.proc.get_pid() == proc.get_pid()
    }
}
impl<'a> Display for MemPage<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "(proc:{:x}, addr:{:x}, size:{:x}, exec:{})",
            self.proc.get_proc() as usize,
            self.addr as usize,
            self.size,
            self.exec
        )
    }
}
impl<'a> Drop for MemPage<'a> {
    ///Free Memory
    fn drop(&mut self) {
        trace!("Releasing VirtualAlloc'd Memory");
        if unsafe { VirtualFreeEx(self.proc.get_proc(), self.addr, 0, MEM_RELEASE) } == FALSE {
            error!("Error during cleanup! VirtualFreeEx with MEM_RELEASE should not fail according to doc, but did anyways. A memory page will stay allocated. Addr:{:x},size:{:x}",self.addr as usize,self.size);
            //Supress unused_must_use warning. This is intended, but one cannot use allow, to supress this?
            //todo: a bit hacky? Is there a better way, to achieve something similar?
            void_res(err::<&str>("VirtualFreeEx of VirtualAllocEx"));
            //Do not panic here, since it could cause to an abort.
            // panic!("Error during cleanup")
        }
    }
}
