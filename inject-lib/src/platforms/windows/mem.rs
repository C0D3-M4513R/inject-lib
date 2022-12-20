use crate::Result;
use core::fmt::{Display, Formatter};
use winapi::shared::minwindef::{FALSE, LPCVOID, LPVOID};

use alloc::vec::Vec;

use super::macros::err;
use super::process::Process;
use winapi::um::memoryapi::{ReadProcessMemory, VirtualAllocEx, VirtualFreeEx, WriteProcessMemory};
use winapi::um::winnt::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
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
    ///If size is 0, it returns an error. First of all windows does not like it.
    ///If we were to return something, addr would not be valid.
    pub fn new(proc: &'a Process, size: usize, exec: bool) -> Result<Self> {
        if size == 0 {
            return Err(crate::error::CustomError::InvalidInput.into());
        }
        //https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
        if !proc.has_perm(PROCESS_VM_OPERATION) {
            return Err(crate::error::CustomError::PermissionDenied.into());
        }
        let addr = unsafe {
            VirtualAllocEx(
                proc.get_proc(),
                core::ptr::null_mut(),
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
            return Err(err(
                "VirtualAllocEx failed to allocate the requested amount of bytes on a process",
            ));
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
    pub fn write<T>(&mut self, buffer: &[T]) -> Result<usize> {
        let t_len:usize = core::mem::size_of::<T>();
        //https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
        if !self.proc.has_perm(PROCESS_VM_WRITE) {
            return Err(crate::error::CustomError::PermissionDenied.into());
        }
        let mut n: usize = 0;
        assert!(buffer.len() * t_len <= self.size);
        if unsafe {
            WriteProcessMemory(
                self.proc.get_proc(),
                self.addr,
                buffer.as_ptr() as LPCVOID,
                buffer.len() * t_len ,
                &mut n as *mut usize,
            ) == FALSE
        } {
            return Err(err("WriteProcessMemory"));
        }
        debug_assert!(n == buffer.len() * t_len);
        Ok(n)
    }
    ///Reads the contents of the memory page.
    ///# Panic
    /// This Panics, if the read number of bytes exceed size.
    #[allow(unused)]
    pub fn read(&self, size: usize) -> Result<Vec<u8>> {
        if !self.proc.has_perm(PROCESS_VM_READ) {
            return Err(crate::error::CustomError::PermissionDenied.into());
        }
        let mut buf = Vec::with_capacity(size);
        let mut o = 0;
        if unsafe {
            ReadProcessMemory(
                self.proc.get_proc(),
                self.addr,
                buf.as_mut_ptr() as LPVOID,
                size,
                &mut o as *mut usize,
            )
        } == FALSE
        {
            return Err(err("ReadProcessMemory"));
        }
        assert!(
            o <= size,
            "Buffer overflow occurred. Results may cause unknown code to execute. Aborting {}>{}",
            o,
            size
        );
        //Get buf to size
        unsafe {
            buf.set_len(o);
            buf.shrink_to_fit();
        }
        Ok(buf)
    }
    ///Get the Address, at which the MemPage as allocated
    #[must_use]
    pub fn get_address(&self) -> LPVOID {
        self.addr
    }
    ///Checks, if the Process, this MemoryPage was allocated in is valid in another Process object.
    #[must_use]
    #[allow(dead_code)]
    pub fn check_proc(&self, proc: &Process) -> bool {
        self.proc.get_pid() == proc.get_pid()
    }
}
impl<'a> Display for MemPage<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
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
        crate::trace!("Releasing VirtualAlloc'd Memory");
        if unsafe { VirtualFreeEx(self.proc.get_proc(), self.addr, 0, MEM_RELEASE) } == FALSE {
            crate::error!("Error during cleanup! VirtualFreeEx with MEM_RELEASE should not fail according to doc, but did anyways. A memory page will stay allocated. Addr:{:x},size:{:x}",self.addr as usize,self.size);
            err("VirtualFreeEx of VirtualAllocEx");
            //Panic during tests, to test of proper disposal of object
            #[cfg(test)]
            panic!("VirtualFreeEx resulted in an error");
        }
    }
}

#[cfg(test)]
mod test {
    use crate::Result;

    #[test]
    fn zero_size_page() {
        let proc = &super::super::process::Process::self_proc();
        let m = super::MemPage::new(proc, 0, false);
        assert!(
            m.is_err(),
            "A zero sized allocation is not sensible. Also windows does not allow it."
        )
    }

    #[test]
    fn check_proc() -> Result<()> {
        let proc = &super::super::process::Process::self_proc();
        let m = super::MemPage::new(proc, 1, false)?;
        assert!(m.check_proc(proc));
        Ok(())
    }

    #[test]
    fn new_and_write() -> Result<()> {
        let buf: alloc::vec::Vec<u8> = (0..255).collect();
        let proc = &super::super::process::Process::self_proc();
        //write mem
        let mut m = super::MemPage::new(proc, buf.len(), false)?;
        let w = m.write(buf.as_slice())?;
        assert!(w >= buf.len());
        //and read it again
        let rb: *const [u8; 255] = m.get_address() as *const [u8; 255];
        let rb = unsafe { *rb };
        assert_eq!(rb, buf.as_slice());
        assert_eq!(buf, m.read(w)?);
        Ok(())
    }

    #[test]
    fn other_proc() -> Result<()> {
        let buf: alloc::vec::Vec<u8> = (0..255).collect();
        let (mut c, proc) = super::super::test::create_cmd();
        //write mem
        let mut m = super::MemPage::new(&proc, buf.len(), false)?;
        let w = m.write(buf.as_slice())?;
        assert!(w >= buf.len());
        assert_eq!(m.read(w)?, buf);
        c.kill().unwrap();
        Ok(())
    }
}
