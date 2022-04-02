#![cfg(feature = "ntdll")]
mod types; //These are exclusively ntdll types

use super::macros::{check_ptr, err};
use super::process::Process;
use super::{get_windir, predicate, str_from_wide_str};
use crate::error::Error;
use crate::Result;
use log::{debug, error, info, trace, warn};
use ntapi::ntpsapi::PROCESS_BASIC_INFORMATION;
use ntapi::ntwow64::LDR_DATA_TABLE_ENTRY32;
use once_cell::sync::OnceCell;
use pelite::Wrap;
use std::ffi::OsStr;
use std::ops::Shl;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
pub use types::LDR_DATA_TABLE_ENTRY64;
use winapi::shared::basetsd::{DWORD64, PDWORD64, PULONG64, ULONG64};
use winapi::shared::minwindef::{HMODULE, PULONG, ULONG};
use winapi::shared::ntdef::{NTSTATUS, PVOID, PVOID64};
use winapi::um::libloaderapi::{FreeLibrary, GetProcAddress, LoadLibraryW};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winnt::{HANDLE, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION};

///This class represents the NTDLL module/dll from windows.
///This class is focused on having the least possible NTDLL function calls,
///whilst still preserving functionality with all use cases.
#[derive(Debug)]
pub(crate) struct NTDLL {
    pub(self) handle: usize,
}
impl NTDLL {
    ///Get the NTDLL object.
    ///This class employs the Singleton principle.
    pub(crate) fn new() -> Result<&'static Self> {
        static INST: OnceCell<NTDLL> = OnceCell::new();
        INST.get_or_try_init(|| {
            let ntdll: Vec<u16> = OsStr::new("NTDLL.dll\0").encode_wide().collect();
            let handle = check_ptr!(LoadLibraryW(ntdll.as_ptr())) as usize;
            Ok(NTDLL { handle })
        })
    }

    ///This returns the address at which ntdll is loaded within a Process.
    ///If explicit_x86 is true, this method will search for the x86 variant of ntdll
    ///Otherwise it will return the x64 variant of ntdll.
    ///
    ///If the specified version of ntdll is not loaded within that process, this function will return win an error.
    ///This case should only happen on x86 installs of windows and if explicit_x86 is true.
    ///On x86 installs of windows there is no WOW, and therefore no SysWOW64 folder.
    pub(crate) fn get_ntdll_base_addr(
        &self,
        explicit_x86: bool,
        proc: &Process,
    ) -> Result<(String, u64)> {
        let ntdll = get_windir()?.clone()
            + if !explicit_x86 {
                "\\System32\\ntdll.dll"
            } else {
                "\\SysWOW64\\ntdll.dll"
            };
        let ntdll = ntdll.to_lowercase();
        unsafe {
            self.get_module_in_proc(
                proc,
                predicate(
                    |m: Wrap<LDR_DATA_TABLE_ENTRY32, LDR_DATA_TABLE_ENTRY64>| match m {
                        Wrap::T32(v) => v.DllBase as u64,
                        Wrap::T64(v) => v.DllBase as u64,
                    },
                    |s| s.to_lowercase().ends_with(ntdll.as_str()),
                ),
            )
        }
    }

    ///Runs get_module_in_proc
    ///For safety go to [get_module_in_proc]
    ///
    ///proc: A Process (handle)
    ///predicate: when true is seen, selector is invoked
    ///selector: The selector returns the desired information
    pub(crate) unsafe fn run_get_module_in_proc<S, P, E, R>(
        &self,
        proc: &Process,
        selector: S,
        predicate: P,
    ) -> Result<R>
    where
        S: Fn(
            Wrap<ntapi::ntwow64::LDR_DATA_TABLE_ENTRY32, types::LDR_DATA_TABLE_ENTRY64>,
            &Vec<u16>,
        ) -> R,
        P: Fn(&Vec<u16>) -> bool,
        E: Fn(Error) -> Result<R>,
    {
        self.get_module_in_proc(proc, |w, v| {
            if predicate(&v) {
                Some(selector(w, &v))
            } else {
                None
            }
        })
    }

    ///Gets a module, by reading the Process Environment Block (PEB), of the process, using ntdll functions.
    ///Because this function uses ntdll functions, it should work the same, if running as x86, or x64.
    ///
    /// # Arguments
    ///
    ///- proc: a Process Handle (Can't be a pseudo-handle, like [super::process::Process::self_proc])
    ///- predicate: A function, which selects, what information, from what dll it wants.
    ///- predicate 2nd argument: full path, to dll
    //TODO: add tons of checks
    //todo: reduce if's in this function
    //todo: should we remove unsafe here?
    pub(crate) unsafe fn get_module_in_proc<F, R>(&self, proc: &Process, predicate: F) -> Result<R>
    where
        F: Fn(
            Wrap<ntapi::ntwow64::LDR_DATA_TABLE_ENTRY32, types::LDR_DATA_TABLE_ENTRY64>,
            Vec<u16>,
        ) -> Option<R>,
    {
        if !proc.has_real_handle() {
            return Err(crate::error::Error::Io(std::io::Error::from(
                std::io::ErrorKind::InvalidInput,
            )));
        }
        let pid_under_wow = proc.is_under_wow()?;
        info!("pid is under wow:{}", pid_under_wow);
        let peb_addr: u64=
        //This gets the PEB address, from the PBI
        if proc.is_under_wow()?{
            let pbi: PROCESS_BASIC_INFORMATION=
                self.query_process_information(proc, ntapi::ntpsapi::ProcessBasicInformation)?;
            pbi.PebBaseAddress as u64
        } else {
            let pbi: types::PROCESS_BASIC_INFORMATION_WOW64 =
                self.query_process_information(proc, ntapi::ntpsapi::ProcessBasicInformation)?;
            pbi.PebBaseAddress as u64
        };
        debug!("Peb addr is {:x?}", peb_addr);
        let ldr_addr;
        //This reads the PEB, and gets the LDR address
        {
            type PEB32 = ntapi::ntwow64::PEB32;
            type PEB64 = types::PEB64;
            ldr_addr = if pid_under_wow {
                let peb = *self.read_virtual_mem::<PEB32>(proc, peb_addr)?;
                peb.Ldr as u64
            } else {
                let peb = *self.read_virtual_mem::<PEB64>(proc, peb_addr)?;
                peb.Ldr as u64
            };
            debug!("Ldr Address is {:x}.", ldr_addr);
        }

        let mut modlist_addr;
        //This reads the LDR, and gets the Module list, in Load Order.
        {
            #[allow(non_camel_case_types)]
            type PEB_LDR_DATA32 = ntapi::ntwow64::PEB_LDR_DATA32;
            #[allow(non_camel_case_types)]
            type PEB_LDR_DATA64 = types::PEB_LDR_DATA64;
            modlist_addr = if pid_under_wow {
                let ldr = *self.read_virtual_mem::<PEB_LDR_DATA32>(proc, ldr_addr)?;
                ldr.InLoadOrderModuleList.Flink as u64
            } else {
                let ldr = *self.read_virtual_mem::<PEB_LDR_DATA64>(proc, ldr_addr)?;
                ldr.InLoadOrderModuleList.Flink as u64
            };
            debug!("Ldr InLoadOrderModuleList Address is {:x}", modlist_addr);
        }
        let first_modlist_addr = modlist_addr;
        //This Loops through the Module list, until we have found our module, or we arrive, at the address, we started from.
        loop {
            #[allow(non_camel_case_types)]
            type LDR_DATA_TABLE_ENTRY32 = ntapi::ntwow64::LDR_DATA_TABLE_ENTRY32;
            #[allow(non_camel_case_types)]
            type LDR_DATA_TABLE_ENTRY64 = types::LDR_DATA_TABLE_ENTRY64;
            let ldr_entry_data: Wrap<LDR_DATA_TABLE_ENTRY32, LDR_DATA_TABLE_ENTRY64>;
            if pid_under_wow {
                let entry = *self.read_virtual_mem(proc, modlist_addr as u64)?;
                debug!("Read the LDR_DATA_Table {:#x}", modlist_addr);
                ldr_entry_data = Wrap::T32(entry);
            } else {
                let entry = *self.read_virtual_mem(proc, modlist_addr as u64)?;
                debug!("Read the LDR_DATA_Table {:#x}", modlist_addr);
                ldr_entry_data = Wrap::T64(entry);
            }
            {
                let dll_win_string_length;
                let dll_win_string_buffer;
                match ldr_entry_data {
                    Wrap::T32(ldr_entry) => {
                        //Gather string data
                        dll_win_string_buffer = ldr_entry.FullDllName.Buffer as u64;
                        dll_win_string_length = ldr_entry.FullDllName.Length;
                        //In case we need, to check the next item.
                        modlist_addr = ldr_entry.InLoadOrderLinks.Flink as u64;
                    }
                    Wrap::T64(ldr_entry) => {
                        //Gather string data
                        dll_win_string_buffer = ldr_entry.FullDllName.Buffer as u64;
                        dll_win_string_length = ldr_entry.FullDllName.Length;
                        //In case we need, to check the next item.
                        modlist_addr = ldr_entry.InLoadOrderLinks.Flink as u64
                    }
                };
                if modlist_addr == first_modlist_addr {
                    const RECURSION:&str = "We looped through the whole InLoadOrderModuleList, but still have no match. Aborting, because this would end in an endless loop.";
                    warn!("{}", RECURSION);
                    return Err(Error::Unsuccessful(Some(RECURSION.to_string())));
                }

                let dll_path_buf = self.read_virtual_mem_fn(
                    proc,
                    dll_win_string_buffer,
                    (dll_win_string_length) as u32,
                )?;
                let dll_path_old = dll_path_buf.as_slice();
                let mut dll_path = Vec::with_capacity(((dll_win_string_length >> 1) + 1) as usize);
                let mut i = 0;
                while i < dll_path_buf.len() >> 1 {
                    dll_path
                        .push((dll_path_old[2 * i + 1] as u16).shl(8) | dll_path_old[2 * i] as u16);
                    i += 1;
                }

                let addr = match ldr_entry_data {
                    Wrap::T32(v) => v.DllBase as u64,
                    pelite::Wrap::T64(v) => v.DllBase as u64,
                };
                match str_from_wide_str(dll_path.as_slice()) {
                    Ok(v) => {
                        debug!("dll_name is {},{:x}", v, addr);
                    }
                    Err(e) => {
                        debug!("dll_name could not be printed. os_string is {:?}", e);
                    }
                }
                if let Some(val) = predicate(ldr_entry_data, dll_path) {
                    return Ok(val);
                }
            }
        }
    }

    ///See [read_virtual_mem_fn].
    unsafe fn read_virtual_mem<T>(&self, proc: &Process, addr: u64) -> Result<*mut T> {
        let v = self.read_virtual_mem_fn(proc, addr, core::mem::size_of::<T>() as u32)?;
        Ok(v.leak().as_ptr() as *mut T)
    }

    ///This reads `size` bytes, of memory, from address `addr`, in the process `proc`
    /// This function checks, if we have been passed a pseudo-handle (GetCurrentProcess).
    /// Those types of handles do not work with ntdll for reasons.
    ///
    ///# Safety
    ///`proc` needs to have the PROCESS_VM_READ access rights.
    ///`proc` needs to be valid
    ///
    ///`addr` need to be a valid address, in `proc` address space
    ///`addr` need to be a address, which can be read from
    ///`addr` needs to fulfill the above conditions for `size * std::mem::size_of::<T>()` bytes
    ///
    /// T needs to be non zero sized.
    ///
    unsafe fn read_virtual_mem_fn(&self, proc: &Process, addr: u64, size: u32) -> Result<Vec<u8>> {
        if !proc.has_real_handle() {
            return Err(crate::error::Error::Io(std::io::Error::from(
                std::io::ErrorKind::InvalidInput,
            )));
        }
        static FNS: OnceCell<FnNtdllWOW> = OnceCell::new();
        let fns = FNS.get_or_try_init(|| {
            FnNtdllWOW::new(b"NtReadVirtualMemory\0", b"NtWow64ReadVirtualMemory64\0")
        })?;
        let mut buf: Vec<u8> = Vec::with_capacity(size as usize);
        trace!("reading at address {:x?} {} bytes", addr, size);
        println!("reading at address {:x?} {} bytes", addr, size);
        let mut i: u32 = 0;
        let status = if proc.is_under_wow()? {
            let cfn: types::FnNtReadVirtualMemory = core::mem::transmute(*fns.get_fn()?.take());
            cfn(
                proc.get_proc(),
                addr as PVOID,
                buf.as_mut_ptr() as PVOID,
                size as u32,
                &mut i as *mut u32,
            )
        } else {
            let cfn: types::FnNtWOW64ReadVirtualMemory64 =
                core::mem::transmute(*fns.get_fn()?.take());
            cfn(
                proc.get_proc(),
                addr,
                buf.as_mut_ptr() as PVOID64,
                size as u32,
                &mut i as *mut u32 as u64,
            )
        };

        trace!("rvm {},{}/{}", status, i, size);
        println!("rvm {},{}/{}", status, i, size);
        //We read i bytes. So we let the Vec know, so it can calculate size and deallocate accordingly, if it wants.
        //Also: This will enable debugger inspection, of the buf, since the debugger will now know, that the vec is initialised.
        assert!(
            i <= size as u32,
            "{:#x} bytes were read into a {:#x} byte buffer.",
            i,
            size
        );
        // if i==0{
        //     println!("zero bytes read?");
        //     i=size as u64;
        // }
        buf.set_len(i as usize);
        buf.shrink_to_fit();
        Ok(buf)
    }

    ///This reads `size` elements, of size T, of memory, from address `addr`, in the process `proc`, into `buf`.
    /// This function checks, if we have been passed a pseudo-handle (GetCurrentProcess).
    /// Those types of handles do not work with ntdll for reasons.
    ///
    ///# Safety
    ///`proc` needs to have the PROCESS_QUERY_INFORMATION (or PROCESS_QUERY_LIMITED_INFORMATION?) access rights.
    ///`proc` needs to be valid
    ///
    ///`pic` and the return type need to match up. Not doing so, might end in immediate program termination.
    ///
    ///# Termination
    ///Windows might sometimes decide, to sometimes just end the entire program randomly, meaning, that this function won't return sometimes.
    ///On other occasions, Windows will return some extraneous value of bytes read.
    ///In those cases, this function will Panic.
    //todo:add a test for this?
    unsafe fn query_process_information<T>(
        &self,
        proc: &Process,
        pic: ntapi::ntpsapi::PROCESSINFOCLASS,
    ) -> Result<T>
    where
        T: Copy,
    {
        if !proc.has_real_handle() {
            return Err(crate::error::Error::Io(std::io::Error::from(
                std::io::ErrorKind::InvalidInput,
            )));
        }
        if !proc.has_perm(PROCESS_QUERY_INFORMATION)
            || !proc.has_perm(PROCESS_QUERY_LIMITED_INFORMATION)
        {
            return Err(crate::error::Error::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )));
        }
        //Function prototype, of the NtQueryInformationProcess function in ntdll.
        type FnNtQueryInformationProcess =
            fn(HANDLE, ntapi::ntpsapi::PROCESSINFOCLASS, PVOID, ULONG, PULONG) -> NTSTATUS;

        //Get function
        let cfn = {
            static FNS: OnceCell<FnNtdllWOW> = OnceCell::new();
            let fns = FNS.get_or_try_init(|| {
                FnNtdllWOW::new(
                    b"NtQueryInformationProcess\0",
                    b"NtWow64QueryInformationProcess64\0",
                )
            })?;
            let cfn = if proc.is_under_wow()? {
                fns.get_fn()
            } else {
                fns.get_wow64()
            }?
            .take();
            let cfn: FnNtQueryInformationProcess = core::mem::transmute(*cfn);
            cfn
        };
        //ready things, for function call
        let mut i = 0u32;
        let i_ptr = &mut i as *mut u32;
        let size_peb: usize = std::mem::size_of::<T>();
        let mut buf: Vec<u8> = Vec::with_capacity(size_peb);
        //Call function
        println!("Running NtQueryInformationProcess with fnptr:{:x?} proc:{:x?},pic:{:x}. Size is {}, buf is {:x?}",cfn as usize,proc.get_proc(),pic,size_peb, buf);
        let status = crate::error::Ntdll::new(cfn(
            proc.get_proc(),
            pic,
            buf.as_mut_ptr() as PVOID,
            size_peb as u32,
            i_ptr,
        ));
        println!(
            "qip {:x},0x{:x}|0x{:x}/0x{:x} buf is {:?}",
            status.get_status(),
            i,
            i,
            size_peb,
            buf
        );
        assert!(i<=size_peb as u32,"Detected buffer overflow. Stopping here, due to unknown or possibly malicious side-effects.");
        if i == 0 && size_peb != 0 {
            return Err(crate::error::Error::Unsuccessful(Some(
                "Zero bytes read, but the requested type is not Zero sized.".to_string(),
            )));
        }
        //Truncate vec, to only use initialized memory.
        buf.set_len(i as usize);
        buf.shrink_to_fit();
        //This should be safe, since the vec has as many bytes, as T
        let pbi_ptr: *mut T = std::mem::transmute(buf.leak().as_mut_ptr());
        // trace!("exitstatus:{:x},pebaddress:{:x},baseprio:{:x},upid:{:x},irupid:{:x}",pbi.ExitStatus,pbi.PebBaseAddress,pbi.BasePriority,pbi.UniqueProcessId,pbi.InheritedFromUniqueProcessId);
        Ok(*pbi_ptr)
    }
}
///Helps to differentiate between two function types
enum NtdllFn<T> {
    WOW(T),
    Normal(T),
}
impl<T> NtdllFn<T> {
    ///Gets the content of the enum as a reference
    pub fn get_content(&self) -> &T {
        match self {
            NtdllFn::WOW(t) => t,
            NtdllFn::Normal(t) => t,
        }
    }
    ///Destroys the enum, and gives the contained data
    pub fn take(self) -> T {
        match self {
            NtdllFn::WOW(t) => t,
            NtdllFn::Normal(t) => t,
        }
    }
}
///This holds an abstraction, for functions that are twice inside of NTDLL
///Once for regular interfacing, and a second for specifically querying 64-bit info from inside WOW
#[derive(Clone)]
struct FnNtdllWOW<'a, 'b, 'c> {
    ntdll: &'c NTDLL,
    wow64name: &'b [u8],
    name: &'a [u8],
    wowfn: OnceCell<usize>,
    namefn: OnceCell<usize>,
}
impl<'a, 'b, 'c> FnNtdllWOW<'a, 'b, 'c> {
    ///Constructs D
    pub(self) fn new(name: &'a [u8], wow64name: &'b [u8]) -> Result<Self> {
        Ok(FnNtdllWOW {
            ntdll: NTDLL::new()?,
            wow64name,
            name,
            wowfn: OnceCell::new(),
            namefn: OnceCell::new(),
        })
    }
    ///returns a function which is the wow64name function inside NTDLL, if we are running inside of wow.
    ///If we are not running inside of WOW, this function will return the result of [get_read_mem].
    pub(self) unsafe fn get_wow64(&self) -> Result<NtdllFn<&usize>> {
        #[cfg(target_pointer_width = "64")]
        {
            self.get_fn()
        }
        #[cfg(target_pointer_width = "32")]
        {
            self.wowfn
                .get_or_try_init(|| {
                    Ok(std::mem::transmute(check_ptr!(GetProcAddress(
                        self.ntdll.handle as HMODULE,
                        self.wow64name.as_ptr() as *const i8
                    ))))
                })
                .map(|x| NtdllFn::WOW(x))
        }
    }
    ///returns a function which is the NtReadVirtualMemory function inside NTDLL
    pub(self) unsafe fn get_fn(&self) -> Result<NtdllFn<&usize>> {
        self.namefn
            .get_or_try_init(|| {
                Ok(std::mem::transmute(check_ptr!(GetProcAddress(
                    self.ntdll.handle as HMODULE,
                    self.name.as_ptr() as *const i8
                ))))
            })
            .map(|x| NtdllFn::Normal(x))
    }
}

impl Drop for NTDLL {
    ///Decrement Ntdll module use counter.
    ///Also invalidates handle.
    fn drop(&mut self) {
        if unsafe { FreeLibrary(self.handle as HMODULE) } == 0 {
            warn!("Error whilst unloading NTDLL.dll. This is not actually that bad, since it is present in every Process anyways.");
            err("FreeLibrary");
        };
    }
}
#[cfg(test)]
mod test {
    use super::NTDLL;
    use crate::Result;
    use ntapi::ntpsapi::PROCESS_BASIC_INFORMATION;
    use winapi::um::winnt::PROCESS_ALL_ACCESS;

    #[test]
    fn new() -> Result<()> {
        let ntdll = NTDLL::new();
        assert!(ntdll.is_ok(), "{}", ntdll.unwrap_err());
        Ok(())
    }

    #[test]
    fn get_module_in_proc() -> Result<()> {
        let proc = super::super::process::Process::new(std::process::id(), PROCESS_ALL_ACCESS)?;
        // let proc = super::super::process::Process::self_proc();
        let ntdll = NTDLL::new()?;
        let (b, m) = unsafe {
            ntdll.get_module_in_proc(
                &proc,
                super::predicate(
                    |x: pelite::Wrap<
                        ntapi::ntwow64::LDR_DATA_TABLE_ENTRY32,
                        super::types::LDR_DATA_TABLE_ENTRY64,
                    >| match x {
                        pelite::Wrap::T32(x) => x.DllBase as u64,
                        pelite::Wrap::T64(x) => x.DllBase as u64,
                    },
                    |x| super::super::cmp("KERNEL32.DLL")(&x),
                ),
            )
        }?;
        Ok(())
    }
    #[test]
    fn no_find_get_module_in_proc() -> Result<()> {
        const RECURSION:&str = "We looped through the whole InLoadOrderModuleList, but still have no match. Aborting, because this would end in an endless loop.";
        let proc = super::super::process::Process::new(std::process::id(), PROCESS_ALL_ACCESS)?;
        let ntdll = NTDLL::new()?;
        let x = unsafe { ntdll.get_module_in_proc(&proc, |_, _| None::<()>) };
        assert!(x.is_err(),"get_module_in_proc found something, eventhough it shouldn't have. We asked for NOTHING.");
        assert_eq!(
            x.unwrap_err(),
            crate::error::Error::Unsuccessful(Some(RECURSION.to_string()))
        );
        Ok(())
    }

    #[test]
    fn read_memory() -> Result<()> {
        let buf: Vec<u8> = (0..255).collect();
        let s = buf.as_slice();
        let ntdll = NTDLL::new()?;
        let proc = super::super::process::Process::new(std::process::id(), PROCESS_ALL_ACCESS)?;
        let self_proc = super::super::process::Process::self_proc();
        let mut mem = super::super::mem::MemPage::new(&proc, buf.len(), false)?;
        mem.write(s)?;
        let re = unsafe {
            ntdll.read_virtual_mem_fn(self_proc, mem.get_address() as u64, buf.len() as u32)
        };
        assert!(
            re.is_err(),
            "read_virtual_mem_fn does apparently not work without a real handle"
        );

        println!("mem addr at {:#x}", mem.get_address() as usize);
        let r = unsafe { ntdll.read_virtual_mem_fn(&proc, s.as_ptr() as u64, buf.len() as u32) }?;
        assert_eq!(r, buf);
        Ok(())
    }

    #[test]
    fn query_process_information_self() -> Result<()> {
        let ntdll = super::NTDLL::new()?;
        {
            let proc = super::super::process::Process::new(std::process::id(), PROCESS_ALL_ACCESS)?;
            let r: PROCESS_BASIC_INFORMATION = unsafe {
                ntdll.query_process_information(&proc, ntapi::ntpsapi::ProcessBasicInformation)?
            };
        }
        {
            let proc = super::super::process::Process::self_proc();
            let r: Result<PROCESS_BASIC_INFORMATION> = unsafe {
                ntdll.query_process_information(proc, ntapi::ntpsapi::ProcessBasicInformation)
            };
            assert!(r.is_err(), "Pseudo-Handles do not work on ntdll?");
            let r = unsafe { r.unwrap_err_unchecked() }; //Safety is checked above.
            assert_eq!(
                r,
                crate::error::Error::Io(std::io::Error::from(std::io::ErrorKind::InvalidInput))
            );
        }
        Ok(())
    }
}
