#![cfg(feature = "ntdll")]
mod types; //These are exclusively ntdll types

use crate::error::Error;
use crate::platforms::platform::macros::{check_ptr, err};
pub use crate::platforms::platform::ntdll::types::LDR_DATA_TABLE_ENTRY64;
use crate::platforms::platform::process::Process;
use crate::platforms::platform::{get_windir, predicate, str_from_wide_str};
use crate::Result;
use log::{debug, info, trace, warn};
use ntapi::ntwow64::LDR_DATA_TABLE_ENTRY32;
use once_cell::sync::OnceCell;
use pelite::Wrap;
use std::ffi::OsStr;
use std::ops::Shl;
use std::os::windows::ffi::OsStrExt;
use winapi::shared::basetsd::{DWORD64, PDWORD64, ULONG64};
use winapi::shared::minwindef::{HMODULE, PULONG, ULONG};
use winapi::shared::ntdef::{NTSTATUS, PVOID};
use winapi::um::libloaderapi::{FreeLibrary, GetProcAddress, LoadLibraryW};
use winapi::um::winnt::{HANDLE, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION};
///This class represents the NTDLL module/dll from windows.
///This class is focused on having the least possible NTDLL function calls,
///whilst still preserving functionality with all use cases.
pub(crate) struct NTDLL {
    handle: usize,
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
    ///# Safety
    /// The proc handle must?(ntdll has no docs) have the PROCESS_VM_READ and (PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION?) access rights.
    /// The proc handle should also be valid.
    ///
    /// # Arguments
    ///
    ///- proc: a Process Handle
    ///- predicate: A function, which selects, what information, from what dll it wants.
    ///- predicate 2nd argument: full path, to dll
    //TODO: add tons of checks
    //todo: less if's in this  function
    //todo: test on x86. are the tons of paths even nessesary?
    pub(crate) unsafe fn get_module_in_proc<F, R>(&self, proc: &Process, predicate: F) -> Result<R>
    where
        F: Fn(
            Wrap<ntapi::ntwow64::LDR_DATA_TABLE_ENTRY32, types::LDR_DATA_TABLE_ENTRY64>,
            Vec<u16>,
        ) -> Option<R>,
    {
        let pid_under_wow = proc.is_under_wow()?;
        info!("pid is under wow:{}", pid_under_wow);
        let peb_addr: u64;
        //This gets the PEB address, from the PBI
        {
            // let mut pbi = PROCESS_BASIC_INFORMATION{
            // 	ExitStatus: 0,
            // 	PebBaseAddress: std::ptr::null_mut(),
            // 	AffinityMask: 0,
            // 	BasePriority: 0,
            // 	UniqueProcessId: std::ptr::null_mut(),
            // 	InheritedFromUniqueProcessId: std::ptr::null_mut()
            // };
            // const SIZE_PBI:usize = std::mem::size_of::<PROCESS_BASIC_INFORMATION_WOW64>();
            // let mut buf_pbi:Vec<u8> = Vec::with_capacity(100);
            // let mut buf_pbi:Vec<u8> = Vec::with_capacity(SIZE_PBI);
            let pbi: types::PROCESS_BASIC_INFORMATION_WOW64 =
                self.query_process_information(proc, ntapi::ntpsapi::ProcessBasicInformation)?;
            // buf_pbi.set_len(i as usize);
            // let pbi_ptr:*const PROCESS_BASIC_INFORMATION_WOW64 = std::mem::transmute(buf_pbi.as_ptr());
            // let pbi = *pbi_ptr;
            peb_addr = pbi.PebBaseAddress as u64;
            debug!("Peb addr is {:x?}", peb_addr);
        }
        let ldr_addr;
        //This reads the PEB, and gets the LDR address
        {
            type PEB32 = ntapi::ntwow64::PEB32;
            type PEB64 = types::PEB64;
            ldr_addr = if false && pid_under_wow {
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
            modlist_addr = if false && pid_under_wow {
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
            if false & pid_under_wow {
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
                    (dll_win_string_length) as usize,
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
        let v = self.read_virtual_mem_fn(proc, addr, core::mem::size_of::<T>())?;
        Ok(v.leak().as_ptr() as *mut T)
    }
    ///This reads `size` bytes, of memory, from address `addr`, in the process `proc`
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
    unsafe fn read_virtual_mem_fn(
        &self,
        proc: &Process,
        addr: u64,
        size: usize,
    ) -> Result<Vec<u8>> {
        //This is the prototype, of the NtReadVirtualMemory function
        type FnNtReadVirtualMemory =
            unsafe extern "system" fn(HANDLE, DWORD64, PVOID, ULONG64, PDWORD64) -> NTSTATUS;
        static NT_READ_VIRTUAL_MEMORY_FN: OnceCell<FnNtReadVirtualMemory> = OnceCell::new();

        let NtReadVirtualMemory = NT_READ_VIRTUAL_MEMORY_FN.get_or_try_init(|| {
            //We select the top one, even if proc.is_under_wow()==false, so that we have a constant function type.
            let rvm: &[u8] = if Process::self_proc().is_under_wow()? {
                b"NtWow64ReadVirtualMemory64\0"
            } else {
                b"NtReadVirtualMemory\0"
            };
            Ok(std::mem::transmute(check_ptr!(GetProcAddress(
                self.handle as HMODULE,
                rvm.as_ptr() as *const i8
            ))))
        })?;

        let mut buf: Vec<u8> = Vec::with_capacity(size);
        trace!("reading at address {:x?} {} bytes", addr, size);
        let mut i: u64 = 0;
        let status = crate::error::Ntdll::new(NtReadVirtualMemory(
            proc.get_proc(),
            addr,
            buf.as_mut_ptr() as PVOID,
            size as u64,
            &mut i as *mut u64,
        ));
        trace!("rvm {},{}/{}", status, i, size);
        //We read i bytes. So we let the Vec know, so it can calculate size and deallocate accordingly, if it wants.
        //Also: This will enable debugger inspection, of the buf, since the debugger will now know, that the vec is initialised.
        assert!(
            i <= size as u64,
            "{:#x} bytes were read into a {:#x} byte buffer.",
            i,
            size
        );
        buf.set_len(i as usize);
        buf.shrink_to_fit();
        Ok(buf)
    }

    ///This reads `size` elements, of size T, of memory, from address `addr`, in the process `proc`, into `buf`.
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
    unsafe fn query_process_information<T>(
        &self,
        proc: &Process,
        pic: ntapi::ntpsapi::PROCESSINFOCLASS,
    ) -> Result<T>
    where
        T: Copy,
    {
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
        static NT_QUERY_INFORMATION_PROCESS_OPT: OnceCell<FnNtQueryInformationProcess> =
            OnceCell::new();
        let NtQueryInformationProcess = NT_QUERY_INFORMATION_PROCESS_OPT.get_or_try_init(|| {
            //Todo: make this compatible with x86 injection
            let qip: &[u8] = if Process::self_proc().is_under_wow()? {
                b"NtWow64QueryInformationProcess64\0"
            } else {
                b"NtQueryInformationProcess\0"
            };
            let proc_ptr = check_ptr!(GetProcAddress(
                self.handle as HMODULE,
                qip.as_ptr() as *const i8
            ));
            let proc = std::mem::transmute(proc_ptr);
            trace!("proc is {:x}", proc_ptr as u64);
            Ok(proc)
        })?;
        //ready things, for function call
        let mut i = 0u32;
        let i_ptr = &mut i as *mut u32;
        let size_peb: usize = std::mem::size_of::<T>();
        let mut buf: Vec<u8> = vec![0; size_peb];
        //Call function
        trace!("Running NtQueryInformationProcess with fnptr:{:x?} proc:{:x?},pic:{:x}. Size is {}/{}, buf is {:x?}",*NtQueryInformationProcess as usize,proc.get_proc(),pic,size_peb,i, buf);
        let status = crate::error::Ntdll::new(NtQueryInformationProcess(
            proc.get_proc(),
            pic,
            buf.as_mut_ptr() as PVOID,
            size_peb as u32,
            i_ptr,
        ));
        trace!(
            "qip {:x},0x{:x}|0x{:x}/0x{:x} buf is {:?}",
            status.get_status(),
            i,
            i as u32,
            size_peb,
            buf
        );
        if i as u64 > size_peb as u64 || i as u64 == 0u64 {
            //This should never happen, unless I fucked something up.
            panic!("Read more, than buf can handle, or read 0 bytes!
I do not know, what corrupted, if something corrupted, or if windows reports arbitrary stuff.
Memory might be fucked. Could be, that the function should just have errored. I DO NOT KNOW, what happened.

Windows didn't yet freeze or kill our program. This might mean, that this is recoverable?

Report IMMEDIATELY.
		");
        }
        //This should be safe, since the vec has as many bytes, as T
        let pbi_ptr: *mut T = std::mem::transmute(buf.as_mut_ptr());
        // trace!("exitstatus:{:x},pebaddress:{:x},baseprio:{:x},upid:{:x},irupid:{:x}",pbi.ExitStatus,pbi.PebBaseAddress,pbi.BasePriority,pbi.UniqueProcessId,pbi.InheritedFromUniqueProcessId);
        Ok(*pbi_ptr)
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
