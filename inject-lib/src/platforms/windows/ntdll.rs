#![cfg(feature = "ntdll")]
mod types; //These are exclusively ntdll types

use super::macros::{check_ptr, err};
use super::process::Process;
use super::{get_windir, predicate, str_from_wide_str};
use crate::Result;
use ntapi::ntwow64::LDR_DATA_TABLE_ENTRY32;
use pelite::Wrap;
use core::mem::MaybeUninit;
use core::ops::Shl;
use core::ptr::slice_from_raw_parts;
use core::num::NonZeroUsize;
use widestring::U16CString;
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::string::String;
pub use types::LDR_DATA_TABLE_ENTRY64;
use winapi::shared::minwindef::{HMODULE, PULONG, ULONG};
use winapi::shared::ntdef::{NTSTATUS, PVOID};
use winapi::um::libloaderapi::{FreeLibrary, GetProcAddress, LoadLibraryW};
use winapi::um::winnt::{
    HANDLE, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

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
        static INST: once_cell::race::OnceBox<NTDLL> = once_cell::race::OnceBox::new();
        const NTDLL:&widestring::U16CStr = widestring::u16cstr!("NTDLL.dll");
        debug_assert!(NTDLL.as_slice_with_nul().ends_with(&[0]),"{:x?}",NTDLL.as_slice_with_nul());
        INST.get_or_try_init(|| {
            let handle = check_ptr!(LoadLibraryW(NTDLL.as_ptr())) as usize;
            Ok(Box::new(NTDLL { handle }))
        })
    }

    ///This returns the address at which ntdll is loaded within a Process.
    ///If explicit_x86 is true, this method will search for the x86 variant of ntdll
    ///Otherwise it will return the x64 variant of ntdll.
    ///
    ///If the specified version of ntdll is not loaded within that process, this function will return win an error.
    ///This case should only happen on x86 installs of windows and if explicit_x86 is true.
    ///On x86 installs of windows there is no WOW, and therefore no SysWOW64 folder.
    #[cfg_attr(not(target_arch = "x64"), allow(unused))]
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
            &[u16],
        ) -> Option<R>,
    {
        proc.err_pseudo_handle()?;
        let pid_under_wow = proc.is_under_wow()?;
        crate::info!("pid is under wow:{}", pid_under_wow);
        //This gets the PEB address, from the PBI
        let peb_addr: u64 = {
            if pid_under_wow {
                let pbi: ntapi::ntpsapi::PROCESS_BASIC_INFORMATION =
                    self.query_process_information(proc, ntapi::ntpsapi::ProcessBasicInformation)?;
                pbi.PebBaseAddress as u64
            } else {
                let pbi: types::PROCESS_BASIC_INFORMATION_WOW64 =
                    self.query_process_information(proc, ntapi::ntpsapi::ProcessBasicInformation)?;
                pbi.PebBaseAddress as u64
            }
        };
        crate::debug!("Peb addr is {:x?}", peb_addr);
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
                //Since this is the structure of PEB under 64-bits, this should always hold true
                //A good test, if peb structure is valid.
                //https://docs.microsoft.com/en-us/windows/win32/api/Winternl/ns-winternl-peb
                if *(&peb as *const PEB64 as *const u8 as *const u64).add(3) != peb.Ldr {
                    //If we get here, it means, that the PEB struct we use is invalid.
                    return Err(crate::error::CustomError::InvalidStructure)?;
                }
                peb.Ldr as u64
            };
            if ldr_addr == 0 {
                return Err(crate::error::CustomError::LDRUninit)?;
            }
            crate::debug!("Ldr Address is {:x}.", ldr_addr);
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
            crate::debug!("Ldr InLoadOrderModuleList Address is {:x}", modlist_addr);
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
                crate::debug!("Read the LDR_DATA_Table {:#x}", modlist_addr);
                ldr_entry_data = Wrap::T32(entry);
            } else {
                let entry = *self.read_virtual_mem(proc, modlist_addr as u64)?;
                crate::debug!("Read the LDR_DATA_Table {:#x}", modlist_addr);
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
                    let s = crate::error::CustomError::ModuleListLoop;
                    crate::warn!("{}", s);
                    return Err(s)?;
                }

                let dll_path_buf = self.read_virtual_mem_fn(
                    proc,
                    dll_win_string_buffer,
                    (dll_win_string_length) as u32,
                )?;

                let dll_path_old = dll_path_buf.as_slice();
                //safety:
                //t is valid & size_of(u8)=size_of(u16)/2
                //
                //we do not care about the last potentially byte, that we throw away here, because dll_path_buf was already a WTF string.
                let dll_path = core::slice::from_raw_parts(dll_path_old.as_ptr() as *const u16, dll_path_old.len()/2);
                // let dll_path_old = dll_path_buf.as_slice();
                // let mut dll_path = Vec::with_capacity(((dll_win_string_length >> 1) + 1) as usize);
                // let mut i = 0;
                // while i < dll_path_buf.len() >> 1 {
                //     dll_path
                //         .push((dll_path_old[2 * i + 1] as u16).shl(8) | dll_path_old[2 * i] as u16);
                //     i += 1;
                // }

                let addr = match ldr_entry_data {
                    Wrap::T32(v) => v.DllBase as u64,
                    pelite::Wrap::T64(v) => v.DllBase as u64,
                };
                match str_from_wide_str(dll_path) {
                    Ok(v) => {
                        crate::debug!("dll_name is {},{:x}", v, addr);
                    }
                    Err(e) => {
                        crate::debug!("dll_name could not be printed. os_string is {:?}", e);
                    }
                }
                if let Some(val) = predicate(ldr_entry_data, dll_path) {
                    return Ok(val);
                }
            }
        }
    }

    ///See [read_virtual_mem_fn].
    pub(in super::super) unsafe fn read_virtual_mem<T>(
        &self,
        proc: &Process,
        addr: u64,
    ) -> Result<*mut T> {
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
    ///`addr` needs to fulfill the above conditions for `size * core::mem::size_of::<T>()` bytes
    ///
    /// T needs to be non zero sized.
    ///
    pub(in super::super) unsafe fn read_virtual_mem_fn(
        &self,
        proc: &Process,
        addr: u64,
        size: u32,
    ) -> Result<Vec<u8>> {
        proc.err_pseudo_handle()?;
        if !proc.has_perm(PROCESS_VM_READ) {
            return Err(crate::error::CustomError::PermissionDenied.into());
        }
        static FNS: once_cell::race::OnceBox<FnNtdllWOW> = once_cell::race::OnceBox::new();
        let fns:Result<&FnNtdllWOW,crate::error::Error> = FNS.get_or_try_init(|| {
            Ok(Box::new(FnNtdllWOW::new(b"NtReadVirtualMemory\0", b"NtWow64ReadVirtualMemory64\0")?))
        });
        let fns=fns?;
        let mut buf: Vec<u8> = Vec::with_capacity(size as usize);
        crate::trace!("reading at address {:x?} {} bytes", addr, size);
        let mut i: u64 = 0;
        let func = if proc.is_under_wow()? {
            fns.get_fn()?
        } else {
            fns.get_wow64()?
        };
        let status = match func {
            NtdllFn::Normal(v) => {
                let cfn: types::FnNtReadVirtualMemory = core::mem::transmute(v);
                cfn(
                    proc.get_proc(),
                    addr as PVOID,
                    buf.as_mut_ptr() as PVOID,
                    size as u32,
                    &mut i as *mut u64 as *mut u32,
                )
            }
            #[cfg(target_pointer_width = "32")]
            NtdllFn::WOW(v) => {
                let cfn: types::FnNtWOW64ReadVirtualMemory64 = core::mem::transmute(v);
                cfn(
                    proc.get_proc(),
                    addr,
                    buf.as_mut_ptr() as PVOID,
                    size as u64,
                    &mut i as *mut u64,
                )
            }
        };
        let status = crate::error::Ntdll::new(status);
        crate::trace!("rvm {},{}/{}", status, i, size);
        if status.is_warning() || status.is_error() {
            return Err(status.into());
        }

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

    unsafe fn query_process_information<T>(
        &self,
        proc: &Process,
        pic: ntapi::ntpsapi::PROCESSINFOCLASS,
    ) -> Result<T>
    where
        T: Copy,
    {
        let size = core::mem::size_of::<T>();
        let r = self.query_process_information_raw(proc, pic, size)?;
        assert!(
            r.len() >= core::mem::size_of::<T>(),
            "Not enough bytes, to construct T"
        );
        let mut t: T = MaybeUninit::zeroed().assume_init();
        core::ptr::copy_nonoverlapping(
            r.as_ptr(),
            &mut t as *mut T as *mut u8,
            core::cmp::min(r.len(), size),
        );
        Ok(t)
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
    unsafe fn query_process_information_raw(
        &self,
        proc: &Process,
        pic: ntapi::ntpsapi::PROCESSINFOCLASS,
        size: usize,
    ) -> Result<Vec<u8>> {
        proc.err_pseudo_handle()?;
        if !proc.has_perm(PROCESS_QUERY_INFORMATION)
            && !proc.has_perm(PROCESS_QUERY_LIMITED_INFORMATION)
        {
            return Err(crate::error::CustomError::PermissionDenied.into());
        }
        //Function prototype, of the NtQueryInformationProcess function in ntdll.
        type FnNtQueryInformationProcess =
            fn(HANDLE, ntapi::ntpsapi::PROCESSINFOCLASS, PVOID, ULONG, PULONG) -> NTSTATUS;

        //Get function
        let cfn = {
            static FNS: once_cell::race::OnceBox<FnNtdllWOW> = once_cell::race::OnceBox::new();
            let fns:Result<&FnNtdllWOW,crate::error::Error> = FNS.get_or_try_init(|| {
                Ok(Box::new(FnNtdllWOW::new(
                    b"NtQueryInformationProcess\0",
                    b"NtWow64QueryInformationProcess64\0",
                )?))
            });
            let fns=fns?;
            let cfn =
                if super::process::Process::self_proc().is_under_wow()? && !proc.is_under_wow()? {
                    crate::trace!("Trying to get wow64 fn");
                    fns.get_wow64()
                } else {
                    crate::trace!("Trying to get regular fn");
                    fns.get_fn()
                }?
                .take();
            let cfn: FnNtQueryInformationProcess = core::mem::transmute(&cfn);
            cfn
        };
        //ready things, for function call
        let mut i = 0u32;
        let i_ptr = &mut i as *mut u32;
        //Lets assume the worst case scenario, and allocate as much, as we might need.
        //Then we will later scale back to the size we actually need.
        let mut buf: Vec<u8> = Vec::with_capacity(size);
        for _ in 0..size {
            buf.push(0);
        }
        //Call function
        crate::trace!("Running NtQueryInformationProcess with fnptr:{:x?} proc:{:x?},pic:{:x}. Size is {}, buf is {:x?}",cfn as usize,proc.get_proc(),pic,size, buf);

        let status = crate::error::Ntdll::new(cfn(
            proc.get_proc(),
            pic,
            buf.as_mut_ptr() as PVOID,
            size as u32,
            i_ptr,
        ));
        // let status=crate::error::Ntdll::new(0);
        if status.is_error() || status.is_warning() {
            return Err(status.into());
        }
        assert!(i<= size as u32, "Detected buffer overflow. Stopping here, due to unknown or possibly malicious side-effects.");
        if i == 0 && size != 0 {
            return Err(crate::error::CustomError::ZeroBytes)?;
        }
        //Truncate vec, to only use initialized memory.
        // buf.set_len(i as usize);
        {
            while buf.len() < i as usize {
                //We do not need to check for none here, since it is guaranteed that: buf.len()=>i
                assert!(buf.pop().is_some(),"Buffer was shorter than be expected. earlier asserts should have assured this?");
            }
        }
        buf.shrink_to_fit();
        crate::trace!(
            "qip {:x},0x{:x}/0x{:x} buf is {:x?}",
            status.get_status(),
            i,
            size,
            buf
        );
        Ok(buf)
    }
}
///Helps to differentiate between two function types
enum NtdllFn<T> {
    #[cfg(target_pointer_width = "32")]
    WOW(T),
    Normal(T),
}
impl<T> NtdllFn<T> {
    ///Destroys the enum, and gives the contained data
    pub fn take(self) -> T {
        match self {
            #[cfg(target_pointer_width = "32")]
            NtdllFn::WOW(t) => t,
            NtdllFn::Normal(t) => t,
        }
    }
}
///This holds an abstraction, for functions that are twice inside of NTDLL
///Once for regular interfacing, and a second for specifically querying 64-bit info from inside WOW
struct FnNtdllWOW<'a, 'b, 'c> {
    ntdll: &'c NTDLL,
    #[cfg(target_pointer_width = "32")]
    wow64name: &'b [u8],
    #[cfg(target_pointer_width = "64")]
    _phantom: core::marker::PhantomData<&'b [u8]>,
    name: &'a [u8],
    #[cfg(target_pointer_width = "32")]
    wowfn: once_cell::race::OnceNonZeroUsize,
    namefn: once_cell::race::OnceNonZeroUsize,
}
impl<'a, 'b, 'c> FnNtdllWOW<'a, 'b, 'c> {
    ///Constructs D
    pub(self) fn new(
        name: &'a [u8],
        #[cfg_attr(target_pointer_width = "64", allow(unused))] wow64name: &'b [u8],
    ) -> Result<Self> {
        Ok(FnNtdllWOW {
            ntdll: NTDLL::new()?,
            #[cfg(target_pointer_width = "32")]
            wow64name,
            #[cfg(target_pointer_width = "64")]
            _phantom: core::marker::PhantomData::default(),
            name,
            #[cfg(target_pointer_width = "32")]
            wowfn: once_cell::race::OnceNonZeroUsize::new(),
            namefn: once_cell::race::OnceNonZeroUsize::new(),
        })
    }
    ///returns a function which is the wow64name function inside NTDLL, if we are running inside of wow.
    ///If we are not running inside of WOW, this function will return the result of [get_read_mem].
    pub(self) unsafe fn get_wow64(&self) -> Result<NtdllFn<usize>> {
        #[cfg(target_pointer_width = "64")]
        {
            self.get_fn()
        }
        #[cfg(target_pointer_width = "32")]
        {
            crate::trace!("wow64 fn");
            self.wowfn
                .get_or_try_init(|| {
                    let tmp = check_ptr!(GetProcAddress(
                        self.ntdll.handle as HMODULE,
                        self.wow64name.as_ptr() as *const i8
                    )) as usize;
                    Ok(NonZeroUsize::new(tmp).unwrap())
                })
                .map(|x| NtdllFn::WOW(x.get()))
        }
    }
    ///returns a function which is the NtReadVirtualMemory function inside NTDLL
    pub(self) unsafe fn get_fn(&self) -> Result<NtdllFn<usize>> {
        crate::trace!("regular fn");

        self.namefn
            .get_or_try_init(|| {
                let tmp = check_ptr!(GetProcAddress(
                            self.ntdll.handle as HMODULE,
                            self.name.as_ptr() as *const i8
                        )) as usize;
                Ok(core::num::NonZeroUsize::new(tmp).unwrap())
            })
            .map(|x| NtdllFn::Normal(x.get()))
    }
}

impl Drop for NTDLL {
    ///Decrement Ntdll module use counter.
    ///Also invalidates handle.
    fn drop(&mut self) {
        if unsafe { FreeLibrary(self.handle as HMODULE) } == 0 {
            crate::warn!("Error whilst unloading NTDLL.dll. This is not actually that bad, since it is present in every Process anyways.");
            err("FreeLibrary");
        };
    }
}
#[cfg(test)]
//Fixme: regression(stdless): Wierdness is happening again. Help?!?
pub mod test {
    extern crate std;
    use std::prelude::rust_2021;
    use alloc::vec::Vec;

    use super::NTDLL;
    use crate::platforms::windows::ntdll::types;
    use crate::Result;
    use winapi::um::winnt::PROCESS_ALL_ACCESS;

    #[test]
    fn new() -> Result<()> {
        let ntdll = NTDLL::new();
        assert!(ntdll.is_ok(), "{}", ntdll.unwrap_err());
        Ok(())
    }

    #[test]
    #[ignore]
    fn get_module_in_proc() -> Result<()> {
        let ntdll = NTDLL::new()?;
        let test = |proc: &super::super::process::Process| unsafe {
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
                    |x| super::super::cmp(crate::Data::Str("ntdll.dll"))(crate::Data::Str(x.as_str())),
                ),
            )
        };
        //test self real-handle
        {
            let proc = super::super::process::Process::new(std::process::id(), PROCESS_ALL_ACCESS)?;
            test(&proc)?;
        }
        //test foreign
        {
            let (mut c, proc) = super::super::test::create_cmd();
            let r = test(&proc);
            c.kill().unwrap();
            assert!(r.is_ok(), "other: {}", r.unwrap_err());
        }
        Ok(())
    }
    #[test]
    #[ignore]
    fn no_find_get_module_in_proc() -> Result<()> {
        let proc = super::super::process::Process::new(std::process::id(), PROCESS_ALL_ACCESS)?;
        let ntdll = NTDLL::new()?;
        let x = unsafe { ntdll.get_module_in_proc(&proc, |_, _| None::<()>) };
        assert!(x.is_err(),"get_module_in_proc found something, eventhough it shouldn't have. We asked for NOTHING.");
        assert_eq!(
            x.unwrap_err(),
            crate::error::Error::InjectLib(crate::error::CustomError::ModuleListLoop)
        );
        Ok(())
    }

    #[test]
    fn read_memory() -> Result<()> {
        //test read_mem on self
        {
            let buf: Vec<u8> = (0..255).collect();
            let s = buf.as_slice();
            let ntdll = NTDLL::new()?;
            //Test self proc
            {
                let self_proc = super::super::process::Process::self_proc();
                let re = unsafe {
                    ntdll.read_virtual_mem_fn(&self_proc, s.as_ptr() as u64, buf.len() as u32)
                };
                assert!(
                    re.is_err(),
                    "read_virtual_mem_fn does apparently not work without a real handle"
                );
            }
            //test proc real handle self
            {
                let proc =
                    super::super::process::Process::new(std::process::id(), PROCESS_ALL_ACCESS)?;
                let r = unsafe {
                    ntdll.read_virtual_mem_fn(&proc, s.as_ptr() as u64, buf.len() as u32)
                }?;
                assert_eq!(r, buf);
            }
            //test foreign process
            {
                let (mut c, proc) = super::super::test::create_cmd();
                let mut mem = super::super::mem::MemPage::new(&proc, buf.len(), false)?;
                let s = mem.write(buf.as_slice())?;
                let r = unsafe {
                    ntdll.read_virtual_mem_fn(&proc, mem.get_address() as u64, s as u32)
                }?;
                c.kill().unwrap();
                assert_eq!(r, buf, "Foreign read failed");
            }
        }

        Ok(())
    }

    #[test]
    #[ignore]
    fn query_process_information_self() -> Result<()> {
        let ntdll = super::NTDLL::new()?;
        //test real handle self
        {
            let proc = super::super::process::Process::new(std::process::id(), PROCESS_ALL_ACCESS)?;

            let r = unsafe {
                ntdll.query_process_information::<ntapi::ntpsapi::PROCESS_BASIC_INFORMATION>(
                    &proc,
                    ntapi::ntpsapi::ProcessBasicInformation,
                )
            };
            assert!(r.is_ok(), "self query process information failed");
        }
        //test foreign process
        {
            let (mut c, proc) = super::super::test::create_cmd();
            let r = unsafe {
                ntdll.query_process_information::<types::PROCESS_BASIC_INFORMATION_WOW64>(
                    &proc,
                    ntapi::ntpsapi::ProcessBasicInformation,
                )
            };
            c.kill().unwrap();
            assert!(
                r.is_ok(),
                "foreign query process information failed,{}",
                r.unwrap_err()
            );
        }
        //test pseudo handle self
        {
            let proc = super::super::process::Process::self_proc();
            let r = unsafe {
                ntdll.query_process_information::<ntapi::ntpsapi::PROCESS_BASIC_INFORMATION>(
                    &proc,
                    ntapi::ntpsapi::ProcessBasicInformation,
                )
            };
            assert!(r.is_err(), "Pseudo-Handles do not work on ntdll?");
            let r = unsafe { r.unwrap_err_unchecked() }; //Safety is checked above.
            assert_eq!(
                r,
                crate::error::Error::InjectLib(crate::error::CustomError::InvalidInput)
            );
        }
        Ok(())
    }
    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_size() {
        assert_eq!(
            core::mem::size_of::<ntapi::ntpsapi::PROCESS_BASIC_INFORMATION>(),
            core::mem::size_of::<types::PROCESS_BASIC_INFORMATION_WOW64>()
        )
    }
}
