#![cfg(windows)]
mod macros;

use crate::{strip_path, Injector, Result};
use macros::check_ptr;
use std::ffi::{CStr, CString, OsString};

use log::{debug, error, info, trace, warn};
use pelite::{Pod, Wrap};
use std::fmt::{Debug, Display};
use std::mem::size_of;
use std::ops::{Add, Deref, Shl, Shr};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use winapi::ctypes::c_void;
use winapi::shared::basetsd::{DWORD64, PDWORD64, PULONG64, SIZE_T, ULONG64};
use winapi::shared::minwindef::{DWORD, FALSE, LPVOID, MAX_PATH};
use winapi::shared::ntdef::{NTSTATUS, PULONG, PVOID, PVOID64, ULONG, ULONGLONG};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::libloaderapi::{
    FreeLibrary, GetModuleHandleA, GetProcAddress, LoadLibraryA, DONT_RESOLVE_DLL_REFERENCES,
    LOAD_LIBRARY_AS_DATAFILE, LOAD_LIBRARY_AS_IMAGE_RESOURCE,
};
use winapi::um::memoryapi::VirtualAlloc;
use winapi::um::processthreadsapi::{CreateRemoteThread, GetCurrentProcess, OpenProcess};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::sysinfoapi::{
    GetNativeSystemInfo, GetSystemWindowsDirectoryA, GetSystemWindowsDirectoryW, SYSTEM_INFO,
};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    LPPROCESSENTRY32W, MAX_MODULE_NAME32, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use winapi::um::winbase::INFINITE;
use winapi::um::winnt::{
    BOOLEAN, CONTEXT, HANDLE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386,
    IMAGE_FILE_MACHINE_UNKNOWN, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    PAGE_READWRITE, PHANDLE, PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_INTEL,
    PROCESS_ALL_ACCESS, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR, WOW64_CONTEXT, WOW64_FLOATING_SAVE_AREA,
};

mod mem;
#[cfg(feature = "ntdll")]
mod ntdll;
mod process;
mod thread;

use ntapi::ntapi_base::CLIENT_ID;
use ntapi::ntwow64::LDR_DATA_TABLE_ENTRY32;
use std::thread::{sleep, yield_now};

use crate::error::Error;
use crate::platforms::platform::macros::{err, void_res};
use crate::platforms::platform::mem::MemPage;
use crate::platforms::platform::process::Process;
use crate::platforms::platform::thread::Thread;
use once_cell::sync::OnceCell;

pub fn str_from_wide_str(v: &[u16]) -> Result<String> {
    OsString::from_wide(v).into_string().map_err(|e| {
        warn!("Couldn't convert widestring, to string. The Buffer contained invalid non-UTF-8 characters . Buf is {:#?}.", e);
        crate::error::Error::WTFConvert(e)
    })
}

impl<'a> Injector<'a> {
    pub fn find_pid(name: &str) -> Result<Vec<u32>> {
        Self::find_pid_selector(|p| {
            return match str_from_wide_str(crate::trim_wide_str(p.szExeFile.to_vec()).as_slice()) {
                Ok(str) => {
                    debug!("Checking {} against {}", str, name);
                    if let Ok(s) = strip_path(str.as_str()) {
                        return s.as_str() == name;
                    }
                    false
                }
                Err(e) => {
                    warn!("Skipping check of process. Can't construct string, to compare against. Err:{:#?}",e);
                    false
                }
            };
        })
    }
    //todo: use the structs
    pub fn eject(&self) -> Result<()> {
        let proc = Process::new(
            self.pid,
            PROCESS_CREATE_THREAD
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ
                | PROCESS_VM_OPERATION
                | PROCESS_QUERY_INFORMATION,
        )?;
        if Process::self_proc().is_under_wow()? && !proc.is_under_wow()? {
            return Err(crate::error::Error::Unsupported(Some(
                "ejecting is not currently supported from a x86 binary targeting a x64 process."
                    .to_string(),
            )));
        }

        let name = strip_path(self.dll)?;
        let (_path, base) = get_module(name.as_str(), &proc)?;
        let handle = get_module_in_pid(
            self.pid,
            |m| {
                if let Ok(v) = str_from_wide_str(&m.szModule) {
                    if cmp(&name)(v.as_str()) {
                        Some(m.hModule)
                    } else {
                        None
                    }
                } else {
                    None
                }
            },
            None,
        )?;
        info!("Found dll in proc, at addr:{:#x?}", base);
        //If the target process is x86, this is slightly too much,
        //but the windows kernel seems to allocate at least 4k, so this does not matter.
        const SIZE: usize = core::mem::size_of::<u64>();
        //scope here, so Vec will get deleted after this
        let mem = {
            let mut mempage = MemPage::new(&proc, SIZE, false)?;
            let mut buf = Vec::with_capacity(SIZE);
            if proc.is_under_wow()? {
                buf.append(&mut (base as usize).as_bytes().to_vec());
            } else {
                buf.append(&mut base.as_bytes().to_vec());
            }
            buf.shrink_to_fit();
            mempage.write(buf.as_slice())?;
            mempage
        };
        self.exec_fn_in_proc(&proc, "FreeLibrary", mem)
    }

    ///Actually Inject the DLL.
    ///For now, the injection is only likely to succeed, if the injector, dll and target process have the same bitness (all x64, or all x86)
    ///Open a Pr, if you know more about this!
    ///Return information (Outside of Ok and Err) is purely informational (for now)! It should not be relied upon, and may change in Minor updates.
    ///Notice:This implementation blocks, and waits, until the library is injected, or the injection failed.
    /// # Panic
    /// This function may panic, if a Handle cleanup fails.
    pub fn inject(&self) -> Result<()> {
        let proc = Process::new(
            self.pid,
            PROCESS_CREATE_THREAD
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ
                | PROCESS_VM_OPERATION
                | PROCESS_QUERY_INFORMATION,
        )?;
        //Is the dll already injected?
        if get_module(strip_path(self.dll)?.as_str(), &proc).is_ok() {
            return Err(Error::Unsupported(Some("dll already injected".to_string())));
        }

        //Prepare Argument for LoadLibraryW
        //scope here, so Vec will get deleted after this
        let mem = {
            let full_path: PathBuf = std::fs::canonicalize(self.dll)?;
            let path: Vec<u16> = full_path.as_os_str().encode_wide().chain(Some(0)).collect();
            let mut mempage =
                mem::MemPage::new(&proc, path.len() * core::mem::size_of::<u16>(), false)?;
            mempage.write(path.as_bytes())?;
            mempage
        };
        self.exec_fn_in_proc(&proc, "LoadLibraryW", mem)
    }

    fn exec_fn_in_proc(&self, proc: &Process, entry_fn: &str, mem: MemPage) -> Result<()> {
        //What follows is a bunch of things, for injecting dlls cross-platform
        //https://rce.co/knockin-on-heavens-gate-dynamic-processor-mode-switching/
        //https://medium.com/@fsx30/hooking-heavens-gate-a-wow64-hooking-technique-5235e1aeed73
        //https://userexistserror.blogspot.com/2018/12/windows-cross-architecture-code.html
        //https://github.com/UserExistsError/InjectDll/
        //https://github.com/UserExistsError/DllLoaderShellcode
        //https://www.fireeye.com/blog/threat-research/2020/11/wow64-subsystem-internals-and-hooking-techniques.html
        //http://blog.rewolf.pl/blog/?p=102
        //https://github.com/JustasMasiulis/wow64pp
        //https://wbenny.github.io/2018/11/04/wow64-internals.html#leaving-32-bit-mode

        //https://wbenny.github.io/2018/11/04/wow64-internals.html
        //https://helloacm.com/how-to-check-if-a-dll-or-exe-is-32-bit-or-64-bit-x86-or-x64-using-vbscript-function/
        //TODO: Recheck this Fn, and all the winapi calls
        if self.pid == 0 {
            warn!("Supplied id is 0. Will not inject, as it is not supported by windows.");
            return Err(Error::Unsupported(Some(
                "PID 0 is an invalid target under windows.".to_string(),
            )));
        }

        let self_proc = Process::self_proc();
        debug!("Process is {}", proc);

        //Is the target exe x86?
        let pid_is_under_wow = proc.is_under_wow()?;
        // Is this exe x86?
        let self_is_under_wow = self_proc.is_under_wow()?;

        info!(
            "pid_is_under_wow:{},self_is_under_wow:{}",
            pid_is_under_wow, self_is_under_wow
        );
        if self_is_under_wow && !pid_is_under_wow {
            if cfg!(feature = "ntdll") {
                warn!("This injection will use a slightly different method, than usually. This is normal, when the injector is x86, but the pid specified is a x64 process.\
				We will be using ntdll methods. The ntdll.dll is technically not a public facing windows api.");
            } else {
                return Err(Error::Unsupported(Some("Cannot continue injection. You are trying to inject from a x86 injector into a x64 application. That is unsupportable, without access to ntdll functions.".to_string())));
            }
        };

        let dll_is_x64 = self.get_is_dll_x64()?;

        if dll_is_x64 && pid_is_under_wow {
            error!(
                "Injecting a x64 dll, into a x86 exe is unsupported. Will not continue for now."
            );
            return Err(Error::Unsupported(Some(
                "Injecting a x64 dll, into a x86 exe is unsupported.".to_string(),
            )));
        } else if !dll_is_x64 && !pid_is_under_wow {
            error!("Injecting a x86 dll, into a x64 exe is unsupported. Could this case be supported? Send a PR, if you think, you can make this work! Will NOT abort, but expect the dll-injection to fail");
            return Err(Error::Unsupported(Some(
                "Injecting a x86 dll, into a x64 exe is unsupported.".to_string(),
            )));
        }
        #[cfg(not(feature = "ntdll"))]
        if self_is_under_wow && !pid_is_under_wow {
            return Err(Error::Unsupported(Some(
                "Cannot inject into a x64 Application without ntdll access.".to_string(),
            )));
        }

        let entry_point = {
            let (path, base) = get_module("KERNEL32.DLL", &proc)?;
            base + get_dll_export(entry_fn, path)? as u64
        };
        info!(
            "Allocated {} Parameter at {:#x?}. fn ptr is {:#x} vs {:#x}",
            entry_fn,
            mem.get_address(),
            entry_point,
            entry_point as usize
        );
        //Execute LoadLibraryW in remote thread, and wait for dll to load
        #[cfg(all(feature = "x86tox64", target_arch = "x86"))]
        {
            //This method is intended to be only used, when we are compiled as x86, and are injecting to x64.
            if self_is_under_wow && !pid_is_under_wow {
                let mut thread: HANDLE = null_mut();
                let mut client: CLIENT_ID = CLIENT_ID {
                    UniqueProcess: null_mut(),
                    UniqueThread: null_mut(),
                };
                let ntdll = ntdll::NTDLL::new()?;
                let (path, base) = ntdll.get_ntdll_base_addr(pid_is_under_wow, &proc)?;
                let rva = get_dll_function(path, "RtlCreateUserThread".to_string())?;
                let va = base + rva as u64;
                let (r, t, c) = unsafe {
                    crate::platforms::x86::exec(
                        va,
                        proc.get_proc(),
                        null_mut(),
                        0,
                        0,
                        0,
                        0,
                        entry_point as u64,
                        mem.get_address() as u64,
                    )?
                };
                match crate::error::Ntdll::new(r) {
                    crate::error::Ntdll::Error(v) => {
                        return Err(Error::Ntdll(v));
                    }
                    crate::error::Ntdll::Warning(v) => {
                        return Err(Error::Ntdll(v));
                    }
                    _ => {}
                }
                return unsafe { Thread::new(t)? }.wait_for_thread();
            }
        }
        if !self_is_under_wow || pid_is_under_wow {
            let mut thread_id: u32 = 0;
            let thread = unsafe {
                thread::Thread::new(CreateRemoteThread(
                    proc.get_proc(),
                    std::ptr::null_mut(),
                    0,
                    Some(std::mem::transmute(entry_point as usize)),
                    mem.get_address(),
                    0,
                    &mut thread_id as *mut u32,
                ))
            }?;
            let thread_id = thread_id;
            trace!("Thread is {:?} and thread id is {}", *thread, thread_id);
            info!("Waiting for DLL");
            // std::thread::sleep(Duration::new(0,500));//todo: why is this necessary, (only) when doing cargo run?
            return thread.wait_for_thread();
        }
        return Err(Error::Unsuccessful(Some(
            "No viable injection method.".to_string(),
        )));
        //Check, if the dll is actually loaded?
        //todo: can we skip this? is the dll always guaranteed to be loaded here, or is it up to the dll, to decide that?
        //todo: re-add a check, for loaded modules

        // get_module_in_pid_predicate_selector(self.pid,self.dll,|_|(),None)
        //Err(("".to_string(), 0))
    }

    ///Find a PID, where the process-name matches some user defined selector
    pub fn find_pid_selector<F>(select: F) -> Result<Vec<u32>>
    where
        F: Fn(&PROCESSENTRY32W) -> bool,
    {
        let mut pids: Vec<DWORD> = Vec::new();
        let snap_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap_handle == INVALID_HANDLE_VALUE {
            return Err(macros::err("CreateToolhelp32Snapshot"));
        }
        trace!("Got Snapshot of processes");
        let mut val = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            cntUsage: 0,      //This member is no longer used and is always set to zero.
            th32ProcessID: 0, //This member is no longer used and is always set to zero.
            th32DefaultHeapID: 0, //This member is no longer used and is always set to zero.
            th32ModuleID: 0,  //This member is no longer used and is always set to zero.
            cntThreads: 0,    //The number of execution threads started by the process.
            th32ParentProcessID: 0, //The identifier of the process that created this process (its parent process).
            pcPriClassBase: 0,      //The base priority of any threads created by this process.
            dwFlags: 0,             //This member is no longer used, and is always set to zero.
            szExeFile: [0u16; MAX_PATH],
            //The name of the executable file for the process.
            //To retrieve the full path to the executable file,
            // call the Module32First function and check the szExePath member
            // of the MODULEENTRY32 structure that is returned.
        };
        let entry: LPPROCESSENTRY32W = &mut val as *mut PROCESSENTRY32W;

        if unsafe { Process32FirstW(snap_handle, entry) == FALSE } {
            return Err(macros::err("Process32FirstW"));
        }

        trace!("Ran Process32FirstW");
        loop {
            if select(&val) {
                pids.push(val.th32ProcessID);
            }
            if unsafe { Process32NextW(snap_handle, entry) == FALSE } {
                break;
            }
        }
        Ok(pids)
    }
    ///This function will return, whether a dll is x64, or x86.
    ///The Return value will be Ok(true), if the dll is x64(64bit), and Ok(false), if the dll is x86(32bit).
    pub fn get_is_dll_x64(&self) -> Result<bool> {
        let dll = std::fs::read(self.dll)?;
        // let parsed = result!(Wrap::<Pelite::pe32::PeFile,Pelite::pe64::PeFile>::from_bytes(dll.as_slice()));
        return match pelite::pe64::PeFile::from_bytes(dll.as_slice()) {
            Ok(_) => Ok(true),
            Err(pelite::Error::PeMagic) => pelite::pe32::PeFile::from_bytes(dll.as_slice())
                .map_err(|e| e.into())
                .map(|_| false),
            Err(err) => Err(err.into()),
        };
        // let machine = parsed.file_header().Machine;
        // let dll_is_x64 = machine == IMAGE_FILE_MACHINE_AMD64;
        // let dll_is_x86 = machine == IMAGE_FILE_MACHINE_I386;
        // info!("Dll is {:x}, x64:{},x86:{}",machine,dll_is_x64,dll_is_x86);
        // if dll_is_x64 == dll_is_x86 {
        // 	unreachable!("Cannot be both or neither x64 and x86! This path should be impossible! Something has gone catastrophically wrong.");
        // }
        // Ok(dll_is_x64)
    }
}

///Does NOT work, if the injector is x86, and the target exe is x64.
///This is, due to Microsoft constraints.
///The Constraint lies with the Function `CreateToolhelp32Snapshot`. More in the Microsoft docs [here](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot).
///
/// # Arguments
///- pid: process pid
///- predicate: a Function, which returns Some(value), when the desired module is found.
///- snapshot_flags: an option, to pass other flags, to `CreateToolhelp32Snapshot`
fn get_module_in_pid<F, T>(pid: u32, predicate: F, snapshot_flags: Option<u32>) -> Result<T>
where
    F: Fn(&MODULEENTRY32W) -> Option<T>,
{
    let snap_modules = check_ptr!(
        CreateToolhelp32Snapshot(
            snapshot_flags.unwrap_or(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE),
            pid
        ),
        |v| v == INVALID_HANDLE_VALUE
    );
    let mut module_entry = MODULEENTRY32W {
        dwSize: size_of::<MODULEENTRY32W>() as u32, //The size of the structure, in bytes. Before calling the Module32First function, set this member to sizeof(MODULEENTRY32). If you do not initialize dwSize, Module32First fails.
        th32ModuleID: 1,  //This member is no longer used, and is always set to one.
        th32ProcessID: 0, //The identifier of the process whose modules are to be examined.
        GlblcntUsage: 0, //The load count of the module, which is not generally meaningful, and usually equal to 0xFFFF.
        ProccntUsage: 0, //The load count of the module (same as GlblcntUsage), which is not generally meaningful, and usually equal to 0xFFFF.
        modBaseAddr: std::ptr::null_mut(), //The base address of the module in the context of the owning process.
        modBaseSize: 0,                    //The size of the module, in bytes.
        hModule: std::ptr::null_mut(), //A handle to the module in the context of the owning process.
        szModule: [0; MAX_MODULE_NAME32 + 1], //The module name.
        szExePath: [0; MAX_PATH],      //The module path.
    };
    check_ptr!(
        Module32FirstW(snap_modules, &mut module_entry as *mut MODULEENTRY32W),
        |val| val == FALSE
    );

    loop {
        //This is kinda slow in debug mode. Can't do anything about it.
        if let Some(v) = predicate(&module_entry) {
            check_ptr!(CloseHandle(snap_modules), |v| v == 0);
            return Ok(v);
        }
        if unsafe { Module32NextW(snap_modules, &mut module_entry as *mut MODULEENTRY32W) } == FALSE
        {
            return Err(Error::from("Module32NextW"));
        }
    }
}

fn get_windir<'a>() -> Result<&'a String> {
    static WINDIR: once_cell::sync::OnceCell<String> = once_cell::sync::OnceCell::new();

    let str = WINDIR.get_or_try_init(||{
		let i=check_ptr!(GetSystemWindowsDirectoryW(std::ptr::null_mut(),0),|v|v==0);
		let mut str_buf:Vec<u16> = Vec::with_capacity( i as usize);
		let i2=check_ptr!(GetSystemWindowsDirectoryW(str_buf.as_mut_ptr(),i),|v|v==0);
        assert!(i2<=i,"GetSystemWindowsDirectoryA says, that {} bytes are needed, but then changed it's mind. Now {} bytes are needed.",i,i2);
		unsafe{str_buf.set_len(i2 as usize)};
		let string = str_from_wide_str(str_buf.as_slice())?;
		debug!("Windir is {},{},{}",string,i,i2);
		Ok(string)
	})?;
    debug!("Windir is '{}'", str);
    Ok(str)
}
///Converts v to a String, and compares it using compare.
///Will return the string, if compare returned true, for that string.
//todo: could we remove this?
fn converter(compare: impl Fn(&String) -> bool) -> impl Fn(Vec<u16>) -> Option<String> {
    move |v| match str_from_wide_str(v.as_slice()) {
        Ok(s) => {
            if compare(&s) {
                Some(s)
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

///This gets the Relative Virtual Address (rva) of the function name, from a ntdll file.
///If explicit_x86 is true, this function will ALWAYS try to open the x86 ntdll in the SysWOW64 folder.
///Otherwise if native is true, this function will try to open whatever ntdll is native to the system.
///(if you have a x86 install this will pick x86. if you have a x64 install this will  pick x64)
///If both explicit_x86 and native are false, this function will use whatever ntdll is in System32.
fn get_dll_function(path: String, name: String) -> Result<u32> {
    //We need to replace System32, by Sysnative, in case we are running under WOW, because Windows will otherwise redirect all our file access.

    //One can also use the following methods: https://docs.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-wow64disablewow64fsredirection,https://docs.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-wow64revertwow64fsredirection
    //I am not using those methods, because that WILL have impacts, if those functions fail.
    //On failing to re-enable Filesystem redirection, I'd have to panic, since a x86 program, using this library, might do unwanted things.
    //todo: to function

    // let ntdll_path = if self_is_under_wow{
    // 	let str = get_windir()?.clone();
    // 	ntdll_path.replace(&(str.clone() + &"\\SYSTEM32".to_string()),&(str + &"\\Sysnative".to_string()))
    // }else{
    // 	ntdll_path
    // };
    // check_ptr!(Wow64DisableWow64FsRedirection(&mut par as *mut PVOID),|v|v==0);

    //avoid filesystem redirection by WOW.
    let str = get_windir()?.clone();
    let path = if Process::self_proc().is_under_wow()? {
        path.replace(
            &(str.clone() + &"\\SYSTEM32".to_string()),
            &(str + &"\\Sysnative".to_string()),
        )
    } else {
        path
    };
    debug_assert!(
        std::fs::canonicalize(&path).is_ok(),
        "parsing {} failed",
        path
    );
    let k32 = std::fs::read(&path)?;
    trace!("read file correctly");
    // check_ptr!(Wow64RevertWow64FsRedirection(par),|v|v==0);

    let dll_parsed = pelite::PeFile::from_bytes(k32.as_slice())?;
    trace!("Parsed dll file!");
    let rva = dll_parsed.get_export_by_name(&name)?.symbol().unwrap();
    trace!("Got RTLCreateUserThread export at {:x}", rva);
    Ok(rva)
}
///Takes in a Name. From that it returns a matcher
///Takes a Selector, and returns a type, for use with get_module_in_proc and get_module_in_pid
///name specifies, what module to look for.
///f processes the other input from other functions
//todo: does this bring a performance benefit?
fn predicate<'a, T: 'a, F: 'a, C: 'a>(
    f: T,
    cmp: C,
) -> impl Fn(F, Vec<u16>) -> Option<(String, u64)> + 'a
where
    T: Fn(F) -> u64,
    C: Fn(&str) -> bool,
{
    move |i2, v| match str_from_wide_str(v.as_slice()) {
        Ok(s) => {
            if cmp(s.as_str()) {
                Some((s, f(i2)))
            } else {
                None
            }
        }
        Err(_) => None,
    }
}
///Returns a function, which compares a &str against a name
fn cmp(name: impl ToString) -> impl Fn(&str) -> bool {
    move |s| {
        if let Ok(string) = strip_path(s) {
            string == name.to_string()
        } else {
            false
        }
    }
}

fn get_module(name: &str, proc: &Process) -> Result<(String, u64)> {
    let cmp = cmp(name);
    if !process::Process::self_proc().is_under_wow()? || proc.is_under_wow()? {
        match get_module_in_pid(
            proc.get_pid(),
            |m| predicate(|m: &MODULEENTRY32W| m.modBaseAddr as u64, &cmp)(m, m.szExePath.to_vec()),
            None,
        ) {
            Ok(r) => return Ok(r),
            //This should return, if ntdll is disabled. If ntdll is enabled, this gets discarded
            Err(v) =>
            {
                #[cfg(not(feature = "ntdll"))]
                return Err(v)
            }
        }
    } else {
        warn!("We are injecting from a x86 injector into a x64 target executable. ");
        #[cfg(not(feature = "ntdll"))]
        return Err(Error::Unsupported(Some("No Ntdll support enabled. Cannot get module. Target process is x64, but we are compiled as x86.".to_string())));
    }
    #[cfg(feature = "ntdll")]
    {
        info!("Trying get_module_in_proc as fallback method.");
        unsafe {
            return ntdll::NTDLL::new()?.get_module_in_proc(
                proc,
                predicate(
                    |w: Wrap<LDR_DATA_TABLE_ENTRY32, ntdll::LDR_DATA_TABLE_ENTRY64>| match w {
                        Wrap::T32(w) => w.DllBase as u64,
                        Wrap::T64(w) => w.DllBase as u64,
                    },
                    &cmp,
                ),
            );
        }
    }
}
///Gets a function export from the dll at the specified path (even under WOW), and return the rva, if found.
fn get_dll_export(name: &str, path: String) -> Result<u32> {
    let path = if process::Process::self_proc().is_under_wow()? {
        let str = get_windir()?.clone();
        path.replace(
            &(str.clone() + &"\\System32".to_string()),
            &(str + &"\\Sysnative".to_string()),
        )
    } else {
        path
    };
    debug_assert!(
        std::fs::canonicalize(&path).is_ok(),
        "parsing {} failed",
        path,
    );
    let k32 = std::fs::read(&path)?;
    let dll_parsed = pelite::PeFile::from_bytes(k32.as_slice())?;
    let rva = dll_parsed.get_export_by_name(name)?.symbol().unwrap();
    trace!("Found {} at rva:{} in dll {}", name, rva, path);
    Ok(rva)
}
