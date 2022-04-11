#![cfg(windows)]
mod macros;

use crate::{strip_path, Injector, Result};
use macros::check_ptr;
use std::ffi::OsString;

use log::{debug, error, info, trace, warn};
#[cfg(feature = "ntdll")]
use ntapi::ntapi_base::CLIENT_ID64;
#[cfg(feature = "ntdll")]
use ntapi::ntrtl::RtlCreateUserThread;
use pelite::{Pod, Wrap};
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use winapi::shared::minwindef::{DWORD, FALSE, MAX_PATH};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::processthreadsapi::CreateRemoteThread;
use winapi::um::sysinfoapi::GetSystemWindowsDirectoryW;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    LPPROCESSENTRY32W, MAX_MODULE_NAME32, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use winapi::um::winnt::{
    PROCESS_ALL_ACCESS, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE,
};

mod mem;
#[cfg(feature = "ntdll")]
mod ntdll;
pub(super) mod process;
mod thread;

#[cfg(feature = "ntdll")]
use ntapi::ntwow64::LDR_DATA_TABLE_ENTRY32;
use winapi::shared::ntdef::PHANDLE;

use crate::error::Error;
use mem::MemPage;
use process::Process;
use thread::Thread;

///This function builds a String, from a WTF-encoded buffer.
pub fn str_from_wide_str(v: &[u16]) -> Result<String> {
    OsString::from_wide(v).into_string().map_err(|e| {
        warn!("Couldn't convert widestring, to string. The Buffer contained invalid non-UTF-8 characters . Buf is {:#?}.", e);
        crate::error::Error::WTFConvert(e)
    })
}

impl<'a> Injector<'a> {
    ///This Function will find all currently processes, with a given name.
    ///Even if no processes are found, an empty Vector should return.
    pub fn find_pid<P: AsRef<Path>>(name: P) -> Result<Vec<u32>> {
        let name = name.as_ref();
        Self::find_pid_selector(|p| {
            return match str_from_wide_str(crate::trim_wide_str(p.szExeFile.to_vec()).as_slice()) {
                Ok(str) => {
                    debug!("Checking {} against {}", str, name.to_string_lossy());
                    return name.ends_with(str.as_str());
                }
                Err(e) => {
                    warn!("Skipping check of process. Can't construct string, to compare against. Err:{:#?}",e);
                    false
                }
            };
        })
    }
    ///This function will attempt, to eject a dll from another process.
    ///Notice:This implementation blocks, and waits, until the library is ejected?, or the ejection failed.
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
        // let (_path, base) = get_module(name.as_str(), &proc)?;
        let handle = get_module_in_pid(
            self.pid,
            |m| {
                if let Ok(v) = str_from_wide_str(&m.szModule) {
                    if cmp(&name)(&&v) {
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
        info!("Found dll in proc, with handle:{:#x?}", handle);
        //If the target process is x86, this is slightly too much,
        //but the windows kernel seems to allocate at least 4k, so this does not matter.
        const SIZE: usize = core::mem::size_of::<u64>();
        //scope here, so Vec will get deleted after this
        let mem = {
            let mut mempage = MemPage::new(&proc, SIZE, false)?;
            let mut buf = Vec::with_capacity(SIZE);
            if proc.is_under_wow()? {
                buf.append(&mut (handle as usize).as_bytes().to_vec());
            } else {
                buf.append(&mut handle.as_bytes().to_vec());
            }
            buf.shrink_to_fit();
            mempage.write(buf.as_slice())?;
            mempage
        };
        self.exec_fn_in_proc(&proc, "FreeLibrary", mem)
    }

    ///Inject a DLL into another process
    ///Notice:This implementation blocks, and waits, until the library is injected, or the injection failed.
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
    ///This function executes the entry_fn from Kernel32.dll with the argument of mem in the process proc.
    ///the process mem was created with, and proc must hold the same handle.
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
        if !mem.check_proc(proc) {
            return Err(crate::error::Error::Io(std::io::Error::from(
                std::io::ErrorKind::AddrNotAvailable,
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
        #[cfg(feature = "x86tox64")]
        {
            //This method is intended to be only used, when we are compiled as x86, and are injecting to x64.
            let ntdll = self_is_under_wow && !pid_is_under_wow;
            #[cfg(test)]
            //Lock this thread for the minimal amount of time possible
            let ntdll = { test::FNS_M.with(|x| x.exec_fn_in_proc.get()) || ntdll };
            if ntdll {
                #[cfg(target_arch = "x86")]
                let (r, t, _c) = {
                    let ntdll = ntdll::NTDLL::new()?;
                    let (path, base) = ntdll.get_ntdll_base_addr(pid_is_under_wow, &proc)?;
                    let rva = get_dll_export("RtlCreateUserThread", path)?;
                    let va = base + rva as u64;
                    unsafe {
                        crate::platforms::x86::exec(
                            va,
                            proc.get_proc(),
                            std::ptr::null_mut(),
                            0,
                            0,
                            0,
                            0,
                            entry_point as u64,
                            mem.get_address() as u64,
                        )?
                    }
                };
                #[cfg(not(target_arch = "x64"))]
                let (r, t, _c) = {
                    let mut c = CLIENT_ID64 {
                        UniqueProcess: 0,
                        UniqueThread: 0,
                    };
                    let mut t = std::ptr::null_mut();
                    let r = unsafe {
                        RtlCreateUserThread(
                            proc.get_proc(),
                            std::ptr::null_mut(),
                            0,
                            0,
                            0,
                            0,
                            std::mem::transmute(entry_point as usize),
                            mem.get_address(),
                            &mut t as PHANDLE,
                            std::mem::transmute(&mut c as *mut CLIENT_ID64),
                        )
                    };
                    (r, t, c)
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
///This gets the directory, where windows files reside. Usually C:\Windows
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

///Takes in a Name. From that it returns a matcher
///Takes a Selector, and returns a type, for use with get_module_in_proc and get_module_in_pid
///name specifies, what module to look for.
///f processes the other input from other functions
//todo: does this bring a performance benefit?
fn predicate<T, F, C>(f: T, cmp: C) -> impl Fn(F, Vec<u16>) -> Option<(String, u64)>
where
    T: Fn(F) -> u64,
    C: Fn(&String) -> bool,
{
    move |i2, v| match str_from_wide_str(crate::trim_wide_str(v).as_slice()) {
        Ok(s) => {
            if cmp(&s) {
                Some((s, f(i2)))
            } else {
                None
            }
        }
        Err(_) => None,
    }
}
///Returns a function, which compares a &str against a name
//todo: make the second function call better
fn cmp<P: AsRef<Path>>(name: P) -> impl Fn(&dyn AsRef<Path>) -> bool {
    move |s| {
        return name.as_ref().ends_with(&s) || s.as_ref().ends_with(&name);
    }
}

///Gets the base address of where a dll is loaded within a process.
///The dll is identified by name. name is checked against the whole file name.
///if the process has a pseudo-handle, the ntdll methods will not run.
fn get_module<P: AsRef<Path>>(name: P, proc: &Process) -> Result<(String, u64)> {
    let cmp = cmp(name);
    let ntdll = !process::Process::self_proc().is_under_wow()? || proc.is_under_wow()?;
    #[cfg(test)]
    let ntdll = { test::FNS_M.with(|x| x.get_module.get()) || ntdll };
    if ntdll {
        match get_module_in_pid(
            proc.get_pid(),
            |m| {
                predicate(|m: &MODULEENTRY32W| m.modBaseAddr as u64, |x| (&cmp)(&x))(
                    m,
                    m.szExePath.to_vec(),
                )
            },
            None,
        ) {
            Ok(r) => return Ok(r),
            //This should return, if ntdll is disabled. If ntdll is enabled, this gets discarded
            #[cfg_attr(feature = "ntdll", allow(unused_variables))]
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
                    |x| (&cmp)(&x),
                ),
            );
        }
    }
}
///Gets a function export from the dll at the specified path (even under WOW), and return the rva, if found.
///
///This gets the Relative Virtual Address (rva) of the function name, from a pe-file.
///This function will make sure, that all requests, that according to path should go to %windir%/System32, actually go there.
///If you want to get an export from a 32-bit dll under 64-bit windows specify %windir%/SysWOW64.
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

#[cfg(test)]
pub mod test {
    use crate::{Injector, Result};
    use std::cell::Cell;
    use std::ffi::OsString;
    use std::io::Read;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::process::Child;
    use std::thread::sleep;
    use std::time::Duration;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::libloaderapi::{FreeLibrary, LoadLibraryA};
    use winapi::um::tlhelp32::MODULEENTRY32W;
    use winapi::um::winbase::CREATE_NEW_CONSOLE;
    use winapi::um::winnt::PROCESS_ALL_ACCESS;

    thread_local! {
        pub(in super) static FNS_M:FNS=FNS::default();
    }
    #[derive(Debug)]
    pub(super) struct FNS {
        pub get_module: Cell<bool>,
        pub exec_fn_in_proc: Cell<bool>,
    }
    impl Default for FNS {
        fn default() -> Self {
            FNS {
                get_module: Cell::new(false),
                exec_fn_in_proc: Cell::new(false),
            }
        }
    }

    pub fn create_cmd() -> (Child, super::process::Process) {
        let c = std::process::Command::new("cmd.exe")
            .creation_flags(CREATE_NEW_CONSOLE)
            .spawn()
            .unwrap();
        sleep(Duration::from_millis(50)); //Let the process init.
        let proc = unsafe {
            super::process::Process::from_raw_parts(
                c.as_raw_handle() as usize,
                c.id(),
                CREATE_NEW_CONSOLE | PROCESS_ALL_ACCESS,
            )
        };
        (c, proc)
    }

    #[test]
    fn get_windir() -> Result<()> {
        let r = super::get_windir();
        assert!(r.is_ok(), "get_windir returned Err({})", r.unwrap_err());
        let f = std::fs::read_dir(r.unwrap());
        assert!(
            f.is_ok(),
            "Couldn't read Windows dir. Error is {}",
            f.unwrap_err()
        );
        //can't do too much in this test sadly, since we can't assume a "normal" windows environment.
        //Testing if the string returned from get_windir is the most I can do here.
        Ok(())
    }

    #[test]
    fn get_dll_export() -> Result<()> {
        let mut path = std::path::PathBuf::from(super::get_windir()?);
        path.push("System32"); //Cannot assume, that everyone has WOW installed.
        {
            let mut ntdll = path.clone();
            ntdll.push("ntdll.dll");
            let r =
                super::get_dll_export("RtlCreateUserThread", ntdll.to_str().unwrap().to_string());
            assert!(r.is_ok(), "get_dll_export returned err:{}", r.unwrap_err());
            r?;
        }
        {
            let mut kernel32 = path;
            kernel32.push("kernel32.dll");
            let r = super::get_dll_export("LoadLibraryW", kernel32.to_str().unwrap().to_string());
            assert!(r.is_ok(), "get_dll_export returned err:{}", r.unwrap_err());
            r?;
        }
        Ok(())
    }

    #[test]
    fn cmp() {
        //Simple case
        {
            let f = super::cmp("test");
            assert!(f(&"test"));
            assert!(!f(&"not test"));
            let f = super::cmp("KERNEL32.DLL");
            assert!(f(&&"C:\\Windows\\System32\\KERNEL32.DLL".to_string()));
            let f = super::cmp("ntdll.dll");
            assert!(f(&&"C:\\Windows\\SYSTEM32\\ntdll.dll".to_string()));
        }
        //complicated paths
        {
            let f = vec![
                super::cmp("C:\\this\\is\\a\\test\\path\\with\\a\\dir\\at\\the\\end\\"),
                super::cmp("C:\\this\\is\\a\\test\\path\\with\\a\\dir\\at\\the\\end"),
                super::cmp("C:/this/is/a/test/path/with/a/dir/at/the/end/"),
                super::cmp("C:/this/is/a/test/path/with/a/dir/at/the/end"),
            ];
            for f in f {
                assert!(f(&"end"));
                assert!(f(&"the\\end"));
                assert!(f(&"the/end"));
                assert!(f(&"at/the\\end"));
                assert!(f(&"at\\the/end"));
            }
        }
    }

    #[test]
    fn str_from_wide_str() -> Result<()> {
        //test empty string
        assert_eq!(super::str_from_wide_str(vec![].as_slice())?, "".to_string());
        //Test just about every special char I could think of.
        let wide_str: Vec<u16> = OsString::from(crate::test::STR.to_string())
            .as_os_str()
            .encode_wide()
            .collect();
        assert_eq!(
            super::str_from_wide_str(wide_str.as_slice())?,
            crate::test::STR.to_string()
        );

        Ok(())
    }

    #[test]
    fn predicate() {
        //If nothing matches, we should get NONE back
        assert_eq!(super::predicate(|_| 0, |_| false)((), vec![]), None);
        //If something matches, we should get a result
        assert_eq!(
            super::predicate(|_| 0, |_| true)((), vec![]),
            Some(("".to_string(), 0))
        );
    }

    #[test]
    fn get_module_in_pid() -> Result<()> {
        let test = |id: u32| {
            super::get_module_in_pid(
                id,
                |m| {
                    super::predicate(
                        |m: &MODULEENTRY32W| m.modBaseAddr as u64,
                        |x| super::cmp("ntdll.dll")(&x),
                    )(m, m.szModule.to_vec())
                },
                None,
            )
        };
        //test self
        {
            let h = unsafe { LoadLibraryA(b"ntdll.dll\0".as_ptr() as *mut i8) };
            assert!(!h.is_null(), "Couldn't load ntdll into our current process");
            let (_, n) = test(std::process::id())?;
            if n != h as u64 {
                println!("Base Address!=LoadLibraryA, {}!={}", n, h as u64)
            };
            let r = unsafe { FreeLibrary(h) };
            assert_ne!(r, 0, "FreeLibrary failed, because {}", unsafe {
                GetLastError()
            });
        }
        //test other
        {
            let (mut c, p) = create_cmd();
            if p.is_under_wow()? || !super::process::Process::self_proc().is_under_wow()? {
                test(c.id())?;
            }
            c.kill().unwrap();
        }
        Ok(())
    }

    #[test]
    fn get_module() -> Result<()> {
        //self test
        {
            let r = super::get_module("ntdll.dll", super::process::Process::self_proc());
            assert!(r.is_ok(), "normal self get_module err:{}", r.unwrap_err());
        }
        let (mut c, cp) = create_cmd();
        //other test
        {
            let r = super::get_module("ntdll.dll", &cp);
            assert!(r.is_ok(), "normal other get_module err:{}", r.unwrap_err());
        }
        #[cfg(feature = "ntdll")]
        {
            let proc = super::process::Process::new(std::process::id(), PROCESS_ALL_ACCESS)?;
            FNS_M.with(|x| x.get_module.set(true));
            let r = super::get_module("KERNEL32.DLL", &proc);
            let r1 = super::get_module("KERNEL32.DLL", &cp);
            FNS_M.with(|x| x.get_module.set(false));
            assert!(r.is_ok(), "ntdll self get_module:{}", r.unwrap_err());
            assert!(r1.is_ok(), "ntdll other get_module:{}", r.unwrap_err());
        }
        c.kill().unwrap();
        Ok(())
    }

    #[test]
    fn find_pid() -> Result<()> {
        let exe = std::env::current_exe()?;
        let i = Injector::find_pid(exe);
        assert!(i.is_ok(), "{}", i.unwrap_err());
        assert!(
            i?.contains(&std::process::id()),
            "The result did not contain our current process id."
        );

        Ok(())
    }
}
