#![cfg(target_os = "windows")]
mod macros;

use crate::macros::{err_str, result};
use crate::{strip_rust_path, strip_win_path, Error, Injector, Result};
use macros::{check_nt_status, check_ptr};
use std::cell::Cell;

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
use winapi::shared::ntdef::{
    NTSTATUS, NT_ERROR, NT_WARNING, PULONG, PVOID, PVOID64, ULONG, ULONGLONG,
};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::libloaderapi::{
    FreeLibrary, GetModuleHandleA, GetProcAddress, LoadLibraryA, DONT_RESOLVE_DLL_REFERENCES,
    LOAD_LIBRARY_AS_DATAFILE, LOAD_LIBRARY_AS_IMAGE_RESOURCE,
};
use winapi::um::memoryapi::VirtualAlloc;
use winapi::um::processthreadsapi::{CreateRemoteThread, GetCurrentProcess, OpenProcess};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::sysinfoapi::{GetNativeSystemInfo, GetSystemWindowsDirectoryA, SYSTEM_INFO};
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

#[cfg(feature = "ntdll")]
mod types; //These are exclusively ntdll types

mod mem;
mod process;
mod thread;

use std::thread::{sleep, yield_now};
//todo: are these imports gateable?
use ntapi::ntapi_base::{CLIENT_ID, CLIENT_ID64, PCLIENT_ID, PCLIENT_ID64};
use ntapi::ntpsapi::{NtCreateProcess, NtCreateThread};
use ntapi::ntrtl::{RtlCreateUserThread, PUSER_THREAD_START_ROUTINE};

use crate::platforms::platform::macros::{err, void_res};
use crate::platforms::platform::mem::MemPage;
use crate::platforms::platform::process::Process;
use once_cell::sync::OnceCell;
use pelite::Align::File;
use pelite::Wrap::T32;

impl<'a> Injector<'a> {
    //todo: use the structs
    pub fn eject(&self) -> Result<()> {
        if self.pid == 0 {
            warn!("Supplied id is 0. Will not eject.");
            return err_str("PID is 0");
        }
        let addr = match get_module_in_pid_predicate(self.pid, self.dll, None) {
            Ok(v) => v,
            Err(err) => {
                return Err(err);
            }
        };

        info!("Found dll in proc, at addr:{:#x?}", addr);
        //Spawn the thread, that ejects the dll
        {
            let proc = process::Process::new(
                self.pid,
                PROCESS_CREATE_THREAD
                    | PROCESS_VM_WRITE
                    | PROCESS_VM_OPERATION
                    | PROCESS_QUERY_INFORMATION,
            )?;
            debug!("Process Handle is {:?}", proc.get_proc());

            let thread_start = {
                //try to get the LoadLibraryA function direct from the target executable.
                let (k32path, k32addr) = get_module_in_pid_predicate_selector(
                    self.pid,
                    "KERNEL32.DLL",
                    |m| (m.szExePath, m.modBaseAddr),
                    None,
                )?;
                let str = result!(crate::str_from_wide_str(&k32path)
                    .map_err(|_| "Couldn't convert Wide string to rust string."));
                let k32 = result!(std::fs::read(&str));

                let dll_parsed = result!(
                    Wrap::<pelite::pe32::PeFile, pelite::pe64::PeFile>::from_bytes(k32.as_slice())
                );
                let lla = result!(dll_parsed.get_export_by_name("FreeLibraryAndExitThread"))
                    .symbol()
                    .unwrap();
                debug!("FreeLibraryAndExitThread is {:x}", lla);
                //todo: can we use add instead of wrapping_add?
                k32addr.wrapping_add(lla as usize)
            };

            let mut thread_id: u32 = 0;
            let thread = unsafe {
                thread::Thread::new(CreateRemoteThread(
                    proc.get_proc(),
                    std::ptr::null_mut(),
                    0,
                    Some(std::mem::transmute(thread_start)),
                    addr as *mut c_void,
                    0,
                    // *ptr_attr_list,
                    &mut thread_id as *mut u32,
                ))
            }?;
            let thread_id = thread_id;
            trace!("Thread is {:?} and thread id is {}", *thread, thread_id);
            debug!("Waiting for DLL to eject");
            match unsafe { WaitForSingleObject(*thread, INFINITE) } {
                0x80 => {
                    return err_str("WaitForSingleObject returned WAIT_ABANDONED");
                } //WAIT_ABANDONED
                0x0 => {
                    info!("Dll eject success? IDK?! Hopefully? WaitForSingleObject returned WAIT_OBJECT_0")
                } //WAIT_OBJECT_0
                0x102 => {
                    return err_str("Timeout hit at WaitForSingleObject.");
                } //WAIT_TIMEOUT
                0xFFFFFFFF => {
                    return macros::err("WaitForSingleObject");
                } //WAIT_FAILED
                _ => {}
            }
        }
        if get_module_in_pid_predicate(self.pid, self.dll, None).is_err() {
            error!("The above error is expected!");
            Ok(())
        } else {
            info!("Inject actually failed");
            Err((
                "Inject didn't succeed. Blame the dll, or Windows, but I tried.".to_string(),
                0,
            ))
        }
    }

    ///Actually Inject the DLL.
    ///For now, the injection is only likely to succeed, if the injector, dll and target process have the same bitness (all x64, or all x86)
    ///Open a Pr, if you know more about this!
    ///Return information (Outside of Ok and Err) is purely informational (for now)! It should not be relied upon, and may change in Minor updates.
    ///Notice:This implementation blocks, and waits, until the library is injected, or the injection failed.
    /// # Panic
    /// This function may panic, if a Handle cleanup fails.
    #[no_mangle]
    pub fn inject(&self) -> Result<()> {
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
            warn!("Supplied id is 0. Will not inject, as it is not supported by windows");
            return err_str("PID is 0");
        }
        let proc = Process::new(
            self.pid,
            PROCESS_CREATE_THREAD
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ
                | PROCESS_VM_OPERATION
                | PROCESS_QUERY_INFORMATION
                | PROCESS_ALL_ACCESS,
        )?;
        let self_proc = Process::self_proc();
        debug!("Process is {}", proc);
        //Check DLL, target process bitness and the bitness, of this injector
        // let sys_is_x64;
        // let sys_is_x86;
        // {
        // 	let mut sysinfo: MaybeUninit<SYSTEM_INFO> = MaybeUninit::zeroed();
        // 	unsafe { GetNativeSystemInfo(sysinfo.as_mut_ptr()) }//Has no return-value, so should always succeed?
        // 	let sysinfo = unsafe { sysinfo.assume_init() };
        // 	sys_is_x64 = unsafe { sysinfo.u.s() }.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64;
        // 	sys_is_x86 = unsafe { sysinfo.u.s() }.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL;
        // 	assert_ne!(sys_is_x64,sys_is_x86,"Cannot be both or neither x64 and x86! This path should be impossible! Something has gone catastrophically wrong.")
        // }

        //Is the target exe x86?
        let pid_is_under_wow = *proc.is_under_wow()?;
        // Is this exe x86?
        let self_is_under_wow = *self_proc.is_under_wow()?;

        info!(
            "pid_is_under_wow:{},self_is_under_wow:{}",
            pid_is_under_wow, self_is_under_wow
        );
        if self_is_under_wow && !pid_is_under_wow {
            if cfg!(feature = "ntdll") {
                warn!("This injection will use a slightly different method, than usually. This is normal, when the injector is x86, but the pid specified is a x64 process.\
				We will be using ntdll methods. The ntdll.dll is technically not a public facing windows api.");
            } else {
                return err_str("Cannot continue injection. You are trying to inject from a x86 injector into a x64 application. That is unsupportable, without access to ntdll functions.");
            }
        };

        let dll_is_x64 = self.get_is_dll_x64()?;

        if dll_is_x64 && pid_is_under_wow {
            error!("Injecting a x64 dll, into a x86 exe is unsupported. Will NOT abort, but expect the dll-injection to fail");
            return Err(("Unsupported".to_string(), 0));
        } else if !dll_is_x64 && !pid_is_under_wow {
            error!("Injecting a x86 dll, into a x64 exe is unsupported. Could this case be supported? Send a PR, if you think, you can make this work! Will NOT abort, but expect the dll-injection to fail");
            return Err(("Unsupported".to_string(), 0));
        }
        #[cfg(not(feature = "ntdll"))]
        if self_is_under_wow && !pid_is_under_wow {
            return err_str("Cannot inject into a x64 Application without ntdll access.");
        }
        //This check makes sure, that get_module_in_pid_predicate will not fail, due to x86->x64 injection.
        if !self_is_under_wow || pid_is_under_wow {
            //Is the dll already injected?
            if get_module_in_pid_predicate(self.pid, self.dll, None).is_ok() {
                return err_str("dll already injected");
            } else {
                error!("The above error is expected!")
            }
        }
        //todo: check with get_module_in_proc?

        //todo: add other paths, if bitness of injector == bitness of dll == bitness of target?
        //todo: That could lead to better performance.

        let entry_point = {
            let (path, base) = get_module("KERNEL32.DLL", &proc)?;
            base + get_dll_export("LoadLibraryW", path)? as u64
        };

        //Prepare Argument for LoadLibraryA
        let mem = {
            let test = std::fs::canonicalize(self.dll)
                .unwrap()
                .to_str()
                .unwrap()
                .as_bytes();
            let full_path: PathBuf = result!(std::fs::canonicalize(self.dll));
            let path: Vec<u16> = full_path.as_os_str().encode_wide().chain(Some(0)).collect();
            let mempage = mem::MemPage::new(
                proc.get_proc(),
                path.len() * core::mem::size_of::<u16>(),
                false,
            )?;
            mempage.write(path.as_bytes())?;
            mempage
        };
        info!(
            "Allocated LoadLibraryW Parameter at {:x?}",
            mem.get_address()
        );
        debug!("entry proc:{:x} vs {:x}", entry_point, entry_point as usize);

        //Execute LoadLibraryW in remote thread, and wait for dll to load
        #[cfg(all(feature = "ntdll", target_arch = "x86"))]
        {
            //This method is intended to be only used, when we are compiled as x86, and are injecting to x64.
            if self_is_under_wow && !pid_is_under_wow {
                let mut thread: HANDLE = null_mut();
                let mut client: CLIENT_ID = CLIENT_ID {
                    UniqueProcess: null_mut(),
                    UniqueThread: null_mut(),
                };

                let (path, base) = get_ntdll_base_addr(pid_is_under_wow, &proc)?;
                let rva = get_ntdll_function(path, "RtlCreateUserThread".to_string())?;
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
                        entry_point as LPVOID,
                        mem.get_address(),
                    )?
                };
                if let Some(tmp) = check_nt_status(r) {
                    return Err(tmp);
                }
                //Idea: Replace the x64 pointer with a x86 pointer, we could theoretically pass.
                //      That x86 pointer will be a jmp instruction, to the place we actually want to jump to.
                // const MOV_RAX:&[u8]=&[0x48u8,0xB8]; /* mov rax, */
                // const JMP:&[u8]=&[0xFFu8,0xE0];  /* jmp rax */
                //
                // let mut jmp_fn:Vec<u8> = Vec::with_capacity(MOV_RAX.len()+8+ JMP.len());
                // jmp_fn.append(&mut MOV_RAX.to_vec());
                // jmp_fn.append(&mut entry_point.to_le_bytes().to_vec());
                // jmp_fn.append(&mut JMP.to_vec());
                // jmp_fn.shrink_to_fit();
                // let jmp_fn=jmp_fn;
                // let entry_jmp_fn = mem::MemPage::new(proc.get_proc(),jmp_fn.len(),true)?;
                // entry_jmp_fn.write(jmp_fn.as_bytes())?;
                //Idea 1: Use regular CreateRemoteThread, but instead of having a x64 ptr, that we cannot pass, we create a mempage within x86 address space, that jmp's to the target fn.
                //Will not work, because Access Denied 0x5
                // let mut thread_id:u32=0;
                // let thread = guard_check_ptr!(
                //     CreateRemoteThread(
                //         proc.get_proc(),
                //         std::ptr::null_mut(),
                //         0,
                //         Some(std::mem::transmute(entry_jmp_fn.get_address())),
                //         mem.get_address(),
                //         0,
                //         &mut thread_id as *mut u32
                //     ),"thread");
                // let thread_id = thread_id;
                // trace!("Thread is {:?} and thread id is {}", *thread, thread_id);
                // info!("Waiting for DLL");
                // // std::thread::sleep(Duration::new(0,500));//todo: why is this necessary, (only) when doing cargo run?
                // match unsafe{WaitForSingleObject(*thread,INFINITE)}{
                // 	0x80=>{return err_str("WaitForSingleObject returned WAIT_ABANDONED")},//WAIT_ABANDONED
                // 	0x0=>{info!("Dll inject success? IDK?! Hopefully? WaitForSingleObject returned WAIT_OBJECT_0");},//WAIT_OBJECT_0
                // 	0x102=>{return err_str("Timeout hit at WaitForSingleObject.")},//WAIT_TIMEOUT
                // 	0xFFFFFFFF=>{return macros::err("WaitForSingleObject")},//WAIT_FAILED
                // 	_=>{}
                // }
                //Idea 2: Use RTLCreateUserThread
                //Will not work. Has the same issue, as idea #1. 0xc0000022 Access Denied
                // unsafe {
                // 	let r = RtlCreateUserThread(proc.get_proc(),null_mut(),0,0,0,0,std::mem::transmute(entry_jmp_fn.get_address()),mem.get_address(),&mut thread as PHANDLE,&mut client as PCLIENT_ID);
                // 	match check_nt_status(r){
                // 		Some(e)=>return Err(e),
                // 		None=>{},
                // 	};
                // 	println!("{:x}",r);
                // }
                return err_str("Not implemented");
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
            match unsafe { WaitForSingleObject(*thread, INFINITE) } {
                0x80 => return err_str("WaitForSingleObject returned WAIT_ABANDONED"), //WAIT_ABANDONED
                0x0 => {
                    info!("Dll inject success? IDK?! Hopefully? WaitForSingleObject returned WAIT_OBJECT_0");
                } //WAIT_OBJECT_0
                0x102 => return err_str("Timeout hit at WaitForSingleObject."), //WAIT_TIMEOUT
                0xFFFFFFFF => return macros::err("WaitForSingleObject"),        //WAIT_FAILED
                _ => {}
            }
            return Ok(());
        }
        return err_str("No viable injection method.");
        //Check, if the dll is actually loaded?
        //todo: can we skip this? is the dll always guaranteed to be loaded here, or is it up to the dll, to decide that?
        //todo: re-add a check, for loaded modules

        // get_module_in_pid_predicate_selector(self.pid,self.dll,|_|(),None)
        Err(("".to_string(), 0))
    }

    ///Find a PID, where the process-name matches some user defined selector
    pub fn find_pid_selector<F>(select: F) -> Result<Vec<u32>>
    where
        F: Fn(&PROCESSENTRY32W) -> bool,
    {
        let mut pids: Vec<DWORD> = Vec::new();
        let snap_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap_handle == INVALID_HANDLE_VALUE {
            return macros::err("CreateToolhelp32Snapshot");
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
            return macros::err("Process32FirstW");
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
        let dll = result!(std::fs::read(self.dll));
        // let parsed = result!(Wrap::<pelite::pe32::PeFile,pelite::pe64::PeFile>::from_bytes(dll.as_slice()));
        return match pelite::pe64::PeFile::from_bytes(dll.as_slice()) {
            Ok(_) => return Ok(true),
            Err(pelite::Error::PeMagic) => pelite::pe32::PeFile::from_bytes(dll.as_slice())
                .map_err(|err| {
                    error!("{}", err);
                    (format!("{}", err), 0)
                })
                .map(|_| false),
            Err(err) => return err_str(err),
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
            error!("Encountered error, while calling Module32NextW. This is expected, if there isn't a dll, with the specified name loaded.");
            return macros::err("Module32NextW");
        }
    }
}
///Does NOT work, if the injector is x86, and the target exe is x64.
///This is, due to Microsoft constraints.
///The Constraint lies with the Function `CreateToolhelp32Snapshot`. More in the Microsoft docs [here](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot).
///
/// # Arguments
///- pid: process pid
///- dll: the dll, that is to be searched for
///- selector: a Function, which returns any desired value.
///- snapshot_flags: an option, to pass other flags, to `CreateToolhelp32Snapshot`
fn get_module_in_pid_predicate_selector<F, T>(
    pid: u32,
    dll: &str,
    selector: F,
    snapshot_flags: Option<u32>,
) -> Result<T>
where
    F: Fn(&MODULEENTRY32W) -> T,
{
    let dll_no_path = strip_rust_path(dll);
    trace!("dll_no_path='{}'", dll_no_path);
    get_module_in_pid(
        pid,
        move |module_entry: &MODULEENTRY32W| {
            //The errors below are not handled really well, because I do not think, they will actually occur.
            let module = match crate::str_from_wide_str(&module_entry.szModule) {
                Ok(v) => v,
                Err(e) => {
                    return None;
                }
            };
            trace!(
                "module:'{}', module==dll_no_path:'{}'",
                module,
                module == dll_no_path
            );
            if module == dll_no_path {
                return Some(selector(&module_entry.clone()));
            }
            None
        },
        snapshot_flags,
    )
}
///Does NOT work, if the injector is x86, and the target exe is x64.
///This is, due to Microsoft constraints.
///The Constraint lies with the Function `CreateToolhelp32Snapshot`. More in the Microsoft docs [here](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot).
///
/// # Arguments
///- pid: process pid
///- dll: the dll, that is to be searched for
///- snapshot_flags: an option, to pass other flags, to `CreateToolhelp32Snapshot`
///# Return value
/// Returns the dll's base address.
fn get_module_in_pid_predicate(
    pid: u32,
    dll: &str,
    snapshot_flags: Option<u32>,
) -> Result<*mut u8> {
    get_module_in_pid_predicate_selector(
        pid,
        dll,
        |module_entry: &MODULEENTRY32W| module_entry.modBaseAddr,
        snapshot_flags,
    )
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
#[cfg(feature = "ntdll")]
unsafe fn get_module_in_proc<F, R>(proc: &Process, predicate: F) -> Result<R>
where
    F: Fn(
        Wrap<ntapi::ntwow64::LDR_DATA_TABLE_ENTRY32, types::LDR_DATA_TABLE_ENTRY64>,
        Vec<u16>,
    ) -> Option<R>,
{
    let pid_under_wow = *proc.is_under_wow()?;
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
            query_process_information(proc.get_proc(), ntapi::ntpsapi::ProcessBasicInformation)?;
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
            let peb = read_virtual_mem::<PEB32>(proc.get_proc(), peb_addr)?;
            (*peb).Ldr as u64
        } else {
            let peb = read_virtual_mem::<PEB64>(proc.get_proc(), peb_addr)?;
            (*peb).Ldr as u64
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
            let ldr = read_virtual_mem::<PEB_LDR_DATA32>(proc.get_proc(), ldr_addr)?;
            (*ldr).InLoadOrderModuleList.Flink as u64
        } else {
            let ldr = read_virtual_mem::<PEB_LDR_DATA64>(proc.get_proc(), ldr_addr)?;
            (*ldr).InLoadOrderModuleList.Flink as u64
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
            let entry = read_virtual_mem(proc.get_proc(), modlist_addr as u64)?;
            debug!("Read the LDR_DATA_Table {:#?}", entry);
            ldr_entry_data = Wrap::T32(*entry);
        } else {
            let entry = read_virtual_mem(proc.get_proc(), modlist_addr as u64)?;
            debug!("Read the LDR_DATA_Table {:#?}", entry);
            ldr_entry_data = Wrap::T64(*entry);
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
                return Err((RECURSION.to_string(), 0));
            }

            let dll_path_buf = read_virtual_mem_fn(
                proc.get_proc(),
                dll_win_string_buffer,
                (dll_win_string_length) as usize,
            )?;
            let dll_path_old = dll_path_buf.as_slice();
            let mut dll_path = Vec::with_capacity(((dll_win_string_length >> 1) + 1) as usize);
            let mut i = 0;
            while i < dll_path_buf.len() >> 1 {
                dll_path.push((dll_path_old[2 * i + 1] as u16).shl(8) | dll_path_old[2 * i] as u16);
                i += 1;
            }

            match crate::str_from_wide_str(dll_path.as_slice()) {
                Ok(v) => {
                    debug!("dll_name is {}", v);
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

///Checks a NtStatus. Will return Some value, if it is a critical error.
///Otherwise, it will log the status, and return None.
fn check_nt_status(status: NTSTATUS) -> Option<Error> {
    if NT_ERROR(status) {
        error!(
            "Received error type, from ntdll. Status code is: {:x}",
            status
        );
        return Some(("ntdll".to_string(), status as u32));
    }
    if NT_WARNING(status) {
        warn!(
            "Received warning type, from ntdll. Status code is: {:x}",
            status
        );
    }
    None
}
///See [read_virtual_mem_fn].
#[cfg(feature = "ntdll")]
unsafe fn read_virtual_mem<T>(proc: HANDLE, addr: u64) -> Result<*mut T> {
    let v = read_virtual_mem_fn(proc, addr, size_of::<T>())?;
    Ok(v.leak().as_mut_ptr() as *mut T)
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
#[cfg(feature = "ntdll")]
unsafe fn read_virtual_mem_fn(proc: HANDLE, addr: u64, size: usize) -> Result<Vec<u8>> {
    //This is the prototype, of the NtReadVirtualMemory function
    type FnNtReadVirtualMemory = fn(HANDLE, DWORD64, PVOID, ULONG64, PDWORD64) -> NTSTATUS;
    //todo: use once cell, or make a struct, for ntdll.
    static mut NT_READ_VIRTUAL_MEMORY_OPT: Option<FnNtReadVirtualMemory> = None;
    // let NtReadVirtualMemory=match NT_READ_VIRTUAL_MEMORY_OPT {
    // 	None=> {
    //      //This is false. we should
    // 		let self_is_under_wow = get_proc_under_wow(GetCurrentProcess())?;
    // 		let rvm: &[u8] = if self_is_under_wow { b"NtWow64ReadVirtualMemory64\0" } else { b"NtReadVirtualMemory\0" };
    // 		let ntdll = LoadLibraryA(b"ntdll\0".as_ptr() as *const i8);
    // 		let proc= std::mem::transmute(check_ptr!(GetProcAddress(ntdll,rvm.as_ptr() as *const i8)));
    // 		NT_READ_VIRTUAL_MEMORY_OPT.insert(proc);
    // 		proc
    // 	},
    // 	Some(v)=>v,
    // };
    let self_is_under_wow = *Process::self_proc().is_under_wow()?;
    let rvm: &[u8] = if self_is_under_wow {
        b"NtWow64ReadVirtualMemory64\0"
    } else {
        b"NtReadVirtualMemory\0"
    };
    let ntdll = LoadLibraryA(b"ntdll\0".as_ptr() as *const i8);
    let fnc: FnNtReadVirtualMemory =
        std::mem::transmute(check_ptr!(GetProcAddress(ntdll, rvm.as_ptr() as *const i8)));
    let NtReadVirtualMemory = fnc;

    let mut buf: Vec<u8> = Vec::with_capacity(size);
    trace!("reading at address {:x?} {} bytes", addr, size);
    let mut i: u64 = 0;
    let status = check_nt_status!(NtReadVirtualMemory(
        proc,
        addr,
        buf.as_mut_ptr() as *mut c_void,
        size as u64,
        &mut i as *mut u64
    ));
    trace!("rvm {:x},{}/{}", status as u32, i, size);
    //We read i bytes. So we let the Vec know, so it can calculate size and deallocate accordingly, if it wants.
    //Also: This will enable debugger inspection, of the buf, since the debugger will now know, that the vec is initialised.
    buf.set_len(i as usize);
    Ok(buf)
}
///This reads `size` elements, of size T, of memory, from address `addr`, in the process `proc`, into `buf`.
///
///# Safety
///`proc` needs to have the PROCESS_QUERY_INFORMATION (or PROCESS_QUERY_LIMITED_INFORMATION?) access rights.
///`proc` needs to be valid
///
// ///`buf` needs to be a valid address, to a allocated object, which can hold `size` bytes.
///
///`pic` and the return type need to match up. Not doing so, might end in immediate program termination.
///
///# Termination
///Windows might sometimes decide, to sometimes just end the entire program randomly, meaning, that this function won't return sometimes.
///On other occasions, Windows will return some extraneous value of bytes read.
///In those cases, this function will Panic.
#[cfg(feature = "ntdll")]
unsafe fn query_process_information<T>(
    proc: HANDLE,
    pic: ntapi::ntpsapi::PROCESSINFOCLASS,
) -> Result<T>
where
    T: Copy,
{
    //Function prototype, of the NtQueryInformationProcess function in ntdll.
    type FnNtQueryInformationProcess =
        fn(HANDLE, ntapi::ntpsapi::PROCESSINFOCLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
    //Get function
    static NT_QUERY_INFORMATION_PROCESS_OPT: OnceCell<FnNtQueryInformationProcess> =
        OnceCell::new();
    unsafe fn get_query_info_fn() -> Result<FnNtQueryInformationProcess> {
        let ntdll = LoadLibraryA(b"ntdll\0".as_ptr() as *const i8);
        let self_is_under_wow = *Process::self_proc().is_under_wow()?; //Todo: make this compatible with x86 injection
        let qip: &[u8] = if self_is_under_wow {
            b"NtWow64QueryInformationProcess64\0"
        } else {
            b"NtQueryInformationProcess\0"
        };
        trace!("self_is_under_wow={}", self_is_under_wow);
        let proc_ptr = check_ptr!(GetProcAddress(ntdll, qip.as_ptr() as *const i8));
        let proc = std::mem::transmute(proc_ptr);
        trace!("proc is {:x}", proc_ptr as u64);
        Ok(proc)
    }
    let NtQueryInformationProcess =
        NT_QUERY_INFORMATION_PROCESS_OPT.get_or_try_init(|| unsafe { get_query_info_fn() })?;
    //ready things, for function call
    let mut i = 0u32;
    let i_ptr = &mut i as *mut u32;
    let size_peb: usize = std::mem::size_of::<T>();
    let mut buf: Vec<u8> = vec![0; size_peb];
    //Call function
    trace!("Running NtQueryInformationProcess with fnptr:{:x?} proc:{:x?},pic:{:x}. Size is {}/{}, buf is {:x?}",*NtQueryInformationProcess as usize,proc,pic,size_peb,i, buf);
    let status = check_nt_status!(NtQueryInformationProcess(
        proc,
        pic,
        buf.as_mut_ptr() as *mut c_void,
        size_peb as u32,
        i_ptr
    ));
    trace!(
        "qip {:x},0x{:x}|0x{:x}/0x{:x} buf is {:?}",
        status as u32,
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

fn get_windir<'a>() -> Result<&'a String> {
    static WINDIR: once_cell::sync::OnceCell<String> = once_cell::sync::OnceCell::new();

    let str = WINDIR.get_or_try_init(||{
		let i=check_ptr!(GetSystemWindowsDirectoryA(std::ptr::null_mut(),0),|v|v==0);
		let mut str_buf:Vec<u8> = Vec::with_capacity( i as usize);
		let i2=check_ptr!(GetSystemWindowsDirectoryA(str_buf.as_mut_ptr() as *mut i8,i),|v|v==0);
		unsafe{str_buf.set_len(i2 as usize)};
		if i2>i{
			return err_str(format!("GetSystemWindowsDirectoryA says, that {} bytes are needed, but then changed it's mind. Now {} bytes are needed.",i,i2));
		}
		let string = result!(String::from_utf8(str_buf.clone()));
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
    move |v| match crate::str_from_wide_str(v.as_slice()) {
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

///This returns the address at which ntdll is loaded within a Process.
///If explicit_x86 is true, this method will search for the x86 variant of ntdll
///Otherwise it will return the x64 variant of ntdll.
///
///If the specified version of ntdll is not loaded within that process, this function will return win an error.
///This case should only happen on x86 installs of windows and if explicit_x86 is true.
///On x86 installs of windows there is no WOW, and therefore no SysWOW64 folder.
fn get_ntdll_base_addr(explicit_x86: bool, proc: &Process) -> Result<(String, u64)> {
    let ntdll = get_windir()?.clone()
        + if !explicit_x86 {
            "\\System32\\ntdll.dll"
        } else {
            "\\SysWOW64\\ntdll.dll"
        };
    let ntdll = ntdll.to_lowercase();
    //let proc_self = guard_check_ptr!(OpenProcess(PROCESS_ALL_ACCESS,FALSE,std::process::id()),"Process");
    unsafe {
        get_module_in_proc(proc, |m, v| {
            let base = match m {
                Wrap::T32(v) => v.DllBase as u64,
                Wrap::T64(v) => v.DllBase as u64,
            };
            //This selects only the ntdll.dll entries.
            let str = converter(|s| {
                println!("{},{:x}", s.to_lowercase(), base);
                s.to_lowercase() == ntdll
            })(v);
            str.map(|s| (s, base))
        })
    }
}
///This gets the Relative Virtual Address (rva) of the function name, from a ntdll file.
///If explicit_x86 is true, this function will ALWAYS try to open the x86 ntdll in the SysWOW64 folder.
///Otherwise if native is true, this function will try to open whatever ntdll is native to the system.
///(if you have a x86 install this will pick x86. if you have a x64 install this will  pick x64)
///If both explicit_x86 and native are false, this function will use whatever ntdll is in System32.
fn get_ntdll_function(path: String, name: String) -> Result<u32> {
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
    let path = if *Process::self_proc().is_under_wow()? {
        path.replace(
            &(str.clone() + &"\\SYSTEM32".to_string()),
            &(str + &"\\Sysnative".to_string()),
        )
    } else {
        path
    };
    info!(
        "parsing {}|{}",
        path,
        result!(std::fs::canonicalize(&path)).to_string_lossy()
    );
    let k32 = result!(std::fs::read(&path));
    trace!("read file correctly");
    // check_ptr!(Wow64RevertWow64FsRedirection(par),|v|v==0);

    let dll_parsed = result!(pelite::PeFile::from_bytes(k32.as_slice()));
    trace!("Parsed dll file!");
    let rva = result!(dll_parsed.get_export_by_name(&name))
        .symbol()
        .unwrap();
    trace!("Got RTLCreateUserThread export at {}", rva);
    Ok(rva)
}
///Takes in a Name. From that it returns a matcher
///Takes a Selector, and returns a type, for use with get_module_in_proc and get_module_in_pid
//todo: does this bring a performance benefit?
fn predicate<'a, T: 'a, F: 'a>(
    name: &'a str,
    f: T,
) -> impl Fn(F, Vec<u16>) -> Option<(String, u64)> + 'a
where
    T: Fn(F) -> u64,
{
    crate::hof::swap_fn_args(crate::hof::optpredicate(
        converter(move |s| strip_win_path(s.as_str()) == name),
        move |s, i2| (s, f(i2)),
    ))
}
///Runs get_module_in_proc
///For safety go to [get_module_in_proc]
///
///proc: A Process (handle)
///predicate: when true is seen, selector is invoked
///selector: The selector returns the desired information
#[cfg(feature = "ntdll")]
unsafe fn run_get_module_in_proc<S, P, E, R>(proc: &Process, selector: S, predicate: P) -> Result<R>
where
    S: Fn(
        Wrap<ntapi::ntwow64::LDR_DATA_TABLE_ENTRY32, types::LDR_DATA_TABLE_ENTRY64>,
        &Vec<u16>,
    ) -> R,
    P: Fn(&Vec<u16>) -> bool,
    E: Fn(Error) -> Result<R>,
{
    unsafe {
        get_module_in_proc(proc, |w, v| {
            if predicate(&v) {
                Some(selector(w, &v))
            } else {
                None
            }
        })
    }
}

fn get_module(name: &str, proc: &Process) -> Result<(String, u64)> {
    if !*process::Process::self_proc().is_under_wow()? || *proc.is_under_wow()? {
        match get_module_in_pid(
            proc.get_pid(),
            |m| predicate(name, |m: &MODULEENTRY32W| m.modBaseAddr as u64)(m, m.szExePath.to_vec()),
            None,
        ) {
            Ok(r) => return Ok(r),
            Err((s, n)) => {
                warn!(
                    "get_module_in_pid_predicate_selector failed, with str:{}, n:{}.",
                    s, n
                );
            }
        }
    } else {
        warn!("We are injecting from a x86 injector into a x64 target executable. ")
    }
    #[cfg(feature = "ntdll")]
    {
        info!("Trying get_module_in_proc as fallback method.");
        unsafe {
            return get_module_in_proc(
                proc,
                predicate(
                    name,
                    |w: Wrap<
                        ntapi::ntwow64::LDR_DATA_TABLE_ENTRY32,
                        types::LDR_DATA_TABLE_ENTRY64,
                    >| match w {
                        Wrap::T32(v) => v.DllBase as u64,
                        Wrap::T64(v) => v.DllBase as u64,
                    },
                ),
            );
        }
    }
}
///Gets a function export from the dll at the specified path (even under WOW), and return the rva, if found.
fn get_dll_export(name: &str, path: String) -> Result<u32> {
    let mut path = path;
    let path = if *process::Process::self_proc().is_under_wow()? {
        let str = get_windir()?.clone();
        path.replace(
            &(str.clone() + &"\\System32".to_string()),
            &(str + &"\\Sysnative".to_string()),
        )
    } else {
        path
    };
    debug!(
        "parsing {}|{}",
        path,
        result!(std::fs::canonicalize(&path)).to_string_lossy()
    );
    let k32 = result!(std::fs::read(&path));
    let dll_parsed = result!(pelite::PeFile::from_bytes(k32.as_slice()));
    let rva = result!(dll_parsed.get_export_by_name(name))
        .symbol()
        .unwrap();
    trace!("Found {} at rva:{} in dll {}", name, rva, path);
    Ok(rva)
}
