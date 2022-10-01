#![cfg(windows)]
mod macros;

use crate::{cmp, Data, Inject, Injector, Result};
use macros::check_ptr;

use alloc::string::{String, ToString};
#[cfg(all(not(feature = "std"), feature = "alloc"))]
//On std Vec is already imported, so we don't need to actually import this again
use alloc::vec::Vec;
use core::mem::size_of;
use pelite::Pod;
use winapi::shared::minwindef::{DWORD, FALSE, HMODULE, LPVOID, MAX_PATH};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::processthreadsapi::CreateRemoteThread;
use winapi::um::sysinfoapi::GetSystemWindowsDirectoryW;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    LPPROCESSENTRY32W, MAX_MODULE_NAME32, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use winapi::um::winnt::{
    PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE,
};

mod mem;
#[cfg(feature = "ntdll")]
mod ntdll;
pub(super) mod process;
mod thread;

const KERNEL32: &'static str = "KERNEL32.DLL";
const SYSWOW64: &'static str = "SysWOW64";
const SYSTEM32: &'static str = "System32";

#[cfg(feature = "ntdll")]
use ntapi::ntwow64::LDR_DATA_TABLE_ENTRY32;
#[cfg(not(feature = "std"))]
use winapi::um::errhandlingapi::GetLastError;
#[cfg(not(feature = "std"))]
use winapi::um::winbase::GetFileInformationByHandleEx;

use crate::error::Error;
use process::Process;

///This function builds a String, from a WTF-encoded buffer.
pub fn str_from_wide_str(v: &[u16]) -> Result<String> {
    let tmp: Vec<Result<char, widestring::error::DecodeUtf16Error>> =
        widestring::decode_utf16(v.iter().map(|x| *x)).collect();
    let mut o = String::with_capacity(v.len());
    for i in tmp {
        match i {
            Err(e) => return Err(crate::error::Error::WTFConvert(e)),
            Ok(v) => o.push(v),
        }
    }
    o.shrink_to_fit();
    Ok(o)
}

///This function builds a String, from a WTF-encoded buffer.
pub fn wide_str_from_str(v: &str) -> Vec<u16> {
    let tmp: Vec<u16> = widestring::encode_utf16(v.chars()).collect();
    //mp.shrink_to_fit();
    tmp
}

fn canonicalize(p: &crate::Data) -> Result<(String, Option<String>)> {
    match p {
        #[cfg(not(feature = "std"))]
        crate::Data::Str(s) => {
            use winapi::um::fileapi::{CreateFileW, GetFinalPathNameByHandleW};
            //Encode file-name
            let mut file = wide_str_from_str(s);
            file.push(0);
            //Get File/Directory Handle
            let r = unsafe {
                CreateFileW(
                    file.as_ptr(),
                    0,
                    winapi::um::winnt::FILE_SHARE_READ
                        | winapi::um::winnt::FILE_SHARE_WRITE
                        | winapi::um::winnt::FILE_SHARE_DELETE,
                    core::ptr::null_mut(),
                    winapi::um::fileapi::OPEN_EXISTING,
                    // 0x80,
                    winapi::um::winbase::FILE_FLAG_BACKUP_SEMANTICS,
                    core::ptr::null_mut(),
                )
            };
            //If we did not open a handle, we don't need to do any cleanup
            if r == INVALID_HANDLE_VALUE {
                return Err(crate::error::Error::from("CreateFileW in canonicalize"));
            }
            //get needed buffer size
            let mut buf = Vec::<u16>::with_capacity(0);
            let size = unsafe {
                GetFinalPathNameByHandleW(
                    r,
                    buf.as_mut_ptr(),
                    buf.capacity() as u32,
                    winapi::um::winbase::VOLUME_NAME_DOS,
                )
            };
            log::trace!("Size of fp is {}", size);
            //Get Full Path
            //todo: why is +1 needed here?
            //      Without dropping this will result in a error (Heap Corruprion or Access violations).
            //      Also the return value for GetFinalPathNameByHandleW should include the size of the null-byte if not enough capacity exists.
            buf.reserve_exact(size as usize + 1);

            unsafe {
                core::ptr::write_bytes(buf.as_mut_ptr(), 0, size as usize + 1);
            }
            let size = unsafe {
                GetFinalPathNameByHandleW(
                    r,
                    buf.as_mut_ptr(),
                    buf.capacity() as u32,
                    winapi::um::winbase::VOLUME_NAME_DOS,
                )
            };
            let err = if size == 0 {
                0
            } else {
                unsafe { GetLastError() }
            };

            const SIZE: usize = 2 + 1 + MAX_PATH;
            //size of file-name as u32, and MaxPath characters plus NULL
            let mut name = Vec::<u16>::with_capacity(SIZE);

            let lps = if unsafe {
                //init elements
                core::ptr::write_bytes(name.as_mut_ptr(), 0, SIZE);
                name.set_len(SIZE);
                //Get info
                GetFileInformationByHandleEx(
                    r,
                    winapi::um::minwinbase::FileNameInfo,
                    name.as_mut_ptr() as *mut winapi::ctypes::c_void,
                    SIZE as u32,
                )
            } != 0
            {
                let size = unsafe { core::ptr::read(name.as_ptr() as *const u32) };
                log::info!("Size is {}", size);
                let name = &name.as_slice()[2..size as usize + 2];
                let name = crate::trim_wide_str::<true>(name);
                str_from_wide_str(name).ok().map(|s| {
                    let index = s.rfind('\\');
                    if let Some(index) = index {
                        s.split_at(index).1.trim_start_matches('\\').to_string()
                    } else {
                        s
                    }
                })
            } else {
                let error =
                    crate::error::Error::from("GetFileInformationByHandleEx in canonicalize");
                log::error!("{}", error);
                None
            };

            unsafe {
                CloseHandle(r);
            }
            //We need to defer these things, until we actually are finished with the file handle, and have closed it.
            //Otherwise we would never close the handle
            if size == 0 {
                return Err(crate::error::Error::Winapi(
                    "GetFinalPathNameByHandleW in canonicalize",
                    err,
                ));
            }
            log::info!("Size of fp is {},{}", size, err);
            assert!(buf.capacity() >= size as usize);
            //Safety: Trust windows
            unsafe { buf.set_len(size as usize) };

            let fp = str_from_wide_str(buf.as_slice())?;
            return Ok((fp, lps));
        }
        #[cfg(feature = "std")]
        crate::Data::Str(s) => return canonicalize(&crate::Data::Path(std::path::Path::new(*s))),
        #[cfg(feature = "std")]
        crate::Data::Path(p) => {
            use std::os::windows::ffi::OsStrExt;
            let s = std::fs::canonicalize(p)?;
            let tmp: Vec<u16> = s.as_os_str().encode_wide().collect();

            let fp = str_from_wide_str(tmp.as_slice())?;
            let lps = s
                .file_name()
                .map(|v| v.to_str().map(|x| x.to_string()))
                .flatten();
            return Ok((fp, lps));
        }
    }
}

#[cfg(not(feature = "std"))]
//Fixme:stdless Not reliable
fn read(file: &Data) -> Result<Vec<u8>> {
    use winapi::um::fileapi::{CreateFileW, GetFileSizeEx, ReadFile};

    let file = match file {
        crate::Data::Str(s) => *s,
    };
    //Get File Handle
    let mut filew = wide_str_from_str(file);
    filew.push(0);
    let filew = filew;
    let r = unsafe {
        CreateFileW(
            filew.as_ptr(),
            winapi::um::winnt::GENERIC_READ,
            winapi::um::winnt::FILE_SHARE_READ
                | winapi::um::winnt::FILE_SHARE_WRITE
                | winapi::um::winnt::FILE_SHARE_DELETE,
            core::ptr::null_mut(),
            winapi::um::fileapi::OPEN_EXISTING,
            winapi::um::winnt::FILE_ATTRIBUTE_NORMAL,
            core::ptr::null_mut(),
        )
    };
    if r == INVALID_HANDLE_VALUE {
        return Err(crate::error::Error::from("CreateFileW in read"));
    }
    //Function for closing the File Handle again
    let cleanup = || {
        return if unsafe { CloseHandle(r) } == 0 {
            Err(crate::error::Error::from("CloseHandle in read."))
        } else {
            Ok(())
        };
    };
    //How much space do we need to read the file?
    let mut size = winapi::um::winnt::LARGE_INTEGER::default();
    if unsafe { GetFileSizeEx(r, &mut size as *mut winapi::um::winnt::LARGE_INTEGER) } == 0 {
        let _ = cleanup();
        return Err(crate::error::Error::from("GetFileSizeEx in read"));
    }
    let size = *unsafe { size.QuadPart() };
    let mut read = 0;
    log::info!("Requested read of {} byte file", size);
    //Create a buffer
    let mut file_contents = Vec::<u8>::with_capacity(0);
    file_contents.reserve(size as usize);
    //Read
    while read < size {
        let mut bytes_read: u32 = 0;
        //we are not reading async, because we did not set FILE_FLAG_OVERLAPPED in the handle creation
        let return_code = unsafe {
            ReadFile(
                r,
                file_contents.as_mut_ptr().add(file_contents.len()) as *mut winapi::ctypes::c_void,
                size as u32,
                &mut bytes_read as *mut u32,
                core::ptr::null_mut(),
            )
        };
        if return_code == 0 {
            let _ = cleanup();
            return Err(crate::error::Error::from("ReadFile in read"));
        }
        read += bytes_read as i64;
        log::info!("read {} bytes, and {} in total", bytes_read, read);
    }
    //Safety: Trust Windows
    unsafe {
        file_contents.set_len(read as usize);
    }
    cleanup()?;
    Ok(file_contents)
}
#[cfg(feature = "std")]
fn read(file: &Data<'_>) -> Result<Vec<u8>> {
    let file = match file {
        crate::Data::Str(v) => std::path::Path::new(v),
        crate::Data::Path(p) => p,
    };
    std::fs::read(file).map_err(|x| x.into())
}

pub struct InjectWin<'a> {
    pub inj: &'a Injector<'a>,
    pub wait: bool,
}

impl<'a> Inject for InjectWin<'a> {
    ///Inject a DLL into another process
    ///Notice:This implementation blocks, and waits, until the library is injected, or the injection failed.
    fn inject(&self) -> Result<()> {
        let proc = Process::new(
            self.inj.pid,
            PROCESS_CREATE_THREAD
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ
                | PROCESS_VM_OPERATION
                | PROCESS_QUERY_INFORMATION,
        )?;
        //Is the dll already injected?
        let (path, dll_name) = canonicalize(&self.inj.dll)?;
        {
            match dll_name {
                Some(name) => {
                    if get_module(crate::Data::Str(name.as_str()), &proc).is_ok() {
                        return Err(Error::Unsupported(Some("dll already injected")));
                    }
                }
                None => return Err(crate::error::CustomError::DllPathNoFile.into()),
            }
        }

        //Prepare Argument for LoadLibraryW
        //scope here, so Vec will get deleted after this
        let mem = {
            let mut full_path = wide_str_from_str(path.as_str());
            full_path.push(0);
            let mut mempage =
                mem::MemPage::new(&proc, full_path.len() * core::mem::size_of::<u16>(), false)?;
            mempage.write(full_path.as_bytes())?;
            mempage
        };
        self.exec_fn_in_proc(&proc, "LoadLibraryW", mem.get_address())
    }
    ///This function will attempt, to eject a dll from another process.
    ///Notice: This implementation blocks, and waits, until the library is ejected?, or the ejection failed.
    fn eject(&self) -> Result<()> {
        const X86EJECTX64: crate::error::Error = crate::error::Error::Unsupported(Some(
            "ejecting is not currently supported from a x86 binary targeting a x64 process.",
        ));

        let proc = Process::new(
            self.inj.pid,
            PROCESS_CREATE_THREAD
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ
                | PROCESS_VM_OPERATION
                | PROCESS_QUERY_INFORMATION,
        )?;


        let name = canonicalize(&self.inj.dll)?.1;
        let name = match name {
            Some(name) => name,
            None => return Err(crate::error::CustomError::DllPathNoFile.into()),
        };
        // let (_path, base) = get_module(name.as_str(), &proc)?;
        let handle = match get_module(crate::Data::Str(name.as_str()), &proc) {
            Ok((_, (_, Some(h)))) => h,
            Ok(_) => {
                return Err(X86EJECTX64);
            }
            Err(_) => {
                return Err(crate::error::Error::InjectLib(
                    crate::error::CustomError::LibraryNotFound(self.inj.dll.to_string()),
                ));
            }
        };
        crate::info!("Found dll in proc, with handle:{:#x?}", handle);
        self.exec_fn_in_proc(&proc, "FreeLibrary", handle as LPVOID)
    }

    ///This Function will find all currently processes, with a given name.
    ///Even if no processes are found, an empty Vector should return.
    fn find_pid(name: crate::Data) -> Result<Vec<u32>> {
        Self::find_pid_selector(|p| {
            return match str_from_wide_str(crate::trim_wide_str::<true>(&p.szExeFile)) {
                Ok(str) => match name {
                    crate::Data::Str(s) => {
                        crate::debug!("Checking {} against {}", str, s);
                        return s.ends_with(str.as_str());
                    }
                    #[cfg(feature = "std")]
                    crate::Data::Path(p) => {
                        crate::debug!("Checking {} against {}", str, p.to_string_lossy());
                        return p.ends_with(str.as_str());
                    }
                },
                Err(e) => {
                    crate::warn!("Skipping check of process. Can't construct string, to compare against. Err:{:#?}",e);
                    false
                }
            };
        })
    }
}

impl<'a> InjectWin<'a> {
    ///This function executes the entry_fn from Kernel32.dll with the argument of mem in the process proc.
    ///the process mem was created with, and proc must hold the same handle.
    fn exec_fn_in_proc(&self, proc: &Process, entry_fn: &str, param: LPVOID) -> Result<()> {
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
        if self.inj.pid == 0 {
            crate::warn!("Supplied id is 0. Will not inject, as it is not supported by windows.");
            return Err(Error::Unsupported(Some(
                "PID 0 is an invalid target under windows.",
            )));
        }

        let self_proc = Process::self_proc();
        crate::debug!("Process is {}", proc);

        //Is the target exe x86?
        let pid_is_under_wow = proc.is_under_wow()?;
        // Is this exe x86?
        let self_is_under_wow = self_proc.is_under_wow()?;

        crate::info!(
            "pid_is_under_wow:{},self_is_under_wow:{}",
            pid_is_under_wow,
            self_is_under_wow
        );
        if self_is_under_wow && !pid_is_under_wow {
            if cfg!(feature = "ntdll") {
                crate::warn!("This injection will use a slightly different method, than usually. This is normal, when the injector is x86, but the pid specified is a x64 process.\
				We will be using ntdll methods. The ntdll.dll is technically not a public facing windows api.");
            } else {
                return Err(Error::Unsupported(Some("Cannot continue injection. You are trying to inject from a x86 injector into a x64 application. That is unsupportable, without access to ntdll functions.")));
            }
        };

        let dll_is_x64 = self.get_is_dll_x64()?;

        if dll_is_x64 && pid_is_under_wow {
            crate::error!(
                "Injecting a x64 dll, into a x86 exe is unsupported. Will not continue for now."
            );
            return Err(Error::Unsupported(Some(
                "Injecting a x64 dll, into a x86 exe is unsupported.",
            )));
        } else if !dll_is_x64 && !pid_is_under_wow {
            crate::error!("Injecting a x86 dll, into a x64 exe is unsupported. Could this case be supported? Send a PR, if you think, you can make this work! Will NOT abort, but expect the dll-injection to fail");
            return Err(Error::Unsupported(Some(
                "Injecting a x86 dll, into a x64 exe is unsupported.",
            )));
        }
        #[cfg(not(feature = "ntdll"))]
        if self_is_under_wow && !pid_is_under_wow {
            return Err(Error::Unsupported(Some(
                "Cannot inject into a x64 Application without ntdll access.",
            )));
        }

        let entry_point = {
            let (path, (base, _)) = get_module(crate::Data::Str(KERNEL32), &proc)?;
            let path = if proc.is_under_wow()? {
                path.replace(SYSTEM32, SYSWOW64)
            } else {
                path
            };
            base + get_dll_export(entry_fn, path)? as u64
        };
        crate::info!(
            "Allocated {} Parameter at {:#x?}. fn ptr is {:#x} vs {:#x}",
            entry_fn,
            param,
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
                            core::ptr::null_mut(),
                            0,
                            0,
                            0,
                            0,
                            entry_point as u64,
                            param as u64,
                        )?
                    }
                };
                #[cfg(not(target_arch = "x86"))]
                let (r, t, _c) = {
                    let mut c = ntapi::ntapi_base::CLIENT_ID64 {
                        UniqueProcess: 0,
                        UniqueThread: 0,
                    };
                    let mut t = core::ptr::null_mut();
                    let r = unsafe {
                        ntapi::ntrtl::RtlCreateUserThread(
                            proc.get_proc(),
                            core::ptr::null_mut(),
                            0,
                            0,
                            0,
                            0,
                            core::mem::transmute(entry_point as usize),
                            param,
                            &mut t as winapi::shared::ntdef::PHANDLE,
                            core::mem::transmute(&mut c as ntapi::ntapi_base::PCLIENT_ID64),
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
                return if self.wait {
                    unsafe { thread::Thread::new(t)? }.wait_for_thread()
                } else {
                    Ok(())
                };
            }
        }
        if !self_is_under_wow || pid_is_under_wow {
            let mut thread_id: u32 = 0;
            let thread = unsafe {
                thread::Thread::new(CreateRemoteThread(
                    proc.get_proc(),
                    core::ptr::null_mut(),
                    0,
                    Some(core::mem::transmute(entry_point as usize)),
                    param,
                    0,
                    &mut thread_id as *mut u32,
                ))
            }?;
            let thread_id = thread_id;
            crate::trace!("Thread is {:?} and thread id is {}", *thread, thread_id);
            crate::info!("Waiting for DLL");
            // std::thread::sleep(Duration::new(0,500));//todo: why is this necessary, (only) when doing cargo run?
            return if self.wait {
                thread.wait_for_thread()
            } else {
                Ok(())
            };
        }
        //The ? should automatically convert this to the correct Error type.
        Err(crate::error::CustomError::NoViableInjector)?
        //Check, if the dll is actually loaded?
        //todo: can we skip this? is the dll always guaranteed to be loaded here, or is it up to the dll, to decide that?
        //todo: re-add a check, for loaded modules

        // get_module_in_pid_predicate_selector(self.pid,self.dll,|_|(),None)
        //Err(("".to_string(), 0))
    }

    ///Find a PID, where the process-name matches some user defined selector
    fn find_pid_selector<F>(select: F) -> Result<Vec<u32>>
    where
        F: Fn(&PROCESSENTRY32W) -> bool,
    {
        let mut pids: Vec<DWORD> = Vec::new();
        let snap_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap_handle == INVALID_HANDLE_VALUE {
            return Err(macros::err("CreateToolhelp32Snapshot"));
        }
        crate::trace!("Got Snapshot of processes");
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

        crate::trace!("Ran Process32FirstW");
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
    fn get_is_dll_x64(&self) -> Result<bool> {
        let dll = read(&self.inj.dll)?;
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
//Do not use, use get_module instead.
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
        modBaseAddr: core::ptr::null_mut(), //The base address of the module in the context of the owning process.
        modBaseSize: 0,                     //The size of the module, in bytes.
        hModule: core::ptr::null_mut(), //A handle to the module in the context of the owning process.
        szModule: [0; MAX_MODULE_NAME32 + 1], //The module name.
        szExePath: [0; MAX_PATH],       //The module path.
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
fn get_windir<'a>() -> Result<&'a alloc::string::String> {
    static WINDIR: once_cell::race::OnceBox<alloc::string::String> =
        once_cell::race::OnceBox::new();
    let str = WINDIR.get_or_try_init(||{
		let i=check_ptr!(GetSystemWindowsDirectoryW(core::ptr::null_mut(),0),|v|v==0);
		let mut str_buf:alloc::vec::Vec<u16> = Vec::with_capacity( i as usize);
		let i2=check_ptr!(GetSystemWindowsDirectoryW(str_buf.as_mut_ptr(),i),|v|v==0);
        assert!(i2<=i,"GetSystemWindowsDirectoryA says, that {} bytes are needed, but then changed it's mind. Now {} bytes are needed.",i,i2);
		unsafe{str_buf.set_len(i2 as usize)};
		let string = str_from_wide_str(str_buf.as_slice())?;
        crate::debug!("Windir is {},{},{}",string,i,i2);
		Ok(alloc::boxed::Box::new(string))
	})?;
    crate::debug!("Windir is '{}'", str);
    Ok(str)
}

///Takes in a Name. From that it returns a matcher
///Takes a Selector, and returns a type, for use with get_module_in_proc and get_module_in_pid
///name specifies, what module to look for.
///f processes the other input from other functions
//todo: does this bring a performance benefit?
fn predicate<T, F, O, C>(f: T, cmp: C) -> impl Fn(F, &[u16]) -> Option<(String, O)>
where
    T: Fn(F) -> O,
    C: Fn(&String) -> bool,
{
    move |i2, v| match str_from_wide_str(crate::trim_wide_str::<true>(v)) {
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

///Gets the base address of where a dll is loaded within a process.
///The dll is identified by name. name is checked against the whole file name.
///if the process has a pseudo-handle, the ntdll methods will not run.
///
///The return value is (dll name, (dll base address, dll handle))
//This return type is getting out of hand. Mayebe consider a struct for this?
fn get_module(name: crate::Data, proc: &Process) -> Result<(String, (u64, Option<LPVOID>))> {
    let cmp = cmp(name);
    let ntdll = !process::Process::self_proc().is_under_wow()? || proc.is_under_wow()?;
    #[cfg(test)]
    let ntdll = { test::FNS_M.with(|x| x.get_module.get()) || ntdll };
    if ntdll {
        match get_module_in_pid(
            proc.get_pid(),
            |m| {
                predicate(
                    |m: &MODULEENTRY32W| (m.modBaseAddr as u64, Some(m.hModule as LPVOID)),
                    |x| (&cmp)(crate::Data::Str(x.as_str())),
                )(m, &m.szExePath)
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
        crate::warn!("We are injecting from a x86 injector into a x64 target executable. ");
        #[cfg(not(feature = "ntdll"))]
        return Err(Error::Unsupported(Some("No Ntdll support enabled. Cannot get module. Target process is x64, but we are compiled as x86.")));
    }
    #[cfg(feature = "ntdll")]
    {
        crate::info!("Trying get_module_in_proc as fallback method.");
        unsafe {
            let ntdll = ntdll::NTDLL::new()?;
            return ntdll.get_module_in_proc(
                proc,
                predicate(
                    |w: pelite::Wrap<LDR_DATA_TABLE_ENTRY32, ntdll::LDR_DATA_TABLE_ENTRY64>| match w
                    {
                        //todo: the dll address is not garunteed to be the dll handle, but that seems to be the case.
                        pelite::Wrap::T32(w) => (w.DllBase as u64, Some(w.DllBase as LPVOID)),
                        pelite::Wrap::T64(w) => (w.DllBase as u64, Some(w.DllBase as LPVOID)),
                    },
                    |x| (&cmp)(crate::Data::Str(x.as_str())),
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
fn get_dll_export(name: &str, path: alloc::string::String) -> Result<u32> {
    let path = if process::Process::self_proc().is_under_wow()? {
        let str = get_windir()?.clone();
        path.replace(
            (str.clone() + "\\System32").as_str(),
            (str + "\\Sysnative").as_str(),
        )
    } else {
        path
    };
    log::trace!(r#"Path is "{}""#, path);
    let path = canonicalize(&crate::Data::Str(path.as_str()))?.0;
    log::trace!(r#"Canonical Path is "{}""#, path);
    debug_assert!(
        canonicalize(&crate::Data::Str(path.as_str())).is_ok(),
        "parsing {} failed",
        path,
    );
    let k32 = read(&crate::Data::Str(path.as_str()))?;
    log::trace!("{:#x?}", &k32.as_slice()[0..32]);
    let dll_parsed = pelite::PeFile::from_bytes(k32.as_slice())?;
    let rva = dll_parsed.get_export_by_name(name)?.symbol().unwrap();
    crate::trace!("Found {} at rva:{} in dll {}", name, rva, path);
    Ok(rva)
}

#[cfg(test)]
pub mod test {
    extern crate std;
    use alloc::string::ToString;
    use std::prelude::*;
    use std::println;
    use std::vec::Vec;

    use crate::error::Error;
    use crate::platforms::windows::InjectWin;
    use crate::{Inject, Result};
    use std::cell::Cell;
    use std::ffi::OsString;
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

    std::thread_local! {
        pub(in super) static FNS_M:FNS=FNS::default();
    }
    #[derive(Debug)]
    pub(super) struct FNS {
        pub get_module: Cell<bool>,
        #[cfg(feature = "ntdll")]
        pub exec_fn_in_proc: Cell<bool>,
    }
    impl Default for FNS {
        fn default() -> Self {
            FNS {
                get_module: Cell::new(false),
                #[cfg(feature = "ntdll")]
                exec_fn_in_proc: Cell::new(false),
            }
        }
    }
    ///This will create a new cmd process.
    ///You MUST bind the Process to something else than _ (even _a is apparently fine?).
    pub fn create_cmd() -> (Child, super::process::Process) {
        #[cfg(not(target_pointer_width = "32"))]
        let path = "cmd.exe";
        #[cfg(target_pointer_width = "32")]
        let path = {
            let mut path = super::get_windir().unwrap().clone();
            path.push_str(r"\Sysnative\cmd.exe");
            path
        };

        let c = std::process::Command::new(path)
            .creation_flags(CREATE_NEW_CONSOLE)
            .spawn()
            .unwrap();
        sleep(Duration::from_millis(100)); //Let the process init.
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
    ///Tests, that create_cmd does not panic, and that the drop will work.
    ///The decompiler tells some interesting stuff. I would rather have it tested here.
    fn test_create_cmd() {
        //we need to bind process to _a here, so that drop doesn't get called instantly.
        //Dropping Process will close the child handle, which isn't what we want
        let (mut c, _a) = create_cmd();
        c.kill().unwrap();
    }

    #[test]
    fn canonicalise() -> Result<()> {
        simple_logger::init().ok();
        let windir = super::get_windir()?;
        let mut path = windir.clone();

        const cmd_path: &'static str = if cfg!(target_pointer_width = "32")
        //On 32-bit wow redirects the path
        {
            r"\SysWOW64\cmd.exe"
        } else {
            r"\System32\cmd.exe"
        };

        path.push_str(cmd_path);

        log::info!("{}", path);
        //non-std
        {
            let (fp, lps) = super::canonicalize(&crate::Data::Str(path.as_str()))?;
            let fp = fp.trim_start_matches(r"\\?\");
            assert_eq!(fp, path);
            assert_eq!(lps, Some("cmd.exe".to_string()));
        }
        //std
        #[cfg(all(feature = "std", test))]
        {
            let (fp, lps) = super::canonicalize(&crate::Data::Path(std::path::Path::new(&path)))?;
            assert_eq!(lps, Some("cmd.exe".to_string()));
            let fp = fp.trim_start_matches(r"\\?\");

            assert_eq!(fp, path);
        }
        Ok(())
    }

    #[test]
    fn read() -> Result<()> {
        simple_logger::SimpleLogger::new().init().ok();
        let windir = super::get_windir()?;
        let mut path = windir.clone();
        path.push_str(r"\System32\cmd.exe");

        log::info!("{}", path);

        let cstd = std::fs::read(&path).unwrap();
        log::info!("STD read size is {}", cstd.len());
        let c = super::read(&crate::Data::Str(path.as_str()))?;
        log::info!("self read size is {}", c.len());
        //assert_eq!(c,cstd,"std and self read result is not same");
        assert!(c == cstd);
        Ok(())
    }

    #[test]
    fn get_windir() -> Result<()> {
        let r = super::get_windir();
        assert!(r.is_ok(), "get_windir returned Err({})", r.unwrap_err());
        let r = r.unwrap();
        let env_var_windir = std::env::var("WINDIR").unwrap();
        assert_eq!(r, &env_var_windir);
        let f = std::fs::read_dir(r);
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
    fn str_from_wide_str() -> Result<()> {
        //test empty string
        assert_eq!(
            super::str_from_wide_str(std::vec![].as_slice())?,
            "".to_string()
        );
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
        assert_eq!(super::predicate(|_| 0, |_| false)((), &[]), None);
        //If something matches, we should get a result
        assert_eq!(
            super::predicate(|_| 0, |_| true)((), &[]),
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
                        |x| super::cmp(crate::Data::Str("ntdll.dll"))(crate::Data::Str(x.as_str())),
                    )(m, &m.szModule)
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
            let r = super::get_module(
                crate::Data::Str("ntdll.dll"),
                &super::process::Process::self_proc(),
            );
            assert!(r.is_ok(), "normal self get_module err:{}", r.unwrap_err());
        }
        let (mut c, cp) = create_cmd();
        //other test
        {
            let r = super::get_module(crate::Data::Str("ntdll.dll"), &cp);
            if cfg!(target_pointer_width = "64") || cfg!(feature = "ntdll") {
                assert!(r.is_ok(), "normal other get_module err:{}", r.unwrap_err());
            } else {
                assert_eq!(r.unwrap_err(),Error::Unsupported(Some("No Ntdll support enabled. Cannot get module. Target process is x64, but we are compiled as x86.")));
            }
        }
        // #[cfg(feature = "ntdll")]
        #[cfg(target_pointer_width = "0")] //FIXME: Fix ntdll stuff
        {
            let proc = super::process::Process::new(std::process::id(), PROCESS_ALL_ACCESS)?;
            FNS_M.with(|x| x.get_module.set(true));
            let r = super::get_module(crate::Data::Str("KERNEL32.DLL"), &proc);
            let r1 = super::get_module(crate::Data::Str("KERNEL32.DLL"), &cp);
            FNS_M.with(|x| x.get_module.set(false));
            assert!(r.is_ok(), "ntdll self get_module:{}", r.unwrap_err());
            assert!(r1.is_ok(), "ntdll other get_module:{}", r.unwrap_err());
        }
        c.kill().unwrap();
        Ok(())
    }

    #[test]
    fn find_pid() -> Result<()> {
        let exe = std::env::current_exe().map_err(|_| crate::error::Error::Unsupported(None))?;
        #[cfg(feature = "std")]
        {
            let i = InjectWin::find_pid(crate::Data::Path(exe.as_path()));
            assert!(i.is_ok(), "{}", i.unwrap_err());
            assert!(
                i?.contains(&std::process::id()),
                "The result did not contain our current process id."
            );
        }
        let i = InjectWin::find_pid(crate::Data::Str(exe.as_os_str().to_str().unwrap()));
        assert!(i.is_ok(), "{}", i.unwrap_err());
        assert!(
            i?.contains(&std::process::id()),
            "The result did not contain our current process id."
        );

        Ok(())
    }
}
