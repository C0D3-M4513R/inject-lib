#![cfg(target_os = "windows")]

use crate::Injector;
use log::{debug, error, info, trace, warn};
use std::ffi::{CString, CStr, OsStr, OsString};
use std::fs;
use std::mem::size_of;
use widestring::WideCString;
use winapi::shared::minwindef::{DWORD, FALSE, MAX_PATH, FARPROC, HMODULE, __some_function};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::libloaderapi::{LoadLibraryA, LoadLibraryW, GetProcAddress};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{CreateRemoteThreadEx, OpenProcess, PROC_THREAD_ATTRIBUTE_LIST, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, DeleteProcThreadAttributeList, CreateRemoteThread};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, LPPROCESSENTRY32W, PROCESSENTRY32W, TH32CS_SNAPPROCESS, TH32CS_SNAPMODULE, MODULEENTRY32W, MAX_MODULE_NAME32, Module32FirstW, Module32NextW};
use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE, PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, MEM_RESERVE, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, IMAGE_FILE_MACHINE_UNKNOWN};
use winapi::ctypes::{c_void, c_long, c_ulong};
use scopeguard::guard;
use winapi::um::synchapi::WaitForSingleObject;
use std::fmt::Display;
use winapi::um::winbase::INFINITE;

type Error = (String,u32);
type Result<T> = std::result::Result<T,Error>;

macro_rules! check_ptr{
    ($name:ident($($args:expr),*))=>{
        {
            match check_null_ptr(unsafe{$name($($args),*)},std::stringify!($name)) {
                Ok(val) => val,
                Err(err) => return Err(err),
            }
        }
    };
    ($name:ident($($args:expr),*),$guard:literal) => {
            check_ptr!($name($($args),*),
            |guard| {
            trace!("Cleaning {} Handle",$guard);
            if unsafe { CloseHandle(guard) } == FALSE {
                error!("Error during cleanup!");
                //Supress unused_must_use warning. This is intended, but one cannot use allow, to supress this?
                //todo: a bit hacky? Is there a better way, to achieve something similar?
                match err::<()>(("CloseHandle of ".to_string()+std::stringify!($name)).as_str()){
                    Ok(_)=>{},
                    Err(_)=>{},
                };
                panic!("Error during cleanup")
            }
        }
        )
    };
    ($name:ident($($args:expr),*),$guard:expr) => {
        scopeguard::guard(check_ptr!($name($($args),*)),$guard)
    };
}

impl<'a> Injector<'a> {
    pub fn eject(&self) -> Result<()> {
        if self.pid == 0 {
            warn!("Supplied id is 0. Will not eject. This is a todo!");//todo: check, if ejecting dlls on pid 0 is possible
            return err_str("PID is 0");
        }
        let addr;
        {
            let snap_modules = unsafe{CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,self.pid)};
            if snap_modules==INVALID_HANDLE_VALUE{
                return err("CreateToolhelp32Snapshot");
            }
            let mut module_entry = MODULEENTRY32W{
                dwSize: size_of::<MODULEENTRY32W>() as u32,//The size of the structure, in bytes. Before calling the Module32First function, set this member to sizeof(MODULEENTRY32). If you do not initialize dwSize, Module32First fails.
                th32ModuleID: 1,//This member is no longer used, and is always set to one.
                th32ProcessID: 0,//The identifier of the process whose modules are to be examined.
                GlblcntUsage: 0,//The load count of the module, which is not generally meaningful, and usually equal to 0xFFFF.
                ProccntUsage: 0,//The load count of the module (same as GlblcntUsage), which is not generally meaningful, and usually equal to 0xFFFF.
                modBaseAddr: std::ptr::null_mut(),//The base address of the module in the context of the owning process.
                modBaseSize: 0,//The size of the module, in bytes.
                hModule: std::ptr::null_mut(),//A handle to the module in the context of the owning process.
                szModule: [0;MAX_MODULE_NAME32+1],//The module name.
                szExePath: [0;MAX_PATH]//The module path.
            };
            if unsafe{Module32FirstW(snap_modules, &mut module_entry as *mut MODULEENTRY32W)}==FALSE {
                return err("Module32FirstW");
            }
            let mut dll_no_path=self.dll;
            
            if let Some(n) = self.dll.rfind('/'){
                //I do n+1 here, since, the rfind will actually keep the /.
                //This gets rid of the /
                dll_no_path=self.dll.get((n+1)..).unwrap();
            }
            
            debug!("self.dll='{}' and dll_no_path='{}'",self.dll,dll_no_path);
            
            loop{
                //The errors below are not handled really well, because I do not think, they will actually occur.
                let module_cstr = match unsafe{ WideCString::from_ptr_with_nul(module_entry.szModule.as_ptr(),module_entry.szModule.len())}{
                    Ok(v)=>v,
                    Err(e)=>{return err_str(e);},
                };
                let module = match module_cstr.to_string(){
                    Ok(v)=>v,
                    Err(e)=>{return err_str(e)}
                };
                if module==dll_no_path{
                    addr=module_entry.modBaseAddr;
                    break;
                }
                if unsafe{Module32NextW(snap_modules, &mut module_entry as *mut MODULEENTRY32W)}==FALSE {
                    error!("Encountered error, while calling Module32NextW. This is expected, if there isn't a dll, with the specified name loaded!");
                    return err("Module32NextW");
                }
            }
        }
        //Spawn the thread, that ejects the dll
        {
            let proc = check_ptr!(
                OpenProcess(
                PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                FALSE,self.pid),"Process");
            debug!("Process Handle is {:?}",*proc);
            let k32_handle = check_ptr!(LoadLibraryW(WideCString::from_str("kernel32.dll").unwrap().as_ptr()));
            let thread_start = check_ptr!(GetProcAddress(k32_handle,b"FreeLibrary\0".as_ptr() as *const i8));
        
            let mut thread_id:u32=0;
            let thread = check_ptr!(
                        CreateRemoteThread(
                            *proc,
                            std::ptr::null_mut(),
                            0,
                            Some(std::mem::transmute(thread_start)),
                            addr as *mut c_void,
                            0,
                            // *ptr_attr_list,
                            &mut thread_id as *mut u32
                        ),"thread");
            let thread_id = thread_id;
            trace!("Thread is {:?} and thread id is {}", *thread, thread_id);
            debug!("Waiting for DLL to eject");
            match unsafe{WaitForSingleObject(*thread,INFINITE)}{
                0x80=>{return err_str("WaitForSingleObject returned WAIT_ABANDONED")},//WAIT_ABANDONED
                0x0=>{info!("Dll eject success? IDK?! Hopefully? WaitForSingleObject returned WAIT_OBJECT_0");return Ok(())},//WAIT_OBJECT_0
                0x102=>{return err_str("Timeout hit at WaitForSingleObject.")},//WAIT_TIMEOUT
                0xFFFFFFFF=>{return err("WaitForSingleObject")},//WAIT_FAILED
                _=>{}
            }
        }
        warn!("Something went wrong! This path should never be taken.");
        Ok(())//todo: is this always ok? is this even hit?
    }
    
    ///Actually Inject the DLL.
    ///Notice:This implementation blocks, and waits, until the library is injected, or the injection failed.
    ///Return information is purely informational (for now)! It should not be relied upon, and may change in Minor updates.
    //TODO:If return is OK(()), is the lib always injected? If Return is Err(_), is there actually some error?
    pub fn inject(&self) -> Result<()> {
        //TODO:Recheck this Fn, and all the winapi calls
        if self.pid == 0 {
            warn!("Supplied id is 0. Will not inject, as it is not supported by windows");
            return err_str("PID is 0");
        }
    
        //from_str_unchecked should be fine. There are no null bytes, in that literal string.
        // let str = WideCString::from_str("kernel32.dll").unwrap().as_ptr();
        let k32_handle = check_ptr!(LoadLibraryW(WideCString::from_str("kernel32.dll").unwrap().as_ptr()));
        let load_library_a = check_ptr!(GetProcAddress(k32_handle,"LoadLibraryA".as_ptr() as *const i8));

        let proc = check_ptr!(
            OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            FALSE,self.pid),"Process");
        info!("Process Handle is {:?}",*proc);
        {
            let full_path = match fs::canonicalize(self.dll) {
                Ok(p) => p.to_str().unwrap().to_string(),
                Err(e) => {
                    return Err((format!("failed to canoicalize path. error is:{}", e), 0));
                }
            };
            let path_size = full_path.len() + 1;
            if path_size>MAX_PATH {
                error!("Path is bigger, than MAX_PATH!");
                return Err(("Path Size is bigger, than MAX_PATH".to_string(), 0));
            }
            let addr = check_ptr!(VirtualAllocEx(
                *proc,
                std::ptr::null_mut(),
                path_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            ),|addr|{
                trace!("Releasing VirtualAlloc'd Memory");
                if (unsafe{VirtualFreeEx(*proc,addr,0,MEM_RELEASE)}==FALSE){
                    error!("Error during cleanup!");
                    //Supress unused_must_use warning. This is intended, but one cannot use allow, to supress this?
                    //todo: a bit hacky? Is there a better way, to achieve something similar?
                    #[allow(unused_must_use)]
                    err::<()>("VirtualFreeEx of VirtualAllocEx");
                    panic!("Error during cleanup")
                }
            }
            );
            trace!("Address is {:?}",*addr);
            
            let mut n = 0;
            let bytes = full_path.as_bytes();
            if unsafe { WriteProcessMemory(*proc, *addr, bytes.as_ptr() as *const c_void, path_size, &mut n) } == FALSE {
                return err("WriteProcessMemory");
            }
            trace!("Wrote {} bytes. path has {} bytes. A difference of 1 is expected, since the path in C has a Null-byte-terminator.",n, bytes.len());
           
            {
                let mut thread_id:u32=0;
                let thread = check_ptr!(
                    CreateRemoteThread(
                        *proc,
                        std::ptr::null_mut(),
                        0,
                        Some(std::mem::transmute(thread_start)),
                        *addr,
                        0,
                        // *ptr_attr_list,
                        &mut thread_id as *mut u32
                    ),"thread");
                let thread_id = thread_id;
                trace!("Thread is {:?} and thread id is {}", *thread, thread_id);
                debug!("Waiting for DLL");
                match unsafe{WaitForSingleObject(*thread,INFINITE)}{
                    0x80=>{return err_str("WaitForSingleObject returned WAIT_ABANDONED")},//WAIT_ABANDONED
                    0x0=>{info!("Dll inject success? IDK?! Hopefully? WaitForSingleObject returned WAIT_OBJECT_0");return Ok(())},//WAIT_OBJECT_0
                    0x102=>{return err_str("Timeout hit at WaitForSingleObject.")},//WAIT_TIMEOUT
                    0xFFFFFFFF=>{return err("WaitForSingleObject")},//WAIT_FAILED
                    _=>{}
                }
                
            }
        }
        warn!("Something went wrong! This path should never be taken.");
        Ok(())//todo: is this always ok? is this even hit?
    }
    ///Find a PID, where the process-name matches some user defined selector
    pub fn find_pid_selector<F>(select: F) -> Result<Vec<u32>>
    where
        F: Fn(&String) -> bool,
    {
        let mut pids: Vec<DWORD> = Vec::new();
        let snap_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap_handle == INVALID_HANDLE_VALUE {
            return err("CreateToolhelp32Snapshot");
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
            return err("Process32FirstW");
        }

        trace!("Ran Process32FirstW");
        loop {
            match WideCString::from_vec_with_nul(val.szExeFile)
				.map_err(|_| "NULL expected in String, but not found. Skipping process.".to_string())
				.and_then(|str| str.to_string()
					.map_err(|_| format!("Invalid UTF-16 found. Skipping this proc. Lossy conversion would be:{}", str.to_string_lossy()))
				) {
				Ok(str) => {
					trace!("Checking {}", str);
					if select(&str) {
						debug!("proc_name is {}. Adding to process matches", str);
						pids.push(val.th32ProcessID);
					}
				}
				Err(str) => warn!("{}", str)
			}
            if unsafe { Process32NextW(snap_handle, entry) == FALSE } {
                break;
            }
        }
        Ok(pids)
    }
}

fn check_null_ptr<T>(ptr:*mut T,fn_name:&str) -> Result<*mut T>{
    if ptr.is_null(){
        return err(fn_name);
    }
    Ok(ptr)
}

fn err<T>(fn_name: &str) -> Result<T> {
    {
        let err = unsafe { GetLastError() };
        error!("{} failed! Errcode is:'{}'. Check, what the error code means here:'https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes'", fn_name, err);
        Err((fn_name.to_string(), err))
    }
}

fn err_str<T>(err:impl Display) -> Result<T> {
    error!("{}",err);
    Err((format!("{}",err),0))
}
