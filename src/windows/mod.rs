#![cfg(target_os = "windows")]

use crate::Injector;
use log::{debug, error, info, trace, warn};
use std::ffi::{CString, CStr};
use std::fs;
use std::mem::size_of;
use widestring::WideCString;
use winapi::shared::minwindef::{DWORD, FALSE, MAX_PATH, FARPROC, HMODULE, __some_function};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::libloaderapi::{LoadLibraryA, LoadLibraryW, GetProcAddress};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{CreateRemoteThreadEx, OpenProcess, PROC_THREAD_ATTRIBUTE_LIST, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, DeleteProcThreadAttributeList, CreateRemoteThread};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, LPPROCESSENTRY32W, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use winapi::um::winnt::{MEM_COMMIT, MEM_DECOMMIT, PAGE_READWRITE, PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, MEM_RESERVE, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION};
use winapi::ctypes::{c_void, c_long, c_ulong};
use scopeguard::guard;
use winapi::um::synchapi::WaitForSingleObject;
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
            info!("Cleaning {} Handle",$guard);
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
                return Err(("Path Size is bigger, than MAX_PATH".to_string(),0))
            }
            let addr = check_ptr!(VirtualAllocEx(
                    *proc,
                    std::ptr::null_mut(),
                    path_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE
                ),"Allocated Memory"
            );
            info!("Address is {:?}",*addr);
            
            let mut n = 0;
            let bytes = full_path.as_bytes();
            if unsafe { WriteProcessMemory(*proc, *addr, bytes.as_ptr() as *const c_void, path_size, &mut n) } == FALSE {
                return err("WriteProcessMemory");
            }
            trace!("Wrote {} bytes. path has {} bytes",n, bytes.len()*8);
           
            {
                let starting_point = unsafe{std::mem::transmute(load_library_a)};
                let mut thread_id:u32=0;
                let thread = check_ptr!(
                    CreateRemoteThread(
                        *proc,
                        std::ptr::null_mut(),
                        0,
                        Some(starting_point),
                        *addr,
                        0,
                        // *ptr_attr_list,
                        &mut thread_id as *mut u32
                    ),"thread");
                let thread_id = thread_id;
                info!("Thread is {:?} and thread id is {}", *thread, thread_id);
                info!("Waiting for DLL");
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

fn err_str<T>(err:&str) -> Result<T> {
    error!("{}",err);
    Err((err.to_string(),0))
}
