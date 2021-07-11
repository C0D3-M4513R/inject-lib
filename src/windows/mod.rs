#![cfg(target_os = "windows")]

use crate::Injector;
use log::{debug, error, info, trace, warn};
use std::ffi::{CString, CStr};
use std::fs;
use std::mem::size_of;
use widestring::WideCString;
use winapi::shared::minwindef::{DWORD, FALSE, MAX_PATH, FARPROC};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::libloaderapi::{LoadLibraryA, LoadLibraryW, GetProcAddress};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{CreateRemoteThreadEx, OpenProcess, PROC_THREAD_ATTRIBUTE_LIST, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, DeleteProcThreadAttributeList, CreateRemoteThread};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, LPPROCESSENTRY32W, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use winapi::um::winnt::{MEM_COMMIT, MEM_DECOMMIT, PAGE_READWRITE, PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, MEM_RESERVE, PROCESS_ALL_ACCESS};
use winapi::ctypes::{c_void, c_long, c_ulong};
use scopeguard::guard;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::INFINITE;

impl<'a> Injector<'a> {
    ///Actually Inject the DLL.
    ///Notice:This implementation blocks, and waits, until the library is injected, or the injection failed.
    ///Return information is purely informational (for now)! It should not be relied upon, and may change in Minor updates.
    //TODO:If return is OK(()), is the lib always injected? If Return is Err(_), is there actually some error?
    pub fn inject(&self) -> Result<(), (String, u32)> {
        //TODO:Recheck this Fn, and all the winapi calls
        if self.pid == 0 {
            warn!("Supplied id is 0. Will not inject, as it is not supported by windows");
            return Err(("PID is 0".to_string(), u32::MAX));
        }
    
        //from_str_unchecked should be fine. There are no null bytes, in that literal string.
        // let str = WideCString::from_str("kernel32.dll").unwrap().as_ptr();
        let k32_handle = unsafe{LoadLibraryW(WideCString::from_str("kernel32.dll").unwrap().as_ptr())};
        if k32_handle.is_null(){
            return Err(err("LoadLibraryW".to_string()));
        }

        let load_library_a = unsafe{GetProcAddress(k32_handle, b"LoadLibraryA\0".as_ptr() as *const i8)};
        if load_library_a.is_null(){
            return Err(err("GetProcAddress".to_string()));
        }
        
        let proc = unsafe {
            OpenProcess(
                // PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                PROCESS_ALL_ACCESS,
                FALSE,
                self.pid,
            )
        };
        let proc = guard(proc,
        |proc| {
            info!("Cleaning Process Handle");
            if unsafe { CloseHandle(proc) } == FALSE {
                error!("Error during cleanup!");
                err("CloseHandle".to_string());
                panic!("Error during cleanup")
            }
        });
        if proc.is_null() {
            return Err(err("OpenProcess".to_string()));
        }
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
            let addr = unsafe {
                VirtualAllocEx(
                    *proc,
                    std::ptr::null_mut(),
                    path_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                )
            };
            if addr.is_null() {
                return Err(err("VirtualAllecEx".to_string()));
            }
            //Add Drop fn
            let addr = guard(addr,|_|{
                info!("Cleaning Allocated Memory in proc.");
                if unsafe { VirtualFreeEx(*proc, addr, path_size, MEM_DECOMMIT) } == FALSE {
                    error!("Error during cleanup!");
                    err("VirtualFreeEx".to_string());
                    panic!("Error during cleanup")
                }
            });
            info!("Address is {:?}",*addr);
            
            let mut n = 0;
            // let cstr = match CString::new(full_path.as) {
            //     Ok(buf) => buf,
            //     Err(_) => {
            //         return Err((
            //             "The full dll path contained NULL bytes. That is not allowed in CStrings.".to_string(),
            //             0,
            //         ));
            //     }
            // };
            //
            // let buffer = cstr.as_ptr() as *const c_void;
            let bytes = full_path.as_bytes();
            if unsafe { WriteProcessMemory(*proc, *addr, bytes.as_ptr() as *const c_void, path_size, &mut n) } == FALSE {
                return Err(err("WriteProcessMemory".to_string()));
            }
            trace!("Wrote {} bytes. path has {} bytes",n, bytes.len()*8);
           
            {
                // let mut size:usize=0;
                // if unsafe{
                //     InitializeProcThreadAttributeList(
                //         std::ptr::null_mut(),
                //         0,
                //         0,
                //         &mut size as *mut usize
                //     )
                // } == FALSE {
                //     err("InitializeProcThreadAttributeList n1".to_string());
                //     error!("Not returning. The error above might be expected!");
                // }
                // let mut attr_list:PROC_THREAD_ATTRIBUTE_LIST = PROC_THREAD_ATTRIBUTE_LIST { dummy: std::ptr::null_mut() };
                // let ptr_attr_list:LPPROC_THREAD_ATTRIBUTE_LIST = &mut attr_list as *mut PROC_THREAD_ATTRIBUTE_LIST;
                // if unsafe{
                //     InitializeProcThreadAttributeList(
                //         ptr_attr_list,
                //         0,
                //         0,
                //         &mut size as *mut usize
                //     )
                // } == FALSE {
                //     return Err(err("InitializeProcThreadAttributeList n2".to_string()))
                // }
                // let ptr_attr_list = guard(ptr_attr_list,|list|{
                //     unsafe{DeleteProcThreadAttributeList(list)}
                // });
                
                // let starting_point = unsafe{std::mem::transmute(LoadLibraryW as FARPROC)};
                let starting_point = unsafe{std::mem::transmute(load_library_a)};
                let mut thread_id:u32=0;
                let thread = unsafe {
                    CreateRemoteThread(
                        *proc,
                        std::ptr::null_mut(),
                        0,
                        Some(starting_point),
                        *addr,
                        0,
                        // *ptr_attr_list,
                        &mut thread_id as *mut u32
                    )
                };
                let thread_id = thread_id;
                if thread.is_null() {
                    return Err(err("CreateRemoteThread".to_string()));
                }
                let thread = guard(thread,
                                 |thread| {
                                     info!("Cleaning thread Handle");
                                     if unsafe { CloseHandle(thread) } == FALSE {
                                         error!("Error during cleanup!");
                                         err("CloseHandle".to_string());
                                         panic!("Error during cleanup")
                                     }
                                 });
                info!("Thread is {:?} and thread id is {}", *thread, thread_id);
                info!("Waiting for DLL");
                match unsafe{WaitForSingleObject(*thread,INFINITE)}{
                    0x80=>{return Err(err_str("WaitForSingleObject returned WAIT_ABANDONED".to_string()))},//WAIT_ABANDONED
                    0x0=>{info!("Dll inject success? IDK?! Hopefully? WaitForSingleObject returned WAIT_OBJECT_0");return Ok(())},//WAIT_OBJECT_0
                    0x102=>{return Err(err_str("Timeout hit at WaitForSingleObject.".to_string()))},//WAIT_TIMEOUT
                    0xFFFFFFFF=>{return Err(err("WaitForSingleObject".to_string()))},//WAIT_FAILED
                    _=>{}
                }
                
            }
        }
        warn!("Something went wrong! This path should never be taken.");
        Ok(())//todo: is this always ok? is this even hit?
    }
    ///Find a PID, where the process-name matches some user defined selector
    pub fn find_pid_selector<F>(select: F) -> Result<Vec<u32>, (String, u32)>
    where
        F: Fn(&String) -> bool,
    {
        let mut pids: Vec<DWORD> = Vec::new();
        let snap_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap_handle == INVALID_HANDLE_VALUE {
            return Err(err("CreateToolhelp32Snapshot".to_string()));
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
            return Err(err("Process32FirstW".to_string()));
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

fn err(fn_name: String) -> (String, u32) {
    {
        let err = unsafe { GetLastError() };
        error!("{} failed! Errcode is:'{}'. Check, what the error code means here:'https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes'", fn_name, err);
        (fn_name, err)
    }
}

fn err_str(err:String) -> (String, u32) {
    error!("{}",err);
    (err,0)
}
