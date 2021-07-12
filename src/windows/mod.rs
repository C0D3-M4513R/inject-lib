#![cfg(target_os = "windows")]

use crate::{Injector, strip_rust_path};
use log::{debug, error, info, trace, warn};
use std::fs;
use std::mem::size_of;
use widestring::WideCString;
use winapi::shared::minwindef::{DWORD, FALSE, MAX_PATH};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::libloaderapi::{GetProcAddress, GetModuleHandleA};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{OpenProcess, CreateRemoteThread, GetCurrentProcess};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, LPPROCESSENTRY32W, PROCESSENTRY32W, TH32CS_SNAPPROCESS, TH32CS_SNAPMODULE, MODULEENTRY32W, MAX_MODULE_NAME32, Module32FirstW, Module32NextW};
use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE, PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, MEM_RESERVE, PROCESS_QUERY_INFORMATION, IMAGE_FILE_MACHINE_UNKNOWN};
use winapi::ctypes::{c_void};
use winapi::um::synchapi::WaitForSingleObject;
use std::fmt::Display;
use winapi::um::winbase::{INFINITE, GetBinaryTypeA};
use winapi::um::wow64apiset::{IsWow64Process2, GetSystemWow64DirectoryA};

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
    fn get_module_in_pid(&self) ->Result<*mut u8>{
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
        
        let dll_no_path = strip_rust_path(self.dll);
        
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
                return Ok(module_entry.modBaseAddr);
            }
            if unsafe{Module32NextW(snap_modules, &mut module_entry as *mut MODULEENTRY32W)}==FALSE {
                error!("Encountered error, while calling Module32NextW. This is expected, if there isn't a dll, with the specified name loaded.");
                return err("Module32NextW");
            }
        }
    }
    
    pub fn eject(&self) -> Result<()> {
        if self.pid == 0 {
            warn!("Supplied id is 0. Will not eject.");
            return err_str("PID is 0");
        }
        let addr= match self.get_module_in_pid(){
            Ok(v)=>v,
            Err(err)=>{return Err(err);},
        };
        
        info!("Found dll in proc, at addr:{:#x?}",addr);
        //Spawn the thread, that ejects the dll
        {
            let proc = check_ptr!(
                OpenProcess(
                PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                FALSE,self.pid),"Process");
            debug!("Process Handle is {:?}",*proc);
            let k32_handle = check_ptr!(GetModuleHandleA(b"kernel32.dll\0".as_ptr() as *const i8));
            //One could also use FreeLibrary here?
            let thread_start = check_ptr!(GetProcAddress(k32_handle,b"FreeLibraryAndExitThread\0".as_ptr() as *const i8));
        
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
                0x0=>{info!("Dll eject success? IDK?! Hopefully? WaitForSingleObject returned WAIT_OBJECT_0")},//WAIT_OBJECT_0
                0x102=>{return err_str("Timeout hit at WaitForSingleObject.")},//WAIT_TIMEOUT
                0xFFFFFFFF=>{return err("WaitForSingleObject")},//WAIT_FAILED
                _=>{}
            }
        }
        if self.get_module_in_pid().is_err(){
            error!("The above error is expected!");
            Ok(())
        }else {
            info!("Inject actually failed");
            Err(("Inject didn't succeed. Blame the dll, or Windows, but I tried.".to_string(),0))
        }
    }
    
    ///Actually Inject the DLL.
    ///For now, the injection is only likely to succeed, if the injector, dll and target process have the same bitness (all x64, or all x86)
    ///Open a Pr, if you know more about this!
    ///Return information (Outside of Ok and Err) is purely informational (for now)! It should not be relied upon, and may change in Minor updates.
    ///Notice:This implementation blocks, and waits, until the library is injected, or the injection failed.
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
        
        
        //https://helloacm.com/how-to-check-if-a-dll-or-exe-is-32-bit-or-64-bit-x86-or-x64-using-vbscript-function/
        //TODO:Recheck this Fn, and all the winapi calls
        if self.pid == 0 {
            warn!("Supplied id is 0. Will not inject, as it is not supported by windows");
            return err_str("PID is 0");
        }
        let proc = check_ptr!(
            OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            FALSE,self.pid),"Process");
        debug!("Process Handle is {:?}",*proc);
        
        let mut process_machine:u16=0;
        let mut native_machine:u16=0;
        
        if unsafe{IsWow64Process2(
            *proc,
            &mut process_machine as * mut u16,
            &mut native_machine as * mut u16,
        )}==FALSE{
            return err("IsWow64Process2 number 1");
        }
        //That is, if the target exe, is compiled x86, but run on x64
        let pid_is_under_WOW = process_machine != IMAGE_FILE_MACHINE_UNKNOWN;
        println!("proc:{:#x}",process_machine);
        println!("native:{:#x}",native_machine);
    
        if unsafe{IsWow64Process2(
            GetCurrentProcess(),
            &mut process_machine as * mut u16,
            &mut native_machine as * mut u16,
        )}==FALSE{
            return err("IsWow64Process2 number 2");
        }
        println!("proc:{:#x}",process_machine);
        println!("native:{:#x}",native_machine);
        //That is, if this exe, this lib is used in, is compiled x86, but run on x64
        let self_is_under_WOW = process_machine != IMAGE_FILE_MACHINE_UNKNOWN;
        
        debug!("Target Pid is running under WOW:{}, Self is running under WOW:{}",pid_is_under_WOW,self_is_under_WOW);
        
        if !pid_is_under_WOW && self_is_under_WOW{
            //We wanna print this, even, if no debugger exists.
            eprintln!("Currently unsupported! injector is x86, but process is x64. Is this even supportable? Create a pr, if you are interested.");
            eprintln!("Will try injection anyways");
        }else if pid_is_under_WOW && !self_is_under_WOW {
            //We wanna print this, even, if no debugger exists.
            eprintln!("Currently unsupported! injector is x64, but process is x86. This is supportable, I just don't know how!");
            eprintln!("Will try injection anyways");
            
            //This code is WIP.
            //While it is run, it should not do any harm, or have any side-effects.
            let size = unsafe{GetSystemWow64DirectoryA(std::ptr::null_mut(),0)};
            if size==0{
                return err("GetSystemWow64DirectoryA number1");
            }
            let mut buffer:Vec<u8>=Vec::with_capacity(size as usize);
            let buffer_ptr = buffer.as_mut_ptr() as *mut i8;
            let written_size=unsafe{GetSystemWow64DirectoryA(buffer_ptr,size)};
            if written_size==0{
                return err("GetSystemWow64DirectoryA number2");
            };
            //We could turn the buffer into a string, and back now, but why?
            //It is an obscene amount of code, that can be avoided.
            unsafe{buffer.set_len(written_size as usize)};
            //truncate the null-byte, which terminates the c_string
            // buffer.truncate((written_size - 1) as usize);
            let mut path = match String::from_utf8(buffer){
                Ok(v)=>v,
                Err(e)=>{return err_str(e);},
            };
            trace!("WOW64 System Directory is:{}", path);
            if !path.ends_with('\\') {
                path+="\\";
            }
            path+="kernel32.dll";
            debug!("Full path to WOW64 kernel32.dll is:{}",path);
            let wpath = match WideCString::from_os_str(path.as_str()){
                Ok(v)=>v,
                Err(e)=>{return err_str(e);}
            };
            // panic!("Right before LoadLibraryW call. Loading x64 dll (Is the dll actually x64? Are we injecting x86 dll into x86? IDK! This is unsupported.) on x86 is unsupported.");
            // let k32_handle = check_ptr!(LoadLibraryW(wpath.as_ptr()));
            // return err_str("none");
        }
        
        
        let k32_handle=check_ptr!(GetModuleHandleA(b"kernel32.dll\0".as_ptr() as *const i8));
        let thread_start = check_ptr!(GetProcAddress(k32_handle,b"LoadLibraryA\0".as_ptr() as *const i8));
        trace!("Thread start addr. will be:{:#x?}. Kernel32.dll handle is: {:#x?}. thread_start-k32_handle:{:#x?}",thread_start,k32_handle,(thread_start as usize) - (k32_handle as usize));
        
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
                    if err::<()>("VirtualFreeEx of VirtualAllocEx").is_ok() {};
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
                    0x0=>{info!("Dll inject success? IDK?! Hopefully? WaitForSingleObject returned WAIT_OBJECT_0");},//WAIT_OBJECT_0
                    0x102=>{return err_str("Timeout hit at WaitForSingleObject.")},//WAIT_TIMEOUT
                    0xFFFFFFFF=>{return err("WaitForSingleObject")},//WAIT_FAILED
                    _=>{}
                }
                
            }
        }
        self.get_module_in_pid().map(|_|())
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
    
    //todo:Use this instead of IsWOW64Process? Would that be better?
    unsafe fn get_binary_type(full_path:*const i8)->Result<(u32,String,String)>{
        let mut binary_type:u32=u32::MAX;
        if GetBinaryTypeA(full_path,&mut binary_type as *mut u32)==0{
            return err("GetBinaryTypeA");
        }
        let (value,meaning) =
            if binary_type==0{
                ("SCS_32BIT_BINARY","A 32-bit Windows-based application")
            } else if binary_type==6 {
                ("SCS_64BIT_BINARY","A 64-bit Windows-based application.")
            }else if binary_type==1 {
                ("SCS_DOS_BINARY","An MS-DOS – based application")
            } else if binary_type==5 {
                ("SCS_OS216_BINARY","A 16-bit OS/2-based application")
            } else if binary_type==3 {
                ("SCS_PIF_BINARY","A PIF file that executes an MS-DOS – based application")
            } else if binary_type==4 {
                ("SCS_POSIX_BINARY","A POSIX – based application")
            } else if binary_type==2 {
                ("SCS_WOW_BINARY","A 16-bit Windows-based application")
            } else{
                panic!("Invalid state. We should have returned an error earlier.");
            };
        trace!("GetBinaryTypeA returned '{}' as Binary type. That is: '{}', or in other words: '{}'",binary_type,value,meaning);
        Ok((binary_type,value.to_string(),meaning.to_string()))
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
