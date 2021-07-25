#![cfg(target_os = "windows")]

use crate::{Injector, strip_rust_path, Result, err_str};
use log::{debug, error, info, trace, warn};
use std::fs;
use std::mem::{size_of, MaybeUninit};
use widestring::WideCString;
use winapi::shared::minwindef::{DWORD, FALSE, MAX_PATH};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::libloaderapi::{GetProcAddress, GetModuleHandleA};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{OpenProcess, CreateRemoteThread, GetCurrentProcess};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, LPPROCESSENTRY32W, PROCESSENTRY32W, TH32CS_SNAPPROCESS, TH32CS_SNAPMODULE, MODULEENTRY32W, MAX_MODULE_NAME32, Module32FirstW, Module32NextW};
use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE, PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, MEM_RESERVE, PROCESS_QUERY_INFORMATION, IMAGE_FILE_MACHINE_UNKNOWN, PROCESSOR_ARCHITECTURE_INTEL, PROCESSOR_ARCHITECTURE_AMD64, HANDLE, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS, IMAGE_NT_SIGNATURE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386, PAGE_EXECUTE_READWRITE, PHANDLE};
use winapi::ctypes::{c_void};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::{INFINITE, GetBinaryTypeA};
use winapi::um::wow64apiset::{IsWow64Process2, GetSystemWow64DirectoryA};
use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO, SYSTEM_INFO_u, SYSTEM_INFO_u_s, GetNativeSystemInfo};
use std::time::Duration;
use std::fmt::Display;
use ntapi::winapi::shared::ntdef::{NT_SUCCESS, NT_ERROR, NT_INFORMATION};
use winapi::shared::ntdef::NT_WARNING;
use winapi::shared::basetsd::UINT64;

mod loaders;

macro_rules! guard_check_ptr {
    ($name:ident($($args:expr),*),$guard:literal) => {
            guard_check_ptr!($name($($args),*),
            |guard| {
            trace!("Cleaning {} Handle",$guard);
            if unsafe { CloseHandle(guard) } == FALSE {
                error!("Error during cleanup!");
                //Supress unused_must_use warning. This is intended, but one cannot use allow, to supress this?
                //todo: a bit hacky? Is there a better way, to achieve something similar?
                void_res::<()>(err(("CloseHandle of ".to_string()+std::stringify!($name))));
                panic!("Error during cleanup");
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
        check_ptr!(Module32FirstW(snap_modules, &mut module_entry as *mut MODULEENTRY32W),|val|val==FALSE);
        
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
            // trace!("module:{}",module);
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
            let proc = guard_check_ptr!(
                OpenProcess(
                PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                FALSE,self.pid),"Process");
            debug!("Process Handle is {:?}",*proc);
            //todo:make eject work independent of injector bitness
            let k32_handle = check_ptr!(GetModuleHandleA(b"kernel32.dll\0".as_ptr() as *const i8));
            //One could also use FreeLibrary here?
            let thread_start = check_ptr!(GetProcAddress(k32_handle,b"FreeLibraryAndExitThread\0".as_ptr() as *const i8));
        
            let mut thread_id:u32=0;
            let thread = guard_check_ptr!(
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
        //TODO: Recheck this Fn, and all the winapi calls
        if self.pid == 0 {
            warn!("Supplied id is 0. Will not inject, as it is not supported by windows");
            return err_str("PID is 0");
        }
        
        if self.get_module_in_pid().is_ok(){
            return err_str("dll already injected");
        }else{
            error!("The above error is expected!")
        }
        
        let proc = guard_check_ptr!(
            OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            FALSE,self.pid),"Process");
        debug!("Process Handle is {:?}",*proc);
    
        let sys_is_x64;
        let sys_is_x86;
        
        {
            let mut sysinfo:MaybeUninit<SYSTEM_INFO> = MaybeUninit::zeroed();
            unsafe{GetNativeSystemInfo(sysinfo.as_mut_ptr())}//Has no return-value, so should always succeed?
            let sysinfo = unsafe{sysinfo.assume_init()};
            sys_is_x64 = unsafe{sysinfo.u.s()}.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64;
            sys_is_x86 = unsafe{sysinfo.u.s()}.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_INTEL;
        }
        
        if sys_is_x64==sys_is_x86 {
            unreachable!("Cannot be both or neither x64 and x86! This path should be impossible! Something has gone catastrophically wrong.")
        }
        
        //Is the target exe x86?
        let pid_is_under_wow=if !sys_is_x64{false} else{
            get_proc_under_wow(*proc)?
        };
        
        // Is this exe x86?
        let self_is_under_wow= if !sys_is_x64{false} else {
            get_proc_under_wow(unsafe { GetCurrentProcess() })?
        };
        info!("pid_is_under_wow:{},self_is_under_wow:{}",pid_is_under_wow,self_is_under_wow);

        let dll=std::fs::read(self.dll)
            .map_err(|e|err_str::<(),std::io::Error>(e).unwrap_err())?;
        let dos_header = unsafe{Self::get_dll_dos_header(dll.as_ptr())}?;
        let nt_header = unsafe{Self::get_dll_nt_header(dll.as_ptr(),dll.len(),dos_header)}?;
        let dll_is_x64 = unsafe { Self::get_is_dll_x64_nt(nt_header) }?;
    
        if dll_is_x64  && pid_is_under_wow {
            warn!("Injecting a x64 dll, into a x86 exe is unsupported. Will NOT abort, but expect the dll-injection to fail");
        }else if !dll_is_x64  && !pid_is_under_wow {
            warn!("Injecting a x86 dll, into a x64 exe is unsupported. Could this case be supported? Send a PR, if you think, you can make this work! Will NOT abort, but expect the dll-injection to fail");
        }
        
        //Prepare the right loader
        let loader:&[u8];
        if pid_is_under_wow{
            debug!("Loading x86 loader");
            loader=loaders::LOADER_X86;
        }else {
            debug!("Loading x64 loader");
            loader=loaders::LOADER_X64;
        }
        //Calculate size needed for loader+dll
        let shellcode_size = loader.len()+dll.len();
        let remote_shellcode = guard_check_ptr!(VirtualAllocEx(
                *proc,
                std::ptr::null_mut(),
                shellcode_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            ),|addr|{
                trace!("Releasing VirtualAlloc'd Memory");
                if (unsafe{VirtualFreeEx(*proc,addr,0,MEM_RELEASE)}==FALSE){
                    error!("Error during cleanup!");
                    //Supress unused_must_use warning. This is intended, but one cannot use allow, to supress this?
                    //todo: a bit hacky? Is there a better way, to achieve something similar?
                    void_res(err::<(),&str>("VirtualFreeEx of VirtualAllocEx"));
                    panic!("Error during cleanup")
                }
            });
        let mut n:usize=0;
        if unsafe {
            WriteProcessMemory(
                *proc,
                *remote_shellcode,
                loader.as_ptr() as *const c_void,
                loader.len(),
                &mut n as *mut usize)
                == FALSE
                ||
            WriteProcessMemory(
                *proc,
                (*remote_shellcode).wrapping_add(loader.len()),
                dll.as_ptr() as *const c_void,
                dll.len(),
                &mut n as *mut usize)==FALSE
        }{
            return err("WriteProcessMemory");
        }
        #[allow(clippy::nonminimal_bool)]
        if !self_is_under_wow || (self_is_under_wow && pid_is_under_wow) {
            // let mut thread_id:u32=0;
            // let thread = guard_check_ptr!(
            //     CreateRemoteThread(
            //         *proc,
            //         std::ptr::null_mut(),
            //         0,
            //         Some(std::mem::transmute(*remote_shellcode)),
            //         std::ptr::null_mut(),
            //         0,
            //         &mut thread_id as *mut u32
            //     ),"thread");
            // let thread_id = thread_id;
            // trace!("Thread is {:?} and thread id is {}", *thread, thread_id);
            // debug!("Waiting for DLL");
            // // std::thread::sleep(Duration::new(0,500));//todo: why is this necessary, (only) when doing cargo run?
            // match unsafe{WaitForSingleObject(*thread,INFINITE)}{
            //     0x80=>{return err_str("WaitForSingleObject returned WAIT_ABANDONED")},//WAIT_ABANDONED
            //     0x0=>{info!("Dll inject success? IDK?! Hopefully? WaitForSingleObject returned WAIT_OBJECT_0");},//WAIT_OBJECT_0
            //     0x102=>{return err_str("Timeout hit at WaitForSingleObject.")},//WAIT_TIMEOUT
            //     0xFFFFFFFF=>{return err("WaitForSingleObject")},//WAIT_FAILED
            //     _=>{}
            // }
            let mut hThread:HANDLE=std::ptr::null_mut();
            let status=unsafe{ntapi::ntrtl::RtlCreateUserThread(
                *proc,
                std::ptr::null_mut(),
                0,
                0,
                0,
                0,
                Some(std::mem::transmute(*remote_shellcode)),
                std::ptr::null_mut(),
                &mut hThread as PHANDLE,
                std::ptr::null_mut(),
            )};
            if NT_SUCCESS(status){
                info!("RtlCreateUserThread success")
            }
            if NT_ERROR(status) {
                info!("RtlCreateUserThread error")
            }
            if NT_WARNING(status) {
                info!("RtlCreateUserThread warning")
            }
            if NT_INFORMATION(status) {
                info!("RtlCreateUserThread information")
            }
            std::thread::sleep(Duration::new(0,500));//todo:cargo run breaks stuff. adding this makes stuff work again
            let status = unsafe{ ntapi::
            ntobapi::NtWaitForSingleObject(hThread,0,std::ptr::null_mut()) };
            if NT_SUCCESS(status){
                info!("NtWaitForSingleObject success")
            }
            if NT_ERROR(status) {
                info!("NtWaitForSingleObject error")
            }
            if NT_WARNING(status) {
                info!("NtWaitForSingleObject warning")
            }
            if NT_INFORMATION(status) {
                info!("NtWaitForSingleObject information")
            }
        }else {
            struct InjectArgs {
                start:UINT64, // remote shellcode address
                hProcess:UINT64, // handle of process to inject
                hThread:UINT64, // new thread id
            };
        }
        std::thread::sleep(Duration::new(0,500));
        // self.get_module_in_pid().map(|_|())//todo: get this to work again https://github.com/UserExistsError/InjectDll/issues/3
        error!("I am currently not checking, if the dll was actually loaded. Prepare for seeing the dll init, but not having it marked as injected.");
        Ok(())
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
    ///This gets the dll dos-header, from a dll
    ///# Safety
    ///Constraint:
    ///* the dll pointer has to come from an actual dll, or otherwise, the function will (probably) not complete successfully
    pub unsafe fn get_dll_dos_header(dll:*const u8) -> Result<*const IMAGE_DOS_HEADER> {
        //This is https://github.com/UserExistsError/InjectDll/blob/master/InjectDll/fileutils.cpp
        //Many thanks, for the research!
        let dos_header: *const IMAGE_DOS_HEADER = std::mem::transmute(dll);
        if dos_header.is_null(){
            return err_str("dos_header is Null");
        }else if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE{
            return err_str("Invalid DOS Signature in dll");
        }
        Ok(dos_header)
    }
    
    ///This function will get the appropriate NT-Header, for the dll, that we wanna inject.
    ///This is useful, to get various information
    /// # Safety
    ///Constraints:
    ///* ptr and dos_header have to be the same pointer
    pub unsafe fn get_dll_nt_header(ptr:*const u8, len:usize, dos_header:*const IMAGE_DOS_HEADER) ->Result<*const IMAGE_NT_HEADERS>{
        //todo: prove, that this is platform independent, the winapi import works on non-windows, and this can't cause UB
        
        if ptr!=std::mem::transmute(dos_header){
            return err_str("get_dll_nt_header constraint violated!")
        }
        
        let nt_header: * const IMAGE_NT_HEADERS = std::mem::transmute(ptr.wrapping_offset((*dos_header).e_lfanew as isize));
        let nt_header_u8: * const u8 = std::mem::transmute(nt_header);
        if nt_header_u8 < ptr || nt_header_u8 > ptr.wrapping_add(len - std::mem::size_of::< IMAGE_NT_HEADERS > ()) {
            return err_str("Invalid NT Header in dll. Pointer out of bounds!");
        } else if nt_header.is_null() {
            return err_str("nt_header is null");
        } else if (*nt_header).Signature != IMAGE_NT_SIGNATURE{
            return err_str("Invalid NT Signature in dll.");
        }
        Ok(nt_header)
    }
    ///This function will return, whether a dll is x64, or x86.
    ///The Return value will be Ok(true), if the dll is x64(64bit), and Ok(false), if the dll is x86(32bit).
    pub fn get_is_dll_x64(&self)->Result<bool>{
        let dll = match std::fs::read(self.dll){
            Ok(v)=>v,
            Err(err)=>return err_str(err),
        };
        let dos_header=match unsafe{Self::get_dll_dos_header(dll.as_ptr())} {
            Err(err)=>return Err(err),
            Ok(v)=>v,
        };
        let nt_header= match unsafe{Self::get_dll_nt_header(dll.as_ptr(),dll.len(),dos_header)}{
            Ok(v)=>v,
            Err(err)=>return Err(err),
        };
        let dll_is_x64=unsafe{*nt_header}.FileHeader.Machine==IMAGE_FILE_MACHINE_AMD64;
        let dll_is_x86=unsafe{*nt_header}.FileHeader.Machine==IMAGE_FILE_MACHINE_I386;
        info!("Dll is {:x}, x64:{},x86:{}",unsafe{*nt_header}.FileHeader.Machine,dll_is_x64,dll_is_x86);
    
        if dll_is_x64==dll_is_x86 {
            unreachable!("Cannot be both or neither x64 and x86! This path should be impossible! Something has gone catastrophically wrong.");
        }
        Ok(dll_is_x64)
    }
    ///This function will return, whether a dll is x64, or x86.
    ///The Return value will be Ok(true), if the dll is x64(64bit), and Ok(false), if the dll is x86(32bit).
    /// # Safety
    /// nt_header has to be a valid Type and point to reasonable data
    /// Since this function doesn't know, or check, what is in nt_header, it is best, that other safe methods are used.
    pub unsafe fn get_is_dll_x64_nt(nt_header:*const IMAGE_NT_HEADERS)->Result<bool>{
        let dll_is_x64=(*nt_header).FileHeader.Machine==IMAGE_FILE_MACHINE_AMD64;
        let dll_is_x86=(*nt_header).FileHeader.Machine==IMAGE_FILE_MACHINE_I386;
        info!("Dll is {:x}, x64:{},x86:{}",(*nt_header).FileHeader.Machine,dll_is_x64,dll_is_x86);
        
        if dll_is_x64==dll_is_x86 {
            unreachable!("Cannot be both or neither x64 and x86! This path should be impossible! Something has gone catastrophically wrong.");
        }
        Ok(dll_is_x64)
    }
    
    //todo:Use this instead of IsWOW64Process? Would that be better?
    fn get_binary_type(full_path:*const i8)->Result<(u32,String,String)>{
        let mut binary_type:u32=u32::MAX;
        if unsafe {GetBinaryTypeA(full_path,&mut binary_type as *mut u32)}==0{
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

fn get_proc_under_wow(proc:HANDLE)->Result<bool>{
    let mut process_machine:u16=0;
    let mut native_machine:u16=0;
    
    if unsafe{IsWow64Process2(
        proc,
        &mut process_machine as * mut u16,
        &mut native_machine as * mut u16,
    )}==FALSE{
        return err("IsWow64Process2 number 1");
    }
    println!("proc:{:#x}",process_machine);
    println!("native:{:#x}",native_machine);
    
    //That is, if the target exe, is compiled x86, but run on x64
    Ok(process_machine != IMAGE_FILE_MACHINE_UNKNOWN)//The value will be IMAGE_FILE_MACHINE_UNKNOWN if the target process is not a WOW64 process; otherwise, it will identify the type of WoW process.
}

fn err<T,E>(fn_name:E) -> Result<T>
where E:Display{
    let err = unsafe { GetLastError() };
    error!("{} failed! Errcode is:'{}'. Check, what the error code means here:'https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes'", fn_name, err);
    Err((fn_name.to_string(), err))
}
///NOP function.
///This exists, to do the same as #[allow(unused_must_use)].
///The above doesn't work for me right now though.
#[inline]
fn void_res<T>(_:Result<T>){}
