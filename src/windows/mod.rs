#![cfg(target_os = "windows")]

use crate::{Injector, strip_rust_path, Result, err_str};
use log::{debug, error, info, trace, warn};
use std::mem::{size_of, MaybeUninit};
use widestring::{WideCString, WideCStr};
use winapi::shared::minwindef::{DWORD, FALSE, MAX_PATH};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::libloaderapi::{GetProcAddress, GetModuleHandleA};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{OpenProcess, CreateRemoteThread, GetCurrentProcess};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, LPPROCESSENTRY32W, PROCESSENTRY32W, TH32CS_SNAPPROCESS, TH32CS_SNAPMODULE, MODULEENTRY32W, MAX_MODULE_NAME32, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE32};
use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, MEM_RESERVE, PROCESS_QUERY_INFORMATION, IMAGE_FILE_MACHINE_UNKNOWN, PROCESSOR_ARCHITECTURE_INTEL, PROCESSOR_ARCHITECTURE_AMD64, HANDLE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386, PAGE_EXECUTE_READWRITE};
use winapi::ctypes::c_void;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::INFINITE;
use winapi::um::wow64apiset::IsWow64Process2;
use winapi::um::sysinfoapi::{SYSTEM_INFO, GetNativeSystemInfo};
use std::fmt::Display;
use pelite::Wrap;

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

macro_rules! result {
	($res:expr) => {
		match $res{
			Ok(v)=>v,
			Err(e)=>{return err_str(e);},
		}
	};
}

impl<'a> Injector<'a> {
	pub fn eject(&self) -> Result<()> {
		if self.pid == 0 {
			warn!("Supplied id is 0. Will not eject.");
			return err_str("PID is 0");
		}
		let addr = match get_module_in_pid_predicate(self.pid, self.dll, None) {
			Ok(v) => v,
			Err(err) => { return Err(err); }
		};
		
		info!("Found dll in proc, at addr:{:#x?}",addr);
		//Spawn the thread, that ejects the dll
		{
			let proc = guard_check_ptr!(
                OpenProcess(
                PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                FALSE,self.pid),"Process");
			debug!("Process Handle is {:?}",*proc);
			
			let thread_start = {
				//try to get the LoadLibraryA function direct from the target executable.
				let (k32path, k32addr) = get_module_in_pid_predicate_selector(self.pid,
				                                                              "KERNEL32.DLL",
				                                                              |m| (m.szExePath, m.modBaseAddr),
				                                                              None
				)?;
				let str = match WideCStr::from_slice_with_nul(&k32path) {
					Ok(v) => result!(v.to_string()),
					Err(e) => { return err_str(e); },
				};
				let k32 = result!(std::fs::read(&str));
				
				let dll_parsed = result!(Wrap::<pelite::pe32::PeFile,pelite::pe64::PeFile>::from_bytes(k32.as_slice()));
				let lla = result!(dll_parsed.get_export_by_name("FreeLibraryAndExitThread")).symbol().unwrap();
				debug!("FreeLibraryAndExitThread is {:x}",lla);
				//todo: can we use add instead of wrapping_add?
				k32addr.wrapping_add(lla as usize)
			};
			
			
			let mut thread_id: u32 = 0;
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
			match unsafe { WaitForSingleObject(*thread, INFINITE) } {
				0x80 => { return err_str("WaitForSingleObject returned WAIT_ABANDONED"); }//WAIT_ABANDONED
				0x0 => { info!("Dll eject success? IDK?! Hopefully? WaitForSingleObject returned WAIT_OBJECT_0") }//WAIT_OBJECT_0
				0x102 => { return err_str("Timeout hit at WaitForSingleObject."); }//WAIT_TIMEOUT
				0xFFFFFFFF => { return err("WaitForSingleObject"); }//WAIT_FAILED
				_ => {}
			}
		}
		if get_module_in_pid_predicate(self.pid, self.dll, None).is_err() {
			error!("The above error is expected!");
			Ok(())
		} else {
			info!("Inject actually failed");
			Err(("Inject didn't succeed. Blame the dll, or Windows, but I tried.".to_string(), 0))
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
		let proc = guard_check_ptr!(
            OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            FALSE,self.pid),"Process");
		debug!("Process Handle is {:?}",*proc);
		//Check DLL, target process bitness and the bitness, of this injector
		let sys_is_x64;
		let sys_is_x86;
		{
			let mut sysinfo: MaybeUninit<SYSTEM_INFO> = MaybeUninit::zeroed();
			unsafe { GetNativeSystemInfo(sysinfo.as_mut_ptr()) }//Has no return-value, so should always succeed?
			let sysinfo = unsafe { sysinfo.assume_init() };
			sys_is_x64 = unsafe { sysinfo.u.s() }.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64;
			sys_is_x86 = unsafe { sysinfo.u.s() }.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL;
		}
		
		if sys_is_x64 == sys_is_x86 {
			unreachable!("Cannot be both or neither x64 and x86! This path should be impossible! Something has gone catastrophically wrong.")
		}
		
		//Is the target exe x86?
		let pid_is_under_wow = if !sys_is_x64 { false } else {
			get_proc_under_wow(*proc)?
		};
		
		// Is this exe x86?
		let self_is_under_wow = if !sys_is_x64 { false } else {
			get_proc_under_wow(unsafe { GetCurrentProcess() })?
		};
		info!("pid_is_under_wow:{},self_is_under_wow:{}",pid_is_under_wow,self_is_under_wow);
		if self_is_under_wow && !pid_is_under_wow {
			return err_str("Injection from a x86 injector into a x64 process is currently not supported, due to Limitations of CreateToolhelp32Snapshot.
			https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
			If the specified process is a 64-bit process and the caller is a 32-bit process, this function fails and the last error code is ERROR_PARTIAL_COPY (299).");
		};
		
		let dll_is_x64 = self.get_is_dll_x64()?;
		
		if dll_is_x64 && pid_is_under_wow {
			warn!("Injecting a x64 dll, into a x86 exe is unsupported. Will NOT abort, but expect the dll-injection to fail");
		} else if !dll_is_x64 && !pid_is_under_wow {
			warn!("Injecting a x86 dll, into a x64 exe is unsupported. Could this case be supported? Send a PR, if you think, you can make this work! Will NOT abort, but expect the dll-injection to fail");
		}
		
		//Is the dll already injected?
		if get_module_in_pid_predicate(self.pid, self.dll, None).is_ok() {
			return err_str("dll already injected");
		} else {
			error!("The above error is expected!")
		}
	
		//todo: add other paths, if bitness of injector == bitness of dll == bitness of target?
		//todo: That could lead to better performance.
		let entry_point = {
			//try to get the LoadLibraryA function direct from the target executable.
			let (k32path, k32addr) = get_module_in_pid_predicate_selector(self.pid,
			                                                              "KERNEL32.DLL",
			                                                              |m| (m.szExePath, m.modBaseAddr),
			                                                              None
			)?;
			let str = match WideCStr::from_slice_with_nul(&k32path) {
				Ok(v) => result!(v.to_string()),
				Err(e) => { return err_str(e); },
			};
			let k32 = result!(std::fs::read(&str));
			
			let dll_parsed = result!(Wrap::<pelite::pe32::PeFile,pelite::pe64::PeFile>::from_bytes(k32.as_slice()));
			let lla = result!(dll_parsed.get_export_by_name("LoadLibraryA")).symbol().unwrap();
			debug!("LoadLibraryA is {:x}",lla);
			//todo: can we use add instead of wrapping_add?
			k32addr.wrapping_add(lla as usize)
		};
	
		//Prepare Argument for LoadLibraryA
		let mem = {
			let full_path = result!(std::fs::canonicalize(self.dll));
			let path = full_path.to_str().unwrap();
			let path_size=path.len()+1;
			if path_size>MAX_PATH {
				return err_str("Path Size is bigger, than MAX_PATH");
			}
			//Allocate Memory in the remote process.
			let mem = {
				guard_check_ptr!(VirtualAllocEx(
	                *proc,
	                std::ptr::null_mut(),
	                path_size,
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
	            })
			};
			//Write the Argument for LoadLibraryA, in the previously allocated memory
			{
				let mut n: usize = 0;
				let bytes = path.as_bytes();
				if unsafe {
					WriteProcessMemory(
						*proc,
						*mem,
						bytes.as_ptr() as *const c_void,
						path_size,
						&mut n as *mut usize)
						== FALSE
				} {
					return err("WriteProcessMemory");
				}
			}
			mem
		};
		//Execute LoadLibraryA in remote thread, and wait for dll to load
		{
			let mut thread_id:u32=0;
			let thread = guard_check_ptr!(
			    CreateRemoteThread(
			        *proc,
			        std::ptr::null_mut(),
			        0,
			        Some(std::mem::transmute(entry_point)),
			        *mem,
			        0,
			        &mut thread_id as *mut u32
			    ),"thread");
			let thread_id = thread_id;
			trace!("Thread is {:?} and thread id is {}", *thread, thread_id);
			debug!("Waiting for DLL");
			// std::thread::sleep(Duration::new(0,500));//todo: why is this necessary, (only) when doing cargo run?
			match unsafe{WaitForSingleObject(*thread,INFINITE)}{
			    0x80=>{return err_str("WaitForSingleObject returned WAIT_ABANDONED")},//WAIT_ABANDONED
			    0x0=>{info!("Dll inject success? IDK?! Hopefully? WaitForSingleObject returned WAIT_OBJECT_0");},//WAIT_OBJECT_0
			    0x102=>{return err_str("Timeout hit at WaitForSingleObject.")},//WAIT_TIMEOUT
			    0xFFFFFFFF=>{return err("WaitForSingleObject")},//WAIT_FAILED
			    _=>{}
			}
		}
		//Check, if the dll is actually loaded?
		//todo: can we skip this? is the dll always guaranteed to be loaded here, or is it up to the dll, to decide that?
		get_module_in_pid_predicate_selector(self.pid,self.dll,|_|(),None)
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
	///This function will return, whether a dll is x64, or x86.
	///The Return value will be Ok(true), if the dll is x64(64bit), and Ok(false), if the dll is x86(32bit).
	pub fn get_is_dll_x64(&self) -> Result<bool> {
		let dll=result!(std::fs::read(self.dll));
		let parsed = result!(Wrap::<pelite::pe32::PeFile,pelite::pe64::PeFile>::from_bytes(dll.as_slice()));
		let machine = parsed.file_header().Machine;
		let dll_is_x64 = machine == IMAGE_FILE_MACHINE_AMD64;
		let dll_is_x86 = machine == IMAGE_FILE_MACHINE_I386;
		info!("Dll is {:x}, x64:{},x86:{}",machine,dll_is_x64,dll_is_x86);
		if dll_is_x64 == dll_is_x86 {
			unreachable!("Cannot be both or neither x64 and x86! This path should be impossible! Something has gone catastrophically wrong.");
		}
		Ok(dll_is_x64)
	}
}

fn get_module_in_pid<F, T>(pid: u32, predicate: F, snapshot_flags: Option<u32>) -> Result<T>
	where F: Fn(&MODULEENTRY32W) -> Option<T> {
	let snap_modules =check_ptr!(CreateToolhelp32Snapshot(snapshot_flags.unwrap_or(TH32CS_SNAPMODULE32|TH32CS_SNAPMODULE), pid),|v|v==INVALID_HANDLE_VALUE);
	let mut module_entry = MODULEENTRY32W {
		dwSize: size_of::<MODULEENTRY32W>() as u32,//The size of the structure, in bytes. Before calling the Module32First function, set this member to sizeof(MODULEENTRY32). If you do not initialize dwSize, Module32First fails.
		th32ModuleID: 1,//This member is no longer used, and is always set to one.
		th32ProcessID: 0,//The identifier of the process whose modules are to be examined.
		GlblcntUsage: 0,//The load count of the module, which is not generally meaningful, and usually equal to 0xFFFF.
		ProccntUsage: 0,//The load count of the module (same as GlblcntUsage), which is not generally meaningful, and usually equal to 0xFFFF.
		modBaseAddr: std::ptr::null_mut(),//The base address of the module in the context of the owning process.
		modBaseSize: 0,//The size of the module, in bytes.
		hModule: std::ptr::null_mut(),//A handle to the module in the context of the owning process.
		szModule: [0; MAX_MODULE_NAME32 + 1],//The module name.
		szExePath: [0; MAX_PATH],//The module path.
	};
	check_ptr!(Module32FirstW(snap_modules, &mut module_entry as *mut MODULEENTRY32W),|val|val==FALSE);
	
	loop {
		//This is kinda slow in debug mode. Can't do anything about it.
		if let Some(v) = predicate(&module_entry) { check_ptr!(CloseHandle(snap_modules),|v|v==0); return Ok(v); }
		if unsafe { Module32NextW(snap_modules, &mut module_entry as *mut MODULEENTRY32W) } == FALSE {
			error!("Encountered error, while calling Module32NextW. This is expected, if there isn't a dll, with the specified name loaded.");
			return err("Module32NextW");
		}
	}
}

fn get_module_in_pid_predicate_selector<F, T>(pid: u32, dll: &str, selector: F, snapshot_flags: Option<u32>) -> Result<T>
	where F: Fn(&MODULEENTRY32W) -> T {
	let dll_no_path = strip_rust_path(dll);
	trace!("dll_no_path='{}'",dll_no_path);
	get_module_in_pid(pid,
	                  |module_entry: &MODULEENTRY32W| {
		                  //The errors below are not handled really well, because I do not think, they will actually occur.
		                  let module_cstr = match unsafe { WideCString::from_ptr_with_nul(module_entry.szModule.as_ptr(), module_entry.szModule.len()) } {
			                  Ok(v) => v,
			                  Err(e) => {
				                  let _: Result<()> = err_str(e);
				                  return None;
			                  }
		                  };
		                  let module = match module_cstr.to_string() {
			                  Ok(v) => v,
			                  Err(e) => {
				                  let _: Result<()> = err_str(e);
				                  return None;
			                  }
		                  };
		                  trace!("module:'{}', module==dll_no_path:'{}'",module,module==dll_no_path);
		                  if module == dll_no_path
		                  {
			                  return Some(selector(module_entry));
		                  }
		                  None
	                  },
	                  snapshot_flags,
	)
}

fn get_module_in_pid_predicate(pid: u32, dll: &str, snapshot_flags: Option<u32>) -> Result<*mut u8> {
	get_module_in_pid_predicate_selector(pid,dll,
	                  |module_entry: &MODULEENTRY32W| { module_entry.modBaseAddr },
	                  snapshot_flags)
}

fn get_proc_under_wow(proc: HANDLE) -> Result<bool> {
	let mut process_machine: u16 = 0;
	let mut native_machine: u16 = 0;
	
	if unsafe {
		IsWow64Process2(
			proc,
			&mut process_machine as *mut u16,
			&mut native_machine as *mut u16,
		)
	} == FALSE {
		return err("IsWow64Process2 number 1");
	}
	println!("proc:{:#x}", process_machine);
	println!("native:{:#x}", native_machine);
	
	//That is, if the target exe, is compiled x86, but run on x64
	Ok(process_machine != IMAGE_FILE_MACHINE_UNKNOWN)//The value will be IMAGE_FILE_MACHINE_UNKNOWN if the target process is not a WOW64 process; otherwise, it will identify the type of WoW process.
}

fn err<T, E>(fn_name: E) -> Result<T>
	where E: Display {
	let err = unsafe { GetLastError() };
	error!("{} failed! Errcode is:'{}'. Check, what the error code means here:'https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes'", fn_name, err);
	Err((fn_name.to_string(), err))
}


///NOP function.
///This exists, to do the same as #[allow(unused_must_use)].
///The above doesn't work for me right now though.
#[inline]
fn void_res<T>(_: Result<T>) {}
