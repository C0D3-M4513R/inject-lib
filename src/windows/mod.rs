#![cfg(target_os = "windows")]

use crate::{Injector, strip_rust_path, Result, err_str, strip_win_path, Error};
use log::{debug, error, info, trace, warn};
use std::mem::{size_of, MaybeUninit};
use widestring::{WideCString, WideCStr, WideStr};
use winapi::shared::minwindef::{DWORD, FALSE, MAX_PATH};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{OpenProcess, CreateRemoteThread, GetCurrentProcess};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, LPPROCESSENTRY32W, PROCESSENTRY32W, TH32CS_SNAPPROCESS, TH32CS_SNAPMODULE, MODULEENTRY32W, MAX_MODULE_NAME32, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE32};
use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, MEM_RESERVE, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, IMAGE_FILE_MACHINE_UNKNOWN, PROCESSOR_ARCHITECTURE_INTEL, PROCESSOR_ARCHITECTURE_AMD64, HANDLE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386, PAGE_EXECUTE_READWRITE, PROCESS_VM_READ};
use winapi::ctypes::c_void;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::INFINITE;
use winapi::um::wow64apiset::IsWow64Process2;
use winapi::um::sysinfoapi::{SYSTEM_INFO, GetNativeSystemInfo};
use std::fmt::Display;
use pelite::Wrap;
use ntapi::ntpsapi::{ProcessBasicInformation, PROCESS_BASIC_INFORMATION, PEB_LDR_DATA, PROCESSINFOCLASS};
use ntapi::ntpebteb::PEB;
use winapi::shared::ntdef::{PVOID, ULONG, PULONG, NTSTATUS, NT_SUCCESS, NT_ERROR, NT_WARNING};
use winapi::shared::basetsd::{SIZE_T, PSIZE_T, DWORD64, ULONG64, PDWORD64};
use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;

macro_rules! guard_check_ptr {
    ($name:ident($($args:expr),*),$guard:literal) => {
            guard_check_ptr!($name($($args),*),
            |guard| {
            trace!("Cleaning {} Handle",$guard);
            if unsafe { CloseHandle(guard) } == FALSE {
                error!("Error during cleanup!");
                //Supress unused_must_use warning. This is intended, but one cannot use allow, to supress this?
                //todo: a bit hacky? Is there a better way, to achieve something similar?
                void_res(err::<(),String>(("CloseHandle of ".to_string()+std::stringify!($name))));
                panic!("Error during cleanup");
            }
        }
        )
    };
    ($name:ident($($args:expr),*),$guard:expr) => {
        scopeguard::guard(check_ptr!($name($($args),*)),$guard)
    };
}
macro_rules! check_nt_status {
	($status:expr)=>{
		{
			let status = $status;
			if let Some(tmp)=check_nt_status(status){
				return Err(tmp);
			}
			status
		}
	}
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
	/// # Panic
	/// This function may panic, if a Handle cleanup fails.
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
            PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_READ| PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION ,
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
			unsafe{get_proc_under_wow(*proc)?}
		};
		
		// Is this exe x86?
		let self_is_under_wow = if !sys_is_x64 { false } else {
			unsafe {get_proc_under_wow( GetCurrentProcess() )}?
		};
		info!("pid_is_under_wow:{},self_is_under_wow:{}",pid_is_under_wow,self_is_under_wow);
		if self_is_under_wow && !pid_is_under_wow {
			info!("This injection will use a slightly different method, than usually. This is normal, when the injector is x86, but the pid specified is a x64 process.");
		};
		
		let dll_is_x64 = self.get_is_dll_x64()?;
		
		if dll_is_x64 && pid_is_under_wow {
			warn!("Injecting a x64 dll, into a x86 exe is unsupported. Will NOT abort, but expect the dll-injection to fail");
		} else if !dll_is_x64 && !pid_is_under_wow {
			warn!("Injecting a x86 dll, into a x64 exe is unsupported. Could this case be supported? Send a PR, if you think, you can make this work! Will NOT abort, but expect the dll-injection to fail");
		}
		//This check makes sure, that get_module_in_pid_predicate will not fail, due to x86->x64 injection.
		if !self_is_under_wow || pid_is_under_wow{
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
			let (k32path, k32addr) = {
				let predicate= |e:LDR_DATA_TABLE_ENTRY,s:Vec<u16>|{
					let dll_name = match match WideCStr::from_slice_with_nul(s.as_slice()){
						Ok(v)=>v.to_string(),
						Err(e)=>{warn!("Couldn't convert full dll path, to string. Will skip this dll, in assumption, that this dll is invalid. Error is {}. Buf is {:x?}.",e,s); return None;}
					}{
						Ok(v)=>v,
						Err(e)=>{warn!("Couldn't convert full dll path, to string. Will skip this dll, in assumption, that this dll is invalid. Error is {}. Buf is {:x?}.",e,s); return None;}
					};
					if strip_win_path(dll_name.as_str()) == "KERNEL32.DLL" {
						return Some((s,e.DllBase));
					}
					return None;
				};
					if self_is_under_wow&&!pid_is_under_wow{
						match unsafe{ get_module_in_proc(*proc,predicate)} {
							Err((s,n))=>{
								error!("get_module_in_proc has failed str:{} n:{:x}. There is no fallback available, since this injector seems to be x86, and the targeted exe is x64.",s,n);
								return Err((s,n));
							},
							Ok(v)=>v,
						}
					} else{
						match get_module_in_pid_predicate_selector(self.pid,
						                                           "KERNEL32.DLL",
						                                           |m| (m.szExePath, m.modBaseAddr),
						                                           None
						){
							Ok((v,a))=>(v.to_vec(),a as *mut c_void),
							Err((s,n))=>{
								warn!("get_module_in_pid_predicate_selector failed, with str:{}, n:{}. Trying get_module_in_proc as fallback method.",s,n);
								match unsafe{ get_module_in_proc(*proc,predicate)}{
									Ok(v)=>v,
									Err((s,n))=>{
										error!("get_module_in_proc failed also, as a fallback. Is something fundamentally wrong? Is the process handle valid? str:{},n:{}",s,n);
										return Err((s,n));
									},
								}
							}
						}
					}
				};
			
			//try to get the LoadLibraryA function direct from the target executable.
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
		//todo: re-add a check, for loaded modules
		
		// get_module_in_pid_predicate_selector(self.pid,self.dll,|_|(),None)
		Err(("".to_string(),0))
	}
	///Find a PID, where the process-name matches some user defined selector
	pub fn find_pid_selector<F>(select: F) -> Result<Vec<u32>>
		where
			F: Fn(&PROCESSENTRY32W) -> bool,
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
///Does NOT work, if the inejector is x86, and the target exe is x64.
///This is, due to Microsoft constraints.
///The Constraint lies with the Function `CreateToolhelp32Snapshot`. More in the Microsoft docs [here](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot).
///
/// # Arguments
///- pid: process pid
///- predicate: a Function, which returns Some(value), when the desired module is found.
///- snapshot_flags: an option, to pass other flags, to `CreateToolhelp32Snapshot`
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
///Does NOT work, if the inejector is x86, and the target exe is x64.
///This is, due to Microsoft constraints.
///The Constraint lies with the Function `CreateToolhelp32Snapshot`. More in the Microsoft docs [here](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot).
///
/// # Arguments
///- pid: process pid
///- dll: the dll, that is to be searched for
///- selector: a Function, which returns any desired value.
///- snapshot_flags: an option, to pass other flags, to `CreateToolhelp32Snapshot`
fn get_module_in_pid_predicate_selector<F, T>(pid: u32, dll: &str, selector: F, snapshot_flags: Option<u32>) -> Result<T>
	where F: Fn(&MODULEENTRY32W) -> T {
	let dll_no_path = strip_rust_path(dll);
	trace!("dll_no_path='{}'",dll_no_path);
	get_module_in_pid(pid,
	                  move |module_entry: &MODULEENTRY32W| {
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
			                  return Some(selector(&module_entry.clone()));
		                  }
		                  None
	                  },
	                  snapshot_flags,
	)
}
///Does NOT work, if the inejector is x86, and the target exe is x64.
///This is, due to Microsoft constraints.
///The Constraint lies with the Function `CreateToolhelp32Snapshot`. More in the Microsoft docs [here](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot).
///
/// # Arguments
///- pid: process pid
///- dll: the dll, that is to be searched for
///- snapshot_flags: an option, to pass other flags, to `CreateToolhelp32Snapshot`
///# Return value
/// Returns the dll's base address.
fn get_module_in_pid_predicate(pid: u32, dll: &str, snapshot_flags: Option<u32>) -> Result<*mut u8> {
	get_module_in_pid_predicate_selector(pid,dll,
	                  |module_entry: &MODULEENTRY32W| { module_entry.modBaseAddr },
	                  snapshot_flags)
}

///Returns true, if the supplied process-handle is running under WOW, otherwise false.
///# Safety
///The process handle must have the PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION access right.
unsafe fn get_proc_under_wow(proc: HANDLE) -> Result<bool> {
	let mut process_machine: u16 = 0;
	let mut native_machine: u16 = 0;
	
	if IsWow64Process2(
			proc,
			&mut process_machine as *mut u16,
			&mut native_machine as *mut u16,
		) == FALSE {
		return err("IsWow64Process2 number 1");
	}
	println!("proc:{:#x}", process_machine);
	println!("native:{:#x}", native_machine);
	
	//That is, if the target exe, is compiled x86, but run on x64
	Ok(process_machine != IMAGE_FILE_MACHINE_UNKNOWN)//The value will be IMAGE_FILE_MACHINE_UNKNOWN if the target process is not a WOW64 process; otherwise, it will identify the type of WoW process.
}
///Gets a module, by reading the Process Environment Block (PEB), of the process, using ntdll functions.
///Because this function uses ntdll functions, it should work the same, if running as x86, or x64.
///# Safety
/// The proc handle must?(ntdll has no docs) have the PROCESS_VM_READ and (PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION?).
/// The proc handle should also be valid.
///
/// # Arguments
///
///- proc: a Process Handle
///- predicate: A function, which selects, what information, from what dll it wants.
//TODO: add tons of checks
//TODO: this could endlessly loop, if the predicate never matches!
unsafe fn get_module_in_proc<F,R>(proc:HANDLE,predicate:F)->Result<R>
where F:Fn(LDR_DATA_TABLE_ENTRY,Vec<u16>)->Option<R>{
	let ntdll = LoadLibraryA(b"ntdll\0".as_ptr() as *const i8);
	let self_is_under_wow = get_proc_under_wow(GetCurrentProcess())?;
	let rvm:&[u8] = if self_is_under_wow{b"NtWow64ReadVirtualMemory64\0"} else {b"NtReadVirtualMemory\0"};
	let qip:&[u8] = if self_is_under_wow{b"NtWow64QueryInformationProcess64\0"} else {b"NtQueryInformationProcess\0"};
	
	let NtQueryInformationProcess:fn(HANDLE,PROCESSINFOCLASS,PVOID, ULONG, PULONG) -> NTSTATUS = std::mem::transmute(check_ptr!(GetProcAddress(ntdll,qip.as_ptr() as *const i8)));
	let NtReadVirtualMemory:fn (HANDLE, DWORD64, PVOID, ULONG64, PDWORD64) -> NTSTATUS = std::mem::transmute(check_ptr!(GetProcAddress(ntdll,rvm.as_ptr() as *const i8)));
	
	let peb_addr;
	{
		const SIZE_PBI:usize = std::mem::size_of::<PROCESS_BASIC_INFORMATION>();
		let mut pbi = PROCESS_BASIC_INFORMATION{
			ExitStatus: 0,
			PebBaseAddress: std::ptr::null_mut(),
			AffinityMask: 0,
			BasePriority: 0,
			UniqueProcessId: std::ptr::null_mut(),
			InheritedFromUniqueProcessId: std::ptr::null_mut()
		};
		let pbi_ptr=(&mut pbi as *mut PROCESS_BASIC_INFORMATION) as *mut c_void;
		let mut i:u32=0;
		let status = check_nt_status!(NtQueryInformationProcess(proc,ProcessBasicInformation,pbi_ptr,SIZE_PBI as u32,&mut i as *mut u32));
		trace!("qip1 {:x},{}/{}",status as u32,i,SIZE_PBI);
		peb_addr = pbi.PebBaseAddress;
		trace!("Peb addr is {:?}",peb_addr);
	}
	let ldr_addr;
	{
		let mut i:u64=0;
		const SIZE_PEB:usize = std::mem::size_of::<PEB>();
		let mut buf_peb = Vec::with_capacity(SIZE_PEB);
		let status = check_nt_status!(NtReadVirtualMemory(proc, peb_addr as u64, buf_peb.as_mut_ptr() as *mut c_void, SIZE_PEB as u64, &mut i as *mut u64));
		buf_peb.set_len(i as usize);
		debug!("rvm peb {:x},{}/{}",status as u32,i,SIZE_PEB);
		let peb_ptr:*const PEB = std::mem::transmute(buf_peb.as_ptr());
		ldr_addr=(*peb_ptr).Ldr;
	}
	let mut modlist_addr;
	{
		let mut i:u64 =0;
		const SIZE_LDR:usize = std::mem::size_of::<PEB_LDR_DATA>();
		let mut buf_ldr:Vec<u8> = Vec::with_capacity(SIZE_LDR);
		let status = check_nt_status!(NtReadVirtualMemory(proc, ldr_addr as u64, buf_ldr.as_mut_ptr() as *mut c_void, SIZE_LDR as u64, &mut i as *mut u64));
		buf_ldr.set_len(i as usize);
		debug!("rvm ldr {:x},{}/{}",status as u32,i,SIZE_LDR);
		let peb_ldr:*const PEB_LDR_DATA = std::mem::transmute(buf_ldr.as_ptr());
		modlist_addr=(*peb_ldr).InLoadOrderModuleList;
	}
	loop{
		let ldr_entry={
			let mut i:u64 =0;
			const SIZE_LDR_ENTRY:usize = std::mem::size_of::<LDR_DATA_TABLE_ENTRY>();
			let mut buf_ldr_entry:Vec<u8> = Vec::with_capacity(SIZE_LDR_ENTRY);
			trace!("trying to read {:x?}",modlist_addr.Flink);
			let status = check_nt_status!(NtReadVirtualMemory(proc, modlist_addr.Flink as u64, buf_ldr_entry.as_mut_ptr() as *mut c_void, SIZE_LDR_ENTRY as u64, &mut i as *mut u64));
			buf_ldr_entry.set_len(i as usize);
			debug!("rvm ldr_data_table_entry {:x},{}/{}",status as u32,i,SIZE_LDR_ENTRY);
			let ldr_entry_ptr:*const LDR_DATA_TABLE_ENTRY=std::mem::transmute(buf_ldr_entry.as_ptr());
			*ldr_entry_ptr
		};
		{
			let dll_win_string=ldr_entry.FullDllName;
			let mut dll_path:Vec<u16>=Vec::with_capacity(dll_win_string.MaximumLength as usize);
			let mut i:u64=0;
			trace!("trying to read {:x?}",dll_win_string.Buffer);
			let status = check_nt_status!(NtReadVirtualMemory(proc,dll_win_string.Buffer as u64,dll_path.as_mut_ptr() as *mut c_void,dll_win_string.MaximumLength as u64,&mut i as *mut u64));
			dll_path.set_len(i as usize);
			debug!("rvm dll_name {:x},{}/{}",status as u32,i,dll_win_string.MaximumLength);
			match WideCStr::from_slice_with_nul(dll_path.as_slice()){
				Ok(v) => {
					match v.to_string(){
						Ok(dll_name)=>{
							debug!("dll_name is {}",dll_name);
						},
						Err(e)=>{
							debug!("dll_name could not be printed. error is:{}, os_string is {:?}",e,dll_path.as_slice());
						}
					}
				},
				Err(e) => {
					debug!("dll_name could not be printed. error is:{}, os_string is {:?}",e,dll_path.as_slice());
				}
			}
			if let Some(val)=predicate(ldr_entry,dll_path){
				return Ok(val);
			}else{
				modlist_addr=ldr_entry.InLoadOrderLinks;
			}
		}
	}
}

fn err<T, E>(fn_name: E) -> Result<T>
	where E: Display {
	let err = unsafe { GetLastError() };
	error!("{} failed! Errcode is:'{}'. Check, what the error code means here:'https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes'", fn_name, err);
	Err((fn_name.to_string(), err))
}

fn check_nt_status(status:NTSTATUS)->Option<Error>{
	if NT_ERROR(status){
		error!("Received error type, from ntdll, during NtQueryInformationProcess. Status code is: {:x}",status);
		return Some(("ntdll".to_string(),status as u32))
	}
	if NT_WARNING(status){
		warn!("Received warning type, from ntdll, during NtQueryInformationProcess. Status code is: {:x}",status);
	}
	None
}

///NOP function.
///This exists, to do the same as #[allow(unused_must_use)].
///The above doesn't work for me right now though.
#[inline]
fn void_res<T>(_: Result<T>) {}
