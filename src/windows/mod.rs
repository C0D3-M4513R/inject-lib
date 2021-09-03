#![cfg(target_os = "windows")]

use crate::{Injector, strip_rust_path, Result, err_str, strip_win_path, Error, __call__};
use log::{debug, error, info, trace, warn};
use std::mem::{size_of, MaybeUninit, ManuallyDrop};
use widestring::{WideCString, WideCStr};
use winapi::shared::minwindef::{DWORD, FALSE, MAX_PATH, LPVOID, BOOL};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory, CreateFileMappingW, FILE_MAP_ALL_ACCESS, FILE_MAP_EXECUTE, MapViewOfFile, VirtualAlloc};
use winapi::um::processthreadsapi::{OpenProcess, CreateRemoteThread, GetCurrentProcess};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, LPPROCESSENTRY32W, PROCESSENTRY32W, TH32CS_SNAPPROCESS, TH32CS_SNAPMODULE, MODULEENTRY32W, MAX_MODULE_NAME32, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE32};
use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, MEM_RESERVE, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, IMAGE_FILE_MACHINE_UNKNOWN, PROCESSOR_ARCHITECTURE_INTEL, PROCESSOR_ARCHITECTURE_AMD64, HANDLE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386, PAGE_EXECUTE_READWRITE, PROCESS_VM_READ, PAGE_READWRITE, PROCESS_ALL_ACCESS, WOW64_CONTEXT, WOW64_FLOATING_SAVE_AREA, SECURITY_DESCRIPTOR};
use winapi::ctypes::c_void;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::{INFINITE, Wow64SetThreadContext};
use winapi::um::wow64apiset::{IsWow64Process2,Wow64DisableWow64FsRedirection,Wow64RevertWow64FsRedirection};
use winapi::um::sysinfoapi::{SYSTEM_INFO, GetNativeSystemInfo, GetSystemWindowsDirectoryA};
use std::fmt::{Display, Debug};
use pelite::Wrap;
use winapi::shared::ntdef::{PVOID, PVOID64, NTSTATUS, NT_ERROR, NT_WARNING, ULONG, PULONG};
use winapi::shared::basetsd::{DWORD64, ULONG64, PDWORD64, PULONG64, SIZE_T};

#[cfg(feature = "ntdll")]
mod types;//These are exclusively ntdll types

use types::{PROCESS_BASIC_INFORMATION_WOW64,PEB64,PEB_LDR_DATA64,LDR_DATA_TABLE_ENTRY64};
use std::thread::{yield_now, sleep};
use std::ops::Range;
use std::ffi::OsString;
use std::io::Write;


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
///Checks a NtStatus, using [check_nt_status].
///If [check_nt_status] returns Some value, it returns it, as an Err.
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
            PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_READ| PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
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
				type Return=(String,u64);
				///Takes a Selector, and returns a type, for use with get_module_in_proc and get_module_in_pid
				//todo: does this bring a performance benefit?
				#[inline]
				fn predicate<T>(f: impl Fn(T) -> u64) -> impl Fn(T,Vec<u16>) -> Option<Return> {
					crate::hof::swap_fn_args(crate::hof::optpredicate(|v|converter(v,|s|strip_win_path(s.as_str())=="KERNEL32.DLL"),move|s:String,i2|(s,f(i2))))
				}
				
				let selector_pid = |m:&MODULEENTRY32W|m.modBaseAddr as u64;
				///Runs get_module_in_proc, with the supplied error handler.
				fn run_get_module_in_proc(proc:HANDLE,f:impl Fn(Error)->Result<Return>) -> Result<Return>{
					#[cfg(feature = "ntdll")]
					return {
						let selector_proc =|e:Wrap<ntapi::ntwow64::LDR_DATA_TABLE_ENTRY32, types::LDR_DATA_TABLE_ENTRY64>|
							match e {
								Wrap::T32(v)=>v.DllBase as u64,
								Wrap::T64(v)=>v.DllBase as u64,
							};
						match unsafe{ get_module_in_proc(proc, predicate(selector_proc))} {
							Err(e)=>f(e),
							Ok(v)=>Ok(v),
						}
					};
					#[cfg(not(feature = "ntdll"))]
					err_str("ntdll feature is disabled. Injecting from x86 injector to x64 executable is unsupportable, without ntdll")
					
				}
				
				if self_is_under_wow&&!pid_is_under_wow{
					run_get_module_in_proc(*proc,|(s,n)|{
						error!("Could not try get_module_in_pid first. We are a x86 injector, and injecting into a x64 process. Error details: str:{} n:{}",s,n);
						Err((s,n))
					})?
				} else{
					match get_module_in_pid(self.pid,
                                   |m|predicate(selector_pid)(m,m.szExePath.to_vec()),
                                   None
					){
						Ok(r)=>r,
						Err((s,n))=>{
							warn!("get_module_in_pid_predicate_selector failed, with str:{}, n:{}. Trying get_module_in_proc as fallback method.",s,n);
							run_get_module_in_proc(*proc,|(s,n)|{
								error!("get_module_in_proc failed also, as a fallback. Is something fundamentally wrong? Is the process handle valid? str:{},n:{}",s,n);
								Err((s,n))
							})?
						}
					}
				}
			};
			//We need to replace System32, by Sysnative, in case we are running under WOW, because Windows will otherwise redirect all our file access.
			
			//One can also use the following methods: https://docs.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-wow64disablewow64fsredirection,https://docs.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-wow64revertwow64fsredirection
			//I am not using those methods, because that WILL have impacts, if those functions fail.
			//On failing to re-enable Filesystem redirection, I'd have to panic, since a x86 program, using this library, might do unwanted things.
			//todo: to function
			let k32path = if self_is_under_wow{
				let str = get_windir()?.clone();
				k32path.replace(&(str.clone() + &"\\System32".to_string()),&(str + &"\\Sysnative".to_string()))
			}else{
				k32path
			};
			info!("parsing {}|{}",k32path, result!(std::fs::canonicalize(&k32path)).to_string_lossy());
			let k32 = result!(std::fs::read(&k32path));
			
			let dll_parsed = result!(Wrap::<pelite::pe32::PeFile,pelite::pe64::PeFile>::from_bytes(k32.as_slice()));
			let lla = result!(dll_parsed.get_export_by_name("LoadLibraryA")).symbol().unwrap();
			info!("LoadLibraryA is {:x}. Kernel32.dll is at:{:x}. That will be our entry point.",lla,k32addr);
			//todo: can we use add instead of wrapping_add?
			k32addr.wrapping_add(lla as u64)
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
	                PAGE_READWRITE
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
		info!("Allocated LoadLibraryA Parameter at {:x?}",*mem);
		debug!("entry proc:{:x} vs {:x}",entry_point,entry_point as usize);
		
		//Execute LoadLibraryA in remote thread, and wait for dll to load
		if !self_is_under_wow||pid_is_under_wow {
			let mut thread_id:u32=0;
			let thread = guard_check_ptr!(
			    CreateRemoteThread(
			        *proc,
			        std::ptr::null_mut(),
			        0,
			        Some(std::mem::transmute(entry_point as usize)),
			        *mem,
			        0,
			        &mut thread_id as *mut u32
			    ),"thread");
			let thread_id = thread_id;
			trace!("Thread is {:?} and thread id is {}", *thread, thread_id);
			info!("Waiting for DLL");
			// std::thread::sleep(Duration::new(0,500));//todo: why is this necessary, (only) when doing cargo run?
			match unsafe{WaitForSingleObject(*thread,INFINITE)}{
			    0x80=>{return err_str("WaitForSingleObject returned WAIT_ABANDONED")},//WAIT_ABANDONED
			    0x0=>{info!("Dll inject success? IDK?! Hopefully? WaitForSingleObject returned WAIT_OBJECT_0");},//WAIT_OBJECT_0
			    0x102=>{return err_str("Timeout hit at WaitForSingleObject.")},//WAIT_TIMEOUT
			    0xFFFFFFFF=>{return err("WaitForSingleObject")},//WAIT_FAILED
			    _=>{}
			}
		}else if cfg!(feature="ntdll")&&cfg!(feature="x86tox64") {
			#[cfg(feature = "ntdll")]
			let create_user_thread={
				// unimplemented!("CreateRemoteThread is currently broken on x86->x64.");
				//Idea: Grep x64 ntdll CreateRemoteThead equivalent, and somehow call it, with some WOW64CallFunction64 function.
				
				//Get this thread's x64 ntdll
				//Note: that is impossible with get_module_in_proc, since we are enumerating a x86 process, from x86.
				//Therefore, then we would only get the x86 variant, of ntdll.
				
				//This path works, since the PEB is always x64?
				//todo: is that true?
				
				//get x64 ntdll
				let (ntdll_path,base)={
					let ntdll = get_windir()?.clone()+"\\System32\\ntdll.dll";
					let ntdll = ntdll.to_lowercase();
					let proc_self = guard_check_ptr!(OpenProcess(PROCESS_ALL_ACCESS,FALSE,std::process::id()),"Process");
					unsafe{get_module_in_proc(*proc_self,|m,v|{
						let base = match m{
							Wrap::T32(v)=>v.DllBase as u64,
							Wrap::T64(v)=>v.DllBase as u64,
						};
						//This selects only the ntdll.dll entries.
						let str = converter(v,|s| {
							println!("{},{:x}", s.to_lowercase(), base);
							s.to_lowercase()==ntdll});
						str.map(|s|(s, base))
					})}?
				};
				println!("{},{:x}",ntdll_path,base);
				//Find correct function in x64 ntdll
				let tmp={
					//We need to replace System32, by Sysnative, in case we are running under WOW, because Windows will otherwise redirect all our file access.
					
					//One can also use the following methods: https://docs.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-wow64disablewow64fsredirection,https://docs.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-wow64revertwow64fsredirection
					//I am not using those methods, because that WILL have impacts, if those functions fail.
					//On failing to re-enable Filesystem redirection, I'd have to panic, since a x86 program, using this library, might do unwanted things.
					//todo: to function
					let ntdll_path = if self_is_under_wow{
						let str = get_windir()?.clone();
						ntdll_path.replace(&(str.clone() + &"\\SYSTEM32".to_string()),&(str + &"\\Sysnative".to_string()))
					}else{
						ntdll_path
					};
					// check_ptr!(Wow64DisableWow64FsRedirection(&mut par as *mut PVOID),|v|v==0);
					info!("parsing {}|{}",ntdll_path, result!(std::fs::canonicalize(&ntdll_path)).to_string_lossy());
					let k32 = result!(std::fs::read(&ntdll_path));
					// check_ptr!(Wow64RevertWow64FsRedirection(par),|v|v==0);
					
					let dll_parsed = result!(pelite::pe64::PeFile::from_bytes(k32.as_slice()));
					let create_user_thread_rva = result!(dll_parsed.get_export("RtlCreateUserThread")).symbol().unwrap();
					//Technically these are both pointers, so I should use `.wrapping_add`, but this SHOULD be the same.
					let create_user_thread=base+create_user_thread_rva as u64;
					info!("RtlCreateUserThread is {:x}. ntdll.dll is at:{:x}. That will be our entry point.",create_user_thread,base);
					create_user_thread
				};
				tmp
			};

			#[cfg(feature = "x86tox64")]
			{
				panic!("Do not cross. Beyond this point lies never tested, never debugged, not fully functioal code.");
				println!("Injection");
				use x86_64::instructions::segmentation::Segment;
				//see https://stackoverflow.com/questions/22962251/how-to-enter-64-bit-mode-on-a-x86-64
				//this modifies cr0?
				let mut cr0 = x86_64::registers::control::Cr0 as [bool];
				cr0[31]=false;//sets paging to off
				cr0[0]=false;//sets protected mode to off
				//see x86_64::registers::control for more information
				//this modifies cr4?
				let cr4 = x86_64::registers::control::Cr4 | x86_64::registers::control::Cr4Flags::PHYSICAL_ADDRESS_EXTENSION;
				//this enables long mode?
				let efer=x86_64::registers::model_specific::Efer | x86_64::registers::model_specific::EferFlags::LONG_MODE_ENABLE;
				/*
				//load PML4 table into cr3
				let mut cr3=x86_64::registers::control::Cr3;
				cr3=x86_64::structures::paging::mapper::MappedPageTable::
				*/
				unsafe{x86_64::instructions::segmentation::CS::set_reg(x86_64::structures::gdt::SegmentSelector(0x33))};
				unsafe{x86_64::instructions::segmentation::CS::set_reg(x86_64::structures::gdt::SegmentSelector(0x23))};
				println!("Injected");
			}
			
		} else if false&&cfg!(feature="experimental"){
			warn!("Using experimental feature. This should NEVER be used in production systems");
			//todo: either fix this, or completely remove this.
			panic!("This doesn't work, and will just result in some machine-code being run.");
			//asmcompiled::callgate()?;
		} else{
			return err_str("No viable injection method. This will print, if the injector is x86, but the target executable is x64.\
If you think, that you can provide a stable implementation, for this use-case, please open a pr.");
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
///Does NOT work, if the injector is x86, and the target exe is x64.
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
///Does NOT work, if the injector is x86, and the target exe is x64.
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
unsafe fn get_module_in_proc<F,R>(proc:HANDLE,predicate:F)->Result<R>
where F:Fn(Wrap<ntapi::ntwow64::LDR_DATA_TABLE_ENTRY32,types::LDR_DATA_TABLE_ENTRY64>,Vec<u16>)->Option<R>{
	let pid_under_wow = get_proc_under_wow(proc)?;
	info!("pid is under wow:{}",pid_under_wow);
	let peb_addr:u64;
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
		let pbi:types::PROCESS_BASIC_INFORMATION_WOW64 = query_process_information(proc,ntapi::ntsapi::ProcessBasicInformation)?;
		// buf_pbi.set_len(i as usize);
		// let pbi_ptr:*const PROCESS_BASIC_INFORMATION_WOW64 = std::mem::transmute(buf_pbi.as_ptr());
		// let pbi = *pbi_ptr;
		peb_addr = pbi.PebBaseAddress as u64;
		debug!("Peb addr is {:x?}",peb_addr);
	}
	let ldr_addr ;
	//This reads the PEB, and gets the LDR address
	{
		type PEB32=ntapt::ntwow64::PEB32;
		type PEB64=types::PEB64;
		ldr_addr = if false&&pid_under_wow{
			let size_peb=std::mem::size_of::<PEB32>();
			let peb=read_virtual_mem::<PEB32>(proc, peb_addr, size_peb)?;
			(*peb).Ldr as u64
		}else{
			let size_peb=std::mem::size_of::<PEB64>();
			let peb = read_virtual_mem::<PEB64>(proc, peb_addr, size_peb)?;
			(*peb).Ldr as u64
		};
		debug!("Ldr Address is {:x}.",ldr_addr);
	}
	
	let mut modlist_addr;
	//This reads the LDR, and gets the Module list, in Load Order.
	{
		type PEB_LDR_DATA32=ntapt::ntwow64::PEB_LDR_DATA32;
		type PEB_LDR_DATA64=types::PEB_LDR_DATA64;
		modlist_addr = if false&&pid_under_wow{
			let size_ldr=std::mem::size_of::<PEB_LDR_DATA32>();
			let ldr= read_virtual_mem::<PEB_LDR_DATA32>(proc, ldr_addr, size_ldr)?;
			(*ldr).InLoadOrderModuleList.Flink as u64
		}else {
			let size_ldr=std::mem::size_of::<PEB_LDR_DATA64>();
			let ldr= read_virtual_mem::<PEB_LDR_DATA64>(proc, ldr_addr, size_ldr)?;
			(*ldr).InLoadOrderModuleList.Flink as u64
		};
		debug!("Ldr InLoadOrderModuleList Address is {:x}",modlist_addr);
	}
	let first_modlist_addr=modlist_addr;
	//This Loops through the Module list, until we have found our module, or we arrive, at the address, we started from.
	loop{
		type LDR_DATA_TABLE_ENTRY32=ntapt::ntwow64::LDR_DATA_TABLE_ENTRY32;
		type LDR_DATA_TABLE_ENTRY64=types::LDR_DATA_TABLE_ENTRY64;
		let ldr_entry_data:*const u8;
		{
			let size_ldr_entry= if false&&pid_under_wow{
				std::mem::size_of::<LDR_DATA_TABLE_ENTRY32>()
			}else{
				std::mem::size_of::<LDR_DATA_TABLE_ENTRY64>()
			};
			ldr_entry_data = read_virtual_mem(proc, modlist_addr as u64, size_ldr_entry)?;
			debug!("Read the LDR_DATA_Table {:x?} {} bytes",modlist_addr,size_ldr_entry);
		};
		{
			let dll_win_string_max_length;
			let dll_win_string_buffer;
			let ldr_entry_data_wrap;
			if false&&pid_under_wow{
				let ldr_entry_ptr:*const LDR_DATA_TABLE_ENTRY32=std::mem::transmute(ldr_entry_data);
				let ldr_entry=*ldr_entry_ptr;
				ldr_entry_data_wrap=Wrap::T32(ldr_entry);
				//Gather string data
				dll_win_string_buffer=ldr_entry.FullDllName.Buffer as u64;
				dll_win_string_max_length=ldr_entry.FullDllName.MaximumLength;
				//In case we need, to check the next item.
				modlist_addr=ldr_entry.InLoadOrderLinks.Flink as u64;
			}else{
				let ldr_entry_ptr:*const LDR_DATA_TABLE_ENTRY64=std::mem::transmute(ldr_entry_data);
				let ldr_entry=*ldr_entry_ptr;
				ldr_entry_data_wrap=Wrap::T64(ldr_entry);
				//Gather string data
				dll_win_string_buffer=ldr_entry.FullDllName.Buffer as u64;
				dll_win_string_max_length=ldr_entry.FullDllName.MaximumLength;
				//In case we need, to check the next item.
				modlist_addr=ldr_entry.InLoadOrderLinks.Flink as u64
			}
			if modlist_addr==first_modlist_addr{
				const RECURSION:&str = "We looped through the whole InLoadOrderModuleList, but still have no match. Aborting, because this would end in an endless loop.";
				warn!("{}",RECURSION);
				return Err((RECURSION.to_string(), 0));
			}
			
			let dll_path_buf= read_virtual_mem_fn(proc, dll_win_string_buffer, (dll_win_string_max_length*2) as usize,move |v|v.leak() )?;
			let dll_path:&mut [u16] = std::mem::transmute(dll_path_buf);
			
			match WideCStr::from_slice_with_nul(dll_path){
				Ok(v) => {
					match v.to_string(){
						Ok(dll_name)=>{
							debug!("dll_name is {}",dll_name);
						},
						Err(e)=>{
							debug!("dll_name could not be printed. error is:{}, os_string is {:?}",e,dll_path);
						}
					}
				},
				Err(e) => {
					debug!("dll_name could not be printed. error is:{}, os_string is {:?}",e,dll_path);
				}
			}
			if let Some(val)=predicate(ldr_entry_data_wrap, Vec::from(dll_path)){
				return Ok(val);
			}
		}
	}
}
///Gets the windows Error, prints it, and returns an error.
fn err<T, E>(fn_name: E) -> Result<T>
	where E: Display {
	let err = unsafe { GetLastError() };
	error!("{} failed! Errcode is:'{}'. Check, what the error code means here:'https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes'", fn_name, err);
	Err((fn_name.to_string(), err))
}

///Checks a NtStatus. Will return Some value, if it is a critical error.
///Otherwise, it will log the status, and return None.
fn check_nt_status(status:NTSTATUS)->Option<Error>{
	if NT_ERROR(status){
		error!("Received error type, from ntdll. Status code is: {:x}",status);
		return Some(("ntdll".to_string(),status as u32))
	}
	if NT_WARNING(status){
		warn!("Received warning type, from ntdll. Status code is: {:x}",status);
	}
	None
}
///See [read_virtual_mem_fn].
#[cfg(feature = "ntdll")]
unsafe fn read_virtual_mem<T>(proc:HANDLE, addr:u64, size:usize) ->Result<*mut T>{
	read_virtual_mem_fn(proc,addr,size,move |mut v|std::mem::transmute(v.leak().as_mut_ptr()))
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
unsafe fn read_virtual_mem_fn<T>(proc:HANDLE, addr:u64, size:usize, f:impl FnOnce(Vec<u8>)->T) ->Result<T>
{
	//This is the prototype, of the NtReadVirtualMemory function
	type FnNtReadVirtualMemory = fn (HANDLE, DWORD64, PVOID, ULONG64, PDWORD64) -> NTSTATUS;
	static mut NT_READ_VIRTUAL_MEMORY_OPT:Option<FnNtReadVirtualMemory> = None;
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
	let self_is_under_wow = get_proc_under_wow(GetCurrentProcess())?;
	let rvm: &[u8] = if self_is_under_wow { b"NtWow64ReadVirtualMemory64\0" } else { b"NtReadVirtualMemory\0" };
	let ntdll = LoadLibraryA(b"ntdll\0".as_ptr() as *const i8);
	let fnc:FnNtReadVirtualMemory = std::mem::transmute(check_ptr!(GetProcAddress(ntdll,rvm.as_ptr() as *const i8)));
	let NtReadVirtualMemory=fnc;
	
	
	let mut buf:Vec<u8> = Vec::with_capacity(size);
	trace!("reading at address {:x?} {} bytes",addr,size);
	let mut i:u64=0;
	let status = check_nt_status!(NtReadVirtualMemory(proc, addr,buf.as_mut_ptr() as *mut c_void, size as u64, &mut i as *mut u64));
	trace!("rvm {:x},{}/{}",status as u32,i,size);
	//We read i bytes. So we let the Vec know, so it can calculate size and deallocate accordingly, if it wants.
	//Also: This will enable debugger inspection, of the buf, since the debugger will now know, that the vec is initialised.
	buf.set_len(i as usize);
	Ok(f(buf))
}
///This reads `size` elements, of size T, of memory, from address `addr`, in the process `proc`, into `buf`.
///
///# Safety
///`proc` needs to have the PROCESS_QUERY_INFORMATION (or PROCESS_QUERY_LIMITED_INFORMATION?) access rights.
///`proc` needs to be valid
///
///`buf` needs to be a valid address, to a allocated object, which can hold `size` bytes.
///
///`pic` and the return type need to match up. Not doing so, might end in immediate program termination.
///
///# Termination
///Windows might sometimes decide, to sometimes just end the entire program randomly, meaning, that this function won't return sometimes.
///On other occasions, Windows will return some extraneous value of bytes read.
///In those cases, this function will Panic.
//todo: get this function to be stable
//todo: why did user supplied buffers always crash?
#[cfg(feature = "ntdll")]
unsafe fn query_process_information<T>(proc:HANDLE,pic:ntapi::ntpsapi::PROCESSINFOCLASS) -> Result<T>
where T:Copy
{
	//Function prototype, of the NtQueryInformationProcess function in ntdll.
	type FnNtQueryInformationProcess = fn(HANDLE, ntapi::ntpsapi::PROCESSINFOCLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
	//Get function
	static mut NT_QUERY_INFORMATION_PROCESS_OPT:Option<FnNtQueryInformationProcess> =None;
	let NtQueryInformationProcess = match NT_QUERY_INFORMATION_PROCESS_OPT{
		None=>{
			let ntdll = LoadLibraryA(b"ntdll\0".as_ptr() as *const i8);
			let self_is_under_wow = get_proc_under_wow(GetCurrentProcess())?;
			let qip:&[u8] = if self_is_under_wow{b"NtWow64QueryInformationProcess64\0"} else {b"NtQueryInformationProcess\0"};
			trace!("self_is_under_wow={}",self_is_under_wow);
			let proc_ptr = check_ptr!(GetProcAddress(ntdll,qip.as_ptr() as *const i8));
			let proc = std::mem::transmute(proc_ptr);
			trace!("proc is {:x}",proc_ptr as u64);
			NT_QUERY_INFORMATION_PROCESS_OPT.insert(proc);
			proc
		},
		Some(v)=>v,
	};
	//ready things, for function call
	let mut i=0u32;
	let i_ptr=&mut i as *mut u32;
	let size_peb:usize = std::mem::size_of::<T>();
	let mut buf:Vec<u8> = vec![0;size_peb];
	//Call function
	trace!("Running NtQueryInformationProcess with fnptr:{:x?} proc:{:x?},pic:{:x}. Size is {}/{}, buf is {:x?}",NtQueryInformationProcess as usize,proc,pic,size_peb,i, buf);
	let status = check_nt_status!(NtQueryInformationProcess(proc,pic,buf.as_mut_ptr() as *mut c_void,size_peb as u32,i_ptr));
	trace!("qip {:x},0x{:x}|0x{:x}/0x{:x} buf is {:?}",status as u32,i,i as u32,size_peb,buf);
	if i as u64> size_peb as u64 || i as u64 == 0u64{
		//This should never happen, unless I fucked something up.
		panic!("Read more, than buf can handle, or read 0 bytes!
I do not know, what corrupted, if something corrupted, or if windows reports arbitrary stuff.
Memory might be fucked. Could be, that the function should just have errored. I DO NOT KNOW, what happened.

Windows didn't yet freeze or kill our program. This might mean, that this is recoverable?

Report IMMEDIATELY.
		");
	}
	//This should be safe, since the vec has as many bytes, as T
	let pbi_ptr:*mut T = std::mem::transmute(buf.as_mut_ptr());
	// trace!("exitstatus:{:x},pebaddress:{:x},baseprio:{:x},upid:{:x},irupid:{:x}",pbi.ExitStatus,pbi.PebBaseAddress,pbi.BasePriority,pbi.UniqueProcessId,pbi.InheritedFromUniqueProcessId);
	Ok(*pbi_ptr)
}
///This creates len bytes of unmapped memory
fn exec_ptr(len:usize) -> Result<LPVOID> {
	Ok(check_ptr!(VirtualAlloc(
		std::ptr::null_mut(),
		len,
		MEM_COMMIT|MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	)))
}

fn get_windir<'a>() -> Result<&'a String> {
	static WINDIR:once_cell::sync::OnceCell<String> = once_cell::sync::OnceCell::new();

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
	debug!("Windir is '{}'",str);
	Ok(str)
}
///Compares
fn converter(v:Vec<u16>,compare:impl Fn(&String)->bool) -> Option<String>
{
	let dll_name = match match WideCStr::from_slice_with_nul(v.as_slice()){
		Ok(s)=>s.to_string(),
		Err(e)=>{warn!("Couldn't convert full dll path, to string. Will skip this dll, in assumption, that this dll is invalid. Error is {}. Buf is {:x?}.",e,v); return None;}
	}{
		Ok(string)=>string,
		Err(e)=>{warn!("Couldn't convert full dll path, to string. Will skip this dll, in assumption, that this dll is invalid. Error is {}. Buf is {:x?}.",e,v); return None;}
	};
	if compare(&dll_name) {
		return Some(dll_name);
	}
	return None;
}

///NOP function.
///This exists, to do the same as #[allow(unused_must_use)].
///The above doesn't work for me right now though.
#[inline]
fn void_res<T>(_: Result<T>) {}
