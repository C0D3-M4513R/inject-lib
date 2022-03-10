use std::borrow::Borrow;
use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcess};
use winapi::um::winnt::{HANDLE, IMAGE_FILE_MACHINE_UNKNOWN, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION};
use crate::platforms::platform::macros::{check_ptr,err};
use crate::Result;
use log::{debug, error, info, trace, warn};
use once_cell::unsync::OnceCell;
use winapi::um::handleapi::CloseHandle;
use winapi::um::wow64apiset::IsWow64Process2;
use crate::macros::err_str;


pub struct Process{
	proc:HANDLE,
	perms:DWORD,
	wow:OnceCell<bool>,
}
impl Process{
	pub fn new(pid:u32, perms:DWORD) ->Result<Self>{
		let proc=check_ptr!(OpenProcess(perms, FALSE,pid));
		Ok(Self{proc,perms, wow: Default::default() })
	}
	pub fn self_proc()->&'static Self{
		static prc:Process=
		Process{
			proc:unsafe{GetCurrentProcess()},
			perms:PROCESS_ALL_ACCESS,
			wow: Default::default()
		};
		&prc
	}
	///Returns true, if the supplied process-handle is running under WOW, otherwise false.
	///# Safety
	///The process handle must have the PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION access right.
	unsafe fn unchecked_impl_is_under_wow(&self) -> Result<bool> {
		let mut process_machine: u16 = 0;
		let mut native_machine: u16 = 0;
		if IsWow64Process2(
			self.proc,
			&mut process_machine as *mut u16,
			&mut native_machine as *mut u16,
		) == FALSE {
			return err("IsWow64Process2 number 1");
		}
		println!("proc:{:#x}", process_machine);
		println!("native:{:#x}", native_machine);
		
		//That is, if the target exe, is compiled x86, but run on x64
		
		//The value will be IMAGE_FILE_MACHINE_UNKNOWN if the target process is not a WOW64 process; otherwise, it will identify the type of WoW process.
		Ok(process_machine != IMAGE_FILE_MACHINE_UNKNOWN)
	}
	///Returns true, if the supplied process-handle is running under WOW, otherwise false.
	///# Safety
	///The process handle must have the PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION access right.
	pub fn unchecked_is_under_wow(&self)->Result<&bool>{
		self.wow.get_or_try_init(||unsafe{self.unchecked_impl_is_under_wow()})
	}
	///Returns true, if the supplied process-handle is running under WOW, otherwise false.
	pub fn is_under_wow(&self)->Result<&bool> {
		if self.perms|PROCESS_QUERY_INFORMATION || self.perms|PROCESS_QUERY_LIMITED_INFORMATION {
			self.unchecked_is_under_wow()
		}else {
			err_str("Process Handle does not have the required permissions.")
		}
	}
	pub fn get_proc(&self)->HANDLE{self.proc}
}

impl Drop for Process{
	fn drop(&mut self) {
		trace!("Cleaning Process Handle");
		if unsafe { CloseHandle(self.proc) } == FALSE {
			error!("Error during Process Handle cleanup!");
			//Supress unused_must_use warning. This is intended, but one cannot use allow, to supress this?
			//todo: a bit hacky? Is there a better way, to achieve something similar?
			crate::platforms::platform::macros::void_res(crate::platforms::platform::macros::err::<(),String>(("CloseHandle of ".to_string()+std::stringify!($name))));
			//Do not panic here, since it could cause to an abort.
			// panic!("Error during cleanup");
		}
	}
}