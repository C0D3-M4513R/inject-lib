use std::alloc::alloc;
use std::fmt::{Display, format, Formatter};
use std::ops::Deref;
use crate::Result;
use winapi::shared::minwindef::{LPVOID, FALSE, LPCVOID};

use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, MEM_RESERVE, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, IMAGE_FILE_MACHINE_UNKNOWN, PROCESSOR_ARCHITECTURE_INTEL, PROCESSOR_ARCHITECTURE_AMD64, HANDLE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386, PAGE_EXECUTE_READWRITE, PROCESS_VM_READ, PAGE_READWRITE, PROCESS_ALL_ACCESS, WOW64_CONTEXT, WOW64_FLOATING_SAVE_AREA, SECURITY_DESCRIPTOR, PHANDLE, CONTEXT, PSECURITY_DESCRIPTOR, BOOLEAN};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory, CreateFileMappingW, FILE_MAP_ALL_ACCESS, FILE_MAP_EXECUTE, MapViewOfFile, VirtualAlloc};
use crate::platforms::platform::macros::{guard_check_ptr,err,void_res};
use log::{debug, error, info, trace, warn};
use winapi::shared::basetsd::SIZE_T;

#[derive(Debug)]
pub struct MemPage{
	proc:HANDLE,
	addr:LPVOID,
	size:usize,
	exec:bool,
}
impl MemPage{
	pub fn new(proc:HANDLE,size:usize,exec:bool)->Result<Self>{
		let addr=unsafe{VirtualAllocEx(
			proc,
			std::ptr::null_mut(),
			size,
			MEM_COMMIT | MEM_RESERVE,
			if exec {PAGE_EXECUTE_READWRITE} else {PAGE_READWRITE}
		)};
		if addr.is_null() {return err(format!("VirtualAllocEx failed to allocate {} {} bytes on process {:x}",size,if exec {"executable"} else {""},proc as usize))}
		Ok(MemPage{
			proc,
			addr,
			size,
			exec
		})
	}
	///Writes the buffer to the allocated memory page.
	///
	///# Panic
	/// This Panics, if the buffer would overflow the size of allocated memory.
	pub fn write(&self,buffer:&[u8])->Result<usize>{
		let mut n:usize = 0;
		assert!(buffer.len()<=self.size);
		if unsafe {
			WriteProcessMemory(
				self.proc,
				self.addr,
				buffer.as_ptr() as LPCVOID,
				buffer.len(),
				&mut n as *mut usize
			) == FALSE
		} {
			return crate::platforms::platform::macros::err("WriteProcessMemory");
		}
		debug_assert!(n==buffer.len());
		Ok(n)
	}
	#[must_use]
	pub fn get_address(&self)->LPVOID{
		self.addr
	}
}
impl Display for MemPage{
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		write!(f, "(proc:{:x}, addr:{:x}, size:{:x}, exec:{})", self.proc as usize,self.addr as usize,self.size,self.exec)
	}
}
impl Drop for MemPage{
	fn drop(&mut self) {
		trace!("Releasing VirtualAlloc'd Memory");
		if unsafe{VirtualFreeEx(self.proc, self.addr, 0, MEM_RELEASE)}==FALSE {
			error!("Error during cleanup! VirtualFreeEx with MEM_RELEASE should not fail according to doc, but did anyways. A memory page will stay allocated. Addr:{:x},size:{:x}",self.addr as usize,self.size);
			//Supress unused_must_use warning. This is intended, but one cannot use allow, to supress this?
			//todo: a bit hacky? Is there a better way, to achieve something similar?
			void_res(err::<(),&str>("VirtualFreeEx of VirtualAllocEx"));
			//Do not panic here, since it could cause to an abort.
			// panic!("Error during cleanup")
		}
	}
}