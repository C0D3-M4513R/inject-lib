use std::ops::Add;
use std::os::windows::process::CommandExt;
use std::process::Child;
use std::thread::sleep;
use std::time::Duration;
use winapi::um::sysinfoapi::GetSystemWindowsDirectoryW;
use inject_lib::Inject;
use inject_lib::{Data, Injector};
use inject_lib::str_from_wide_str;

const SYSTEMDIR64:&str = "System32";
const SYSTEMDIR32:&str = "SYSWOW64";


const DLLNAME:&str = "dnsapi.dll";
const CMD:&str = "cmd.exe";

#[test]
fn inject_x86() -> Result<(),()>{
	print_arch();
	let path = get_windir().add("\\").add(SYSTEMDIR32).add("\\");
	let cmd = path.clone().add(CMD);
	let mut c = create_process(cmd);
	let dll = path.add(DLLNAME);
	let r = inject_test(dll.as_str(),c.id());
	c.kill().unwrap();
	r}
#[cfg(all(target_pointer_width = "32",feature = "x86tox64"))]
#[test]
fn inject_x86_to_x64() -> Result<(),()>{
	print_arch();
	let path = get_windir().add("\\").add(SYSTEMDIR64).add("\\");
	let cmd = path.clone().add(CMD);
	let mut c = create_process(cmd);
	let dll = path.add(DLLNAME);
	let r = inject_test(dll.as_str(),c.id());
	c.kill().unwrap();
	r
}

#[cfg(target_pointer_width = "64")]
#[test]
fn inject_x64() -> Result<(),()>{
	print_arch();
	let path = get_windir().add("\\").add(SYSTEMDIR64).add("\\");
	let cmd = path.clone().add(CMD);
	let mut c = create_process(cmd);
	let dll = path.add(DLLNAME);
	let r = inject_test(dll.as_str(),c.id());
	c.kill().unwrap();
	r
}

#[cfg(target_pointer_width = "64")]
fn print_arch(){
	println!("Arch is 64bit")
}
#[cfg(target_pointer_width = "32")]
fn print_arch(){
	println!("Arch is 32bit")
}

///This gets the directory, where windows files reside. Usually C:\Windows
fn get_windir<'a>() -> String {
	unsafe{
		let i=GetSystemWindowsDirectoryW(core::ptr::null_mut(),0);
		if i==0{panic!("GetSystemWindowsDirectoryW failed");}
		let mut str_buf:Vec<u16> = Vec::with_capacity( i as usize);
		let i2=GetSystemWindowsDirectoryW(str_buf.as_mut_ptr(),i);
		if i2==0{panic!("GetSystemWindowsDirectoryW failed");}
		assert!(i2<=i,"GetSystemWindowsDirectoryA says, that {} bytes are needed, but then changed it's mind. Now {} bytes are needed.",i,i2);
		str_buf.set_len(i2 as usize);
		let string = str_from_wide_str(str_buf.as_slice()).unwrap();
		println!("Windir is {},{},{}",string,i,i2);
		string
	}
}

fn create_process(cmd:String)->Child{
	let c = std::process::Command::new(cmd)
	.creation_flags(winapi::um::winbase::CREATE_NEW_CONSOLE)
	.spawn()
	.unwrap();
	println!("Spawned a new process");
	sleep(Duration::from_millis(100)); //Let the process init.
	c
}

pub fn inject_test(dllpath:&str,pid:u32) -> Result<(),()> {

	let inject = Injector::new(
		Data::Str(dllpath),
		pid);
	println!("Created Injector");
	let injector = inject.inject(true);
	println!("Injecting");
	let mut ok:bool=true;
	if let Err(err) = injector.inject(){
		ok=false;
		eprintln!("Inject error: {}",err);
	};
	println!("Ejecting");
	if let Err(err) = injector.eject(){
		ok=false;
		eprintln!("Eject error: {}",err);
	};
	println!("Ejected");
	return if ok{ Ok(()) } else { Err(()) };
}
