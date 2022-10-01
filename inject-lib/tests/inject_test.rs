use std::ops::Add;
use std::os::windows::process::CommandExt;
use std::process::Child;
use std::thread::sleep;
use std::time::Duration;
use inject_lib::Inject;
use inject_lib::{Data, Injector};

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

fn get_windir() -> String{
	let windir_a = Vec::from_iter(std::env::vars_os().filter(|(k,_)|k.to_string_lossy()=="WINDIR"));
	if windir_a.len()<1usize {panic!("Expected a Windir env variable")}
	let dir = windir_a.get(0).unwrap().1.to_str().unwrap().to_string();
	println!("Got Windir");
	dir
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
