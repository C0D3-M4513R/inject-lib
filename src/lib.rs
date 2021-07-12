mod platforms;
use log::debug;

pub struct Injector<'a> {
    pub dll: &'a str,
    pub pid: u32,
}

impl<'a> Injector<'a> {
    pub fn new(dll: &'a str, pid: u32) -> Self {
        Injector { dll, pid }
    }
    pub fn set_dll(&mut self, dll: &'a str) {
        self.dll = dll;
    }
    pub fn set_pid(&mut self, pid: u32) {
        self.pid = pid;
    }
    pub fn find_pid(name: &str) -> Result<Vec<u32>, (String, u32)> {
        Self::find_pid_selector(|str| str == name)
    }
}
impl<'a> Default for Injector<'a> {
    fn default() -> Self {
        Self::new("", 0)
    }
}

pub fn strip_rust_path(str:&str)->&str{
    let mut str_no_path =str;
    
    if let Some(n) = str.rfind('/'){
        //I do n+1 here, since, the rfind will actually keep the last /.
        //This gets rid of the /
        str_no_path =str.get((n+1)..).unwrap();
    }
    debug!("self.dll='{}' and dll_no_path='{}'", str, str_no_path);
    str_no_path
}