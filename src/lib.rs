// #![cfg_attr(feature = "nightly", feature(asm,global_asm, asm_const))]

use log::{debug,error,warn, trace};



pub struct Injector<'a> {
    pub dll: &'a str,
    pub pid: u32,
}

mod macros;
pub(crate) type Error = (String,u32);
pub(crate) type Result<T> = std::result::Result<T,Error>;

mod hof;

mod platforms;


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
    pub fn find_pid(name: &str) -> Result<Vec<u32>> {
        Self::find_pid_selector(|p|{
            match match widestring::WideCStr::from_slice_with_nul(&p.szExeFile){
                Ok(v)=>v.to_string(),
                Err(e)=>{
                    warn!("Skipping check of process. Can't construct string, to compare against. Err:{}",e);
                    return false;
                }
            }{
                Ok(str)=>{
                    debug!("Checking {} against {}",str,name);
                    strip_rust_path(str.as_str())==name
                },
                Err(e)=>{
                    warn!("Skipping check of process. Can't construct string, to compare against. Err:{}",e);
                    false
                }
            }
        })
    }
}

impl<'a> Default for Injector<'a> {
    fn default() -> Self {
        Self::new("", 0)
    }
}
///This takes a string, and cuts off, everything before the last `/`.
/// The intention is, that this will truncate any rust(/Linux?) path (since rust uses `/`), to it's filename, without having to actually look the file up.
pub fn strip_rust_path(str:&str)->&str{
    let mut str_no_path =str;
    
    if let Some(n) = str.rfind('/'){
        //I do n+1 here, since, the rfind will actually keep the last /.
        //This gets rid of the /
        str_no_path =str.get((n+1)..).unwrap();
    }
    debug!("str='{}' and truncated='{}'", str, str_no_path);
    str_no_path
}
///This takes a string, and cuts off, everything before the last `\`.
/// The intention is, that this will truncate any windows path (since windows uses `\`), to it's filename, without having to actually look the file up.
pub fn strip_win_path(str:&str)->&str{
    let mut str_no_path =str;
    
    if let Some(n) = str.rfind('\\'){
        //I do n+1 here, since, the rfind will actually keep the last /.
        //This gets rid of the /
        str_no_path =str.get((n+1)..).unwrap();
    }
    trace!("str='{}' and truncated='{}'", str, str_no_path);
    str_no_path
}