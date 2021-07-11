mod platforms;

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
