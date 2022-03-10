use log::{debug,error,warn, trace};
use crate::Result;
use std::fmt::Display;

pub(crate) fn err_str<T,E>(err:E) -> Result<T>
	where E:Display {
	error!("{}",err);
	Err((format!("{}",err),0))
}

///Calls a closure
pub(crate) fn __call__<T,R>(arg:T,f:impl FnOnce(T)->R)->R{
	f(arg)
}

macro_rules! result {
	($res:expr) => {
		match $res{
			Ok(v)=>v,
			Err(e)=>{return $crate::macros::err_str(e);},
		}
	};
}
pub(crate) use result;
