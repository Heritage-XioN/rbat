pub use crate::error::Error;
pub use crate::traits::*;
pub use crate::types::*;
pub use capstone::prelude::*;

pub type Result<T> = core::result::Result<T, Error>;

// generic type tuple struct
#[derive(Debug)]
pub struct W<T>(pub T);
