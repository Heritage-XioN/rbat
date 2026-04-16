pub use crate::error::RbatError;
pub use crate::traits::*;
pub use crate::types::*;
pub use crate::utils::*;
pub use capstone::prelude::*;

pub type Result<T> = core::result::Result<T, RbatError>;

// generic type tuple struct
#[derive(Debug)]
pub struct W<T>(pub T);
