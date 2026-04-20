pub use crate::error::RbatError;
pub use crate::traits::*;
pub use crate::types::*;
pub use capstone::prelude::*;

pub type Result<T> = core::result::Result<T, RbatError>;
