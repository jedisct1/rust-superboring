#![doc = include_str!("../README.md")]

#[cfg(feature = "enabled")]
mod implementation;

#[cfg(not(feature = "enabled"))]
mod implementation {
    pub const SUPERBORING_HAS_BEEN_DISABLED: bool = true;
}

pub use implementation::*;
