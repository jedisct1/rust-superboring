#[cfg(feature = "enabled")]
mod implementation;

#[cfg(not(feature = "enabled"))]
mod implementation {
    #[cfg(not(feature = "boring"))]
    pub const SUPERBORING_HAS_BEEN_DISABLED: bool = true;
    #[cfg(feature = "boring")]
    pub use boring::*;
}

pub use implementation::*;
