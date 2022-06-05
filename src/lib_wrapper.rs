#[cfg(not(target_family = "wasm"))]
mod lib;
#[cfg(target_family = "wasm")]
mod lib_wasm;

#[cfg(not(target_family = "wasm"))]
pub use lib::*;
#[cfg(target_family = "wasm")]
pub use lib_wasm::*;
