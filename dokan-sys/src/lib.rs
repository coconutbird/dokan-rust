#![cfg(windows)]
#![allow(
	non_camel_case_types,
	non_snake_case,
	non_upper_case_globals,
	unsafe_op_in_unsafe_fn
)]
#![allow(rustdoc::bare_urls)]
#![doc(html_root_url = "https://dokan-dev.github.io/dokan-rust-doc/html")]

//! Raw FFI bindings for [Dokany].
//!
//! The declarations in this crate are generated from the vendored Dokany
//! headers. Regenerate `bindings.rs` with the repository's
//! `tools/generate-bindings` utility when updating Dokany.
//!
//! Most applications should use the safe [`dokan`] crate instead.
//!
//! [Dokany]: https://github.com/dokan-dev/dokany
//! [`dokan`]: https://crates.io/crates/dokan

mod bindings;
pub mod win32;

pub use bindings::*;

include!(concat!(env!("OUT_DIR"), "/version.rs"));

// bindgen intentionally does not emit these macro constants. Keeping the
// public constants here gives them precise Rust types and avoids signedness
// changes when C headers or bindgen versions change.
pub const DOKAN_OPTION_DEBUG: ULONG = 1 << 0;
pub const DOKAN_OPTION_STDERR: ULONG = 1 << 1;
pub const DOKAN_OPTION_ALT_STREAM: ULONG = 1 << 2;
pub const DOKAN_OPTION_WRITE_PROTECT: ULONG = 1 << 3;
pub const DOKAN_OPTION_NETWORK: ULONG = 1 << 4;
pub const DOKAN_OPTION_REMOVABLE: ULONG = 1 << 5;
pub const DOKAN_OPTION_MOUNT_MANAGER: ULONG = 1 << 6;
pub const DOKAN_OPTION_CURRENT_SESSION: ULONG = 1 << 7;
pub const DOKAN_OPTION_FILELOCK_USER_MODE: ULONG = 1 << 8;
pub const DOKAN_OPTION_CASE_SENSITIVE: ULONG = 1 << 9;
pub const DOKAN_OPTION_ENABLE_UNMOUNT_NETWORK_DRIVE: ULONG = 1 << 10;
pub const DOKAN_OPTION_DISPATCH_DRIVER_LOGS: ULONG = 1 << 11;
pub const DOKAN_OPTION_ALLOW_IPC_BATCHING: ULONG = 1 << 12;

pub const VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE: usize = 16 * 1024;

pub const DOKAN_SUCCESS: i32 = 0;
pub const DOKAN_ERROR: i32 = -1;
pub const DOKAN_DRIVE_LETTER_ERROR: i32 = -2;
pub const DOKAN_DRIVER_INSTALL_ERROR: i32 = -3;
pub const DOKAN_START_ERROR: i32 = -4;
pub const DOKAN_MOUNT_ERROR: i32 = -5;
pub const DOKAN_MOUNT_POINT_ERROR: i32 = -6;
pub const DOKAN_VERSION_ERROR: i32 = -7;
