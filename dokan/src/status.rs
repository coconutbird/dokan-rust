//! Common NT status values returned by filesystem operations.
//!
//! The constants use the stable [`NtStatus`] representation,
//! so callers do not need a Windows binding crate merely to report errors.

use crate::NtStatus;

pub const SUCCESS: NtStatus = 0x0000_0000;
pub const BUFFER_OVERFLOW: NtStatus = 0x8000_0005_u32 as i32;
pub const ACCESS_DENIED: NtStatus = 0xC000_0022_u32 as i32;
pub const INVALID_HANDLE: NtStatus = 0xC000_0008_u32 as i32;
pub const INVALID_PARAMETER: NtStatus = 0xC000_000D_u32 as i32;
pub const NOT_IMPLEMENTED: NtStatus = 0xC000_0002_u32 as i32;
pub const INVALID_DEVICE_REQUEST: NtStatus = 0xC000_0010_u32 as i32;
pub const OBJECT_NAME_INVALID: NtStatus = 0xC000_0033_u32 as i32;
pub const OBJECT_NAME_NOT_FOUND: NtStatus = 0xC000_0034_u32 as i32;
pub const OBJECT_NAME_COLLISION: NtStatus = 0xC000_0035_u32 as i32;
pub const OBJECT_PATH_NOT_FOUND: NtStatus = 0xC000_003A_u32 as i32;
pub const SHARING_VIOLATION: NtStatus = 0xC000_0043_u32 as i32;
pub const DELETE_PENDING: NtStatus = 0xC000_0056_u32 as i32;
pub const CANNOT_DELETE: NtStatus = 0xC000_0121_u32 as i32;
pub const FILE_IS_A_DIRECTORY: NtStatus = 0xC000_00BA_u32 as i32;
pub const NOT_A_DIRECTORY: NtStatus = 0xC000_0103_u32 as i32;
pub const DIRECTORY_NOT_EMPTY: NtStatus = 0xC000_0101_u32 as i32;
pub const INTERNAL_ERROR: NtStatus = 0xC000_00E5_u32 as i32;
