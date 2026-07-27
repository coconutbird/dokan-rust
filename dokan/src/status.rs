//! Common NT status values returned by filesystem operations.
//!
//! The constants use the stable [`NtStatus`] representation,
//! so callers do not need a Windows binding crate merely to report errors.

use crate::NtStatus;

pub const SUCCESS: NtStatus = NtStatus::from_raw(0x0000_0000);
pub const BUFFER_OVERFLOW: NtStatus = NtStatus::from_raw(0x8000_0005_u32 as i32);
pub const ACCESS_DENIED: NtStatus = NtStatus::from_raw(0xC000_0022_u32 as i32);
pub const INVALID_HANDLE: NtStatus = NtStatus::from_raw(0xC000_0008_u32 as i32);
pub const INVALID_PARAMETER: NtStatus = NtStatus::from_raw(0xC000_000D_u32 as i32);
pub const NOT_IMPLEMENTED: NtStatus = NtStatus::from_raw(0xC000_0002_u32 as i32);
pub const INVALID_DEVICE_REQUEST: NtStatus = NtStatus::from_raw(0xC000_0010_u32 as i32);
pub const OBJECT_NAME_INVALID: NtStatus = NtStatus::from_raw(0xC000_0033_u32 as i32);
pub const OBJECT_NAME_NOT_FOUND: NtStatus = NtStatus::from_raw(0xC000_0034_u32 as i32);
pub const OBJECT_NAME_COLLISION: NtStatus = NtStatus::from_raw(0xC000_0035_u32 as i32);
pub const OBJECT_PATH_NOT_FOUND: NtStatus = NtStatus::from_raw(0xC000_003A_u32 as i32);
pub const SHARING_VIOLATION: NtStatus = NtStatus::from_raw(0xC000_0043_u32 as i32);
pub const DELETE_PENDING: NtStatus = NtStatus::from_raw(0xC000_0056_u32 as i32);
pub const CANNOT_DELETE: NtStatus = NtStatus::from_raw(0xC000_0121_u32 as i32);
pub const FILE_IS_A_DIRECTORY: NtStatus = NtStatus::from_raw(0xC000_00BA_u32 as i32);
pub const NOT_A_DIRECTORY: NtStatus = NtStatus::from_raw(0xC000_0103_u32 as i32);
pub const DIRECTORY_NOT_EMPTY: NtStatus = NtStatus::from_raw(0xC000_0101_u32 as i32);
pub const INTERNAL_ERROR: NtStatus = NtStatus::from_raw(0xC000_00E5_u32 as i32);

// Windows-compatible spellings ease migration without exposing a binding crate.
pub const STATUS_SUCCESS: NtStatus = SUCCESS;
pub const STATUS_BUFFER_OVERFLOW: NtStatus = BUFFER_OVERFLOW;
pub const STATUS_ACCESS_DENIED: NtStatus = ACCESS_DENIED;
pub const STATUS_INVALID_HANDLE: NtStatus = INVALID_HANDLE;
pub const STATUS_INVALID_PARAMETER: NtStatus = INVALID_PARAMETER;
pub const STATUS_NOT_IMPLEMENTED: NtStatus = NOT_IMPLEMENTED;
pub const STATUS_INVALID_DEVICE_REQUEST: NtStatus = INVALID_DEVICE_REQUEST;
pub const STATUS_OBJECT_NAME_INVALID: NtStatus = OBJECT_NAME_INVALID;
pub const STATUS_OBJECT_NAME_NOT_FOUND: NtStatus = OBJECT_NAME_NOT_FOUND;
pub const STATUS_OBJECT_NAME_COLLISION: NtStatus = OBJECT_NAME_COLLISION;
pub const STATUS_OBJECT_PATH_NOT_FOUND: NtStatus = OBJECT_PATH_NOT_FOUND;
pub const STATUS_SHARING_VIOLATION: NtStatus = SHARING_VIOLATION;
pub const STATUS_DELETE_PENDING: NtStatus = DELETE_PENDING;
pub const STATUS_CANNOT_DELETE: NtStatus = CANNOT_DELETE;
pub const STATUS_FILE_IS_A_DIRECTORY: NtStatus = FILE_IS_A_DIRECTORY;
pub const STATUS_NOT_A_DIRECTORY: NtStatus = NOT_A_DIRECTORY;
pub const STATUS_DIRECTORY_NOT_EMPTY: NtStatus = DIRECTORY_NOT_EMPTY;
pub const STATUS_INTERNAL_ERROR: NtStatus = INTERNAL_ERROR;
