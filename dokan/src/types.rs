use std::{error::Error, ffi::c_void, fmt, ptr::NonNull};

use bitflags::bitflags;
use dokan_sys::DOKAN_IO_SECURITY_CONTEXT;

/// Native NT status returned to Dokany.
///
/// This crate-owned transparent wrapper keeps the public API independent from
/// `windows`, `windows-sys`, and `winapi`. Use [`from_raw`](Self::from_raw) and
/// [`into_raw`](Self::into_raw) when interoperating with any C-style binding.
#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NtStatus(i32);

impl NtStatus {
	#[must_use]
	pub const fn from_raw(value: i32) -> Self {
		Self(value)
	}

	#[must_use]
	pub const fn into_raw(self) -> i32 {
		self.0
	}

	/// Whether the status represents success according to NT semantics.
	#[must_use]
	pub const fn is_success(self) -> bool {
		self.0 >= 0
	}
}

impl From<i32> for NtStatus {
	fn from(value: i32) -> Self {
		Self::from_raw(value)
	}
}

impl From<NtStatus> for i32 {
	fn from(value: NtStatus) -> Self {
		value.into_raw()
	}
}

#[cfg(feature = "windows-interop")]
impl From<windows::Win32::Foundation::NTSTATUS> for NtStatus {
	fn from(value: windows::Win32::Foundation::NTSTATUS) -> Self {
		Self::from_raw(value.0)
	}
}

#[cfg(feature = "windows-interop")]
impl From<NtStatus> for windows::Win32::Foundation::NTSTATUS {
	fn from(value: NtStatus) -> Self {
		Self(value.into_raw())
	}
}

impl fmt::Debug for NtStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "NtStatus(0x{:08X})", self.0 as u32)
	}
}

impl fmt::Display for NtStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "NT status 0x{:08X}", self.0 as u32)
	}
}

impl Error for NtStatus {}

/// Raw Windows access-mask value.
///
/// Use [`AccessRights`] when inspecting the standard file access rights. The
/// raw value is retained because file systems may define additional bits.
pub type AccessMask = u32;

bitflags! {
	/// Standard and file-specific access rights requested by Windows.
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct AccessRights: AccessMask {
		const READ_DATA = 0x0000_0001;
		const LIST_DIRECTORY = Self::READ_DATA.bits();
		const WRITE_DATA = 0x0000_0002;
		const ADD_FILE = Self::WRITE_DATA.bits();
		const APPEND_DATA = 0x0000_0004;
		const ADD_SUBDIRECTORY = Self::APPEND_DATA.bits();
		const READ_EXTENDED_ATTRIBUTES = 0x0000_0008;
		const WRITE_EXTENDED_ATTRIBUTES = 0x0000_0010;
		const EXECUTE = 0x0000_0020;
		const TRAVERSE = Self::EXECUTE.bits();
		const DELETE_CHILD = 0x0000_0040;
		const READ_ATTRIBUTES = 0x0000_0080;
		const WRITE_ATTRIBUTES = 0x0000_0100;
		const DELETE = 0x0001_0000;
		const READ_CONTROL = 0x0002_0000;
		const WRITE_DAC = 0x0004_0000;
		const WRITE_OWNER = 0x0008_0000;
		const SYNCHRONIZE = 0x0010_0000;
		const GENERIC_ALL = 0x1000_0000;
		const GENERIC_EXECUTE = 0x2000_0000;
		const GENERIC_WRITE = 0x4000_0000;
		const GENERIC_READ = 0x8000_0000;
	}
}

bitflags! {
	/// Capabilities reported for a mounted filesystem.
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct VolumeFeatures: u32 {
		const CASE_SENSITIVE_SEARCH = 0x0000_0001;
		const CASE_PRESERVED_NAMES = 0x0000_0002;
		const UNICODE_ON_DISK = 0x0000_0004;
		const PERSISTENT_ACLS = 0x0000_0008;
		const FILE_COMPRESSION = 0x0000_0010;
		const VOLUME_QUOTAS = 0x0000_0020;
		const SUPPORTS_SPARSE_FILES = 0x0000_0040;
		const SUPPORTS_REPARSE_POINTS = 0x0000_0080;
		const SUPPORTS_REMOTE_STORAGE = 0x0000_0100;
		const RETURNS_CLEANUP_RESULT_INFO = 0x0000_0200;
		const SUPPORTS_POSIX_UNLINK_RENAME = 0x0000_0400;
		const VOLUME_IS_COMPRESSED = 0x0000_8000;
		const SUPPORTS_OBJECT_IDS = 0x0001_0000;
		const SUPPORTS_ENCRYPTION = 0x0002_0000;
		const NAMED_STREAMS = 0x0004_0000;
		const READ_ONLY_VOLUME = 0x0008_0000;
		const SEQUENTIAL_WRITE_ONCE = 0x0010_0000;
		const SUPPORTS_TRANSACTIONS = 0x0020_0000;
		const SUPPORTS_HARD_LINKS = 0x0040_0000;
		const SUPPORTS_EXTENDED_ATTRIBUTES = 0x0080_0000;
		const SUPPORTS_OPEN_BY_FILE_ID = 0x0100_0000;
		const SUPPORTS_USN_JOURNAL = 0x0200_0000;
		const SUPPORTS_INTEGRITY_STREAMS = 0x0400_0000;
		const SUPPORTS_BLOCK_REFCOUNTING = 0x0800_0000;
		const SUPPORTS_SPARSE_VDL = 0x1000_0000;
		const DAX_VOLUME = 0x2000_0000;
		const SUPPORTS_GHOSTING = 0x4000_0000;
	}
}

bitflags! {
	/// Requested sharing modes for an opened file.
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct ShareAccess: u32 {
		const READ = 0x0000_0001;
		const WRITE = 0x0000_0002;
		const DELETE = 0x0000_0004;
	}
}

bitflags! {
	/// File attributes supplied by Windows.
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct FileAttributes: u32 {
		const READ_ONLY = 0x0000_0001;
		const HIDDEN = 0x0000_0002;
		const SYSTEM = 0x0000_0004;
		const DIRECTORY = 0x0000_0010;
		const ARCHIVE = 0x0000_0020;
		const DEVICE = 0x0000_0040;
		const NORMAL = 0x0000_0080;
		const TEMPORARY = 0x0000_0100;
		const SPARSE_FILE = 0x0000_0200;
		const REPARSE_POINT = 0x0000_0400;
		const COMPRESSED = 0x0000_0800;
		const OFFLINE = 0x0000_1000;
		const NOT_CONTENT_INDEXED = 0x0000_2000;
		const ENCRYPTED = 0x0000_4000;
		const INTEGRITY_STREAM = 0x0000_8000;
		const NO_SCRUB_DATA = 0x0002_0000;
		const RECALL_ON_OPEN = 0x0004_0000;
		const PINNED = 0x0008_0000;
		const UNPINNED = 0x0010_0000;
		const RECALL_ON_DATA_ACCESS = 0x0040_0000;
	}
}

bitflags! {
	/// Kernel create options supplied to a create/open request.
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct CreateOptions: u32 {
		const DIRECTORY_FILE = 0x0000_0001;
		const WRITE_THROUGH = 0x0000_0002;
		const SEQUENTIAL_ONLY = 0x0000_0004;
		const NO_INTERMEDIATE_BUFFERING = 0x0000_0008;
		const SYNCHRONOUS_IO_ALERT = 0x0000_0010;
		const SYNCHRONOUS_IO_NONALERT = 0x0000_0020;
		const NON_DIRECTORY_FILE = 0x0000_0040;
		const CREATE_TREE_CONNECTION = 0x0000_0080;
		const COMPLETE_IF_OPLOCKED = 0x0000_0100;
		const NO_EA_KNOWLEDGE = 0x0000_0200;
		const OPEN_REMOTE_INSTANCE = 0x0000_0400;
		const RANDOM_ACCESS = 0x0000_0800;
		const DELETE_ON_CLOSE = 0x0000_1000;
		const OPEN_BY_FILE_ID = 0x0000_2000;
		const OPEN_FOR_BACKUP_INTENT = 0x0000_4000;
		const NO_COMPRESSION = 0x0000_8000;
		const OPEN_REQUIRING_OPLOCK = 0x0001_0000;
		const DISALLOW_EXCLUSIVE = 0x0002_0000;
		const SESSION_AWARE = 0x0004_0000;
		const RESERVE_OPFILTER = 0x0010_0000;
		const OPEN_REPARSE_POINT = 0x0020_0000;
		const OPEN_NO_RECALL = 0x0040_0000;
		const OPEN_FOR_FREE_SPACE_QUERY = 0x0080_0000;
	}
}

/// Action requested when a path exists or does not exist.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u32)]
pub enum CreateDisposition {
	Supersede = 0,
	Open = 1,
	Create = 2,
	OpenIf = 3,
	Overwrite = 4,
	OverwriteIf = 5,
}

impl TryFrom<u32> for CreateDisposition {
	type Error = u32;

	fn try_from(value: u32) -> Result<Self, Self::Error> {
		Ok(match value {
			0 => Self::Supersede,
			1 => Self::Open,
			2 => Self::Create,
			3 => Self::OpenIf,
			4 => Self::Overwrite,
			5 => Self::OverwriteIf,
			other => return Err(other),
		})
	}
}

bitflags! {
	/// Parts of a Windows security descriptor requested by an operation.
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct SecurityInformation: u32 {
		const OWNER = 0x0000_0001;
		const GROUP = 0x0000_0002;
		const DACL = 0x0000_0004;
		const SACL = 0x0000_0008;
		const LABEL = 0x0000_0010;
		const ATTRIBUTE = 0x0000_0020;
		const SCOPE = 0x0000_0040;
		const PROCESS_TRUST_LABEL = 0x0000_0080;
		const BACKUP = 0x0001_0000;
		const PROTECTED_DACL = 0x8000_0000;
		const PROTECTED_SACL = 0x4000_0000;
		const UNPROTECTED_DACL = 0x2000_0000;
		const UNPROTECTED_SACL = 0x1000_0000;
	}
}

/// Borrowed security descriptor supplied as part of an open request.
#[derive(Copy, Clone)]
pub struct SecurityDescriptorRef<'a> {
	ptr: NonNull<c_void>,
	_marker: std::marker::PhantomData<&'a c_void>,
}

impl fmt::Debug for SecurityDescriptorRef<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_tuple("SecurityDescriptorRef")
			.field(&self.ptr)
			.finish()
	}
}

impl SecurityDescriptorRef<'_> {
	/// Exposes the descriptor for interoperability with Windows security APIs.
	#[must_use]
	pub const fn as_ptr(self) -> *const c_void {
		self.ptr.as_ptr()
	}
}

/// Safe view over the security information accompanying an open request.
#[derive(Debug, Copy, Clone)]
pub struct SecurityContext<'a> {
	raw: &'a DOKAN_IO_SECURITY_CONTEXT,
}

impl<'a> SecurityContext<'a> {
	pub(crate) const fn new(raw: &'a DOKAN_IO_SECURITY_CONTEXT) -> Self {
		Self { raw }
	}

	#[must_use]
	pub const fn desired_access(self) -> AccessRights {
		AccessRights::from_bits_retain(self.raw.DesiredAccess)
	}

	#[must_use]
	pub fn security_descriptor(self) -> Option<SecurityDescriptorRef<'a>> {
		NonNull::new(self.raw.AccessState.SecurityDescriptor).map(|ptr| SecurityDescriptorRef {
			ptr: ptr.cast(),
			_marker: std::marker::PhantomData,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::NtStatus;

	#[test]
	fn nt_status_preserves_raw_bits_and_semantics() {
		let success = NtStatus::from_raw(0);
		let failure = NtStatus::from_raw(0xC000_0022_u32 as i32);

		assert!(success.is_success());
		assert!(!failure.is_success());
		assert_eq!(failure.into_raw() as u32, 0xC000_0022);
		assert_eq!(format!("{failure}"), "NT status 0xC0000022");
	}

	#[cfg(feature = "windows-interop")]
	#[test]
	fn nt_status_converts_to_projected_windows_type() {
		let status = NtStatus::from_raw(0xC000_0022_u32 as i32);
		let windows_status: windows::Win32::Foundation::NTSTATUS = status.into();
		assert_eq!(NtStatus::from(windows_status), status);
	}
}
