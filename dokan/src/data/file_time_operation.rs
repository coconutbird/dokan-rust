use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dokan_sys::FILETIME;

use crate::to_file_time::FILETIME_OFFSET;

/// Operation to perform on a file's corresponding time information.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FileTimeOperation {
	/// Set corresponding time information of the file.
	SetTime(SystemTime),
	/// Don't change corresponding time information of the file.
	DontChange,
	/// Disable update of corresponding time information caused by further operations on the file handle.
	DisableUpdate,
	/// Resume update of corresponding time information caused by further operations on the file handle.
	ResumeUpdate,
}

impl FileTimeOperation {
	/// Converts the nullable `FILETIME` pointer supplied by Dokany.
	///
	/// # Safety
	///
	/// A non-null `time` must point to a readable, initialized [`FILETIME`].
	pub(crate) unsafe fn from_raw(time: *const FILETIME) -> Self {
		if time.is_null() {
			return Self::DontChange;
		}

		// FILETIME is two little-endian 32-bit words. Reading its fields avoids
		// relying on the layout of LARGE_INTEGER or using a transmute.
		let time = unsafe { &*time };
		let bits = u64::from(time.dwLowDateTime) | (u64::from(time.dwHighDateTime) << 32);
		match bits as i64 {
			0 => Self::DontChange,
			-1 => Self::DisableUpdate,
			-2 => Self::ResumeUpdate,
			_ => {
				let ticks = bits;
				Self::SetTime(
					UNIX_EPOCH - FILETIME_OFFSET
						+ Duration::from_micros(ticks / 10)
						+ Duration::from_nanos(ticks % 10 * 100),
				)
			}
		}
	}
}
