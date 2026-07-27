use std::{
	error::Error,
	fmt::{self, Display, Formatter},
};

use crate::{NtStatus, status};

/// Error type for the `fill_data` callbacks.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FillDataError {
	/// File name exceeds the limit of [`MAX_PATH`].
	///
	/// [`MAX_PATH`]: https://learn.microsoft.com/windows/win32/fileio/maximum-file-path-limitation
	NameTooLong,

	/// Buffer is full.
	BufferFull,
}

impl From<FillDataError> for NtStatus {
	fn from(err: FillDataError) -> NtStatus {
		match err {
			FillDataError::NameTooLong => status::INTERNAL_ERROR,
			FillDataError::BufferFull => status::BUFFER_OVERFLOW,
		}
	}
}

impl Error for FillDataError {}

impl Display for FillDataError {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		let msg = match self {
			FillDataError::NameTooLong => "file name length exceeds the limit of MAX_PATH",
			FillDataError::BufferFull => "buffer is full",
		};
		write!(f, "{}", msg)
	}
}

/// Returned by `fill_data` callbacks.
pub type FillDataResult = Result<(), FillDataError>;
