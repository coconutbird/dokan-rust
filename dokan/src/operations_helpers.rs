use std::panic::{self, AssertUnwindSafe};

use crate::{NtStatus, status};

pub type NtResult = Result<(), NtStatus>;

pub fn wrap_nt_result<F: FnOnce() -> NtResult>(f: F) -> NtStatus {
	// Unwind safety is not a safety property here: the callback is abandoned
	// after a panic and Dokany receives an error. Requiring user state to
	// implement RefUnwindSafe incorrectly rejected normal mutex-based handlers.
	panic::catch_unwind(AssertUnwindSafe(f))
		.map(|result| match result {
			Ok(_) => status::SUCCESS,
			Err(nt_status) => nt_status,
		})
		.unwrap_or(status::INTERNAL_ERROR)
}

#[allow(unused_must_use)]
pub fn wrap_unit<F: FnOnce()>(f: F) {
	panic::catch_unwind(AssertUnwindSafe(f));
}
