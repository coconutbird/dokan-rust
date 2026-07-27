use std::{
	env,
	path::{Path, PathBuf},
};

fn main() {
	let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
		.parent()
		.and_then(Path::parent)
		.expect("generator must remain under tools/generate-bindings");
	let wrapper = workspace.join("dokan-sys/bindings/wrapper.h");
	let output = workspace.join("dokan-sys/src/bindings.rs");
	let dokany_sys = workspace.join("dokan-sys/src/dokany/sys");
	let dokany_dokan = workspace.join("dokan-sys/src/dokany/dokan");

	let bindings = bindgen::Builder::default()
		.header(path_arg(&wrapper))
		.clang_arg(format!("-I{}", path_arg(&dokany_sys)))
		.clang_arg(format!("-I{}", path_arg(&dokany_dokan)))
		.clang_arg("-DUNICODE")
		.clang_arg("-D_UNICODE")
		.clang_arg("-DWINVER=0x0A00")
		.clang_arg("-D_WIN32_WINNT=0x0A00")
		.allowlist_function("Dokan.*")
		.allowlist_type("DOKAN_.*")
		.allowlist_type("P?DOKAN_.*")
		.allowlist_type("PFillFind.*")
		.blocklist_type("FILETIME")
		.blocklist_type("_FILETIME")
		.blocklist_type("BY_HANDLE_FILE_INFORMATION")
		.blocklist_type("_BY_HANDLE_FILE_INFORMATION")
		.blocklist_type("WIN32_FIND_DATAW")
		.blocklist_type("_WIN32_FIND_DATAW")
		.blocklist_type("LARGE_INTEGER")
		.blocklist_type("_LARGE_INTEGER")
		.raw_line("use windows_sys::Win32::Foundation::FILETIME;")
		.raw_line("type LARGE_INTEGER = i64;")
		.raw_line(
			"use windows_sys::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, WIN32_FIND_DATAW};",
		)
		.raw_line("type _BY_HANDLE_FILE_INFORMATION = BY_HANDLE_FILE_INFORMATION;")
		.raw_line("type _WIN32_FIND_DATAW = WIN32_FIND_DATAW;")
		.raw_line("type _LARGE_INTEGER = LARGE_INTEGER;")
		.override_abi(bindgen::Abi::System, ".*")
		.default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
		.derive_debug(true)
		.generate_comments(true)
		.layout_tests(true)
		.generate()
		.expect("failed to generate Dokany bindings; install LLVM/libclang and the Windows SDK");

	bindings
		.write_to_file(&output)
		.expect("failed to write generated bindings");

	println!("generated {}", output.display());
}

fn path_arg(path: &Path) -> String {
	PathBuf::from(path).to_string_lossy().into_owned()
}
