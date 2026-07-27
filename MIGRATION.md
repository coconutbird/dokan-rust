# Rust 2024 API migration

This branch intentionally breaks the pre-2024 wrapper API to remove unsound
lifetime and ownership assumptions.

## Handler and handle state

- Implement `FileSystemHandler` without lifetime parameters.
- The handler must be `Send + Sync + 'static`.
- `FileSystemHandler::Context` must be `Send + Sync + 'static`, because Dokany
  may operate on and close a handle from different worker threads.
- `OperationInfo` is callback-scoped. Its constructor, raw handler lookup, and
  per-open context lookup are no longer public.

## Mounting

`FileSystemMounter::new` now owns the handler, mount point, UNC name, and
options:

```rust
let filesystem = FileSystemMounter::new(handler, mount_point, options).mount()?;
```

`mount` consumes the mounter. The returned `FileSystem` owns all callback
storage and automatically holds a process-wide Dokany runtime reference.

## Notification handles

`FileSystemHandle` is cloneable but no longer `Copy`. It shares the full native
session lifetime and serializes notification calls against native handle
closure. Calls made after unmount return `false`.

## Raw bindings

The raw declarations are checked-in bindgen output generated from the vendored
Dokany headers. Regenerate them with:

```text
cargo run -p generate-dokan-bindings
```

The generator requires LLVM/libclang and a Windows SDK; normal crate consumers
do not.

## Rust-native Windows boundary

- The high-level `dokan` API no longer exposes `winapi` or generated
  `dokan-sys` structures.
- `create_file` now receives a `CreateFileRequest` containing typed
  `AccessRights`, `FileAttributes`, `ShareAccess`, `CreateDisposition`, and
  `CreateOptions`.
- Security callbacks receive `SecurityInformation` and safe byte slices rather
  than unbounded security-descriptor pointers.
- `FileInfo` and `FindData` use `FileAttributes`; `VolumeInfo` uses
  `VolumeFeatures`.
- Common operation failures are available from `dokan::status`.
- `MountOptions::volume_security_descriptor` owns a `Vec<u8>` and validates the
  Dokany size limit when the mounter is constructed.
- The implementation and generated ABI bindings use `windows-sys`; `winapi`
  remains only a development dependency for the legacy Win32-heavy test
  harness and memfs example internals.
