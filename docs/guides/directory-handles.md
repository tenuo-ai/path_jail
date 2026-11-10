# Directory handles

`FdJail::open_dir` provides directory iteration without reconstructing ambient
filesystem paths. It is available on Linux 5.6+ x86_64/aarch64 with the `guard`
feature.

<!-- example: doc-examples/examples/directory.rs#iterate -->
```rust
let directory = jail.open_dir("incoming")?;
let mut contents = Vec::new();
for entry in directory.read_dir()? {
    let entry = entry?;
    let mut file = directory.open(
        entry.file_name(),
        OpenOptions::new()
            .read(true)
            .require_regular_file(true)
            .reject_hard_links(true),
    )?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    contents.push(bytes);
}
```

Directory entry names, inode numbers, and file-type hints are snapshots. An
entry can be replaced between iteration and open. `GuardedDir::open` resolves
the current name beneath the pinned directory with `openat2`; handle policies
then check the object that was actually opened.

`open_dir_with` accepts `ResolveOptions`. Set `no_symlinks` or `no_xdev` there
to constrain resolution from the jail root to the directory. Options passed to
a later `GuardedDir::open` apply beneath the already pinned directory.

The handle refers to an inode, not a pathname. Renaming or replacing the path
used by `open_dir` cannot redirect later operations. If another process moves
the pinned directory outside the jail, however, the existing handle still
reaches it. Use a dedicated filesystem or mount when untrusted processes can
move directories through another writable path.

This API is intentionally unavailable on fallback platforms. Implementing it
by joining entry names onto a pathname would restore the race it is designed to
avoid.
