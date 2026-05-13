# Security Policy

This document is the threat model and security contract for `path_jail`. It
exists because every security library needs one: callers can only use the
library correctly if they know what it defends against and what it doesn't.

If you find a vulnerability, see [Reporting a vulnerability](#reporting-a-vulnerability) below.

---

## Attacker model

`path_jail` is designed to defend against an attacker who supplies path
strings to your application — for example:

- A web client uploading a file with a chosen filename
- A user-controlled config value naming a path inside a sandbox directory
- A workflow step naming a file inside a CI working directory

The attacker can supply:

- Arbitrary bytes in the path (including `..`, leading `/`, null bytes, magic
  link prefixes like `/proc/self/fd/N`)
- A pre-existing symlink inside the jail that points outside the jail
- A pre-existing hard link inside the jail that points to sensitive content
- Concurrent filesystem activity attempting to swap paths between validation
  and open (TOCTOU)

The attacker is assumed to **not** have:

- Privileges to mount filesystems, run as root inside the jail's filesystem,
  call `ptrace`, or otherwise escape the OS sandbox the application runs in
- The ability to modify the running process's memory
- A working kernel exploit

If your attacker can do any of the above, no userspace library can help —
you need a process-level sandbox (`seccomp`, `landlock`, containers, VMs).

---

## What each API defends against

`path_jail` ships three API layers with different security/ergonomics
tradeoffs. Pick the strongest one your environment supports.

| Threat                                        | `Jail` (default) | `secure-open` | `guard` (Linux 5.6+) |
|-----------------------------------------------|:---:|:---:|:---:|
| Path traversal via `..`                       | ✅  | ✅  | ✅                  |
| Absolute path injection (`/etc/passwd`)       | ✅  | ✅  | ✅                  |
| Null-byte injection                           | ✅  | ✅  | ✅                  |
| Symlink target outside the jail               | ✅  | ✅  | ✅                  |
| Broken symlinks (cannot verify target)        | ✅  | ✅  | ✅                  |
| Symlink swap on final component (TOCTOU)      | ❌  | ✅  | ✅                  |
| Symlink swap on intermediate directories      | ❌  | ❌  | ✅                  |
| Concurrent rename of jail root mid-operation  | ❌  | ❌  | ✅¹                 |
| Magic links (`/proc/self/fd`, `/proc/self/root`) | ❌  | ❌  | ✅                  |
| Hard link to sensitive content (detect)       | ❌² | ❌² | ✅³                 |
| Bind-mount escape (opt-in)                    | ❌  | ❌  | ✅⁴                 |
| Atomic open with kernel-enforced containment  | ❌  | ❌  | ✅                  |
| Signed attestation of the open event          | ❌  | ❌  | ✅⁵                 |

Footnotes:

1. `guard::FdJail` pins an `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` fd to the
   jail root at construction time. Subsequent renames or replacements of the
   root *path* do not affect the jail — all operations remain scoped to the
   original directory inode.
2. Hard links are not detectable in user space before open. The path-based
   APIs do not stat the opened file and so cannot surface `nlink`.
3. `guard::JailFile::has_hard_links()` exposes `nlink > 1` from the post-open
   `fstat`. **Policy is the caller's responsibility** — a content-addressed
   store may legitimately use hard links. If your policy rejects hard links,
   check `has_hard_links()` **before** reading or writing.
4. Opt in with `OpenOptions::no_xdev(true)` (maps to `RESOLVE_NO_XDEV`).
   Off by default to preserve directory-tree containment semantics, which
   are what most callers want.
5. Opt in by implementing the `Signer` trait. `path_jail` ships no crypto;
   bring your own (`ed25519-dalek`, `ring`, HSM client, KMS, etc.).

---

## Out of scope

These threats are documented as **not defended** by any API:

- **Privileged local attackers.** A process with root or `CAP_SYS_ADMIN` on
  the host can mount, bind-mount, or `ptrace` around any user-space check.
- **Kernel and filesystem exploits.** A kernel-level bug, a FUSE filesystem
  misbehaving, or an `openat2` semantic regression in a specific kernel
  version are outside our control. We pin to documented kernel ABI.
- **Side-channel attacks.** Timing, cache, filesystem-metadata leaks.
- **Directory iteration (`read_dir`) and recursive walks.** Iterating jail
  contents has its own TOCTOU surface (rename-during-walk) that we do not
  currently address. If you walk a directory tree, treat it as untrusted
  input on every iteration.
- **Windows.** No Windows-specific protections are implemented. `Jail` and
  `secure-open` compile on Windows but provide no defenses beyond the
  cross-platform path-string checks; `guard` is Linux-only.
- **Unicode normalization.** Paths are accepted byte-for-byte. We do not
  normalize NFC/NFD on macOS or fold case on Windows/macOS. If your storage
  layer is case-insensitive, treat `Report.PDF` and `report.pdf` as
  potentially the same file.
- **Resource exhaustion.** Very long paths, deep symlink chains, etc. are
  rejected by the kernel (`ENAMETOOLONG`, `ELOOP`) but `path_jail` does not
  impose its own limits.

---

## Choosing the right API

```text
                              ┌──────────────────────────────────┐
You only need a validated     │ Use `Jail::join` / `join_typed`. │
path (e.g., for logging) →    │ Cheap, portable.                 │
                              └──────────────────────────────────┘

                              ┌──────────────────────────────────┐
You open the file in          │ Use `secure-open`.               │
process, on Unix, and need    │ Protects final-component swaps.  │
final-component TOCTOU →      └──────────────────────────────────┘

                              ┌──────────────────────────────────┐
Security-critical opens on    │ Use `guard` (Linux 5.6+).        │
Linux, attestation needed,    │ Kernel-enforced; signable.       │
or hostile multi-tenant →     └──────────────────────────────────┘
```

`guard` is the strongest. Use it on Linux where you can.

---

## Versioning & supported releases

- We follow semver. While we are pre-1.0 (`0.y.z`), minor-version bumps
  (`0.4 → 0.5`) may include breaking changes; patch bumps (`0.4.0 → 0.4.1`)
  will not.
- Security fixes are issued on the latest minor line. We do not currently
  backport to older 0.x lines.
- The MSRV (currently 1.85) may be bumped in any minor release. We treat MSRV
  bumps as breaking.

---

## Reporting a vulnerability

**Do not** open a public GitHub issue for security bugs.

Use **GitHub Private Vulnerability Reporting** on the
[`tenuo-ai/path_jail` repository](https://github.com/tenuo-ai/path_jail)
(Security tab → "Report a vulnerability"), or email **security@tenuo.ai**
with:

- A minimal reproducer (Rust code that demonstrates the issue)
- The affected `path_jail` version and feature flags
- The platform (OS, kernel version, architecture)
- Your assessment of the impact (information disclosure / write outside jail
  / etc.)

We aim to acknowledge within 5 business days and to ship a fix within 30
days for high-severity findings (escape from a documented containment
guarantee). Lower-severity findings (e.g., a missing defense for a
documented out-of-scope threat) will be triaged on the open repository.

---

## A note on the `Jail` default API

The README quick-start uses `Jail::new` and `Jail::join` — the path-based
API. That API is **not TOCTOU-safe**. It validates a path string and returns
a `PathBuf`; whatever the caller does with that `PathBuf` is a separate
operation with its own race window.

This is documented but easy to miss. If you operate in any of these
environments, **strongly prefer `guard`** over the path-based API:

- Multi-tenant systems where another local process can manipulate the
  filesystem
- File-upload paths where the same directory is also writable by other
  workers
- Anywhere "the file you validated" and "the file you opened" need to be
  the same file with certainty

We may make `guard` the default in a future major release. For now, choose
explicitly.
