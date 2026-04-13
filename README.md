eed — Secure Minimal Text Editor with Encryption (OpenSSL 3.x)

eed is a simple, minimal, secure text editor inspired by ed, written in C.

✅ Supports encrypted text files

✅ Uses Argon2id for password-based key derivation

✅ Uses AES-256-GCM for authenticated encryption

✅ Compatible with OpenSSL 3.5+ for Argon2id + AEAD primitives

✅ Save path writes ciphertext only

✅ Keeps the working buffer in process memory, with optional strict memory-lock enforcement

✅ Works on Linux, macOS

Features

Password protected: securely prompts for password (hidden input)

Fixed Argon2id profile for password-based key derivation

AES-256-GCM authenticated encryption

Authenticated `EED4` file format with header-bound associated data

Atomic encrypted saves with same-directory temp files (ciphertext only)

Compatible with OpenSSL 3.5+ API → uses `EVP_KDF` for Argon2id and `EVP_CIPHER` AEAD APIs

Encrypted recovery snapshots after each mutating command and mirrored backup copies for the latest durable state

Simple ed-like commands:

| Command      | Description                   |
| ------------ | ----------------------------- |
| `p`          | Print buffer                  |
| `a`          | Append lines at end           |
| `i`          | Insert before line number     |
| `c`          | Change line number            |
| `d`          | Delete line number            |
| `=`          | Print number of lines         |
| `/pattern/`  | Search pattern (regex)        |
| `s/old/new/` | Substitute old → new (global) |
| `w`          | Write (encrypt and save)      |
| `q`          | Quit editor                   |
| `h`          | Show help                     |


Security Notes

Editor uses AES-256-GCM with a random 96-bit nonce per file

Uses an authenticated `EED4` header and currently accepts only the fixed supported Argon2id profile

Authenticates the full header as AEAD associated data before any plaintext is accepted

If AEAD authentication fails, the file is not opened

Saves are atomic: encrypted output is written to a temp file, synced, then renamed over the target

Each open file is held with an exclusive advisory lock, and saves refuse to proceed if the pathname no longer points at the file originally opened

The editor save path intentionally writes only ciphertext; swap, hibernation, snapshots, and backups remain outside the editor's control

Every mutating command refreshes an encrypted `.recovery` snapshot, and each save refreshes an encrypted `.bak` mirror before the primary rename so crashes still leave a recoverable ciphertext copy

Quit will attempt to refresh a final encrypted recovery snapshot before exiting if the in-memory buffer is dirty and the prior recovery snapshot is stale

The parent directory must be owned by the current user and not writable by group or others

Plaintext buffer and password are securely wiped on exit

Memory locking is attempted at startup; set `EED_REQUIRE_MLOCK=1` to fail closed on hosts where `mlockall()` is unavailable

Current release writes an `EED4` file format and does not open files written by older releases


Verification

`make` builds the release binary

`make asan` builds the sanitizer-enabled regression binary

`make verify` runs static analysis, PTY smoke testing, property-style round-trip testing, deterministic vector checks, and malformed-file regression sweeps

`make recovery` runs crash-recovery and latest-backup regression coverage

`make fuzz-build` builds a portable sanitizer-backed fuzz harness for `load_encrypted()`

`make libfuzzer-build` attempts the libFuzzer variant and prints guidance when the local toolchain does not provide the runtime

`make audit-manifest` writes `dist/sha256.txt` and `dist/build-info.txt` for exact-build review


Assurance Docs

`docs/threat-model.md` defines the threat model and explicit non-goals

`docs/security-invariants.md` records the invariants the code is expected to preserve

`docs/storage-model.md` explains what the save path can and cannot honestly claim about recoverability

`docs/release-process.md` documents the exact-build audit and signed-release workflow

`docs/file-format-eed4.md` freezes the binary format and includes a deterministic test vector

`docs/c-hardening-roadmap.md` lays out the next hardening steps within a C-only codebase


Limitations

Only supports one file at a time

Max buffer: MAX_LINES (default 16384 lines), MAX_LINE_LEN (1024 chars per line)

No multi-level undo

No support for !shell commands (on purpose → security)

Crash recovery is sidecar-based; there is no multi-version recovery browser or undo journal

Does not support symbolic links or files with multiple hard links
