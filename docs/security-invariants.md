# Security Invariants

These invariants are intended to be true for every supported execution path. If any invariant cannot be maintained, `eed` should fail closed.

1. The edited object must be a single-link regular file.
   `eed` refuses symbolic links, non-regular files, and files with more than one hard link.

2. The parent directory must be trusted.
   `eed` only operates on files whose parent directory is owned by the current user and not writable by group or others.

3. Only one live editor instance may hold the file for writing.
   The open file descriptor is placed under an exclusive advisory lock before editing begins.

4. The pathname must continue to refer to the originally opened file.
   Save checks the file identity before writing the temp file and again immediately before `rename()`.

5. Persistent writes must contain ciphertext only.
   Saving writes an authenticated `EED4` header, AES-256-GCM ciphertext, and a 16-byte AEAD tag to a same-directory temp file, then `fsync()`s and atomically renames it over the target.

6. Every mutating command must leave an encrypted recovery point on disk.
   The editor refreshes a same-directory `.recovery` sidecar after successful buffer mutations so crash recovery does not depend on a manual `w`.

7. The latest durable editor state must remain recoverable from encrypted sidecars.
   Mutations refresh a same-directory `.recovery` snapshot, and save refreshes a same-directory `.bak` mirror before the primary rename, so crashes or later primary-file damage still leave a recoverable ciphertext copy.

8. Newly created or reopened file descriptors must be mode `0600`.
   The editor forces user-read and user-write permissions on the live file descriptor and on save temp files.

9. Only the supported authenticated file format is accepted.
   Loading requires the `EED4` magic, the fixed Argon2id profile, AES-256-GCM, and successful authentication of the header as AEAD associated data.

10. The loader must reject malformed payloads before they can overflow in-memory structures.
   Undersized files, oversized files, authentication failures, NUL bytes, overlong lines, and excessive line counts are rejected.

11. Buffer reloads must be transactional.
   Loading a primary file, backup, or recovery overlay must not append into or destroy an already valid buffer unless the new ciphertext authenticates and parses successfully.

12. Plaintext should remain transient in memory.
   The password buffer and every stored line are explicitly cleansed before release, including replaced lines during substitution and line edits.

13. Unsupported legacy ciphertext must fail closed.
   Older file formats are rejected rather than guessed or partially parsed.
