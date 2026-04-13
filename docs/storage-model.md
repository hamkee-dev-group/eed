# Storage Model

## Honest Guarantee

This build of `eed` is designed so that its save path intentionally writes only authenticated ciphertext to persistent storage. It does **not** guarantee that a normal filesystem, SSD controller, snapshotter, or backup system cannot retain older data or metadata outside the editor's control.

## What This Means In Practice

- Atomic saves prevent the editor from truncating the live file before encryption succeeds.
- The temp file used during save contains ciphertext only, not plaintext.
- The file should live in a parent directory owned by the current user and not writable by group or others.
- Recovery and backup sidecars are encrypted, but they do increase persistent ciphertext copies and metadata presence in the directory.
- The freshest recoverable state may live in `.recovery`, `.bak`, or both, depending on whether the last event was a mutation, a completed save, or a crash during save.
- If the buffer is dirty and its last recovery snapshot went stale, quit will try once more to persist an encrypted recovery snapshot before exiting.
- The editor cannot promise recoverability-resistant deletion of prior disk state on commodity storage.

## Deployment Profiles

### Baseline

Use `eed` on a host with full-disk encryption, encrypted swap, and no untrusted backup/snapshot tooling.

### Stronger

Use a dedicated encrypted removable or isolated volume with tightly controlled backups and a narrow operational window.

### Strongest Practical Claim

Run the editor on a RAM-backed filesystem and copy out only the final encrypted file. This is the closest deployment to "plaintext never persisted" that the current design can honestly support.

## Claims To Avoid

- "Secure delete" on SSDs or journaled filesystems
- "Military-grade recoverability resistance" on ordinary desktop storage
- "Nothing recoverable ever touched disk" unless the deployment really uses volatile storage only
