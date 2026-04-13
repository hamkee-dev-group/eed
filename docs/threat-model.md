# Threat Model

## Security Goal

`eed` is meant to keep plaintext in process memory, store only authenticated ciphertext on persistent media, and fail closed on malformed or tampered encrypted files.

## Protected Assets

- The plaintext editing buffer
- The password entered by the user
- The integrity of the encrypted file on disk
- The binding between the open file descriptor and the pathname the user believes they are editing

## Trust Assumptions

- The host kernel, C runtime, and OpenSSL 3.x behave correctly.
- The user supplies a strong password and protects their terminal session.
- The machine is not already compromised by a privileged attacker.
- `mlockall()` succeeds and the operating system honors it for the current process when strict memory locking is required.
- The edited file lives in a parent directory owned by the current user and not writable by group or others.

## Threats This Build Actively Tries To Resist

- Malformed encrypted files that attempt to crash or corrupt the parser
- Ciphertext tampering, header tampering, or accidental corruption
- Symlink, hard-link, and pathname replacement attacks against the edited file in trusted parent directories
- Concurrent writes from multiple `eed` instances pointed at the same file
- Plaintext leakage through temporary save files

## Explicit Non-Goals

- Secure deletion guarantees on SSDs, journaling filesystems, snapshots, or backups
- Resistance against root, kernel, hypervisor, or physical live-memory attackers
- Safe operation over network filesystems with weak locking semantics
- Multi-user collaboration or merging
- Protection against offline password guessing if an attacker obtains the ciphertext file

## Residual Risks

- `print_buffer()` intentionally writes plaintext to the terminal, which can be captured by terminal logging, scrollback, or screen recording.
- If `mlockall()` is unavailable or later undermined by the platform, plaintext may still reach swap, hibernation, crash reporting, or forensic artifacts outside the editor's control.
- The save path still depends on filesystem rename semantics and cannot provide formal guarantees equivalent to a sealed object store.
- POSIX pathname replacement remains a residual same-UID race even after the editor refuses untrusted parent directories.
- The implementation is still in C, so memory-safety bugs remain a structural risk even after hardening.

## Deployment Guidance

- Use a dedicated local filesystem with full-disk encryption.
- Disable or encrypt swap and hibernation on machines that handle sensitive plaintext.
- Exclude the working directory from backup tools that snapshot temporary states you do not control.
- If recoverability claims matter more than convenience, run the editor on a RAM-backed filesystem and export only the final ciphertext artifact.
- Set `EED_REQUIRE_MLOCK=1` in strict deployments that must fail closed when process memory cannot be locked.
