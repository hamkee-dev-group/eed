eed — Secure Minimal Text Editor with Encryption (OpenSSL 3.x)

eed is a simple, minimal, secure text editor inspired by ed, written in C.

✅ Supports encrypted text files

✅ Uses AES-256-CBC for encryption

✅ Uses HMAC-SHA-256 for integrity protection (MAC)

✅ Compatible with OpenSSL 3.x → no deprecated functions

✅ Does not leak plaintext to disk

✅ Holds buffer in RAM only

✅ Works on Linux, macOS

Features

Password protected: securely prompts for password (hidden input)
PBKDF2 (SHA-256) for key derivation (easy to swap to Argon2 if needed)
AES-256-CBC encryption
HMAC-SHA-256 message authentication (MAC) → detects tampering
No temp files, only in-memory buffer until explicitly written
Compatible with OpenSSL 3.x API → uses EVP_MAC, no deprecated HMAC_CTX

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

Editor uses AES-256-CBC with random IV per file
Uses PBKDF2 with 100,000 iterations (easy to increase or switch to Argon2)
Adds HMAC-SHA-256 over IV + ciphertext → integrity check
If MAC verification fails, the file is not opened
No plaintext is written to disk unless you explicitly write
Plaintext buffer and password are securely wiped on exit

Limitations

Only supports one file at a time
Max buffer: MAX_LINES (default 16384 lines), MAX_LINE_LEN (1024 chars per line)
No multi-level undo
No support for !shell commands (on purpose → security)
No auto-recovery (intentional → secure)
