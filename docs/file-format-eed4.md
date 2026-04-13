# EED4 File Format

## Fixed Crypto Profile

- KDF: Argon2id
- Argon2 version: 19
- Memory cost: 65536 KiB
- Iterations: 3
- Lanes: 1
- Cipher: AES-256-GCM
- Nonce length: 12 bytes
- Tag length: 16 bytes
- Header authentication: the full 48-byte header is passed as AEAD associated data

## Plaintext Encoding

The editor serializes the in-memory buffer as a byte stream of newline-terminated lines. Each stored line is emitted exactly as typed, followed by `0x0a`. An empty editor buffer produces an empty plaintext stream.

## Binary Layout

| Offset | Length | Field |
| ------ | ------ | ----- |
| `0` | `4` | Magic ASCII `EED4` |
| `4` | `1` | File format version (`0x01`) |
| `5` | `1` | KDF identifier (`0x01` = Argon2id) |
| `6` | `1` | Cipher identifier (`0x01` = AES-256-GCM) |
| `7` | `1` | Flags (`0x00`) |
| `8` | `4` | Argon2 memory cost in KiB, big-endian |
| `12` | `4` | Argon2 iteration count, big-endian |
| `16` | `4` | Argon2 lane count, big-endian |
| `20` | `16` | Random salt |
| `36` | `12` | Random AES-GCM nonce |
| `48` | `n` | Ciphertext |
| `48 + n` | `16` | AES-GCM tag |

## Acceptance Rules

- The loader only accepts the fixed profile above.
- Older `EED3` files are intentionally rejected.
- The loader rejects oversized payloads, NUL bytes, overlong lines, excessive line counts, and authentication failures.

## Deterministic Test Vector

This vector is fixed in `tests/test_vectors.py` and is intended to detect accidental format or primitive drift.

- Password: `vector-passphrase`
- Salt: `000102030405060708090a0b0c0d0e0f`
- Nonce: `101112131415161718191a1b`
- Plaintext lines:
  - `alpha`
  - `beta/gamma`
  - `Line 3 with spaces`

Header:

```text
4545443401010100000100000000000300000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b
```

Ciphertext:

```text
e0e8b9f9d13cf983046e60ed522f9e1d27e5b302ee5551ff4135f8a4614a53a20324ff84
```

Tag:

```text
2a1c8c48936d3b5555a2e7b3d1fa2eb2
```

Full file:

```text
4545443401010100000100000000000300000001000102030405060708090a0b0c0d0e0f101112131415161718191a1be0e8b9f9d13cf983046e60ed522f9e1d27e5b302ee5551ff4135f8a4614a53a20324ff842a1c8c48936d3b5555a2e7b3d1fa2eb2
```
