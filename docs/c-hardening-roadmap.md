# C Hardening Roadmap

## Current State

The editor remains a C codebase by design. The current hardening strategy is therefore to narrow the dangerous surface, freeze the crypto container, and keep verification pressure high rather than to promise language-level memory safety.

## Immediate Controls

- Keep the crypto format fixed and documented in `docs/file-format-eed4.md`.
- Keep `make verify` mandatory before release.
- Keep `make fuzz-run` in regular use against `load_encrypted()`.
- Preserve explicit cleansing of passwords, keys, tags, and plaintext buffers.
- Keep risky helper functions `static` and continue preferring fixed-size buffers and explicit bounds checks.

## Near-Term Assurance Work

- Add stricter warning gates such as `-Wconversion`, `-Wshadow`, and `-Wstrict-prototypes` once the tree is clean under them.
- Run `clang-tidy` and `cppcheck` in CI as advisory jobs.
- Perform a manual MISRA-C-oriented review of the parser and save path, while being explicit that the project is not yet claiming formal MISRA compliance.
- Expand deterministic test vectors to cover empty files and maximum-length line edge cases.

## Higher-Assurance Options Without Leaving C

- Split the file-format parser and serializer into a smaller translation unit with a narrower API.
- Add CBMC or Frama-C proofs for header parsing, bounds checks, and line-count safety properties.
- Add negative tests for every rejected header field combination in `EED4`.
- Consider a dedicated hardened build profile with stack canaries, full RELRO, and platform-specific linker hardening flags.

## Explicit Non-Claim

This roadmap improves assurance inside a C codebase. It does not make C memory-safe, and it should not be described that way.
