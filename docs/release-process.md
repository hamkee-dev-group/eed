# Release And Audit Process

## Purpose

This repository can now produce a repeatable internal verification bundle, but an actual independent audit still requires a separate reviewer and a signing key that are not part of this workspace.

## Minimum Release Procedure

1. Build from a clean checkout of the exact commit being released.
2. Set a fixed `SOURCE_DATE_EPOCH` for the release run.
3. Run `make clean all verify audit-manifest`.
4. Archive the resulting binary plus `dist/sha256.txt` and `dist/build-info.txt`.
5. Record the exact OpenSSL version, compiler version, operating system, and committed `EED4` format spec in the release notes.

## External Audit Procedure

1. Hand the auditor the exact commit ID, the release artifact, and the audit manifest.
2. Require the auditor to rebuild from the same commit and compare the resulting hashes against `dist/sha256.txt`.
3. Scope the audit to the exact binary hash being shipped, not just to the source tree in general.
4. Treat any source change, compiler change, or dependency change as a new audit candidate.

## Signed Release Procedure

1. Generate the audit manifest with `make audit-manifest`.
2. Sign `dist/sha256.txt` and the release notes with an offline key that is kept outside the build machine.
3. Publish the signature, the public verification key, and the binary hash together.
4. Make signature verification part of the deployment checklist.

The repository does not ship a signing key, and it should not. Signed releases need an operator-controlled trust root.

## Reproducibility Notes

- Avoid embedding ad hoc local changes, generated files, or untracked patches in the release build.
- Pin the compiler family and OpenSSL build used for production.
- Rebuild from scratch for each release instead of reusing a previously compiled binary.
- Keep the deterministic vector in `docs/file-format-eed4.md` and `tests/test_vectors.py` in sync with the shipping format.

## What This Repo Can Do Today

- Release build: `make`
- Sanitized regression build: `make asan`
- Static analysis: `make analyze`
- PTY smoke test: `make smoke`
- Property-style round-trip test: `make property`
- Deterministic format/vector test: `make vectors`
- Crash-recovery and backup regression test: `make recovery`
- Malformed-file regression sweep: `make malformed`
- Portable parser fuzz harness build: `make fuzz-build`
- Optional libFuzzer build on supported toolchains: `make libfuzzer-build`
  The target prints guidance instead of hard-failing when the local clang does not ship the fuzzer runtime.
- Audit manifest bundle: `make audit-manifest`
- Continuous verify/fuzz workflow: `.github/workflows/verify.yml`

## What Still Requires External Work

- A truly independent review of the final ship binary
- Real release signing with an offline organizational key
- Longer-running fuzz campaigns with corpus management and crash triage
