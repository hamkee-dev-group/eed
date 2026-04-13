#!/usr/bin/env python3
import os
import sys
import tempfile

from common_pty import extract_printed_lines, normalize_output, open_existing_file, open_new_file


PASSWORD = "vector-passphrase"
SALT_HEX = "000102030405060708090a0b0c0d0e0f"
NONCE_HEX = "101112131415161718191a1b"
LINES = ["alpha", "beta/gamma", "Line 3 with spaces"]
EXPECTED_HEX = (
    "4545443401010100000100000000000300000001000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1be0e8b9f9d13cf983046e60ed522f9e1d27e5b302ee5551ff"
    "4135f8a4614a53a20324ff842a1c8c48936d3b5555a2e7b3d1fa2eb2"
)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_vectors.py /path/to/eed")

    binary = os.path.abspath(sys.argv[1])
    env = {
        "EED_TEST_SALT_HEX": SALT_HEX,
        "EED_TEST_NONCE_HEX": NONCE_HEX,
    }

    with tempfile.TemporaryDirectory(prefix="eed-vectors-") as tempdir:
        path = os.path.join(tempdir, "vector.eed")

        session = open_new_file(binary, path, PASSWORD, env=env)
        session.send_line("a")
        session.read_until("Enter lines, single '.' on line to finish:")
        for line in LINES:
            session.send_line(line)
        session.send_line(".")
        session.read_until("> ")

        session.send_line("w")
        output = normalize_output(session.read_until("> ", timeout=60.0))
        if "File written." not in output:
            raise AssertionError(output)
        session.send_line("q")
        _, status = session.read_to_exit()
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise AssertionError(f"unexpected exit status: {status}")

        with open(path, "rb") as handle:
            actual_hex = handle.read().hex()
        if actual_hex != EXPECTED_HEX:
            raise AssertionError(f"expected {EXPECTED_HEX}, got {actual_hex}")

        session = open_existing_file(binary, path, PASSWORD)
        session.send_line("p")
        output = normalize_output(session.read_until("> ", timeout=60.0))
        if extract_printed_lines(output) != LINES:
            raise AssertionError(output)
        session.send_line("q")
        _, status = session.read_to_exit()
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise AssertionError(f"unexpected exit status: {status}")

    print("test-vectors-ok")
