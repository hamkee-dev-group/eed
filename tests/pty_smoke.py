#!/usr/bin/env python3
import os
import stat
import sys
import tempfile

from common_pty import extract_printed_lines, normalize_output, open_existing_file, open_new_file


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: pty_smoke.py /path/to/eed")

    binary = os.path.abspath(sys.argv[1])
    password = "smoke-test-password"

    with tempfile.TemporaryDirectory(prefix="eed-smoke-") as tempdir:
        path = os.path.join(tempdir, "session.eed")

        session = open_new_file(binary, path, password)

        session.send_line("a")
        session.read_until("Enter lines, single '.' on line to finish:")
        session.send_line("alpha")
        session.send_line("beta")
        session.send_line(".")
        session.read_until("> ")

        session.send_line("i")
        session.read_until("Insert before line number: ")
        session.send_line("2")
        session.read_until("Enter lines, single '.' on line to finish:")
        session.send_line("between")
        session.send_line(".")
        session.read_until("> ")

        session.send_line("c")
        session.read_until("Change line number: ")
        session.send_line("1")
        session.read_until("New line: ")
        session.send_line("first")
        session.read_until("> ")

        session.send_line("s/beta/gamma/")
        session.read_until("> ")

        session.send_line("d")
        session.read_until("Delete line number: ")
        session.send_line("2")
        session.read_until("> ")

        session.send_line("=")
        output = normalize_output(session.read_until("> "))
        if "Lines: 2" not in output:
            raise AssertionError(output)

        session.send_line("w")
        output = normalize_output(session.read_until("> ", timeout=60.0))
        if "File written." not in output:
            raise AssertionError(output)

        session.send_line("q")
        _, status = session.read_to_exit()
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise AssertionError(f"unexpected exit status: {status}")

        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode != 0o600:
            raise AssertionError(f"unexpected mode: {oct(mode)}")

        with open(path, "rb") as handle:
            ciphertext = handle.read()
        for marker in (b"first", b"gamma", b"alpha", b"beta", b"between"):
            if marker in ciphertext:
                raise AssertionError("plaintext marker appeared in ciphertext file")

        session = open_existing_file(binary, path, password)
        session.send_line("p")
        output = normalize_output(session.read_until("> ", timeout=60.0))
        if extract_printed_lines(output) != ["first", "gamma"]:
            raise AssertionError(output)

        session.send_line("q")
        _, status = session.read_to_exit()
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise AssertionError(f"unexpected exit status: {status}")

    print("pty-smoke-ok")


if __name__ == "__main__":
    main()
