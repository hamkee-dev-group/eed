#!/usr/bin/env python3
import argparse
import os
import random
import string
import sys
import tempfile

from common_pty import extract_printed_lines, normalize_output, open_existing_file, open_new_file


ALPHABET = string.ascii_letters + string.digits + " _-./"


def random_line(rng):
    while True:
        length = rng.randint(1, 32)
        candidate = "".join(rng.choice(ALPHABET) for _ in range(length)).strip()
        if candidate and candidate != ".":
            return candidate


def build_lines(rng):
    return [random_line(rng) for _ in range(rng.randint(1, 6))]


def roundtrip_once(binary, tempdir, iteration, rng):
    password = f"property-pass-{iteration}"
    path = os.path.join(tempdir, f"case-{iteration}.eed")
    lines = build_lines(rng)

    session = open_new_file(binary, path, password)
    session.send_line("a")
    session.read_until("Enter lines, single '.' on line to finish:")
    for line in lines:
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

    session = open_existing_file(binary, path, password)
    session.send_line("p")
    output = normalize_output(session.read_until("> ", timeout=60.0))
    printed = extract_printed_lines(output)
    if printed != lines:
        raise AssertionError(f"expected {lines!r}, got {printed!r}")
    session.send_line("q")
    _, status = session.read_to_exit()
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise AssertionError(f"unexpected exit status: {status}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--seed", type=int, default=1921)
    args = parser.parse_args()

    binary = os.path.abspath(args.binary)
    rng = random.Random(args.seed)

    with tempfile.TemporaryDirectory(prefix="eed-property-") as tempdir:
        for iteration in range(args.iterations):
            roundtrip_once(binary, tempdir, iteration, rng)

    print(f"property-roundtrip-ok {args.iterations}")


if __name__ == "__main__":
    main()
