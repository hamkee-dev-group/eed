#!/usr/bin/env python3
import argparse
import os
import random
import sys
import tempfile

from common_pty import EditorSession, normalize_output


EDGE_SIZES = [1, 2, 15, 16, 31, 32, 40, 63, 64, 65, 96, 127, 128, 255, 256, 511, 512, 1023]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--seed", type=int, default=1921)
    args = parser.parse_args()

    binary = os.path.abspath(args.binary)
    rng = random.Random(args.seed)

    with tempfile.TemporaryDirectory(prefix="eed-malformed-") as tempdir:
        for iteration in range(args.iterations):
            size = EDGE_SIZES[iteration % len(EDGE_SIZES)] if iteration < len(EDGE_SIZES) else rng.randint(1, 2048)
            path = os.path.join(tempdir, f"garbage-{iteration}.eed")
            with open(path, "wb") as handle:
                handle.write(os.urandom(size))

            session = EditorSession(binary, path)
            session.read_until("Password: ")
            session.send_line("malformed-password")
            output, status = session.read_to_exit(timeout=30.0)
            text = normalize_output(output)

            if "AddressSanitizer" in text or "UndefinedBehaviorSanitizer" in text:
                raise AssertionError(text)
            if os.WIFSIGNALED(status):
                raise AssertionError(f"editor crashed with signal {os.WTERMSIG(status)}")
            if not os.WIFEXITED(status):
                raise AssertionError(f"unexpected wait status: {status}")
            if os.WEXITSTATUS(status) == 0:
                raise AssertionError("malformed input unexpectedly succeeded")

    print(f"malformed-files-ok {args.iterations}")


if __name__ == "__main__":
    main()
