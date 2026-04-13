#!/usr/bin/env python3
import errno
import os
import pty
import re
import select
import time


class EditorSession:
    def __init__(self, binary, path, env=None):
        pid, fd = pty.fork()
        if pid == 0:
            child_env = os.environ.copy()
            if env:
                child_env.update(env)
            os.execve(binary, [binary, path], child_env)
        self.pid = pid
        self.fd = fd
        self.closed = False

    def send_line(self, text):
        os.write(self.fd, text.encode("utf-8") + b"\n")

    def read_until(self, needle, timeout=20.0):
        if isinstance(needle, str):
            needle = needle.encode("utf-8")
        data = bytearray()
        deadline = time.monotonic() + timeout

        while needle not in data:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"timed out waiting for {needle!r}")
            ready, _, _ = select.select([self.fd], [], [], remaining)
            if not ready:
                raise TimeoutError(f"timed out waiting for {needle!r}")
            try:
                chunk = os.read(self.fd, 4096)
            except OSError as exc:
                if exc.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    def read_to_exit(self, timeout=20.0):
        data = bytearray()
        deadline = time.monotonic() + timeout

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("editor did not exit in time")
            ready, _, _ = select.select([self.fd], [], [], min(0.2, remaining))
            if ready:
                try:
                    chunk = os.read(self.fd, 4096)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                data.extend(chunk)
                continue

            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid == self.pid:
                self.closed = True
                os.close(self.fd)
                return bytes(data), status

        _, status = os.waitpid(self.pid, 0)
        self.closed = True
        os.close(self.fd)
        return bytes(data), status


def normalize_output(data):
    return data.decode("utf-8", "replace").replace("\r", "")


def extract_printed_lines(output_text):
    matches = []
    for line in output_text.splitlines():
        match = re.match(r"^\d+: (.*)$", line)
        if match:
            matches.append(match.group(1))
    return matches


def open_new_file(binary, path, password, env=None):
    session = EditorSession(binary, path, env=env)
    session.read_until("Password: ")
    session.send_line(password)
    session.read_until("Confirm Password: ")
    session.send_line(password)
    session.read_until("> ")
    return session


def open_existing_file(binary, path, password, env=None):
    session = EditorSession(binary, path, env=env)
    session.read_until("Password: ")
    session.send_line(password)
    session.read_until("> ")
    return session
