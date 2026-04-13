#!/usr/bin/env python3
import os
import signal
import sys
import tempfile

from common_pty import EditorSession, extract_printed_lines, normalize_output, open_existing_file, open_new_file


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: recovery_backup.py /path/to/eed")

    binary = os.path.abspath(sys.argv[1])
    password = "recovery-password"

    with tempfile.TemporaryDirectory(prefix="eed-recovery-") as tempdir:
        path = os.path.join(tempdir, "session.eed")
        backup_path = path + ".bak"
        recovery_path = path + ".recovery"

        session = open_new_file(binary, path, password)
        session.send_line("a")
        session.read_until("Enter lines, single '.' on line to finish:")
        session.send_line("recover me")
        session.send_line(".")
        session.read_until("> ")

        if not os.path.exists(recovery_path):
            raise AssertionError("recovery snapshot was not created after a mutation")

        os.kill(session.pid, signal.SIGKILL)
        _, status = session.read_to_exit()
        if not os.WIFSIGNALED(status):
            raise AssertionError(f"expected signal exit, got {status}")

        session = open_new_file(binary, path, password)
        session.send_line("p")
        output = normalize_output(session.read_until("> ", timeout=60.0))
        if extract_printed_lines(output) != ["recover me"]:
            raise AssertionError(output)
        session.send_line("w")
        output = normalize_output(session.read_until("> ", timeout=60.0))
        if "File written." not in output:
            raise AssertionError(output)
        session.send_line("q")
        _, status = session.read_to_exit()
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise AssertionError(f"unexpected exit status after recovery save: {status}")

        session = open_existing_file(binary, path, password)
        session.send_line("c")
        session.read_until("Change line number: ")
        session.send_line("1")
        session.read_until("New line: ")
        session.send_line("latest version")
        session.read_until("> ")
        session.send_line("w")
        output = normalize_output(session.read_until("> ", timeout=60.0))
        if "File written." not in output:
            raise AssertionError(output)
        session.send_line("q")
        _, status = session.read_to_exit()
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise AssertionError(f"unexpected exit status after latest save: {status}")

        if not os.path.exists(backup_path):
            raise AssertionError("backup file was not created")

        session = open_existing_file(binary, backup_path, password)
        session.send_line("p")
        output = normalize_output(session.read_until("> ", timeout=60.0))
        if extract_printed_lines(output) != ["latest version"]:
            raise AssertionError(f"backup did not mirror the latest committed file: {output}")
        session.send_line("q")
        _, status = session.read_to_exit()
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise AssertionError(f"unexpected exit status reading backup: {status}")

        with open(path, "wb") as handle:
            handle.write(os.urandom(128))

        session = open_existing_file(binary, path, password)
        session.send_line("p")
        output = normalize_output(session.read_until("> ", timeout=60.0))
        if extract_printed_lines(output) != ["latest version"]:
            raise AssertionError(f"backup recovery did not restore the latest saved state: {output}")
        session.send_line("q")
        _, status = session.read_to_exit()
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise AssertionError(f"unexpected exit status after backup recovery: {status}")

        session = open_existing_file(binary, path, password)
        session.send_line("p")
        output = normalize_output(session.read_until("> ", timeout=60.0))
        if extract_printed_lines(output) != ["latest version"]:
            raise AssertionError(f"backup-restored state was not recoverable after quit: {output}")
        session.send_line("q")
        _, status = session.read_to_exit()
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise AssertionError(f"unexpected exit status after reopening backup-restored state: {status}")

        overlay_path = os.path.join(tempdir, "overlay.eed")
        overlay_backup_path = overlay_path + ".bak"
        overlay_recovery_path = overlay_path + ".recovery"

        session = open_new_file(binary, overlay_path, password)
        session.send_line("a")
        session.read_until("Enter lines, single '.' on line to finish:")
        session.send_line("committed line")
        session.send_line(".")
        session.read_until("> ")
        session.send_line("w")
        output = normalize_output(session.read_until("> ", timeout=60.0))
        if "File written." not in output:
            raise AssertionError(output)
        session.send_line("q")
        _, status = session.read_to_exit()
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise AssertionError(f"unexpected exit status after creating overlay file: {status}")

        if not os.path.exists(overlay_backup_path):
            raise AssertionError("overlay backup file was not created")

        session = open_existing_file(binary, overlay_path, password)
        session.send_line("c")
        session.read_until("Change line number: ")
        session.send_line("1")
        session.read_until("New line: ")
        session.send_line("backup plus recovery")
        session.read_until("> ")

        if not os.path.exists(overlay_recovery_path):
            raise AssertionError("overlay recovery snapshot was not created after an unsaved change")

        os.kill(session.pid, signal.SIGKILL)
        _, status = session.read_to_exit()
        if not os.WIFSIGNALED(status):
            raise AssertionError(f"expected overlay session to be killed, got {status}")

        with open(overlay_path, "wb") as handle:
            handle.write(os.urandom(128))

        session = open_existing_file(binary, overlay_path, password)
        session.send_line("p")
        output = normalize_output(session.read_until("> ", timeout=60.0))
        if extract_printed_lines(output) != ["backup plus recovery"]:
            raise AssertionError(f"backup+recovery restore did not recover the newest edits: {output}")
        session.send_line("q")
        _, status = session.read_to_exit()
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise AssertionError(f"unexpected exit status after backup+recovery restore: {status}")

        session = open_existing_file(binary, overlay_path, password)
        session.send_line("p")
        output = normalize_output(session.read_until("> ", timeout=60.0))
        if extract_printed_lines(output) != ["backup plus recovery"]:
            raise AssertionError(f"backup+recovery restored state was not recoverable after quit: {output}")
        session.send_line("q")
        _, status = session.read_to_exit()
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise AssertionError(f"unexpected exit status after reopening backup+recovery state: {status}")

    print("recovery-backup-ok")


if __name__ == "__main__":
    main()
