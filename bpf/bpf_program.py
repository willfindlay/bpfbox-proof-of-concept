#! /usr/bin/env python3

import os, sys
import signal
import atexit
import time
import argparse
import stat
from textwrap import dedent

from bcc import BPF

from utils import run_binary, powerperm

WEBSERVER_PATH = "../webserver/webserver.py"
STATIC = "../webserver/static/"
GUESTBOOK = "../webserver/guestbook.txt"


class BPFBoxRules:
    def __init__(self):
        self.fs_read_rules = []
        self.fs_write_rules = []
        self.fs_append_rules = []
        self.fs_exec_rules = []

        self.generate_fs_rule('r', '/etc/host.conf')
        self.generate_fs_rule('r', '/usr/lib/python3.*/stringprep.py')
        self.generate_fs_rule('r', '/etc/resolv.conf')
        self.generate_fs_rule('r', '/etc/nsswitch.conf')
        self.generate_fs_rule('r', '/etc/ld.so.cache')
        self.generate_fs_rule('r', '/usr/lib/libnss_files*')
        self.generate_fs_rule('r', '/etc/hosts')
        self.generate_fs_rule('r', '/usr/lib/libgcc_s.*')
        self.generate_fs_rule(
            'r',
            '/usr/lib/python3.8/site-packages/jinja2/__pycache__/ext.cpython-38.pyc',
        )
        self.generate_fs_rule(
            'r',
            '/home/housedhorse/.local/share/virtualenvs/bpfbox-proof-of-'
            'concept-*/lib/python3.8/site-packages/jinja2/__pycache__/*',
        )
        self.generate_fs_rule('r', STATIC)
        # self.generate_fs_rule('rw', GUESTBOOK)
        self.generate_fs_rule('w', GUESTBOOK)

    def generate_fs_rule(self, mode, path):
        """
        Generate fs rule for mode + path.
        Mode is one of 'r', 'w', or 'rw'
        """
        from glob import glob

        assert mode in powerperm(['r', 'w', 'a', 'x'])

        paths = glob(path)

        # Compute rule based on path
        for path in paths:
            # Path is a directory
            if os.path.isdir(path):
                rule = f'parent_inode == {os.lstat(path)[stat.ST_INO]}'
            # Path is a file
            elif os.path.isfile(path):
                rule = f'inode == {os.lstat(path)[stat.ST_INO]}'

            if 'r' in mode:
                self.fs_read_rules.append(rule)

            if 'w' in mode:
                self.fs_write_rules.append(rule)

            if 'a' in mode:
                self.fs_append_rules.append(rule)

            if 'x' in mode:
                self.fs_exec_rules.append(rule)

    def generate_ipc_rule(self, mode, path=None, pids=None, tids=None):
        """
        Generate IPC rule for mode and one of path, pids, or tids.
        TODO: implement this, figure out what modes we need (like kill, etc.)
        """
        # TODO
        pass

    def apply_rules(self, text):
        """
        Generate and apply rules for the BPF program
        """
        text = text.replace(
            'FS_READ_RULES',
            ' || '.join(self.fs_read_rules) if self.fs_read_rules else '0',
        )

        text = text.replace(
            'FS_WRITE_RULES',
            ' || '.join(self.fs_write_rules) if self.fs_write_rules else '0',
        )

        text = text.replace(
            'FS_APPEND_RULES',
            ' || '.join(self.fs_append_rules) if self.fs_append_rules else '0',
        )

        text = text.replace(
            'FS_EXEC_RULES',
            ' || '.join(self.fs_exec_rules) if self.fs_exec_rules else '0',
        )

        return text

    def load_program(self, pid):
        """
        Load the BPF program and set any build flags.
        """
        with open("bpf_program.c", "r") as f:
            text = f.read()
        flags = [
            # The PID of the webserver
            f'-DTHE_PID={pid}',
            # Unknown attributes are okay
            '-Wno-unknown-attributes',
        ]
        text = self.apply_rules(text)
        return BPF(text=text, cflags=flags)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda x, y: sys.exit())
    signal.signal(signal.SIGTERM, lambda x, y: sys.exit())

    parser = argparse.ArgumentParser()
    # parser.add_argument(
    #    "-p", "--pid", required=1, type=int, help="The PID of webserver.py"
    # )
    args = parser.parse_args()

    # Check for root
    if os.geteuid() != 0:
        parser.error("Need superuser privileges to run")

    bpfbox = BPFBoxRules()

    try:
        pid = run_binary(f"python3 {WEBSERVER_PATH}")
        b = bpfbox.load_program(pid=pid)
        os.kill(pid, signal.SIGUSR1)
    except:
        os.kill(pid, signal.SIGKILL)
        sys.exit(-1)

    while 1:
        b.trace_print()
        time.sleep(0.1)
