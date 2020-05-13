#! /usr/bin/env python3

import os
import sys
import signal
import atexit
import time
import argparse

from bcc import BPF

from utils import drop_privileges, which

WEBSERVER_PATH = "../webserver/webserver.py"


def load_program(pid):
    """
    Load the BPF program and set any build flags.
    """
    with open("bpf_program.c", "r") as f:
        text = f.read()
    flags = [f"-DTHE_PID={pid}"]
    return BPF(text=text, cflags=flags)


def cleanup():
    """
    Run any necessary cleanup.
    """
    pass


@drop_privileges
def run_binary(args_str):
    # Wake up and do nothing on SIGCLHD
    signal.signal(signal.SIGUSR1, lambda x, y: None)
    # Reap zombies
    signal.signal(signal.SIGCHLD, lambda x, y: os.wait())
    args = args_str.split()
    binary = which(args[0])
    pid = os.fork()
    # Setup traced process
    if pid == 0:
        signal.pause()
        os.execvp(binary, args)
    # Return pid of traced process
    return pid


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

    atexit.register(cleanup)

    pid = run_binary(f"python3 {WEBSERVER_PATH}")
    b = load_program(pid=pid)
    os.kill(pid, signal.SIGUSR1)

    while 1:
        b.trace_print()
        time.sleep(0.1)
