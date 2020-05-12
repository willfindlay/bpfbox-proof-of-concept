import os
import sys
import signal
import atexit
import time
import argparse

from bcc import BPF


def load_program(args):
    """
    Load the BPF program and set any build flags.
    """
    with open("bpf_program.c", "r") as f:
        text = f.read()
    flags = [f"-DTHE_PID={args.pid}"]
    return BPF(text=text, cflags=flags)


def cleanup():
    pass


if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda x, y: sys.exit())
    signal.signal(signal.SIGTERM, lambda x, y: sys.exit())

    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pid", required=1, help="The PID of webserver.py")
    args = parser.parse_args()

    # Check for root
    # if not os.

    atexit.register(cleanup)

    b = load_program(args)

    while 1:
        time.sleep(0.1)
