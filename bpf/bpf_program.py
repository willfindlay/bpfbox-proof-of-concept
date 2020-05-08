import sys
import signal
import atexit
import time

from bcc import BPF

def load_program():
    with open('bpf_program.c', 'r') as f:
        text = f.read()
    return BPF(text=text)

def cleanup():
    pass

if __name__ == '__main__':
    signal.signal(signal.SIGINT, lambda x, y: sys.exit())
    signal.signal(signal.SIGTERM, lambda x, y: sys.exit())

    atexit.register(cleanup)

    b = load_program()

    while 1:
        time.sleep(0.1)
