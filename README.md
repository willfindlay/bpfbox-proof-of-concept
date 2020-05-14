# 🐝 BPFBox 📦 Proof of Concept

Proof of concept for bpfbox permission model.

## Instructions

**WARNING: It is recommended that you do not try the demo on your own machine. If something goes wrong, the demo has the potential to kill arbitrary processes on your system.** It is recommended to run this demo in a VM.

To try the demo do the following:

1. Clone this repo
2. Run `sudo python3 bpf/bpf_program.py`. It will fork itself and execute the webserver automatically.
3. Go to `localhost:8080` and fill out the form to sign the guestbook.
4. To run the backdoor, enter `testificate <shell command here>`.
5. bpfbox will kill the child process before it can execute the shell command.
6. If you have any problems with the pre-generated policy, you can edit the rules in `__init__` in `bpf_program.py`
7. If you want to see behavior without bpfbox, just run `webserver.py` on its own.

## Warning:

Do not run webserver.py on your own system. It is designed to be extremely insecure.

Running it while bpf_program.py is running should actually be fine, but I do not make any guarantees. Exercise caution.

## Components

- Vulnerable Flask webserver (with a backdoor that we want to defend against)
- Pseudocode confinement policy for the webserver
- eBPF program to represent the confinement policy and enforce it

## As a Proof of Concept

- Figure out how we can get from the *pseudocode policy* to the *generated policy*
- And from the *generated/user-modified policy* to the *final BPF program*

## Some Important Questions

- What does the compilation look like?
- What does the generation of the policy look like?
- How much user intervention do we require to get from a generated policy to the policy we describe here?

## Another Potential Approach

- Have a few default modes
    - unrestricted
    - app directories
    - isolated app
    - custom restricted (this is where we specify custom rules)
- Transition between these states using mode rules
