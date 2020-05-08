# 🐝 BPFBox 📦 Proof of Concept

Proof of concept for bpfbox permission model.

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
