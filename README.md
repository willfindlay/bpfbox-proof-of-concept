# bpfbox Proof of Concept

Proof of concept for bpfbox permission model.

## Components

- Vulnerable Flask webserver (exposes a code injection attack on purpose)
- Pseudocode confinement policy for the webserver
- eBPF program to represent the confinement policy and enforce it

## As a Proof of Concept

- Figure out how we can get from the *pseudocode policy* to the *generated policy*
- And from the *generated* to the *final BPF program*

## Some Important Questions

- What does the compilation look like?
- What does the generation of the policy look like?
- How much user intervention do we require to get from a generated policy to the policy we describe here?
