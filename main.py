#!/usr/bin/env python3
"""
Attack #1 — Fork bomb (resource exhaustion / privilege escalation vector)

Spawns child processes recursively until the OS runs out of PIDs or the VM OOM-kills
everything. The goal is to crash the entire microVM.

Expected result (both raw and nsjail):
  - Firecracker VM is killed by the OOM killer or the outer job timeout fires.
  - run_tests.sh never returns its JSON result.
  - Scheduler records the job as FAILED / TIMEOUT.
  - No neighbouring jobs are affected (disposable VM, blast radius contained).

Note: nsjail adds a PID namespace but, with no --max_cpus / --rlimit_nproc, the fork
bomb still saturates the VM's process table. The only practical difference is that the
nsjail PID namespace may limit cross-namespace visibility — not the exhaustion itself.
"""

import os

def bomb():
    while True:
        os.fork()

if __name__ == "__main__":
    bomb()
    