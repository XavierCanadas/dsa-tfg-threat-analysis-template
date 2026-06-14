#!/usr/bin/env python3
"""
Attack #2 — Memory exhaustion (resource exhaustion vector)

Allocates memory in 32 MiB chunks until the VM's 256 MiB ceiling triggers the
Linux OOM killer, crashing the agent (PID 1) and destroying the VM.

Expected result (both raw and nsjail):
  - OOM killer fires, VM is destroyed.
  - run_tests.sh never returns its JSON result.
  - Scheduler records the job as FAILED.
  - No neighbouring jobs are affected (each job runs in an isolated VM).

Note: The VM has 256 MiB RAM total. The agent process and OS take ~50–80 MiB,
so allocating ~200 MiB in the student process is enough to push the VM over the edge.
nsjail has no --rlimit_as configured (limits were removed), so this attack behaves
identically under raw and nsjail modes.
"""

CHUNK_MB = 32
chunks = []

def exhaust():
    print(f"Allocating memory in {CHUNK_MB} MiB chunks until OOM ...", flush=True)
    allocated = 0
    while True:
        chunks.append(b"X" * (CHUNK_MB * 1024 * 1024))
        allocated += CHUNK_MB
        print(f"  allocated {allocated} MiB so far", flush=True)

if __name__ == "__main__":
    exhaust()



    