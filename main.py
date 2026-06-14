#!/usr/bin/env python3
"""
Attack #5 — Stdout flood (resource exhaustion / integrity vector)

Writes gigabytes of data to stdout. run_tests.sh captures stdout into a shell
variable (`actual=$(...)`) using command substitution, which means the shell must
buffer the entire output in memory. This exhausts the VM's 256 MiB RAM just like
the memory exhaustion attack — but through the I/O path instead of direct allocation.

Additionally, even if the shell doesn't buffer (e.g. the output is redirected), the
volume of data through the vsock channel may exhaust the agent's vsock write buffer or
cause the result JSON to be silently truncated.

Expected result (both raw and nsjail):
  - Shell OOMs trying to buffer the output, or job timeout fires.
  - run_tests.sh never returns valid JSON.
  - Scheduler records the job as FAILED.
  - No neighbouring jobs are affected.

Note: nsjail shares the network namespace (-N) but does not restrict stdout/pipe
buffer sizes; behaviour is identical under both raw and nsjail modes.
"""

import sys

LINE = b"X" * 1023 + b"\n"  # ~1 KiB per line

def flood():
    print("Flooding stdout ...", flush=True)
    count = 0
    while True:
        sys.stdout.buffer.write(LINE)
        count += 1
        if count % 10000 == 0:
            sys.stdout.buffer.flush()

if __name__ == "__main__":
    flood()



    