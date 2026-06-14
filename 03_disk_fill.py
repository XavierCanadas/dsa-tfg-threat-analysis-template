#!/usr/bin/env python3
"""
Attack #3 — Disk fill (resource exhaustion / integrity vector)

Writes a large file to /tmp (writable in both raw and nsjail modes) until the
VM's root filesystem fills up, causing all subsequent writes to fail — including
the agent's attempt to write the job result.

Expected result (both raw and nsjail):
  - Filesystem fills up; agent cannot write the JSON result to vsock.
  - Scheduler records the job as FAILED / TIMEOUT.
  - No neighbouring jobs are affected (each job has its own per-job rootfs copy).

Firecracker I/O rate limiter: 512 MiB/s throughput, 4000 IOPS — so the disk fill
completes quickly. The rootfs image size on disk determines the cap; typically ~1–2 GiB.

Note: in nsjail mode, /tmp is writable (-B /tmp flag in run_student.sh). Writing to
the student's cwd ($PWD) is also writable (-B "$PWD"). Both paths are targets.
"""

import os
import sys

WRITE_PATH = "/tmp/disk_fill_attack"
CHUNK = b"A" * (1024 * 1024)  # 1 MiB per write

def fill():
    print(f"Writing to {WRITE_PATH} until disk is full ...", flush=True)
    written_mb = 0
    try:
        with open(WRITE_PATH, "wb") as f:
            while True:
                f.write(CHUNK)
                written_mb += 1
                if written_mb % 100 == 0:
                    print(f"  written {written_mb} MiB", flush=True)
    except OSError as e:
        print(f"Write failed after {written_mb} MiB: {e}", flush=True)
        sys.exit(1)

if __name__ == "__main__":
    fill()
