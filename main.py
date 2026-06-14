#!/usr/bin/env python3
"""
Attack #4 — CPU spin / infinite loop (resource exhaustion vector)

Runs a tight infinite loop consuming 100% of the single vCPU indefinitely.
This tests whether the outer job timeout in the agent (runner.go, default 60 s,
or the assignment's TimeoutSeconds) correctly terminates the grading job.

Expected result (both raw and nsjail):
  - The outer job timeout (set in runner.go / assignment config) fires.
  - run_tests.sh is killed; job is recorded as FAILED / TIMEOUT.
  - The VM is destroyed after the timeout.
  - No neighbouring jobs are affected.

This is notably different from the fork bomb: the process count stays at 1,
but the vCPU is saturated. The agent's own goroutines and the vsock listener are
still scheduled (on the same vCPU), so the timeout mechanism must be robust.

Note: nsjail has no --time_limit configured (limits were removed), so this attack
relies entirely on the outer job timeout in runner.go — same behaviour in both modes.
"""

def spin():
    print("Spinning forever on the vCPU ...", flush=True)
    while True:
        pass  # busy-wait, no yield

if __name__ == "__main__":
    spin()


    