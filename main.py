#!/usr/bin/env python3
"""
Recon payload — batched non-fatal probes #6–#15 (thesis §4.2)

Each probe attempts one boundary violation, catches any exception, and prints a
single structured line to stdout:

    PROBE <name>: BLOCKED [<optional detail>]
    PROBE <name>: LEAKED  <evidence>

The caller (run_tests.sh) parses these lines into JSON test entries:
  BLOCKED → PASSED (isolation held)
  LEAKED  → FAILED (boundary violated)

The probes never crash the VM — every attempt is wrapped in a try/except.
If Python itself lacks the required module (e.g. socket for vsock), the probe
reports BLOCKED with the reason.

Probe list
----------
 6  read_teacher_repo     — read a file from /repos/teacher (inner boundary)
 7  read_os_secrets       — read /etc/shadow and /etc/passwd
 8  git_token_residue     — read .git/config for both repos for embedded tokens
 9  filesystem_enum       — enumerate /repos to discover sibling files
10  write_os_files        — write to /etc/hacked (read-only filesystem probe)
11  internet_egress       — HTTP GET to an external host (ifconfig.me)
12  api_endpoint          — HTTP GET to the API job-queue URL (no auth → 401 expected, proves reach)
13  lateral_movement      — TCP connect to gateway 172.20.0.1:22 and :80
14  vsock_channel         — AF_VSOCK connect to CID 3 port 52 (scheduler channel)
15  privilege_probe       — uid/gid, /proc/self/status, /proc/self/loginuid, Linux capabilities
"""

from __future__ import annotations

import os
import sys
import subprocess
import traceback

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def report(name: str, blocked: bool, detail: str = "") -> None:
    tag = "BLOCKED" if blocked else "LEAKED"
    line = f"PROBE {name}: {tag}"
    if detail:
        line += f" {detail}"
    print(line, flush=True)


def try_read(path: str) -> tuple[bool, str]:
    """Return (success, content_snippet)."""
    try:
        with open(path, "r", errors="replace") as f:
            content = f.read(200)
        return True, content.replace("\n", "\\n")[:120]
    except Exception as e:
        return False, str(e)


def try_connect_tcp(host: str, port: int, timeout: float = 3.0) -> tuple[bool, str]:
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True, f"connected to {host}:{port}"
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# Probe 6 — Read teacher hidden tests (/repos/teacher)
# ---------------------------------------------------------------------------
def probe_read_teacher_repo() -> None:
    name = "read_teacher_repo"
    targets = [
        "/repos/teacher",
        "/repos/teacher/run_tests.sh",
        "/repos/teacher/tests",
    ]
    for path in targets:
        ok, content = try_read(path)
        if ok:
            report(name, blocked=False, detail=f"read {path}: {content[:80]}")
            return
    # Also try listing the directory
    try:
        entries = os.listdir("/repos/teacher")
        report(name, blocked=False, detail=f"listed /repos/teacher: {entries[:5]}")
    except Exception:
        report(name, blocked=True, detail="cannot read or list /repos/teacher")


# ---------------------------------------------------------------------------
# Probe 7 — Read OS secrets (/etc/shadow, /etc/passwd)
# ---------------------------------------------------------------------------
def probe_read_os_secrets() -> None:
    name = "read_os_secrets"
    ok_shadow, content_shadow = try_read("/etc/shadow")
    if ok_shadow:
        report(name, blocked=False, detail=f"/etc/shadow readable: {content_shadow[:60]}")
        return
    ok_passwd, content_passwd = try_read("/etc/passwd")
    if ok_passwd:
        # /etc/passwd is world-readable by design; count lines to confirm real content
        try:
            lines = open("/etc/passwd").readlines()
            if len(lines) > 1:
                report(name, blocked=False, detail=f"/etc/passwd has {len(lines)} entries (shadow not readable)")
                return
        except Exception:
            pass
    report(name, blocked=True, detail="/etc/shadow not readable, /etc/passwd empty or blocked")


# ---------------------------------------------------------------------------
# Probe 8 — GitHub token residue in .git/config
# ---------------------------------------------------------------------------
def probe_git_token_residue() -> None:
    name = "git_token_residue"
    repo_dirs = ["/repos/student", "/repos/teacher"]
    # Also try relative paths (in case cwd is the student repo)
    cwd = os.getcwd()
    repo_dirs.extend([cwd, os.path.join(cwd, "..")])

    token_indicators = ["x-access-token", "oauth", "token", "ghp_", "ghs_"]

    for base in repo_dirs:
        git_config = os.path.join(base, ".git", "config")
        ok, content = try_read(git_config)
        if not ok:
            continue
        lower = content.lower()
        for indicator in token_indicators:
            if indicator in lower:
                report(name, blocked=False, detail=f"token indicator '{indicator}' in {git_config}: {content[:80]}")
                return

    report(name, blocked=True, detail="no token found in any .git/config")


# ---------------------------------------------------------------------------
# Probe 9 — Filesystem enumeration (discover sibling repos/files)
# ---------------------------------------------------------------------------
def probe_filesystem_enum() -> None:
    name = "filesystem_enum"
    interesting = []
    scan_roots = ["/repos", "/home", "/root", "/var/lib", "/srv"]
    for root in scan_roots:
        try:
            for entry in os.scandir(root):
                interesting.append(entry.path)
        except Exception:
            continue

    if interesting:
        report(name, blocked=False, detail=f"enumerated paths: {interesting[:8]}")
    else:
        report(name, blocked=True, detail="cannot enumerate /repos, /home, /root, /var/lib, /srv")


# ---------------------------------------------------------------------------
# Probe 10 — Write OS files (/etc/hacked, /usr/local/bin/hacked)
# ---------------------------------------------------------------------------
def probe_write_os_files() -> None:
    name = "write_os_files"
    targets = ["/etc/hacked_by_student", "/usr/local/bin/hacked_by_student", "/bin/hacked_by_student"]
    for path in targets:
        try:
            with open(path, "w") as f:
                f.write("pwned\n")
            os.unlink(path)
            report(name, blocked=False, detail=f"wrote and deleted {path} — filesystem is writable!")
            return
        except Exception:
            continue
    report(name, blocked=True, detail="all write targets blocked (read-only filesystem or permission denied)")


# ---------------------------------------------------------------------------
# Probe 11 — Internet egress (HTTP GET to external host)
# ---------------------------------------------------------------------------
def probe_internet_egress() -> None:
    name = "internet_egress"
    # Try urllib first (no external deps); curl as fallback
    try:
        import urllib.request
        req = urllib.request.Request(
            "http://ifconfig.me/ip",
            headers={"User-Agent": "thesis-threat-probe/1.0"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read(100).decode().strip()
        report(name, blocked=False, detail=f"external IP visible: {body}")
        return
    except Exception as e1:
        pass

    # curl fallback
    try:
        result = subprocess.run(
            ["curl", "-s", "--max-time", "5", "http://ifconfig.me/ip"],
            capture_output=True, text=True, timeout=8
        )
        if result.returncode == 0 and result.stdout.strip():
            report(name, blocked=False, detail=f"curl external IP: {result.stdout.strip()[:60]}")
            return
    except Exception:
        pass

    report(name, blocked=True, detail="no internet egress (urllib and curl both failed)")





# ---------------------------------------------------------------------------
# Probe 12 — Reach API job-queue endpoint
# ---------------------------------------------------------------------------
def probe_api_endpoint() -> None:
    name = "api_endpoint"
    # The API lives behind Tailscale/nginx. Try to discover the gateway and probe
    # known ports. A 401 or 403 means we REACHED it (auth blocks, not network).
    # Construct candidate URLs from the Tailscale / local network.
    candidates = []

    # Try to read the scheduler env for API_BASE_URL (unlikely to be in the VM, but worth checking)
    api_url_from_env = os.environ.get("API_BASE_URL", "")
    if api_url_from_env:
        candidates.append(api_url_from_env.rstrip("/") + "/jobs/next")

    # Common Tailscale and private ranges
    gateway_candidates = ["167.172.35.200", "10.110.16.3", "100.74.170.91"]
    for gw in gateway_candidates:
        candidates.append(f"http://{gw}:8080/jobs/next")
        candidates.append(f"https://{gw}/jobs/next")

    for url in candidates:
        try:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "thesis-threat-probe/1.0"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                status = resp.status
                report(name, blocked=False, detail=f"API reachable at {url} → HTTP {status}")
                return
        except Exception as e:
            err_str = str(e)
            # HTTP 401/403/404 means the endpoint is reachable; network errors mean blocked
            if any(code in err_str for code in ["401", "403", "404", "HTTP Error"]):
                report(name, blocked=False, detail=f"API reachable at {url} (HTTP error = network OK): {err_str[:80]}")
                return

    report(name, blocked=True, detail="API endpoint unreachable from all candidate URLs")


# ---------------------------------------------------------------------------
# Probe 13 — Lateral movement (scan gateway and VM subnet)
# ---------------------------------------------------------------------------
def probe_lateral_movement() -> None:
    name = "lateral_movement"
    # Probe gateway ports on 172.20.0.1 (the CNI network gateway per fcnet.conflist.j2)
    targets = [
        ("172.20.0.1", 22),
        ("172.20.0.1", 80),
        ("172.20.0.1", 443),
        ("172.20.0.1", 8080),
    ]
    for host, port in targets:
        ok, detail = try_connect_tcp(host, port, timeout=2.0)
        if ok:
            report(name, blocked=False, detail=detail)
            return

    report(name, blocked=True, detail="cannot reach gateway 172.20.0.1 on ports 22/80/443/8080")


# ---------------------------------------------------------------------------
# Probe 14 — Vsock channel (scheduler ↔ agent, CID 3 / port 52)
# ---------------------------------------------------------------------------
def probe_vsock_channel() -> None:
    name = "vsock_channel"
    # AF_VSOCK = 40 on Linux; socket.AF_VSOCK may not be defined in all Python builds
    try:
        import socket
        AF_VSOCK = getattr(socket, "AF_VSOCK", 40)
        VMADDR_CID_HOST = 2   # host CID (scheduler side)
        VSOCK_PORT = 52
        s = socket.socket(AF_VSOCK, socket.SOCK_STREAM)  # type: ignore[attr-defined]
        s.settimeout(4.0)
        s.connect((VMADDR_CID_HOST, VSOCK_PORT))
        # If we get here we have an open vsock connection — try to send a forged result
        import json
        fake = json.dumps({
            "job_id": "forged",
            "status": "SUCCESS",
            "tests": [{"name": "forged_test", "status": "PASSED", "execution_time_ms": 1}],
            "execution_time_ms": 1
        })
        s.sendall((fake + "\n").encode())
        s.close()
        report(name, blocked=False, detail="connected to vsock CID=2 port=52 and sent forged JobResult")
    except Exception as e:
        # Also try CID 3 (the host may present as CID 3 from inside the guest)
        try:
            import socket
            AF_VSOCK = getattr(socket, "AF_VSOCK", 40)
            s = socket.socket(AF_VSOCK, socket.SOCK_STREAM)  # type: ignore[attr-defined]
            s.settimeout(4.0)
            s.connect((3, 52))
            s.close()
            report(name, blocked=False, detail="connected to vsock CID=3 port=52")
        except Exception as e2:
            report(name, blocked=True, detail=f"vsock connect failed: {e2}")


# ---------------------------------------------------------------------------
# Probe 15 — Privilege probe (uid, capabilities, nsjail indicators)
# ---------------------------------------------------------------------------
def probe_privilege() -> None:
    name = "privilege_probe"
    uid = os.getuid()
    gid = os.getgid()
    details = [f"uid={uid} gid={gid}"]

    # Is the process root?
    is_root = (uid == 0)
    if is_root:
        details.append("RUNNING AS ROOT")

    # Read /proc/self/status for capability sets
    ok_status, status_content = try_read("/proc/self/status")
    if ok_status:
        for line in status_content.replace("\\n", "\n").splitlines():
            if line.startswith("Cap"):
                details.append(line.strip())

    # Check if we can read /proc/1/environ (agent PID 1 environment — contains secrets if any)
    ok_env, env_content = try_read("/proc/1/environ")
    if ok_env:
        details.append(f"read /proc/1/environ ({len(env_content)} bytes)")

    # Check /proc/self/loginuid
    ok_uid, login_uid = try_read("/proc/self/loginuid")
    if ok_uid:
        details.append(f"loginuid={login_uid.strip()}")

    detail_str = " | ".join(details)
    # "LEAKED" if root or if we can read /proc/1/environ
    leaked = is_root or ok_env
    report(name, blocked=not leaked, detail=detail_str)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
PROBES = [
    ("read_teacher_repo",    probe_read_teacher_repo),
    ("read_os_secrets",      probe_read_os_secrets),
    ("git_token_residue",    probe_git_token_residue),
    ("filesystem_enum",      probe_filesystem_enum),
    ("write_os_files",       probe_write_os_files),
    ("internet_egress",      probe_internet_egress),
    ("api_endpoint",         probe_api_endpoint),
    ("lateral_movement",     probe_lateral_movement),
    ("vsock_channel",        probe_vsock_channel),
    ("privilege_probe",      probe_privilege),
]

if __name__ == "__main__":
    print("=== Security Threat Recon Payload (thesis §4.2) ===", flush=True)
    print(f"Running as uid={os.getuid()} gid={os.getgid()}", flush=True)
    print("", flush=True)
    for probe_name, probe_fn in PROBES:
        try:
            probe_fn()
        except Exception:
            print(f"PROBE {probe_name}: ERROR (unhandled exception)", flush=True)
            traceback.print_exc(file=sys.stderr)
    print("", flush=True)
    print("=== Recon complete ===", flush=True)



    