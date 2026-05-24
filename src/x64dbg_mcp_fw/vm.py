"""VMware Workstation/Player lifecycle and guest-IO via `vmrun`.

We deliberately keep this thin: each function maps to one `vmrun` subcommand.
Higher-level recipes (revert -> start -> wait-for-plugin -> drop sample) live
in `recipes.py` so they can be tested separately.

Env vars consulted (see config.py):
    VMRUN_PATH        Full path to vmrun.exe. Required.
    VMX_PATH          Default .vmx file. Per-call override always wins.
    VM_GUEST_USER     Guest OS account used for copy/run.
    VM_GUEST_PASS     Guest OS password.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .config import Config


class VmrunMissing(RuntimeError):
    pass


class VmrunError(RuntimeError):
    def __init__(self, cmd: list[str], code: int, stdout: str, stderr: str):
        self.cmd = cmd
        self.code = code
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(
            f"vmrun {' '.join(cmd[1:3])} failed (exit {code}): "
            f"{stderr.strip() or stdout.strip()}"
        )


@dataclass
class VmResult:
    ok: bool
    stdout: str
    stderr: str
    duration_s: float


def _vmrun_path(cfg: Config) -> str:
    if not cfg.vmrun_path:
        raise VmrunMissing(
            "VMRUN_PATH is not set. Point it at vmrun.exe — typically "
            r"'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'."
        )
    return cfg.vmrun_path


def _resolve_vmx(cfg: Config, vmx: str | None) -> str:
    chosen = vmx or cfg.vmx_path
    if not chosen:
        raise ValueError("No .vmx path given and VMX_PATH env var is unset.")
    p = Path(chosen).expanduser()
    if not p.exists():
        raise FileNotFoundError(f".vmx file not found: {p}")
    return str(p)


def _run(cfg: Config, args: list[str], timeout: float = 120.0) -> VmResult:
    cmd = [_vmrun_path(cfg), "-T", "ws"] + args
    t0 = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    dur = time.monotonic() - t0
    if proc.returncode != 0:
        raise VmrunError(cmd, proc.returncode, proc.stdout, proc.stderr)
    return VmResult(True, proc.stdout, proc.stderr, dur)


# ---- Power state ----------------------------------------------------------

def start(cfg: Config, vmx: str | None = None, gui: bool = True) -> VmResult:
    return _run(cfg, ["start", _resolve_vmx(cfg, vmx), "gui" if gui else "nogui"])


def stop(cfg: Config, vmx: str | None = None, hard: bool = False) -> VmResult:
    return _run(cfg, ["stop", _resolve_vmx(cfg, vmx), "hard" if hard else "soft"])


def reset(cfg: Config, vmx: str | None = None, hard: bool = False) -> VmResult:
    return _run(cfg, ["reset", _resolve_vmx(cfg, vmx), "hard" if hard else "soft"])


# ---- Snapshots ------------------------------------------------------------

def list_snapshots(cfg: Config, vmx: str | None = None) -> list[str]:
    res = _run(cfg, ["listSnapshots", _resolve_vmx(cfg, vmx)])
    # First line is "Total snapshots: N", rest are names.
    lines = [ln for ln in res.stdout.splitlines() if ln.strip()]
    return lines[1:] if lines else []


def create_snapshot(cfg: Config, name: str, vmx: str | None = None) -> VmResult:
    return _run(cfg, ["snapshot", _resolve_vmx(cfg, vmx), name])


def revert(cfg: Config, snapshot_name: str, vmx: str | None = None) -> VmResult:
    return _run(cfg, ["revertToSnapshot", _resolve_vmx(cfg, vmx), snapshot_name])


def delete_snapshot(cfg: Config, name: str, vmx: str | None = None) -> VmResult:
    return _run(cfg, ["deleteSnapshot", _resolve_vmx(cfg, vmx), name])


# ---- Guest IO -------------------------------------------------------------

def _guest_creds(cfg: Config) -> list[str]:
    if not cfg.guest_user or cfg.guest_password is None:
        raise ValueError(
            "Guest credentials missing. Set VM_GUEST_USER and VM_GUEST_PASS, "
            "or the guest-IO tools will fail."
        )
    return ["-gu", cfg.guest_user, "-gp", cfg.guest_password]


def copy_to_guest(
    cfg: Config, host_path: str, guest_path: str, vmx: str | None = None
) -> VmResult:
    return _run(
        cfg,
        _guest_creds(cfg)
        + ["copyFileFromHostToGuest", _resolve_vmx(cfg, vmx), host_path, guest_path],
    )


def copy_from_guest(
    cfg: Config, guest_path: str, host_path: str, vmx: str | None = None
) -> VmResult:
    return _run(
        cfg,
        _guest_creds(cfg)
        + ["copyFileFromGuestToHost", _resolve_vmx(cfg, vmx), guest_path, host_path],
    )


def run_in_guest(
    cfg: Config,
    program: str,
    args: list[str] | None = None,
    vmx: str | None = None,
    interactive: bool = False,
    no_wait: bool = False,
) -> VmResult:
    flags: list[str] = []
    if interactive:
        flags.append("-interactive")
    if no_wait:
        flags.append("-noWait")
    return _run(
        cfg,
        _guest_creds(cfg)
        + ["runProgramInGuest", _resolve_vmx(cfg, vmx)]
        + flags
        + [program]
        + (args or []),
        timeout=600.0,
    )


def vm_state(cfg: Config, vmx: str | None = None) -> str:
    """Return 'running' if the given vmx is among `vmrun list`, else 'stopped'."""
    res = _run(cfg, ["list"])
    target = str(Path(_resolve_vmx(cfg, vmx)).resolve()).lower()
    for ln in res.stdout.splitlines():
        if ln.strip().lower() == target:
            return "running"
    return "stopped"
