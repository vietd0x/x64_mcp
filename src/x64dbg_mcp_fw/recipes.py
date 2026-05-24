"""Multi-step orchestrations that span vmrun + ZMQ connection.

`prepare_session` is the canonical one: get from "clean snapshot on disk" to
"x64dbg running in VM, plugin reachable from host, sample on guest disk" in a
single call. Designed to fail fast and loud — every step's status appears in
the returned dict so the agent can decide what to do next.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from x64dbg_automate import X64DbgClient

from .config import Config
from .session import remote_client
from . import vm


@dataclass
class StepResult:
    name: str
    ok: bool
    detail: str = ""
    duration_s: float = 0.0


@dataclass
class SessionPrep:
    ok: bool
    steps: list[StepResult] = field(default_factory=list)
    guest_sample_path: str | None = None


def _wait_for_plugin(cfg: Config, timeout_s: float, poll_s: float) -> StepResult:
    t0 = time.monotonic()
    last_err = ""
    while time.monotonic() - t0 < timeout_s:
        try:
            with remote_client(cfg) as client:
                _ = client.get_debugger_version()
            return StepResult(
                "wait_for_plugin", True, "plugin reachable",
                duration_s=time.monotonic() - t0,
            )
        except Exception as e:
            last_err = str(e)
            time.sleep(poll_s)
    return StepResult(
        "wait_for_plugin", False,
        f"plugin not reachable after {timeout_s:.0f}s: {last_err}",
        duration_s=time.monotonic() - t0,
    )


def prepare_session(
    cfg: Config,
    *,
    snapshot_name: str,
    sample_host_path: str | None = None,
    sample_guest_path: str | None = None,
    vmx: str | None = None,
    boot_timeout_s: float = 120.0,
    poll_s: float = 3.0,
) -> SessionPrep:
    """Revert -> start -> wait-for-plugin -> drop sample.

    Stops at the first failure and returns whatever it did. Caller inspects
    `steps` to see where it died.
    """
    out = SessionPrep(ok=True)

    def step(name: str, fn):
        t0 = time.monotonic()
        try:
            detail = fn() or ""
            out.steps.append(StepResult(name, True, detail, time.monotonic() - t0))
            return True
        except Exception as e:
            out.steps.append(StepResult(name, False, str(e), time.monotonic() - t0))
            out.ok = False
            return False

    if not step("revert", lambda: vm.revert(cfg, snapshot_name, vmx).stdout.strip()):
        return out

    if not step("start", lambda: vm.start(cfg, vmx, gui=True).stdout.strip()):
        return out

    plugin = _wait_for_plugin(cfg, boot_timeout_s, poll_s)
    out.steps.append(plugin)
    if not plugin.ok:
        out.ok = False
        return out

    if sample_host_path and sample_guest_path:
        if not step(
            "copy_to_guest",
            lambda: vm.copy_to_guest(cfg, sample_host_path, sample_guest_path, vmx).stdout.strip(),
        ):
            return out
        out.guest_sample_path = sample_guest_path

    return out


def cleanup_session(
    cfg: Config,
    *,
    snapshot_name: str | None = None,
    vmx: str | None = None,
    hard: bool = True,
) -> SessionPrep:
    """Power off the VM and optionally revert. Use after each sample."""
    out = SessionPrep(ok=True)

    def step(name: str, fn):
        t0 = time.monotonic()
        try:
            detail = fn() or ""
            out.steps.append(StepResult(name, True, detail, time.monotonic() - t0))
            return True
        except Exception as e:
            out.steps.append(StepResult(name, False, str(e), time.monotonic() - t0))
            out.ok = False
            return False

    state = vm.vm_state(cfg, vmx)
    if state == "running":
        step("stop", lambda: vm.stop(cfg, vmx, hard=hard).stdout.strip())

    if snapshot_name:
        step("revert", lambda: vm.revert(cfg, snapshot_name, vmx).stdout.strip())

    return out
