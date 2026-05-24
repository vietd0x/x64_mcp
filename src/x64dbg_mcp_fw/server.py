"""FastMCP server exposing x64dbg-skills as MCP tools.

Connects to a remote x64dbg-automate plugin (default 127.0.0.1:50000/50001).
Pair this with the upstream `x64dbg-automate-mcp` server in your MCP config —
that one exposes the debugger primitives (read_memory, set_breakpoint, ...);
this one exposes the higher-level skills (snapshot, diff, yara, decompile, ...).
"""

from __future__ import annotations

from dataclasses import asdict

from mcp.server.fastmcp import FastMCP

from . import recipes, skills as static_skills, vm as vmrun
from .config import load as load_config
from .session import remote_client
from .snapshot import take_snapshot

mcp = FastMCP("x64dbg-mcp-fw")


@mcp.tool()
def get_config() -> dict:
    """Return the framework's current configuration (host, ports, paths, vmrun)."""
    cfg = load_config()
    return {
        "vm_host": cfg.vm_host,
        "vm_req_port": cfg.vm_req_port,
        "vm_pub_port": cfg.vm_pub_port,
        "skills_dir": str(cfg.skills_dir) if cfg.skills_dir else None,
        "x64dbg_path": cfg.x64dbg_path,
        "artifact_dir": str(cfg.artifact_dir),
        "vmrun_path": cfg.vmrun_path,
        "vmx_path": cfg.vmx_path,
        "guest_user": cfg.guest_user,
        "guest_password_set": bool(cfg.guest_password),
    }


@mcp.tool()
def ping_vm() -> dict:
    """Verify the framework can reach x64dbg-automate inside the VM.

    Connects, reads the debugger status, disconnects. Use this after VM boot to
    confirm the ZMQ plugin is bound and reachable on the configured host:ports.
    """
    cfg = load_config()
    with remote_client(cfg) as client:
        # get_debugger_version() is the lightest round-trip that proves the
        # ZMQ link + plugin are alive (works even with no debuggee loaded).
        version = client.get_debugger_version()
        debugging = client.is_debugging()
        return {
            "ok": True,
            "x64dbg_version": version,
            "is_debugging": debugging,
            "debuggee_pid": client.debugee_pid() if debugging else None,
        }


@mcp.tool()
def state_snapshot(name: str | None = None) -> dict:
    """Capture a full live snapshot (registers + committed memory) from the VM.

    Writes to `$X64DBG_ARTIFACT_DIR/snapshots/<name-or-timestamp>/`.
    Returns the snapshot directory path plus counts — feed that path back into
    `state_diff`, `yara_scan`, `enum_imports`, or `find_xrefs`.
    """
    cfg = load_config()
    cfg.artifact_dir.mkdir(parents=True, exist_ok=True)
    with remote_client(cfg) as client:
        return take_snapshot(client, cfg.artifact_dir, name)


@mcp.tool()
def state_diff(before_dir: str, after_dir: str) -> dict:
    """Diff two snapshots produced by `state_snapshot`. Writes diff_report.json."""
    cfg = load_config()
    res = static_skills.state_diff(cfg, before_dir, after_dir)
    return asdict(res)


@mcp.tool()
def yara_scan(
    snapshot_dir: str,
    yarasigs_dir: str,
    categories: str = "all",
    module_filter: str | None = None,
) -> dict:
    """Run YARA rules over a snapshot's memory dumps.

    `categories` is one of: packers, crypto, antidebug, all.
    `yarasigs_dir` is a local clone of a YARA rules repository.
    """
    cfg = load_config()
    res = static_skills.yara_scan(cfg, snapshot_dir, yarasigs_dir, categories, module_filter)
    return asdict(res)


@mcp.tool()
def decompile(binary_path: str, func_rva: str) -> dict:
    """Decompile one function via angr. `func_rva` is hex (e.g. "0x1340")."""
    cfg = load_config()
    res = static_skills.decompile(cfg, binary_path, func_rva)
    return asdict(res)


@mcp.tool()
def enum_imports(
    pe_path: str | None = None,
    snapshot_dir: str | None = None,
    base: str | None = None,
) -> dict:
    """Enumerate PE imports/exports/security flags.

    Pass `pe_path` for on-disk analysis, or `snapshot_dir` (+ optional `base`) to
    reconstruct the IAT from a memory snapshot (useful for packed binaries).
    """
    cfg = load_config()
    res = static_skills.enum_imports(
        cfg, pe_path=pe_path, snapshot_dir=snapshot_dir, base=base
    )
    return asdict(res)


@mcp.tool()
def find_xrefs(
    snapshot_dir: str,
    functions: str,
    base: str = "0x400000",
) -> dict:
    """Find code xrefs to IAT slots for the given comma-separated API names."""
    cfg = load_config()
    res = static_skills.find_xrefs(cfg, snapshot_dir, functions, base)
    return asdict(res)


# ---- VM lifecycle (vmrun) ------------------------------------------------

@mcp.tool()
def vm_start(vmx: str | None = None, gui: bool = True) -> dict:
    """Power on the analysis VM. `vmx` defaults to VMX_PATH env var."""
    res = vmrun.start(load_config(), vmx, gui)
    return {"ok": res.ok, "duration_s": res.duration_s, "stdout": res.stdout}


@mcp.tool()
def vm_stop(vmx: str | None = None, hard: bool = False) -> dict:
    """Power off the VM. `hard=True` is the equivalent of pulling the plug."""
    res = vmrun.stop(load_config(), vmx, hard)
    return {"ok": res.ok, "duration_s": res.duration_s, "stdout": res.stdout}


@mcp.tool()
def vm_state(vmx: str | None = None) -> dict:
    """Report 'running' or 'stopped' for the given VMX."""
    return {"state": vmrun.vm_state(load_config(), vmx)}


@mcp.tool()
def vm_list_snapshots(vmx: str | None = None) -> dict:
    """List snapshots for the given VMX."""
    return {"snapshots": vmrun.list_snapshots(load_config(), vmx)}


@mcp.tool()
def vm_create_snapshot(name: str, vmx: str | None = None) -> dict:
    """Take a new snapshot of the VM (must be powered off or running)."""
    res = vmrun.create_snapshot(load_config(), name, vmx)
    return {"ok": res.ok, "duration_s": res.duration_s, "stdout": res.stdout}


@mcp.tool()
def vm_revert(snapshot_name: str, vmx: str | None = None) -> dict:
    """Revert the VM to a named snapshot. VM is left powered off after revert."""
    res = vmrun.revert(load_config(), snapshot_name, vmx)
    return {"ok": res.ok, "duration_s": res.duration_s, "stdout": res.stdout}


@mcp.tool()
def vm_copy_to_guest(host_path: str, guest_path: str, vmx: str | None = None) -> dict:
    """Copy a file from host -> guest. Requires VM_GUEST_USER / VM_GUEST_PASS."""
    res = vmrun.copy_to_guest(load_config(), host_path, guest_path, vmx)
    return {"ok": res.ok, "duration_s": res.duration_s, "stdout": res.stdout}


@mcp.tool()
def vm_copy_from_guest(guest_path: str, host_path: str, vmx: str | None = None) -> dict:
    """Copy a file from guest -> host. Useful for pulling artifacts."""
    res = vmrun.copy_from_guest(load_config(), guest_path, host_path, vmx)
    return {"ok": res.ok, "duration_s": res.duration_s, "stdout": res.stdout}


@mcp.tool()
def vm_run_in_guest(
    program: str,
    args: list[str] | None = None,
    vmx: str | None = None,
    no_wait: bool = False,
    interactive: bool = False,
) -> dict:
    """Run a program inside the guest. Use `no_wait=True` to fire-and-forget
    (e.g. launching x64dbg.exe so it stays running)."""
    res = vmrun.run_in_guest(load_config(), program, args, vmx, interactive, no_wait)
    return {"ok": res.ok, "duration_s": res.duration_s, "stdout": res.stdout}


# ---- End-to-end recipes --------------------------------------------------

@mcp.tool()
def prepare_session(
    snapshot_name: str,
    sample_host_path: str | None = None,
    sample_guest_path: str | None = None,
    vmx: str | None = None,
    boot_timeout_s: float = 120.0,
) -> dict:
    """Revert -> start -> wait for plugin -> drop sample. One call from
    'clean snapshot on disk' to 'ready to debug'.

    Assumes the snapshot has x64dbg + the automate plugin set to launch on boot
    (Startup folder or registered service). If x64dbg isn't auto-launching,
    call `vm_run_in_guest("C:\\\\x64dbg\\\\release\\\\x64\\\\x64dbg.exe", no_wait=True)`
    after start and before the plugin will bind ports.
    """
    out = recipes.prepare_session(
        load_config(),
        snapshot_name=snapshot_name,
        sample_host_path=sample_host_path,
        sample_guest_path=sample_guest_path,
        vmx=vmx,
        boot_timeout_s=boot_timeout_s,
    )
    return {
        "ok": out.ok,
        "guest_sample_path": out.guest_sample_path,
        "steps": [
            {"name": s.name, "ok": s.ok, "detail": s.detail, "duration_s": s.duration_s}
            for s in out.steps
        ],
    }


@mcp.tool()
def cleanup_session(
    snapshot_name: str | None = None,
    vmx: str | None = None,
    hard: bool = True,
) -> dict:
    """Power off and optionally revert. Run after each sample."""
    out = recipes.cleanup_session(
        load_config(), snapshot_name=snapshot_name, vmx=vmx, hard=hard
    )
    return {
        "ok": out.ok,
        "steps": [
            {"name": s.name, "ok": s.ok, "detail": s.detail, "duration_s": s.duration_s}
            for s in out.steps
        ],
    }


def main() -> None:
    """Entry point for `x64dbg-mcp-fw` console script (stdio transport)."""
    # FastMCP defaults to stdio when run() is called without args — that's what
    # Claude Code / Claude Desktop expects from a locally-spawned MCP server.
    mcp.run()


if __name__ == "__main__":
    main()
