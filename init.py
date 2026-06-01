#!/usr/bin/env python3
"""Bootstrap x64dbg-mcp-fw against a (possibly changed) pair of VM IPs.

Usage:
    python init.py -ida 192.168.131.1 -x64 192.168.131.129
    python init.py -ida 192.168.131.1 -x64 192.168.131.129 --extras yara,pe
    python init.py -ida 192.168.131.1 -x64 192.168.131.129 --skills-dir ~/src/x64dbg-skills

What it does:
    1. TCP-pings IDA host on 13337 and x64dbg VM on 41201 + 41200.
    2. Verifies `uv` is installed (installs it if missing on Linux/macOS).
    3. Runs `uv sync` if the local .venv looks stale or absent.
    4. Installs any optional extras you request via `--extras`.
    5. Clones x64dbg-skills if `--skills-dir` is given and the directory is empty.
    6. Writes examples/claude_mcp_config.json with the IPs you passed.

The script is idempotent — re-running with the same args is a no-op except for
the connectivity probes.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
CONFIG_TEMPLATE = REPO_ROOT / "examples" / "claude_mcp_config.json"

IDA_PORT = 13337
X64_REQ_PORT = 41201
X64_PUB_PORT = 41200


def _color(code: str, msg: str) -> str:
    if not sys.stdout.isatty():
        return msg
    return f"\033[{code}m{msg}\033[0m"


def info(msg: str) -> None:
    print(_color("36", "[*]"), msg)


def ok(msg: str) -> None:
    print(_color("32", "[+]"), msg)


def warn(msg: str) -> None:
    print(_color("33", "[!]"), msg)


def fail(msg: str) -> None:
    print(_color("31", "[x]"), msg)


def tcp_probe(host: str, port: int, timeout: float = 3.0) -> bool:
    """Return True iff TCP connect to (host, port) succeeds within `timeout`."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_connectivity(ida_ip: str, x64_ip: str) -> bool:
    """Probe IDA + x64dbg ports. Returns True iff all reachable."""
    targets = [
        ("IDA Pro plugin", ida_ip, IDA_PORT),
        ("x64dbg REQ/REP", x64_ip, X64_REQ_PORT),
        ("x64dbg PUB/SUB", x64_ip, X64_PUB_PORT),
    ]
    all_ok = True
    for label, host, port in targets:
        if tcp_probe(host, port):
            ok(f"{label}: {host}:{port} reachable")
        else:
            fail(f"{label}: {host}:{port} unreachable")
            all_ok = False
    return all_ok


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def ensure_uv() -> bool:
    """Make sure `uv` is on PATH. Auto-install on POSIX via the official script."""
    if have("uv"):
        ok("uv is installed")
        return True
    warn("uv not found")
    if os.name == "nt":
        fail("Install uv manually on Windows: https://docs.astral.sh/uv/getting-started/installation/")
        return False
    info("Installing uv via the official installer (curl | sh)...")
    try:
        subprocess.run(
            "curl -LsSf https://astral.sh/uv/install.sh | sh",
            shell=True,
            check=True,
        )
    except subprocess.CalledProcessError:
        fail("uv install failed")
        return False
    # Installer typically lands uv under ~/.local/bin or ~/.cargo/bin
    for candidate in (Path.home() / ".local/bin", Path.home() / ".cargo/bin"):
        if (candidate / "uv").exists():
            os.environ["PATH"] = f"{candidate}{os.pathsep}{os.environ['PATH']}"
            break
    if have("uv"):
        ok("uv installed")
        return True
    fail("uv installed but not on PATH — open a new shell and re-run")
    return False


def venv_has_package(pkg: str) -> bool:
    """Check if `pkg` is importable inside the project's uv-managed venv."""
    result = subprocess.run(
        ["uv", "run", "--no-sync", "python", "-c", f"import {pkg}"],
        cwd=REPO_ROOT,
        capture_output=True,
    )
    return result.returncode == 0


def ensure_sync() -> bool:
    """Run `uv sync` if the venv looks absent or the core package isn't importable."""
    venv = REPO_ROOT / ".venv"
    py_bin = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if venv.exists() and not py_bin.exists():
        warn(f"Found broken .venv (no python interpreter) — removing {venv}")
        shutil.rmtree(venv, ignore_errors=True)
    needs_sync = not venv.exists() or not venv_has_package("x64dbg_mcp_fw")
    if not needs_sync:
        ok("Project venv is in sync (.venv present, x64dbg_mcp_fw importable)")
        return True
    info("Running `uv sync`...")
    try:
        subprocess.run(["uv", "sync"], cwd=REPO_ROOT, check=True)
    except subprocess.CalledProcessError:
        fail("`uv sync` failed — try `rm -rf .venv` and re-run")
        return False
    ok("`uv sync` complete")
    return True


def install_extras(extras: list[str]) -> bool:
    """Install optional extras like [yara], [pe], [decompile], [all]."""
    if not extras:
        return True
    # Skip extras whose import is already satisfied.
    extras_to_module = {
        "yara": "yara",
        "pe": "lief",
        "decompile": "angr",
        "all": None,  # always install — covers all three
    }
    pending = []
    for e in extras:
        mod = extras_to_module.get(e)
        if mod and venv_has_package(mod):
            ok(f"extra '[{e}]' already satisfied")
        else:
            pending.append(e)
    if not pending:
        return True
    spec = ".[" + ",".join(pending) + "]"
    info(f"Installing extras: {spec}")
    try:
        subprocess.run(["uv", "pip", "install", spec], cwd=REPO_ROOT, check=True)
    except subprocess.CalledProcessError:
        fail(f"Failed to install extras: {spec}")
        return False
    ok(f"Installed extras: {spec}")
    return True


def ensure_skills_dir(path: Path | None) -> bool:
    if path is None:
        return True
    path = path.expanduser().resolve()
    if path.exists() and any(path.iterdir()):
        ok(f"x64dbg-skills already present at {path}")
        return True
    if not have("git"):
        fail("git not installed — can't clone x64dbg-skills")
        return False
    info(f"Cloning x64dbg-skills into {path}...")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["git", "clone", "https://github.com/dariushoule/x64dbg-skills", str(path)],
            check=True,
        )
    except subprocess.CalledProcessError:
        fail("git clone failed")
        return False
    ok(f"x64dbg-skills cloned to {path}")
    return True


def write_config(ida_ip: str, x64_ip: str, skills_dir: Path | None) -> Path:
    """Rewrite examples/claude_mcp_config.json with the supplied IPs."""
    try:
        with CONFIG_TEMPLATE.open() as f:
            cfg = json.load(f)
    except FileNotFoundError:
        fail(f"Template not found: {CONFIG_TEMPLATE}")
        raise

    servers = cfg.get("mcpServers", {})
    if "ida-pro-mcp" in servers:
        # Upstream ida-pro-mcp ignores IDA_HOST/IDA_PORT env vars; the only
        # supported cross-host knob is `--ida-rpc <url>`. Rewrite (or append)
        # that flag in args, and drop any stale env keys left over from older
        # templates so they don't mislead the next reader.
        entry = servers["ida-pro-mcp"]
        args_list = entry.setdefault("args", [])
        ida_url = f"http://{ida_ip}:{IDA_PORT}"
        try:
            idx = args_list.index("--ida-rpc")
            args_list[idx + 1] = ida_url
        except (ValueError, IndexError):
            args_list.extend(["--ida-rpc", ida_url])
        env = entry.get("env")
        if isinstance(env, dict):
            for stale in ("IDA_HOST", "IDA_PORT"):
                env.pop(stale, None)
            if not any(k for k in env if not k.startswith("_")):
                entry.pop("env", None)
    if "x64dbg-mcp-fw" in servers:
        env = servers["x64dbg-mcp-fw"].setdefault("env", {})
        env["X64DBG_VM_HOST"] = x64_ip
        env["X64DBG_VM_REQ_PORT"] = str(X64_REQ_PORT)
        env["X64DBG_VM_PUB_PORT"] = str(X64_PUB_PORT)
        if skills_dir is not None:
            env["X64DBG_SKILLS_DIR"] = str(skills_dir.expanduser().resolve())

    with CONFIG_TEMPLATE.open("w") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
    ok(f"Wrote MCP config: {CONFIG_TEMPLATE}")
    return CONFIG_TEMPLATE


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Bootstrap x64dbg-mcp-fw against a pair of VM IPs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-ida", dest="ida_ip", required=True, help="IDA Pro host IP (port 13337)")
    p.add_argument("-x64", dest="x64_ip", required=True, help="x64dbg VM IP (ports 41201/41200)")
    p.add_argument(
        "--extras",
        default="",
        help="Comma-separated optional extras: yara,pe,decompile,all",
    )
    p.add_argument(
        "--skills-dir",
        type=Path,
        default=None,
        help="Where to clone x64dbg-skills (skipped if omitted)",
    )
    p.add_argument(
        "--skip-connectivity",
        action="store_true",
        help="Skip TCP probes (use when VMs are not up yet)",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    extras = [e.strip() for e in args.extras.split(",") if e.strip()]

    info(f"IDA host:  {args.ida_ip}:{IDA_PORT}")
    info(f"x64dbg VM: {args.x64_ip}:{X64_REQ_PORT}+{X64_PUB_PORT}")
    print()

    info("=== 1/4: VM connectivity ===")
    if args.skip_connectivity:
        warn("skipped (--skip-connectivity)")
    elif not check_connectivity(args.ida_ip, args.x64_ip):
        warn("One or more endpoints unreachable. Continuing setup, but verify the VMs/plugins are running.")
    print()

    info("=== 2/4: Framework host deps ===")
    if not ensure_uv():
        return 1
    if not ensure_sync():
        return 1
    if not install_extras(extras):
        return 1
    print()

    info("=== 3/4: x64dbg-skills ===")
    if not ensure_skills_dir(args.skills_dir):
        return 1
    print()

    info("=== 4/4: MCP config ===")
    write_config(args.ida_ip, args.x64_ip, args.skills_dir)
    print()

    ok("Setup complete.")
    print("  Next: copy examples/claude_mcp_config.json into your Claude config")
    print("  (Claude Desktop: %APPDATA%\\Claude\\claude_desktop_config.json on Windows,")
    print("   ~/Library/Application Support/Claude/claude_desktop_config.json on macOS)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
