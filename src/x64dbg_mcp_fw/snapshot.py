"""Live debuggee state snapshot.

Adapted from the upstream x64dbg-skills `state_snapshot.py`, but connects to
the VM's plugin via `connect_remote` instead of `attach_session(pid)`.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from x64dbg_automate import X64DbgClient


MEM_COMMIT = 0x1000


def _hexify(obj: Any) -> Any:
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {k: _hexify(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_hexify(v) for v in obj]
    return obj


def _make_output_dir(base: Path, name: str | None) -> Path:
    if name:
        out = base / name
    else:
        out = base / "snapshots" / time.strftime("%Y%m%d_%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    return out


def take_snapshot(
    client: X64DbgClient, artifact_root: Path, name: str | None = None
) -> dict:
    """Capture registers + all committed memory regions to `artifact_root`.

    Returns a small summary dict with paths and counts. Mirrors the upstream
    output layout (registers.json, memory_map.json, <base>_<size>.bin).
    """
    out = _make_output_dir(artifact_root, name)

    # get_regs() is annotated list[RegDump32|RegDump64]; depending on the
    # plugin/client build it may return that list or a single RegDump. Handle
    # both, and derive bitness from the model class name (unambiguous) rather
    # than poking at context attributes.
    regs = client.get_regs()
    reg = regs[0] if isinstance(regs, (list, tuple)) else regs
    bitness = 32 if "32" in type(reg).__name__ else 64
    reg_payload = {"bitness": bitness, "registers": _hexify(reg.model_dump())}
    (out / "registers.json").write_text(json.dumps(reg_payload, indent=2))

    pages = client.memmap()
    committed = [p for p in pages if p.state == MEM_COMMIT]

    manifest: list[dict] = []
    saved = 0
    total_bytes = 0
    for page in committed:
        entry = {
            "base": hex(page.base_address),
            "size": hex(page.region_size),
            "protect": hex(page.protect),
            "type": hex(page.type),
            "info": page.info,
            "file": None,
            "read_ok": False,
        }
        fname = f"{page.base_address:016X}_{page.region_size:X}.bin"
        try:
            data = client.read_memory(page.base_address, page.region_size)
            (out / fname).write_bytes(data)
            entry["file"] = fname
            entry["read_ok"] = True
            saved += 1
            total_bytes += len(data)
        except Exception as e:
            entry["error"] = str(e)
        manifest.append(entry)

    (out / "memory_map.json").write_text(json.dumps(manifest, indent=2))

    return {
        "snapshot_dir": str(out),
        "bitness": bitness,
        "regions_total": len(pages),
        "regions_committed": len(committed),
        "regions_saved": saved,
        "bytes_saved": total_bytes,
    }
