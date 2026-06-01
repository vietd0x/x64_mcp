"""Runtime configuration sourced from environment variables.

ZMQ / framework
---------------
X64DBG_VM_HOST          Hostname / IP of the analysis VM running x64dbg + the
                        x64dbg-automate plugin (default: 192.168.131.129 — the
                        VMnet1 host-only guest in the reference setup).
X64DBG_VM_REQ_PORT      ZMQ REQ/REP port — must match the plugin's Settings dialog (default: 41201).
X64DBG_VM_PUB_PORT      ZMQ PUB/SUB port — must match the plugin's Settings dialog (default: 41200).
X64DBG_SKILLS_DIR       Local clone of github.com/dariushoule/x64dbg-skills. Required
                        for the static-analysis MCP tools (state_diff, yara_scan,
                        enum_imports, find_xrefs, decompile).
X64DBG_PATH             Path to x64dbg executable. Optional — only used as a hint to
                        the upstream client.
X64DBG_ARTIFACT_DIR     Directory where snapshots and reports are written
                        (default: ./artifacts on the host).

VMware lifecycle (optional — only needed for the vm_* MCP tools)
----------------------------------------------------------------
VMRUN_PATH              Full path to vmrun.exe.
VMX_PATH                Default .vmx file for the analysis VM.
VM_GUEST_USER           Guest OS account used for copyFileFromHostToGuest / runProgramInGuest.
VM_GUEST_PASS           Guest OS password.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Config:
    vm_host: str
    vm_req_port: int
    vm_pub_port: int
    skills_dir: Path | None
    x64dbg_path: str | None
    artifact_dir: Path
    # VMware
    vmrun_path: str | None
    vmx_path: str | None
    guest_user: str | None
    guest_password: str | None


def load() -> Config:
    skills = os.environ.get("X64DBG_SKILLS_DIR")
    return Config(
        vm_host=os.environ.get("X64DBG_VM_HOST", "192.168.131.129"),
        vm_req_port=int(os.environ.get("X64DBG_VM_REQ_PORT", "41201")),
        vm_pub_port=int(os.environ.get("X64DBG_VM_PUB_PORT", "41200")),
        skills_dir=Path(skills).expanduser().resolve() if skills else None,
        x64dbg_path=os.environ.get("X64DBG_PATH"),
        artifact_dir=Path(
            os.environ.get("X64DBG_ARTIFACT_DIR", "./artifacts")
        ).expanduser().resolve(),
        vmrun_path=os.environ.get("VMRUN_PATH"),
        vmx_path=os.environ.get("VMX_PATH"),
        guest_user=os.environ.get("VM_GUEST_USER"),
        guest_password=os.environ.get("VM_GUEST_PASS"),
    )
