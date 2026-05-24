"""Subprocess wrappers around the static-analysis scripts in x64dbg-skills.

The user clones https://github.com/dariushoule/x64dbg-skills somewhere on the
host and points `X64DBG_SKILLS_DIR` at it. We invoke its Python scripts here
and forward stdout/stderr to the caller.

Why subprocess instead of import: the upstream scripts each have their own
`main()` argparse entry point, and the heavy ones (`decompile.py` -> angr,
`yara_scan.py` -> yara-python) drag in optional deps. Subprocess keeps the
MCP server itself light, and lets users install skill deps into a separate
venv if they want (`X64DBG_SKILLS_PYTHON` to override the interpreter).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .config import Config


class SkillsNotInstalled(RuntimeError):
    pass


@dataclass
class SkillResult:
    ok: bool
    stdout: str
    stderr: str
    output_path: str | None
    parsed: dict | list | None = None


def _skill_script(cfg: Config, relative: str) -> Path:
    if cfg.skills_dir is None:
        raise SkillsNotInstalled(
            "X64DBG_SKILLS_DIR is not set. Clone "
            "https://github.com/dariushoule/x64dbg-skills and point the env var "
            "at the local checkout."
        )
    path = cfg.skills_dir / relative
    if not path.exists():
        raise SkillsNotInstalled(f"Expected skill script at {path}, not found.")
    return path


def _python_for_skills() -> str:
    return os.environ.get("X64DBG_SKILLS_PYTHON") or sys.executable


def _run(args: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    proc = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _maybe_load_json(path: Path) -> dict | list | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def state_diff(cfg: Config, before_dir: str, after_dir: str) -> SkillResult:
    script = _skill_script(cfg, "skills/state-diff/state_diff.py")
    out_json = Path(after_dir) / "diff_report.json"
    code, so, se = _run(
        [_python_for_skills(), str(script), before_dir, after_dir, "--output", str(out_json)]
    )
    return SkillResult(code == 0, so, se, str(out_json), _maybe_load_json(out_json))


def yara_scan(
    cfg: Config,
    snapshot_dir: str,
    yarasigs_dir: str,
    categories: str = "all",
    module_filter: str | None = None,
) -> SkillResult:
    script = _skill_script(cfg, "skills/yara-sigs/yara_scan.py")
    out_json = Path(snapshot_dir) / "yara_results.json"
    args = [
        _python_for_skills(),
        str(script),
        "--snapshot-dir", snapshot_dir,
        "--yarasigs-dir", yarasigs_dir,
        "--categories", categories,
        "--output", str(out_json),
    ]
    if module_filter:
        args += ["--module-filter", module_filter]
    code, so, se = _run(args)
    return SkillResult(code == 0, so, se, str(out_json), _maybe_load_json(out_json))


def decompile(cfg: Config, binary_path: str, func_rva: str) -> SkillResult:
    script = _skill_script(cfg, "skills/decompile/decompile.py")
    code, so, se = _run([_python_for_skills(), str(script), binary_path, func_rva])
    return SkillResult(code == 0, so, se, None, None)


def enum_imports(
    cfg: Config,
    *,
    pe_path: str | None = None,
    snapshot_dir: str | None = None,
    base: str | None = None,
    output: str | None = None,
) -> SkillResult:
    if not (pe_path or snapshot_dir):
        raise ValueError("Provide pe_path or snapshot_dir.")
    script = _skill_script(cfg, "skills/vuln-hunter/enum_imports.py")
    args = [_python_for_skills(), str(script)]
    if pe_path:
        args += ["--pe", pe_path]
    if snapshot_dir:
        args += ["--snapshot-dir", snapshot_dir]
    if base:
        args += ["--base", base]
    out_json = output or (
        str(Path(snapshot_dir) / "imports.json") if snapshot_dir else "imports.json"
    )
    args += ["--output", out_json]
    code, so, se = _run(args)
    return SkillResult(code == 0, so, se, out_json, _maybe_load_json(Path(out_json)))


def find_xrefs(
    cfg: Config,
    snapshot_dir: str,
    functions: str,
    base: str = "0x400000",
    output: str | None = None,
) -> SkillResult:
    script = _skill_script(cfg, "skills/vuln-hunter/find_xrefs.py")
    out_json = output or str(Path(snapshot_dir) / "xrefs.json")
    code, so, se = _run(
        [
            _python_for_skills(),
            str(script),
            snapshot_dir,
            "--base", base,
            "--functions", functions,
            "--output", out_json,
        ]
    )
    return SkillResult(code == 0, so, se, out_json, _maybe_load_json(Path(out_json)))
