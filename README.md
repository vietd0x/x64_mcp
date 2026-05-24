# x64dbg-mcp-fw

Host-side **MCP framework** that drives [x64dbg](https://x64dbg.com) running
inside an **isolated VM** via the
[x64dbg-automate](https://github.com/dariushoule/x64dbg-automate) ZeroMQ
plugin, and exposes
[x64dbg-skills](https://github.com/dariushoule/x64dbg-skills) (decompile,
state-snapshot, state-diff, YARA, enum-imports, find-xrefs) as MCP tools.

> **TL;DR** — Claude debugs malware for you.  x64dbg runs in a throwaway VM,
> Claude controls it from the host over ZMQ, and the malware never touches your
> workstation.

---

## Table of contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
  - [1. VM — VMware Workstation](#1-vm--vmware-workstation)
  - [2. Host — Python install](#2-host--python-install)
  - [3. MCP config (Claude Code / Claude Desktop)](#3-mcp-config)
- [Quick start](#quick-start)
- [MCP tool surface](#mcp-tool-surface)
- [Real-world example: shellcode C2 extraction](#real-world-example)
- [Troubleshooting](#troubleshooting)
- [Security notes](#security-notes)
- [Extending](#extending)
- [License](#license)

---

## Architecture

```
┌─────────────────── HOST (trusted) ────────────────────┐
│                                                       │
│  Claude Code / Claude Desktop                         │
│    │                                                  │
│    ├──stdio──► x64dbg-mcp-fw      (this repo)        │
│    │             19 high-level tools                  │
│    │             VM lifecycle (vmrun)                  │
│    │             Snapshot / diff / YARA / decompile    │
│    │                    │                              │
│    └──stdio──► x64dbg-automate-mcp (upstream)         │
│                  ~40 debugger primitives               │
│                  read_memory, set_breakpoint, step...  │
│                         │                              │
│                         │ ZMQ (tcp)                    │
│                         │ REQ/REP :41201               │
│                         │ PUB/SUB :41200               │
│  artifacts/             │                              │
│    snapshots/           │                              │
│    reports/             │                              │
└─────────────────────────┼──────────────────────────────┘
                          │  host-only network (VMnet1)
┌─────────────────────────┼──────────────────────────────┐
│  VM (untrusted)         │                              │
│                         ▼                              │
│  x64dbg.exe ─► x64dbg-automate plugin                 │
│                  binds 0.0.0.0:41201 (REQ/REP)        │
│                  binds 0.0.0.0:41200 (PUB/SUB)        │
│                                                       │
│  malware.exe  ◄── debuggee                            │
│                                                       │
│  ❌ No internet   ❌ No LAN access                     │
│  ✅ Host-only adapter (ZMQ ports only)                 │
└───────────────────────────────────────────────────────┘
```

### Two-server model

| MCP Server | Package | Role |
|---|---|---|
| **`x64dbg-automate-mcp`** (upstream) | `x64dbg-automate[mcp]` | Low-level debugger primitives: `read_memory`, `write_memory`, `set_breakpoint`, `disassemble`, `step_into`, `go`, `get_all_registers`, etc. (~40 tools) |
| **`x64dbg-mcp-fw`** (this repo) | `x64dbg-mcp-fw` | High-level skills + VM lifecycle + orchestration recipes. Wraps snapshot/diff/YARA/decompile and VMware vmrun. (19 tools) |

Both servers connect to the **same** x64dbg-automate ZMQ plugin in the VM via
`X64DbgClient.connect_remote()`. They share the same venv (one `uv sync`
installs both).

### Key design decisions

- **`connect_remote()` only** — the framework never calls `attach_session(pid)`.
  The MCP server on the host never sees the malware process directly.
- **`detach_session()` on teardown** — only closes the ZMQ socket; x64dbg keeps
  running in the VM. Each MCP tool call opens and closes its own connection.
- **Stateless tools** — config is loaded from env vars on every call. No
  persistent state between tool invocations.
- **Static skills run on host** — decompile (angr), YARA, PE analysis all
  operate on snapshot files pulled to the host. They never execute sample code.

---

## Prerequisites

| Component | Version | Notes |
|---|---|---|
| Python | >= 3.10 | On the **host** only |
| [uv](https://docs.astral.sh/uv/) | latest | Package manager (recommended) |
| VMware Workstation / Player | 15+ | Or any VMware supporting `vmrun` |
| x64dbg | latest | Installed **inside the VM** |
| x64dbg-automate plugin | >= 0.5 | `.dp32` / `.dp64` in x64dbg plugins dir |
| Windows VM | 7 / 10 / 11 | Dedicated malware analysis VM |

Optional (for specific skills):

| Extra | Package | Skill |
|---|---|---|
| `[decompile]` | angr >= 9.2 | `decompile` (heavy, ~2 GB) |
| `[yara]` | yara-python >= 4.5 | `yara_scan` |
| `[pe]` | lief >= 0.14 | `enum_imports` |
| `[all]` | all of the above | everything |

---

## Setup

### 1. VM — VMware Workstation

1. **Create a Windows VM** dedicated to malware analysis.
   - Disable shared clipboard, drag-and-drop, shared folders.
   - Allocate enough RAM (4 GB+) and disk (60 GB+).

2. **Networking** — set the adapter to **Host-only** (VMnet1):
   ```
   VM → Settings → Network Adapter → Host-only
   ```
   > ⚠️ **Never use NAT or Bridged** for live malware analysis. The malware
   > must not reach the internet or your LAN. Only switch to NAT temporarily
   > if you need to fetch a stage-2 payload from a live C2 (see
   > [Real-world example](#real-world-example)).

   Confirm the VM's IP with `ipconfig` inside the guest (e.g. `192.168.232.135`).

3. **Install x64dbg** in the VM (e.g. `C:\x64dbg`).

4. **Install the x64dbg-automate plugin**:
   - Download `.dp32` and `.dp64` from
     [x64dbg-automate releases](https://github.com/dariushoule/x64dbg-automate/releases).
   - Drop into `x64dbg\release\x32\plugins\` and `x64dbg\release\x64\plugins\`.

5. **Configure the plugin** — in x64dbg: *Plugins → x64dbg Automate → Settings*:

   | Setting | Value |
   |---|---|
   | Connection Mode | **Remote (fixed address and ports)** |
   | Bind Address | **0.0.0.0** |
   | REQ/REP Port | **41201** |
   | PUB/SUB Port | **41200** |

   Restart x64dbg after changing settings.

6. **Verify from host**:
   ```powershell
   # Quick TCP check (PowerShell)
   Test-NetConnection -ComputerName 192.168.232.135 -Port 41201
   Test-NetConnection -ComputerName 192.168.232.135 -Port 41200
   ```

7. **Snapshot** the clean VM state in VMware (`VM → Snapshot → Take Snapshot`).
   Name it `clean` — this is what `prepare_session` reverts to.

### 2. Host — Python install

```powershell
cd C:\Users\you\Documents\proj\x64_mcp

# Install core deps (creates .venv automatically)
uv sync

# Optional skill dependencies (pick what you need)
uv pip install ".[yara]"         # yara_scan
uv pip install ".[decompile]"    # decompile (angr — heavy download)
uv pip install ".[pe]"           # enum_imports (lief)
uv pip install ".[all]"          # everything

# Clone upstream skills scripts (state_diff, yara, etc.)
git clone https://github.com/dariushoule/x64dbg-skills %USERPROFILE%\src\x64dbg-skills
```

Verify the MCP server starts:
```powershell
uv run x64dbg-mcp-fw 2>&1 | Select-Object -First 1
# Should print nothing to stdout (stdio transport waits for JSON-RPC)
# Press Ctrl+C to exit
```

### 3. MCP config

Copy [`examples/claude_mcp_config.json`](examples/claude_mcp_config.json) into
your Claude Code or Claude Desktop config and edit paths/IP.

**Claude Desktop** (`%APPDATA%\Claude\claude_desktop_config.json`):

```jsonc
{
  "mcpServers": {
    // High-level skills + VM lifecycle (this repo)
    "x64dbg-mcp-fw": {
      "command": "C:\\Users\\you\\.local\\bin\\uv.exe",
      "args": ["run", "--directory", "C:\\path\\to\\x64_mcp", "x64dbg-mcp-fw"],
      "env": {
        "X64DBG_VM_HOST":      "192.168.232.135",
        "X64DBG_VM_REQ_PORT":  "41201",
        "X64DBG_VM_PUB_PORT":  "41200",
        "X64DBG_ARTIFACT_DIR": "C:\\path\\to\\x64_mcp\\artifacts",
        "X64DBG_SKILLS_DIR":   "C:\\Users\\you\\src\\x64dbg-skills",
        "VMRUN_PATH":          "C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmrun.exe",
        "VMX_PATH":            "C:\\VMs\\malware-analysis\\malware-analysis.vmx",
        "VM_GUEST_USER":       "analyst",
        "VM_GUEST_PASS":       "REPLACE_ME"
      }
    },
    // Low-level debugger primitives (upstream)
    "x64dbg-automate": {
      "command": "C:\\Users\\you\\.local\\bin\\uv.exe",
      "args": ["run", "--directory", "C:\\path\\to\\x64_mcp", "x64dbg-automate-mcp"]
    }
  }
}
```

**Environment variables reference:**

| Variable | Required | Description | Default |
|---|---|---|---|
| `X64DBG_VM_HOST` | ✅ | VM IP on host-only adapter | `127.0.0.1` |
| `X64DBG_VM_REQ_PORT` | | Plugin REQ/REP port | `41201` |
| `X64DBG_VM_PUB_PORT` | | Plugin PUB/SUB port | `41200` |
| `X64DBG_ARTIFACT_DIR` | | Where snapshots/reports land on host | `./artifacts` |
| `X64DBG_SKILLS_DIR` | | Local clone of x64dbg-skills | *(none)* |
| `X64DBG_PATH` | | x64dbg install path in VM | `C:\x64dbg` |
| `VMRUN_PATH` | | Full path to `vmrun.exe` | *(auto-detect)* |
| `VMX_PATH` | | Default `.vmx` for the analysis VM | *(none)* |
| `VM_GUEST_USER` | | Guest OS account (for copy/run) | *(none)* |
| `VM_GUEST_PASS` | | Guest OS password | *(none)* |

---

## Quick start

After setup, the typical analysis session in Claude:

```
You:  "Revert VM to clean, load sample.exe, wait for debugger"
       → Claude calls prepare_session(snapshot_name="clean",
           sample_host_path="C:\\samples\\sample.exe",
           sample_guest_path="C:\\Users\\analyst\\Desktop\\sample.exe")

You:  "Set breakpoint at entry, run to it, disassemble"
       → Claude uses x64dbg-automate tools: set_breakpoint, go, disassemble

You:  "Take a snapshot before unpacking"
       → Claude calls state_snapshot(name="pre_unpack")

You:  "Step through the unpacking loop, take another snapshot"
       → Claude calls state_snapshot(name="post_unpack")

You:  "Diff the two snapshots"
       → Claude calls state_diff(before_dir="...pre_unpack", after_dir="...post_unpack")

You:  "Run YARA on the unpacked snapshot"
       → Claude calls yara_scan(snapshot_dir="...post_unpack", yarasigs_dir="...")

You:  "Clean up and revert"
       → Claude calls cleanup_session(snapshot_name="clean")
```

---

## MCP tool surface

### Diagnostics (2 tools)

| Tool | Description |
|---|---|
| `get_config()` | Show resolved host/ports/paths/vmrun config. |
| `ping_vm()` | Connect via `connect_remote`, confirm plugin is alive. Returns x64dbg version + debug state. |

### Live debugging (1 tool)

| Tool | Description |
|---|---|
| `state_snapshot(name?)` | Capture registers + all committed memory regions to `$ARTIFACT_DIR/snapshots/<name>/`. Returns paths and counts. |

### Static analysis (5 tools)

| Tool | Description |
|---|---|
| `state_diff(before_dir, after_dir)` | JSON diff of two snapshots (register changes + memory region changes). |
| `yara_scan(snapshot_dir, yarasigs_dir, categories?, module_filter?)` | Run YARA rules over snapshot memory dumps. Categories: `packers`, `crypto`, `antidebug`, `all`. |
| `decompile(binary_path, func_rva)` | Decompile one function via angr. `func_rva` is hex (e.g. `"0x1340"`). |
| `enum_imports(pe_path?, snapshot_dir?, base?)` | PE imports/exports/security flags. Works on-disk or from memory snapshot. |
| `find_xrefs(snapshot_dir, functions, base?)` | Find code xrefs to IAT slots for comma-separated API names. |

### VM lifecycle — vmrun (9 tools)

| Tool | Description |
|---|---|
| `vm_state(vmx?)` | Report `"running"` or `"stopped"`. |
| `vm_start(vmx?, gui?)` | Power on the VM. |
| `vm_stop(vmx?, hard?)` | Power off. `hard=True` = pull the plug. |
| `vm_list_snapshots(vmx?)` | List all VMware snapshots. |
| `vm_create_snapshot(name, vmx?)` | Take a new VMware snapshot. |
| `vm_revert(snapshot_name, vmx?)` | Revert to named snapshot (VM left powered off). |
| `vm_copy_to_guest(host_path, guest_path, vmx?)` | Copy file from host into VM. |
| `vm_copy_from_guest(guest_path, host_path, vmx?)` | Copy file from VM to host. |
| `vm_run_in_guest(program, args?, vmx?, no_wait?, interactive?)` | Run a program inside the guest. `no_wait=True` for fire-and-forget (e.g. launching x64dbg). |

### End-to-end recipes (2 tools)

| Tool | Description |
|---|---|
| `prepare_session(snapshot_name, sample_host_path?, sample_guest_path?, vmx?, boot_timeout_s?)` | Revert → start → wait-for-plugin → drop sample. One call from clean snapshot to ready-to-debug. |
| `cleanup_session(snapshot_name?, vmx?, hard?)` | Power off and optionally revert. Run after each sample. |

---

## Real-world example

### Shellcode C2 extraction

This is from an actual analysis session using this framework — a packed
shellcode sample that connects back to a C2 server.

**Step 1 — Connect and recon:**
```
connect_remote(host="192.168.232.135", req=41201, pub=41200)
get_all_registers  → EIP = 0xD40005 (shellcode entry)
disassemble 0xD40000, 20  → CLD; CALL 0xD40714 (API resolver)
```

**Step 2 — Identify the API resolution pattern:**

IDA Hex-Rays decompilation reveals a classic **PEB walk + ROR13 hash** pattern
(Metasploit / Cobalt Strike style):
```c
// Walk PEB → LDR → InMemoryOrderModuleList
peb = __readfsdword(0x30);
ldr = peb->Ldr;
// For each DLL, hash each export name with ROR13 and compare
```

**Step 3 — Find the connect() call:**

Disassembly + decompilation shows:
```
0xD401FA: WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 1)
0xD40262: push 0x10                    ; namelen = sizeof(sockaddr_in)
0xD40264: lea eax, [esp+0x13C]         ; &sockaddr_in
0xD4026D: call [esp+0x164]             ; connect()
0xD40276: jnz 0xD40257                 ; retry loop (Sleep 10s)
```

**Step 4 — Set breakpoint and extract C2:**
```
set_breakpoint(0xD40276, name="connect_call")
go → wait_for_event(EVENT_BREAKPOINT)
read_memory(0xBBEEB8, 16)  → sockaddr_in
```

Result:
```
02 00 5C 0E 2D 4D 2A 59 00 00 00 00 00 00 00 00
│     │     └─ sin_addr = 45.77.42.89
│     └─ sin_port = 0x5C0E (network order) → 3676
└─ sin_family = AF_INET
```

> **C2: `45.77.42.89:3676` (TCP)**

**Step 5 — Trace the stage-2 download flow:**

After `connect()` succeeds, the shellcode:
1. Builds an HTTP GET request with stack strings (User-Agent: Mozilla/5.0 ...)
2. `send()` the request
3. `recv()` byte-by-byte until `\r\n\r\n` (skip HTTP headers)
4. `VirtualAlloc(NULL, 0x1C9C380, MEM_COMMIT, PAGE_EXECUTE_READWRITE)` — 30 MB RWX
5. `recv()` loop (0x64000 bytes per call) into the allocated buffer
6. **XOR 0x99 decode** each chunk inline
7. `closesocket()`
8. `call ebx` — jump to decoded stage 2

The stack-string obfuscation for the IP:
```c
sprintf(buf, "%s%s", "45.7", "7.42");  // → "45.77.42"
strcat(buf, ".89");                     // → "45.77.42.89"
```

**Step 6 — Capture stage 2 (if C2 is live):**
```
set_breakpoint(0xD4070B, name="stage2_entry")  // call ebx
clear_breakpoint(0xD40276)
go → shellcode connects, downloads, XOR-decodes, breaks at call ebx
read_memory(ebx, 4096)  → decoded stage 2 payload header
```

> If the C2 is offline (common with old samples), you can set up a fake C2 on
> the host to capture the HTTP request and verify the decode flow.

---

## Troubleshooting

### "Resource temporarily unavailable" / connection errors

- **ZMQ timeout**: the MCP server's ZMQ connection timed out. The upstream
  `x64dbg-automate` MCP server needs `connect_remote` called first.
- **Plugin not running**: check that x64dbg is open inside the VM with the
  automate plugin loaded (Plugins → x64dbg Automate should show status).
- **Firewall**: Windows Firewall in the VM may block inbound ZMQ. Add a rule
  for ports 41201 and 41200, or disable the firewall in the analysis VM.
- **Wrong IP**: if you switched from Host-only to NAT (or vice versa), the VM's
  IP changes. Update `X64DBG_VM_HOST` accordingly.

### "Operation cannot be accomplished in current state"

The debuggee is running (not paused). Call `pause` first, or wait for a
breakpoint event.

### ping_vm works but set_breakpoint fails

The upstream `x64dbg-automate-mcp` server requires an explicit
`connect_remote(host, req_port, pub_port)` call at the start of each session.
Unlike `x64dbg-mcp-fw` (which connects/disconnects per tool call), the upstream
server maintains a persistent session.

### VM IP changed after switching network adapter

VMware assigns different IPs for Host-only vs NAT:
- **Host-only** (VMnet1): typically `192.168.232.x` or `192.168.56.x`
- **NAT** (VMnet8): typically `192.168.140.x`

Update `X64DBG_VM_HOST` or pass the new IP directly to `connect_remote`.


## Project structure

```
x64_mcp/
├── pyproject.toml                    # Package definition, deps, entry points
├── README.md                         # This file
├── examples/
│   └── claude_mcp_config.json        # Ready-to-copy MCP config template
└── src/
    └── x64dbg_mcp_fw/
        ├── __init__.py               # __version__ = "0.1.0"
        ├── __main__.py               # python -m x64dbg_mcp_fw
        ├── config.py                 # Config dataclass from env vars
        ├── session.py                # remote_client() context manager (ZMQ)
        ├── server.py                 # FastMCP server — 19 @mcp.tool() functions
        ├── snapshot.py               # Live state capture (regs + memory)
        ├── skills.py                 # Subprocess wrappers for x64dbg-skills
        ├── vm.py                     # vmrun CLI wrappers
        └── recipes.py               # Multi-step orchestrations
```

---

## Extending

### Add a new skill

1. Add the skill function to [`skills.py`](src/x64dbg_mcp_fw/skills.py).
2. Register it as `@mcp.tool()` in [`server.py`](src/x64dbg_mcp_fw/server.py).
3. If it needs live debugger access, use the `remote_client` context manager:
   ```python
   from .session import remote_client
   from .config import load as load_config

   @mcp.tool()
   def my_new_skill(param: str) -> dict:
       cfg = load_config()
       with remote_client(cfg) as client:
           # client is an X64DbgClient connected to the VM
           data = client.read_memory(0x401000, 256)
           return {"result": data.hex()}
   ```

### Prompt-based skills (no code)

The orchestration-only skills from x64dbg-skills (`find-oep`,
`shellcode-analyzer`, `tracealyzer`) are prompt patterns that chain calls to
the primitive MCP tools. Drop their `SKILL.md` files into `.claude/skills/`
to use them with Claude Code's skill loader.

---

## License

MIT
