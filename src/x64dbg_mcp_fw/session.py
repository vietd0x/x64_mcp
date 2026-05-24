"""ZMQ connection helpers for talking to x64dbg-automate inside the VM.

Each skill that needs a live debugger connection acquires one via
`remote_client()` as a context manager. The connection is short-lived: we
connect, run the skill, disconnect. This avoids fighting the upstream
x64dbg-automate-mcp server (if also configured) for ownership of the session.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from x64dbg_automate import X64DbgClient

from .config import Config


@contextmanager
def remote_client(cfg: Config) -> Iterator[X64DbgClient]:
    """Yield a connected X64DbgClient pointed at the VM's plugin.

    `connect_remote` is a classmethod that constructs *and* connects the client
    (it raises if the plugin is unreachable or version-incompatible). Teardown
    uses `detach_session()` which only closes our ZMQ socket — x64dbg and the
    debuggee in the VM keep running untouched.
    """
    client = X64DbgClient.connect_remote(
        cfg.vm_host, cfg.vm_req_port, cfg.vm_pub_port
    )
    try:
        yield client
    finally:
        try:
            client.detach_session()
        except Exception:
            pass
