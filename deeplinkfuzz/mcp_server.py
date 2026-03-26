"""DEEPLINKFUZZ MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from deeplinkfuzz.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-deeplinkfuzz[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-deeplinkfuzz[mcp]'")
        return 1
    app = FastMCP("deeplinkfuzz")

    @app.tool()
    def deeplinkfuzz_scan(target: str) -> str:
        """Fuzzes Android/iOS deep links, intents, and custom URL schemes against an emulator/device to surface unvalidated-redirect, injection, and component-hijack bugs.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
