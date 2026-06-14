"""DEEPLINKFUZZ MCP server — exposes fuzz_manifest() as an MCP tool."""
from __future__ import annotations

import json

from deeplinkfuzz.core import fuzz_manifest


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
    def deeplinkfuzz_scan(manifest_xml: str) -> str:
        """Fuzz an Android manifest XML string for deep-link injection bugs.

        Returns a JSON object with entry_points, findings, and severity counts.
        """
        try:
            result = fuzz_manifest(manifest_xml)
        except ValueError as exc:
            return json.dumps({"error": str(exc)})
        return json.dumps(result)

    app.run()
    return 0
