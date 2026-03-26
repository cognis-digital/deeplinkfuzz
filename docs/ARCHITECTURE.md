# DEEPLINKFUZZ — Architecture

> Fuzzes Android/iOS deep links, intents, and custom URL schemes against an emulator/device to surface unvalidated-redirect, injection, and component-hijack bugs.

```
input ──▶ collect ──▶ rules/analyzers ──▶ score ──▶ findings ──▶ table · json
                              │                          │
                         (this repo)                 MCP tool (agents)
```

- **collect** normalizes the target (file/dir/API) into records.
- **rules/analyzers** apply the heuristics shipped in `deeplinkfuzz/core.py`.
- **score** ranks by severity.
- **MCP server** (`deeplinkfuzz mcp`) exposes `scan` for Cognis.Studio agents.

Extend by adding a rule + a test + a `demos/NN-*/SCENARIO.md`. See [CONTRIBUTING.md](../CONTRIBUTING.md).
