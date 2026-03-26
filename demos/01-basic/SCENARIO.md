# Demo 01 - Basic deep-link injection fuzzing

## What this shows

`sample_manifest.xml` is a small Android manifest with three components:

- **`com.example.DeepLinkActivity`** - exported, handles the
  `myapp://open/profile` and `https://example.com/item` deep links, and has
  **no permission guard**. This is the classic vulnerable surface.
- **`com.example.SearchService`** - exported service handling
  `myapp://search`, guarded by a custom permission (severity is downgraded
  because the permission could still be `normal`-protection).
- **`com.example.InternalActivity`** - `exported="false"`, so it is ignored by
  default (use `--include-unexported` to audit it).

DEEPLINKFUZZ enumerates the exported entry points, generates mutated deep
links (SQLi, path traversal, XSS, command injection, intent redirection,
format string, null-byte, overflow) injected into both the path and query,
and replays them through its detector.

## Run it

```
python -m deeplinkfuzz fuzz demos/01-basic/sample_manifest.xml
python -m deeplinkfuzz fuzz demos/01-basic/sample_manifest.xml --format json | jq '.findings[0]'
python -m deeplinkfuzz fuzz demos/01-basic/sample_manifest.xml --min-severity high
```

## Expected result

- Exactly **2** exported entry points are enumerated
  (`DeepLinkActivity`, `SearchService`); `InternalActivity` is skipped.
- Multiple findings are reported. `DeepLinkActivity` yields **critical**
  findings (SQLi UNION/stacked, command injection) because it has no
  permission guard. `SearchService`'s findings are capped at **medium**
  because it is guarded by a custom permission.
- The process exits with status **1** (findings present) - a CI gate would
  fail the build. Adding `--min-severity high` still exits 1 (criticals
  exist); raising it past all findings would exit 0.
