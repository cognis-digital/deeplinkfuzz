"""Smoke tests for DEEPLINKFUZZ. Run with: pytest -q"""
import json
import os
import subprocess
import sys

import pytest

from deeplinkfuzz import (
    TOOL_NAME,
    TOOL_VERSION,
    PAYLOADS,
    enumerate_entry_points,
    fuzz_manifest,
    mutate,
)
from deeplinkfuzz.cli import main

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic",
                    "sample_manifest.xml")


@pytest.fixture(scope="module")
def manifest_text():
    with open(os.path.abspath(DEMO), "r", encoding="utf-8") as fh:
        return fh.read()


def test_metadata():
    assert TOOL_NAME == "deeplinkfuzz"
    assert TOOL_VERSION.count(".") == 2


def test_enumerate_only_exported(manifest_text):
    eps = enumerate_entry_points(manifest_text)
    names = {e.component for e in eps}
    # Two exported components; the exported=false one is excluded.
    assert len(eps) == 2
    assert "com.example.DeepLinkActivity" in names
    assert "com.example.SearchService" in names
    assert "com.example.InternalActivity" not in names


def test_include_unexported(manifest_text):
    eps = enumerate_entry_points(manifest_text, include_unexported=True)
    assert len(eps) == 3
    internal = [e for e in eps if e.component.endswith("InternalActivity")][0]
    assert internal.exported is False


def test_deep_links_built(manifest_text):
    eps = enumerate_entry_points(manifest_text)
    dla = [e for e in eps if e.component.endswith("DeepLinkActivity")][0]
    links = dla.deep_links()
    assert "myapp://open/profile" in links
    assert "https://example.com/item" in links


def test_mutation_covers_payloads_and_targets(manifest_text):
    eps = enumerate_entry_points(manifest_text)
    dla = [e for e in eps if e.component.endswith("DeepLinkActivity")][0]
    cases = mutate(dla)
    # 2 links * len(PAYLOADS) * 2 targets
    assert len(cases) == 2 * len(PAYLOADS) * 2
    assert any(c.target == "path" for c in cases)
    assert any(c.target == "query" for c in cases)
    # payload actually injected into the URL
    sqli = [c for c in cases if c.payload_name == "sqli_union"][0]
    assert "UNION" in sqli.url


def test_fuzz_finds_injection(manifest_text):
    result = fuzz_manifest(manifest_text)
    assert result["entry_point_count"] == 2
    assert result["finding_count"] > 0
    cats = {f["category"] for f in result["findings"]}
    assert "sql_injection" in cats
    assert "path_traversal" in cats
    assert "command_injection" in cats


def test_unguarded_yields_critical_guarded_capped(manifest_text):
    result = fuzz_manifest(manifest_text)
    by_comp = {}
    for f in result["findings"]:
        by_comp.setdefault(f["component"], []).append(f)
    dla = by_comp["com.example.DeepLinkActivity"]
    svc = by_comp["com.example.SearchService"]
    # unguarded activity can be critical
    assert any(f["severity"] == "critical" for f in dla)
    # permission-guarded service is capped at medium
    assert all(f["severity"] in ("info", "low", "medium") for f in svc)


def test_min_severity_filter(manifest_text):
    all_res = fuzz_manifest(manifest_text, min_severity="info")
    high_res = fuzz_manifest(manifest_text, min_severity="high")
    assert high_res["finding_count"] <= all_res["finding_count"]
    assert all(
        f["severity"] in ("high", "critical") for f in high_res["findings"]
    )


def test_cli_exit_code_and_json(capsys):
    code = main(["--format", "json", "fuzz", os.path.abspath(DEMO)])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["finding_count"] > 0
    # findings present -> non-zero exit for CI gate
    assert code == 1


def test_cli_clean_when_no_findings(tmp_path, capsys):
    clean = tmp_path / "clean.xml"
    clean.write_text(
        '<?xml version="1.0"?>'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        '<application>'
        '<activity android:name=".Main" android:exported="false"/>'
        '</application></manifest>',
        encoding="utf-8",
    )
    code = main(["fuzz", str(clean)])
    assert code == 0


def test_module_entrypoint_version():
    proc = subprocess.run(
        [sys.executable, "-m", "deeplinkfuzz", "--version"],
        capture_output=True, text=True,
        cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
    )
    assert proc.returncode == 0
    assert "deeplinkfuzz" in proc.stdout


# ---------------------------------------------------------------------------
# Hardening tests: edge cases and error paths
# ---------------------------------------------------------------------------

def test_parse_manifest_empty_string():
    """Empty input must raise ValueError, not crash."""
    from deeplinkfuzz.core import parse_manifest
    with pytest.raises(ValueError, match="empty"):
        parse_manifest("")


def test_parse_manifest_whitespace_only():
    """Whitespace-only input must raise ValueError."""
    from deeplinkfuzz.core import parse_manifest
    with pytest.raises(ValueError, match="empty"):
        parse_manifest("   \n\t  ")


def test_parse_manifest_malformed_xml():
    """Malformed XML must raise ValueError with a clear message."""
    from deeplinkfuzz.core import parse_manifest
    with pytest.raises(ValueError, match="invalid manifest XML"):
        parse_manifest("<unclosed>")


def test_fuzz_manifest_unknown_severity():
    """fuzz_manifest raises ValueError for an unrecognised min_severity."""
    with pytest.raises(ValueError, match="unknown severity"):
        fuzz_manifest("<manifest/>", min_severity="catastrophic")


def test_fuzz_manifest_empty_input():
    """fuzz_manifest propagates the empty-input ValueError from parse_manifest."""
    with pytest.raises(ValueError):
        fuzz_manifest("")


def test_fuzz_manifest_no_entry_points():
    """A manifest with no exported components returns zero findings, not an error."""
    xml = (
        '<?xml version="1.0"?>'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        "<application/>"
        "</manifest>"
    )
    result = fuzz_manifest(xml)
    assert result["entry_point_count"] == 0
    assert result["finding_count"] == 0
    assert result["fuzz_cases"] == 0


def test_cli_missing_file_exits_2(capsys):
    """CLI returns exit code 2 and prints to stderr for a missing file."""
    code = main(["fuzz", "/nonexistent/path/manifest.xml"])
    err = capsys.readouterr().err
    assert code == 2
    assert "error:" in err.lower()


def test_cli_malformed_xml_exits_2(tmp_path, capsys):
    """CLI returns exit code 2 and prints to stderr for malformed XML."""
    bad = tmp_path / "bad.xml"
    bad.write_text("<not-closed>", encoding="utf-8")
    code = main(["fuzz", str(bad)])
    err = capsys.readouterr().err
    assert code == 2
    assert "error:" in err.lower()


def test_cli_empty_xml_exits_2(tmp_path, capsys):
    """CLI returns exit code 2 and prints to stderr for an empty file."""
    empty = tmp_path / "empty.xml"
    empty.write_text("", encoding="utf-8")
    code = main(["fuzz", str(empty)])
    err = capsys.readouterr().err
    assert code == 2
    assert "error:" in err.lower()


def test_mcp_server_importable():
    """mcp_server must import without errors (broken import is a regression)."""
    import importlib
    mod = importlib.import_module("deeplinkfuzz.mcp_server")
    assert callable(mod.serve)
