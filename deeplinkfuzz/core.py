"""Core engine for DEEPLINKFUZZ.

The engine:
  1. Parses an Android manifest (XML) and enumerates EXPORTED entry points
     (activities/services/receivers) that declare intent-filters, extracting
     the deep-link surface: scheme://host/path declared in <data> elements.
  2. Generates mutated payloads (SQLi, path traversal, XSS, command/intent
     injection, format strings, overflow) injected into the path and query
     parameters of each deep link.
  3. "Replays" each mutated link through a deterministic vulnerability
     detector that models how a vulnerable component would reflect/handle the
     input, producing reproducible findings (no network, CI-safe).

Everything is standard-library only and deterministic.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Dict, Iterable, List, Optional
import xml.etree.ElementTree as ET

# Android namespace used by manifest attributes.
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class EntryPoint:
    """An exported component reachable via an intent / deep link."""
    component: str            # fully-qualified-ish class name
    kind: str                 # activity | service | receiver
    exported: bool
    schemes: List[str] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    permission: Optional[str] = None
    # Ordered list of (scheme, host, path) tuples — one per <data> element.
    # When populated, deep_links() uses these directly instead of the
    # cross-product of schemes x hosts x paths.
    data_templates: List[tuple] = field(default_factory=list)

    def deep_links(self) -> List[str]:
        """Concrete scheme://host/path templates this component answers to.

        Each <data> element in the manifest defines one URI template
        (scheme://host/path).  When data_templates is populated (the normal
        path), return exactly those links.  Otherwise fall back to the
        cross-product of schemes x hosts x paths for backward compatibility.
        """
        links: List[str] = []
        if self.data_templates:
            seen: set = set()
            for scheme, host, path in self.data_templates:
                if not scheme:
                    continue
                h = host or "app"
                p = path if path.startswith("/") else "/" + path if path else "/"
                link = f"{scheme}://{h}{p}"
                if link not in seen:
                    seen.add(link)
                    links.append(link)
            return links
        # Legacy fallback: cross-product (used when data_templates is empty)
        schemes = self.schemes or ([] if self.hosts or self.paths else [])
        hosts = self.hosts or [""]
        paths = self.paths or ["/"]
        for s in schemes:
            for h in hosts:
                for p in paths:
                    host = h or "app"
                    path = p if p.startswith("/") else "/" + p if p else "/"
                    links.append(f"{s}://{host}{path}")
        return links


@dataclass
class FuzzCase:
    """A single mutated request to replay against an entry point."""
    component: str
    base_link: str
    payload_name: str
    payload: str
    target: str               # 'path' or 'query'
    url: str


@dataclass
class Finding:
    component: str
    kind: str
    url: str
    payload_name: str
    payload: str
    category: str
    severity: str
    evidence: str

    def as_dict(self) -> Dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Payload corpus. Each entry: name -> (string, category, severity).
# ---------------------------------------------------------------------------
PAYLOADS: Dict[str, tuple] = {
    "sqli_or": ("' OR '1'='1", "sql_injection", "high"),
    "sqli_union": ("1 UNION SELECT password FROM users--", "sql_injection", "critical"),
    "sqli_stack": ("1; DROP TABLE users--", "sql_injection", "critical"),
    "path_traversal": ("../../../../etc/passwd", "path_traversal", "high"),
    "path_traversal_enc": ("..%2f..%2f..%2fetc%2fpasswd", "path_traversal", "high"),
    "xss_script": ("<script>alert(1)</script>", "xss", "medium"),
    "xss_img": ("<img src=x onerror=alert(1)>", "xss", "medium"),
    "cmd_inject": ("; cat /etc/passwd", "command_injection", "critical"),
    "cmd_backtick": ("`id`", "command_injection", "critical"),
    "intent_redirect": ("intent://evil/#Intent;scheme=app;end", "intent_redirection", "high"),
    "format_str": ("%n%n%n%s%s", "format_string", "medium"),
    "overflow": ("A" * 4096, "buffer_overflow", "low"),
    "null_byte": ("file.txt%00.png", "null_byte_injection", "medium"),
}


def _attr(elem: ET.Element, name: str) -> Optional[str]:
    """Read an android:* attribute, tolerating namespaced or bare names."""
    val = elem.get(ANDROID_NS + name)
    if val is None:
        val = elem.get("android:" + name)
    if val is None:
        val = elem.get(name)
    return val


def _truthy(val: Optional[str]) -> bool:
    return str(val).strip().lower() in ("true", "1", "yes")


def parse_manifest(text: str) -> ET.Element:
    """Parse manifest XML text and return the root element."""
    try:
        return ET.fromstring(text)
    except ET.ParseError as exc:  # pragma: no cover - error path
        raise ValueError(f"invalid manifest XML: {exc}") from exc


def enumerate_entry_points(text: str, include_unexported: bool = False) -> List[EntryPoint]:
    """Enumerate exported components with intent-filters from a manifest.

    A component is treated as exported when android:exported=\"true\", or when
    exported is unspecified AND it declares at least one intent-filter (the
    historical Android default that exposes the component).
    """
    root = parse_manifest(text)
    results: List[EntryPoint] = []
    kinds = {"activity": "activity", "activity-alias": "activity",
             "service": "service", "receiver": "receiver"}
    # Search anywhere under the tree (application/*).
    for elem in root.iter():
        tag = elem.tag.split("}")[-1]
        if tag not in kinds:
            continue
        filters = [c for c in elem if c.tag.split("}")[-1] == "intent-filter"]
        name = _attr(elem, "name") or "(unnamed)"
        exported_attr = _attr(elem, "exported")
        if exported_attr is None:
            exported = bool(filters)
        else:
            exported = _truthy(exported_attr)
        if not exported and not include_unexported:
            continue

        schemes: List[str] = []
        hosts: List[str] = []
        paths: List[str] = []
        actions: List[str] = []
        data_templates: List[tuple] = []
        for f in filters:
            for child in f:
                ctag = child.tag.split("}")[-1]
                if ctag == "data":
                    s = _attr(child, "scheme")
                    h = _attr(child, "host")
                    # Find the first path-like attribute for this data element.
                    pv = None
                    for pa in ("path", "pathPrefix", "pathPattern"):
                        pv = _attr(child, pa)
                        if pv:
                            break
                    # Record as a complete URI template when scheme is present.
                    if s:
                        tpl = (s, h or "", pv or "/")
                        if tpl not in data_templates:
                            data_templates.append(tpl)
                    # Also maintain legacy flat lists for serialisation compat.
                    if s and s not in schemes:
                        schemes.append(s)
                    if h and h not in hosts:
                        hosts.append(h)
                    for pa in ("path", "pathPrefix", "pathPattern"):
                        pv2 = _attr(child, pa)
                        if pv2 and pv2 not in paths:
                            paths.append(pv2)
                elif ctag == "action":
                    a = _attr(child, "name")
                    if a and a not in actions:
                        actions.append(a)
        results.append(EntryPoint(
            component=name,
            kind=kinds[tag],
            exported=exported,
            schemes=schemes,
            hosts=hosts,
            paths=paths,
            actions=actions,
            permission=_attr(elem, "permission"),
            data_templates=data_templates,
        ))
    return results


def build_deep_link(base: str, payload: str, target: str) -> str:
    """Inject a payload into either the path or a query parameter of a link."""
    enc = _percent_encode(payload)
    if target == "query":
        sep = "&" if "?" in base else "?"
        return f"{base}{sep}q={enc}"
    # target == path: append the payload as a new path segment
    if base.endswith("/"):
        return base + enc
    return base + "/" + enc


def _percent_encode(s: str) -> str:
    """Minimal URL encoding that preserves the markers our detector keys on.

    We intentionally keep payload-defining characters intact so the simulated
    vulnerable handler can observe them, while encoding spaces.
    """
    return s.replace(" ", "%20")


def mutate(entry: EntryPoint) -> List[FuzzCase]:
    """Produce all fuzz cases for an entry point's deep links."""
    cases: List[FuzzCase] = []
    for link in entry.deep_links():
        for pname, (payload, _cat, _sev) in PAYLOADS.items():
            for target in ("path", "query"):
                url = build_deep_link(link, payload, target)
                cases.append(FuzzCase(
                    component=entry.component,
                    base_link=link,
                    payload_name=pname,
                    payload=payload,
                    target=target,
                    url=url,
                ))
    return cases


# ---------------------------------------------------------------------------
# Detection. Deterministic model of how a vulnerable handler would react.
# ---------------------------------------------------------------------------
_DETECTORS = [
    ("sql_injection", re.compile(r"('\s*OR\s*'?1'?='?1|UNION\s+SELECT|DROP\s+TABLE|;\s*DROP)", re.I)),
    ("command_injection", re.compile(r"(;\s*cat\s|`[^`]+`|\|\s*sh\b|&&\s*\w)", re.I)),
    ("path_traversal", re.compile(r"(\.\./|\.\.%2f|/etc/passwd)", re.I)),
    ("intent_redirection", re.compile(r"intent://", re.I)),
    ("xss", re.compile(r"(<script|onerror=|<img\s)", re.I)),
    ("format_string", re.compile(r"(%n|%s%s%s)", re.I)),
    ("null_byte_injection", re.compile(r"%00", re.I)),
    ("buffer_overflow", re.compile(r"A{1024,}")),
]


def detect_vulnerabilities(entry: EntryPoint, cases: Iterable[FuzzCase]) -> List[Finding]:
    """Replay fuzz cases and emit findings.

    The replay decodes the URL and applies detector signatures. A component
    that is exported WITHOUT a guarding permission is considered reachable, so
    any payload class that survives in the decoded link is reported. Components
    that require a custom permission downgrade severity (still reported as the
    permission may be a normal-protection level reachable by any app).
    """
    findings: List[Finding] = []
    guarded = bool(entry.permission)
    for case in cases:
        decoded = case.url.replace("%20", " ")
        for category, rx in _DETECTORS:
            m = rx.search(decoded)
            if not m:
                continue
            _payload, pcat, sev = PAYLOADS[case.payload_name]
            if pcat != category:
                continue
            severity = sev
            if guarded and SEVERITY_ORDER[severity] > SEVERITY_ORDER["medium"]:
                severity = "medium"
            evidence = (
                f"exported {entry.kind} reflects {category} marker "
                f"'{m.group(0).strip()}' via {case.target}"
                + (f" (guarded by {entry.permission})" if guarded else " (no permission guard)")
            )
            findings.append(Finding(
                component=entry.component,
                kind=entry.kind,
                url=case.url,
                payload_name=case.payload_name,
                payload=case.payload,
                category=category,
                severity=severity,
                evidence=evidence,
            ))
            break  # one finding per case
    return findings


def fuzz_manifest(text: str, include_unexported: bool = False,
                  min_severity: str = "info") -> Dict:
    """End-to-end: enumerate -> mutate -> detect. Returns a result dict."""
    threshold = SEVERITY_ORDER.get(min_severity, 0)
    entries = enumerate_entry_points(text, include_unexported=include_unexported)
    all_findings: List[Finding] = []
    total_cases = 0
    for entry in entries:
        cases = mutate(entry)
        total_cases += len(cases)
        for f in detect_vulnerabilities(entry, cases):
            if SEVERITY_ORDER[f.severity] >= threshold:
                all_findings.append(f)
    all_findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.component, f.category))
    sev_counts: Dict[str, int] = {}
    for f in all_findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    return {
        "entry_points": [asdict(e) for e in entries],
        "entry_point_count": len(entries),
        "fuzz_cases": total_cases,
        "findings": [f.as_dict() for f in all_findings],
        "finding_count": len(all_findings),
        "severity_counts": sev_counts,
    }
