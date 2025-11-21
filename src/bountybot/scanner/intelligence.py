"""Lightweight heuristics for classifying scanner output."""

from __future__ import annotations

from collections.abc import Iterable

ROLE_PATTERNS: list[tuple[str, set[str]]] = [
    (
        "File Upload",
        {
            "upload",
            "multipart",
            "file upload",
            "image upload",
            "avatar",
            "attachment",
            "media upload",
        },
    ),
    (
        "Login/Auth Endpoint",
        {
            "login",
            "sign-in",
            "signin",
            "authenticate",
            "authentication",
            "oauth",
            "sso",
            "token",
            "password",
            "session",
        },
    ),
    (
        "Admin Panel",
        {
            "admin",
            "dashboard",
            "control panel",
            "console",
            "cms",
            "backoffice",
        },
    ),
    (
        "Debug/Logging",
        {
            "debug",
            "trace",
            "log",
            "logging",
            "status page",
            "metrics",
            "prometheus",
        },
    ),
]

INSIGHT_PATTERNS: list[tuple[set[str], str]] = [
    ({"sqli", "sql injection", "blind-sql"}, "SQLi Suspected"),
    ({"xss", "cross-site scripting"}, "XSS Exposure"),
    ({"lfi", "rfi", "file inclusion", "directory traversal"}, "File Disclosure Risk"),
    ({"rce", "command-injection", "remote code execution"}, "RCE Potential"),
    ({"csrf", "cross-site request forgery"}, "CSRF Vector"),
    ({"ssrf", "request forgery"}, "SSRF Potential"),
    ({"open-redirect", "redirect"}, "Open Redirect"),
    ({"token", "cookie", "jwt"}, "Session Token Exposure"),
    ({"bucket", "s3", "storage"}, "Storage Exposure"),
    ({"debug", "stacktrace"}, "Debug Information Leak"),
]


def _ensure_iterable(value: object) -> Iterable[str]:
    """Normalize arbitrary inputs into an iterable of strings."""
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Iterable):
        return value  # type: ignore[return-value]
    return ()


def _collect_text(finding: dict) -> tuple[str, set[str]]:
    """Collapse relevant fields and tags into a lowercase blob plus a tag set."""
    info = finding.get("info") or {}
    fragments: list[str] = []

    for candidate in (
        finding.get("template-id"),
        info.get("name"),
        info.get("description"),
        finding.get("matched-at"),
        info.get("reference"),
    ):
        if candidate:
            fragments.append(str(candidate))

    tag_set: set[str] = set()
    for container in (_ensure_iterable(info.get("tags")), _ensure_iterable(finding.get("tags"))):
        for entry in container:
            if entry:
                tag_set.add(str(entry).lower())
                fragments.append(str(entry))

    text_blob = " ".join(fragments).lower()
    return text_blob, tag_set


def _text_contains(text: str, keywords: set[str], tags: set[str]) -> bool:
    return any(keyword in text for keyword in keywords) or bool(tags & keywords)


def _role_from_path(path: str) -> str | None:
    """Fast-path role inference using just the matched URL path."""
    if not path:
        return None

    if "login" in path or "auth" in path:
        return "Login/Auth Endpoint"
    if "admin" in path:
        return "Admin Panel"
    if "upload" in path or "/image" in path:
        return "File Upload"
    if "/basic-auth" in path:
        return "Auth Endpoint"
    if "/status/" in path:
        return "Status Checker/API Gate"
    return None


def determine_endpoint_role(finding: dict) -> str:
    """Infer the high-level purpose of an endpoint based on nuclei metadata."""

    matched_at = (finding.get("matched-at") or "").lower()
    path_role = _role_from_path(matched_at)
    if path_role:
        return path_role

    text_blob, tags = _collect_text(finding)

    for role, keywords in ROLE_PATTERNS:
        if _text_contains(text_blob, keywords, tags):
            return role

    if "api" in text_blob or "graphql" in text_blob:
        return "API Endpoint"
    if "database" in text_blob or "sql" in text_blob:
        return "Database Service"

    return "Debug/Logging"


def infer_insights(template_id: str | None, finding: dict) -> list[str]:
    """Produce human-friendly insight tags for a nuclei finding."""

    text_blob, tags = _collect_text(finding)
    info = finding.get("info") or {}
    severity = str(info.get("severity") or "").lower()
    normalized_id = (template_id or "").lower()

    insights: list[str] = []

    def add(label: str) -> None:
        if label not in insights:
            insights.append(label)

    for keywords, label in INSIGHT_PATTERNS:
        if _text_contains(text_blob, keywords, tags):
            add(label)

    if severity in {"critical", "high"}:
        add("High Priority")
    elif severity == "medium":
        add("Needs Review")

    if normalized_id.startswith("cve-"):
        add("CVE Coverage")

    role = finding.get("__arcanum_role")
    if role and role != "General Endpoint":
        add(f"Sensitive Role: {role}")

    return insights


__all__ = ["determine_endpoint_role", "infer_insights"]
