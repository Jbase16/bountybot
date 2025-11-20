"""Mocked tool runner to avoid long-running external scans."""

from __future__ import annotations

import asyncio
import json

MOCK_NUCLEI_RESULTS = [
    {
        "template-id": "cves/CVE-2021-1234",
        "info": {
            "name": "Example Vulnerable Component",
            "severity": "high",
        },
        "matched-at": "http://httpbin.org/forms/post",
        "matcher-name": "FormHandler",
    },
    {
        "template-id": "misconfig/admin-panel",
        "info": {
            "name": "Admin Panel Exposure",
            "severity": "medium",
        },
        "matched-at": "http://httpbin.org/admin/login",
        "matcher-name": "",
    },
]

MOCK_AMASS_RESULTS = [
    {"subdomain": "api.httpbin.org"},
    {"subdomain": "dev.httpbin.org"},
]

MOCK_FFUF_RESULTS = [
    {"ffuf": "/basic-auth/user/passwd"},
    {"ffuf": "/bearer"},
    {"ffuf": "/status/418"},
]


async def run_tool(tool_name, target, domain=None):
    """Return canned responses after a small delay to mimic IO."""

    await asyncio.sleep(0.1)

    mocks = {
        "nuclei": MOCK_NUCLEI_RESULTS,
        "amass": MOCK_AMASS_RESULTS,
        "ffuf": MOCK_FFUF_RESULTS,
    }

    return {tool_name: mocks.get(tool_name, [])}


async def run_all_tools(target):
    """Launch mocked tool executions concurrently and merge their outputs."""

    domain = target.split("//")[1] if "//" in target else target

    tasks = [
        run_tool("nuclei", target),
        run_tool("amass", target, domain=domain),
        run_tool("ffuf", target),
    ]

    merged = {}
    for result in await asyncio.gather(*tasks):
        merged.update(result)

    return merged


__all__ = ["run_tool", "run_all_tools"]
