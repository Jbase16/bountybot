"""Mock tool runner used until the real integrations are wired up."""

from __future__ import annotations

import asyncio
from typing import Dict, List

MOCK_NUCLEI_RESULTS: List[dict] = [
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

MOCK_AMASS_RESULTS: List[dict] = [
    {"subdomain": "api.httpbin.org"},
    {"subdomain": "dev.httpbin.org"},
]

MOCK_FFUF_RESULTS: List[dict] = [
    {"path": "/basic-auth/user/passwd"},
    {"path": "/bearer"},
    {"path": "/status/418"},
]


async def run_tool(tool_name: str, target: str, domain: str | None = None) -> Dict[str, list]:
    """Simulate a tool invocation with a short delay and canned output."""

    await asyncio.sleep(0.1)  # mimic IO latency so async scheduling is exercised

    mock_payloads = {
        "nuclei": MOCK_NUCLEI_RESULTS,
        "amass": MOCK_AMASS_RESULTS,
        "ffuf": MOCK_FFUF_RESULTS,
    }
    return {tool_name: mock_payloads.get(tool_name, [])}


def _extract_domain(target: str) -> str:
    remainder = target.split("//", 1)[-1]
    return remainder.split("/", 1)[0]


async def run_all_tools(target: str) -> Dict[str, list]:
    """
    Launch all mock tools concurrently and merge their JSON-friendly payloads.
    """

    domain = _extract_domain(target)
    tasks = (
        run_tool("nuclei", target),
        run_tool("amass", target, domain=domain),
        run_tool("ffuf", target),
    )

    merged: Dict[str, list] = {}
    for result in await asyncio.gather(*tasks):
        merged.update(result)

    return merged


__all__ = ["run_tool", "run_all_tools"]
