"""Legacy pipeline wrapper for running a full assessment and saving a JSON report.

This mirrors the executor flow but keeps the output in a single report file,
useful for synchronous or CLI-driven runs.
"""

import json
from pathlib import Path

from src.bountybot.tools.runner import run_all_tools
from src.bountybot.analyzer.chainsynthesizer import synthesize_attack_paths
from src.bountybot.exploits.payload_builder import (
    generate_for_vulnerability_chain,
    simulate_attack_attempt,
)
from src.bountybot.reporting.bounty_writer import write_bounty_report
from src.bountybot.scanner.intelligence import determine_endpoint_role

async def run_complete_assessment(target_url):
    # Run the end-to-end workflow for one target and emit a JSON report.
    print("[*] Running Comprehensive Scan...")
    findings = await run_nuclei_scan(target_url)  # Currently uses mocked runner output.

    print("[*] Analyzing Roles...")
    # Attach inferred roles to each finding so downstream synthesis has context.
    enriched_findings = []
    for f in findings:
        role = determine_endpoint_role(f)
        f['__arcanum_role'] = role
        enriched_findings.append(f)

    print("[*] Building Attack Pathways...")
    chains = synthesize_attack_paths(enriched_findings)

    print("[*] Generating Payload Options...")
    # Build a flat queue of payloads associated with their originating chains.
    payloads = []
    for chain in chains:
        pl_list = generate_for_vulnerability_chain(chain, enriched_findings)
        for p in pl_list:
            payloads.append((p, chain))

    print("[*] Simulating Payload Delivery...")
    simulation_results = simulate_attack_attempt(payloads, target_url)

    print("[*] Saving to Report...")
    # Persist the full assessment details for later inspection.
    report_output = {
        "target": target_url,
        "findings": findings,
        "paths": chains,
        "payloads": payloads,
        "simulation_results": simulation_results,
    }

    report_path = Path(
        f"report_{target_url.replace('://', '_').replace('/', '')}.json"
    )
    report_path.write_text(json.dumps(report_output, indent=2))

    print("[✓] Assessment complete.")

async def run_nuclei_scan(target_url):
    """Fetch nuclei findings via the tool runner."""

    # Tool runner returns a dict keyed by tool name; we only need nuclei here.
    tool_results = await run_all_tools(target_url)
    return tool_results.get("nuclei", [])
