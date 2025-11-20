# pipeline.py

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
    print("[*] Running Comprehensive Scan...")
    findings = await run_nuclei_scan(target_url)

    print("[*] Analyzing Roles...")
    enriched_findings = []
    for f in findings:
        role = determine_endpoint_role(f)
        f['__arcanum_role'] = role
        enriched_findings.append(f)

    print("[*] Building Attack Pathways...")
    chains = synthesize_attack_paths(enriched_findings)

    print("[*] Generating Payload Options...")
    payloads = []
    for chain in chains:
        pl_list = generate_for_vulnerability_chain(chain, enriched_findings)
        for p in pl_list:
            payloads.append((p, chain))

    print("[*] Simulating Payload Delivery...")
    simulation_results = simulate_attack_attempt(payloads, target_url)

    print("[*] Saving to Report...")
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

    tool_results = await run_all_tools(target_url)
    return tool_results.get("nuclei", [])
