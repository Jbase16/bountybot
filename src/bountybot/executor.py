"""Entry point for the autonomous assessment pipeline.

This module stitches together scanning, classification, path synthesis,
payload simulation, and report generation for a single target URL.
Each phase is intentionally linear so it is easy to follow and modify.
"""

import sys
import json
import asyncio

from src.bountybot.tools.runner import run_all_tools
from src.bountybot.analyzer.chainsynthesizer import synthesize_attack_paths
from src.bountybot.exploits.payload_builder import (
    generate_for_vulnerability_chain,
    simulate_attack_attempt,
)
from src.bountybot.reporting.bounty_writer import write_bounty_report
from src.bountybot.reporting.breach_summary_builder import summarize_attack_path
from src.bountybot.scanner.intelligence import determine_endpoint_role


async def autonomous_assessment_pipeline(target_url):
    # Orchestrates the full assessment lifecycle for a single target URL.
    # Phase 1: Recon Multi-tool — collect findings from all configured scanners.
    results = await run_all_tools(target_url)
    nuclei_findings = results.get('nuclei', [])
    
    # Phase 2: Role Classification — enrich each finding with a coarse role for later chaining.
    classified_findings = []
    for finding in nuclei_findings:
        role = determine_endpoint_role(finding)
        finding['__arcanum_role'] = role
        classified_findings.append(finding)

    # Phase 3: Pathway Synthesis — turn isolated findings into multi-step attack paths.
    attack_paths = synthesize_attack_paths(classified_findings)
    # Ensure downstream report writers know which target the path refers to.
    for path in attack_paths:
        path["target_url"] = target_url

    # Phase 4: Simulate Payloads — build candidate payloads and exercise the simulator.
    payload_queue = []
    for chain in attack_paths:
        payload_candidates = generate_for_vulnerability_chain(chain, classified_findings)
        for payload in payload_candidates:
            payload_queue.append((payload, chain))

    tested_payloads = simulate_attack_attempt(payload_queue, target_url)

    # Phase 5: Auto-bounty Submission Generation — author simple bounty drafts from simulations.
    bounty_docs = [
        write_bounty_report(
            title=entry["chain"].get("name", "Unnamed Attack Chain"),
            summary=entry.get("log_entry", "Simulation details unavailable."),
            severity="High",
        )
        for entry in tested_payloads
    ]

    # Phase 6: Save Results — persist everything for later review and consumption.
    with open('assessment_output.json', 'w') as f:
        json.dump({
            'target': target_url,
            'findings': classified_findings,
            'attack_paths': attack_paths,
            'tested_payloads': tested_payloads,
            'bounty_reports': bounty_docs
        }, f, indent=2)

    print("[✅] Autonomous Assessment Complete: Saved as assessment_output.json")

    # Save markdown-based summaries — each synthesized path gets a human-readable summary.
    summaries_written = []

    for path in attack_paths:
        # Generate a human-ready markdown summary for each synthesized path.
        summary_md = summarize_attack_path(path)
        filename = f"{path['name'].replace(' ', '_').lower()}_summary.md"
        with open(filename, 'w') as f:
            f.write(summary_md)
        summaries_written.append(filename)
        
    print(f"[✅] Generated Markdown Summaries: {', '.join(summaries_written)}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python -m bountybot.executor TARGET_URL")
        exit(1)

    target = sys.argv[1]
    asyncio.run(autonomous_assessment_pipeline(target))
