"""Command-line interface for running the Multiscan Pentest Suite."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import click

from bountybot.analyzer.chainsynthesizer import synthesize_attack_paths
from bountybot.data.model import init_db, retrieve_successful_chains
from bountybot.reporting.bounty_writer import write_bounty_report
from bountybot.scanner.intelligence import determine_endpoint_role, infer_insights
from bountybot.tools.runner import run_all_tools


@click.command()
@click.argument("url")
def main(url: str) -> None:
    """Run the multi-tool scan suite synchronously."""

    # Click entry point delegates to the async routine.
    asyncio.run(_async_main(url))


async def _async_main(url: str) -> None:
    # Ensure the SQLite backing store exists before logging anything.
    init_db()
    click.echo("[🔍] Launching Multiscan Pentest Suite...")

    # Fan out to all tools and collect their results.
    all_results = await run_all_tools(url)

    nuclei_results = all_results.get("nuclei", [])
    amass_results = all_results.get("amass", [])
    ffuf_results = all_results.get("ffuf", [])

    click.echo(f"[+] Collected {len(nuclei_results)} nuclei findings")
    click.echo(f"[+] Enumerated {len(amass_results)} subdomains")
    click.echo(f"[+] Found {len(ffuf_results)} directories via dirbust")

    process_findings(url, nuclei_results)


def process_findings(target: str, findings: list[dict]) -> None:
    """Pretty-print nuclei findings with analyst-focused enrichment."""

    if not findings:
        click.echo("\n[-] No issues found with the selected profile.")
        return

    click.echo("\n🔍 Findings List\n" + "=" * 40)

    severity_counts: dict[str, int] = {}
    role_counts: dict[str, int] = {}

    for item in findings:
        # Basic nuclei metadata extraction.
        template_id = item.get("template-id", "unknown")
        matcher_name = item.get("matcher-name") or ""
        matched_at = item.get("matched-at", "")

        info = item.get("info", {}) or {}
        severity = (info.get("severity") or "unknown").capitalize()
        name = info.get("name", "[Unnamed Template]")

        # Enrich with role and LLM-style insights for analyst context.
        role_category = determine_endpoint_role(item)
        item["__arcanum_role"] = role_category

        insights = infer_insights(template_id, item)
        display_title = f"{name} ({matcher_name}) [{severity}]".strip()

        click.echo(f"\n📌 {display_title}")
        click.echo(f"   Location: {matched_at or 'Unknown'}")
        click.echo(f"   Matched By: {template_id}")
        click.echo(f"   Detected Role: {role_category}")

        if insights:
            click.echo(f"   Intelligence Tags: {', '.join(insights)}")

        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        role_counts[role_category] = role_counts.get(role_category, 0) + 1

    click.echo("\n🧠 Endpoint Role Distribution")
    click.echo("=" * 40)
    for role, count in sorted(role_counts.items(), key=lambda kv: (-kv[1], kv[0])):
        click.echo(f"{role}: {count}")

    click.echo("\n📊 Summary")
    click.echo("=" * 40)
    for severity, count in sorted(severity_counts.items(), key=lambda kv: (-kv[1], kv[0])):
        click.echo(f"{severity}: {count}")

    click.echo(f"\nTotal Issues Found: {len(findings)}")

    render_attack_chains(findings)


def render_attack_chains(findings: list[dict]) -> None:
    """Display synthesized multi-step attack paths if any are detected."""

    click.echo("\n🔗 Attack Chain Recommendations")
    click.echo("=" * 40)

    # Synthesize attack paths based on roles and tags, then write bounty drafts.
    attack_chains = synthesize_attack_paths(findings)
    bounty_reports = generate_bounty_files(attack_chains)

    if attack_chains:
        for chain in attack_chains:
            score = chain.get("risk_score", "N/A")
            name = chain.get("name", "Unnamed Attack Path")
            description = chain.get("description", "No description provided.")

            click.echo(f"\n🔹 [{score}% Risk] {name}")
            click.echo(description)

        bounty_path = Path("bounty_reports.json")
        bounty_path.write_text(json.dumps(bounty_reports, indent=2))
        click.echo(f"\n[+] Wrote {bounty_path} with synthesized drafts.")
    else:
        click.echo("No multi-step attack paths detected based on current findings.")

    known_good_chains = retrieve_successful_chains()

    click.echo("\n🧠 Previously Successful Vectors in History")
    click.echo("=" * 40)
    if not known_good_chains:
        click.echo("No successful historical chains logged yet.")
    for chain_desc, tags in known_good_chains:
        click.echo(f"- 🟢 {chain_desc}")


def generate_bounty_files(chains: list[dict]) -> list[dict]:
    """Produce bounty draft content for each synthesized attack chain."""

    reports: list[dict] = []
    for chain in chains:
        title = chain.get("name", "Unnamed Attack Chain")
        full_desc = chain.get("description", "No description provided.")
        rep = write_bounty_report(title=title, summary=full_desc)
        reports.append(rep)
    return reports

if __name__ == "__main__":
    main()
