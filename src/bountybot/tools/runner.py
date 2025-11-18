# src/bountybot/tools/runner.py

import json
import shutil
import subprocess
from typing import Dict


class ToolExecutionError(RuntimeError):
    """Raised when an external security tool fails to run."""


TOOLS = {
    'nuclei': {
        'cmd': ['nuclei', '-u', '{target}', '-silent', '-jsonl', '-no-meta'],
        'parser': lambda out: [
            json.loads(line)
            for line in out.splitlines()
            if line.strip()
        ],
        'timeout': 300,
    },
    'amass': {
        'cmd': ['amass', 'enum', '-d', '{domain}', '-silent'],
        'parser': lambda out: [
            {'subdomain': line.strip()}
            for line in out.splitlines()
            if line.strip()
        ],
        'timeout': 180,
    },
    'ffuf': {
        'cmd': [
            'ffuf',
            '-u', '{target}/FUZZ',
            '-w', '/usr/share/wordlists/dirbuster.txt',
            '-mc', '200',
            '-s',
        ],
        'parser': lambda out: [
            {'path': line.strip()}
            for line in out.splitlines()
            if line.strip()
        ],
        'timeout': 180,
    },
}


def run_tool(tool_name: str, target: str, domain: str | None = None) -> Dict[str, list]:
    """Run selected security tools with specified arguments."""

    tool_config = TOOLS[tool_name]
    cmd_template = tool_config['cmd']
    parsed_target = target.rstrip('/')
    computed_domain = domain or parsed_target.split('//')[-1].split('/')[0]

    cmd = [
        arg.format(target=parsed_target, domain=computed_domain)
        for arg in cmd_template
    ]

    binary = cmd[0]
    if shutil.which(binary) is None:
        return {tool_name: []}

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=tool_config.get('timeout', 180),
            check=False,
        )
    except FileNotFoundError as exc:
        raise ToolExecutionError(f"Missing tool binary: {binary}") from exc

    if completed.returncode not in (0, 1):
        raise ToolExecutionError(
            f"{tool_name} exited with code {completed.returncode}: {completed.stderr.strip()}"
        )

    parser = tool_config['parser']
    result = parser(completed.stdout)

    return {tool_name: result}


def run_all_tools(target: str) -> Dict[str, list]:
    """Execute each configured tool sequentially and merge their results."""

    merged: Dict[str, list] = {}

    for tool_name in TOOLS.keys():
        try:
            merged.update(run_tool(tool_name, target))
        except ToolExecutionError:
            # Skip failing tool but continue with the rest
            continue

    return merged
