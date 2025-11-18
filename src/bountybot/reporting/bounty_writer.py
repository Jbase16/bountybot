# src/bountybot/reporting/bounty_writer.py

DEFAULT_PROMPT = """
Given the following technical vulnerability summary:

"{summary}"

Write a professional and concise report suitable for submission to a bug bounty program. Include the following sections:

### Description
Explain clearly how the vulnerability occurs without disclosing sensitive information.

### Proof of Concept
Demonstrate the flaw with a minimal example (curl, etc).

### Impact
Describe what an attacker could do.

### Recommendation
Provide a fix suggestion.
"""

def write_bounty_report(title, summary, severity='high'):
    prompt = DEFAULT_PROMPT.format(summary=summary)
    # Here, we'd ideally plug in a model call like using Ollama or OpenAI API
    # But for prototype purposes, return a static structure + the prompt

    response = simulate_llm_response(prompt)

    return {
        'title': title,
        'severity': severity,
        'prompt_used': prompt,
        'generated_content': response
    }

def simulate_llm_response(prompt):
    # For demo only; replace with actual API or local inference
    return f"""
**Report Title**: Vulnerability Detected

**Summary**: {prompt[:100]}...
...Full generated content would appear here via LLM inference.
"""