# intelligence.py

import re

def infer_insights(template_id, metadata):
    """
    Give our AI actor some dynamic ability to reason why this matters.
    Could later extend with LLM-style prompt injections or lexical embeddings.
    """
    hints = []

    # Local lookup of known patterns
    reason_map = {
        'cves/CVE-2021-XXXX.yaml': ['critical-old-cwe-vuln', 'historical-risk'],
        'misconfiguration/admin-panel.yaml': ['exposed-admin-functionality'],
        'exposures/apis/swagger-endpoint.yaml': ['info-leak-metadata'],
        'takeovers/github-pages.yaml': ['resource-dangling', 'supplychain-risk'],
        'cves/CVE-2023-SQL.yaml': ['high-jwt-reuse-risk'],
    }

    hints.extend(reason_map.get(template_id, []))

    # Check for common enrichment heuristics
    matcher_name = metadata.get("matcher-name", "")
    matched_at = metadata.get("matched-at", "")

    if matcher_name and "-shared-api-key" in matcher_name.lower():
        hints.append("identifier-key-leak")

    if matched_at:
        if ".internal." in matched_at or "internal." in matched_at:
            hints.append("internal_vector_detected")
        if any(kw in matched_at for kw in ['admin', 'config', 'setup']):
            hints.append("sensitive-area-accessed")

    return hints


def determine_endpoint_role(metadata: dict) -> str:
    """
    Attempt behavioral fingerprint analysis of an endpoint.
    Classify as one of:
        'Login/Auth Endpoint',
        'Admin Panel',
        'User Management',
        'Public API',
        'API Gateway',
        'Debug/Logging',
        'File Upload',
        'Unknown Behavior'
    """

    matched_at = metadata.get("matched-at", "")
    response_headers = metadata.get("curl-meta", {}).get("response-headers", "")
    response_status = metadata.get("curl-meta", {}).get("status-code", 200)
    request_method = metadata.get("curl-meta", {}).get("method", "GET")

    header_text = "\n".join([f"{k}: {v}" for k, v in response_headers.items()]) if isinstance(response_headers, dict) else ""

    # Simple rule-based classifier
    if "Authorization" in header_text or "Bearer" in header_text:
        return "Login/Auth Endpoint"
    elif any(kw in matched_at.lower() for kw in ["login", "auth", "signin"]):
        return "Login/Auth Endpoint"
    elif any(kw in matched_at for kw in ["/admin", "/settings", "/config"]):
        return "Admin Panel"
    elif "CORS" in header_text and "*" in header_text:
        if "Access-Control-Allow-Origin" in header_text and response_status in [200, 400]:
            return "API Gateway"
    elif "Content-Type: application/json" in header_text:
        # JSON APIs often involved in business logic
        # Check for POST/PUT + error handling variation
        if request_method in ["POST", "PUT"] and response_status == 200:
            return "Data Processor / Service Handler"
        elif request_method == "GET" and "results" in str(metadata.get("matched", "")):
            return "Public API"
    elif "X-Powered-By" in header_text or "Server:" in header_text:
        # Debug-style responses
        return "Debug/Logging"
    elif any(kw in header_text.lower() for kw in ["upload", "multipart"]):
        return "File Upload"

    return "Unknown Behavior"


# Also export helper
__all__ = ["infer_insights", "determine_endpoint_role"]