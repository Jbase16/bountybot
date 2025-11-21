"""Rule-based attack chain synthesis based on nuclei findings."""

def synthesize_attack_paths(scan_results):
    """
    Analyze multiple vulnerabilities and propose feasible multistep attack vectors.
    Returns list of possible paths composed of two or more related findings.
    """
    # Accumulator for generated attack paths.
    paths = []

    # Buckets for simple rule matching.
    auth_endpoints = []
    uploads = []
    sqli_points = []
    exposed_admins = []
    debug_pages = []

    role_index = {}  # Map endpoints by their inferred roles (reserved for future logic)

    # Index findings by inferred role to feed the rule engine below.
    for idx, item in enumerate(scan_results):
        role = item.get('__arcanum_role', 'Unknown')
        endpoint = item.get('matched-at', '')
        name = item.get("info", {}).get("name", "Unnamed")

        scan_results[idx]['__endpoint_idx'] = idx  # For linking later

        if role == 'Login/Auth Endpoint':
            auth_endpoints.append((idx, endpoint, name))
        elif role == 'File Upload':
            uploads.append((idx, endpoint, name))
        elif role == 'Admin Panel':
            exposed_admins.append((idx, endpoint, name))
        elif role == 'Debug/Logging':
            debug_pages.append((idx, endpoint, name))
        elif "sql injection" in name.lower() or any(tag in item.get("tags", []) for tag in ["sqli"]):
            sqli_points.append((idx, endpoint, name))

    # 🧠 Strategy Rules Engine - Basic Examples Follow

    # 1️⃣ Chain: File Upload + Auth Defects => Privilege Escalation Vector
    for upload_idx, u_path, u_name in uploads:
        for auth_idx, auth_path, auth_name in auth_endpoints:
            paths.append({
                'id': f'path_{len(paths)+1}',
                'name': 'Web Shell via Weak Auth',
                'description': (
                    f"A public file upload path at '{u_path}' exists alongside weak authentication at '{auth_path}'. "
                    "An attacker leveraging the upload may establish persistent access and manipulate authenticated sessions."
                ),
                'steps': [upload_idx, auth_idx],
                'risk_score': 90
            })

    # 2️⃣ Debug Page Revealing Secrets + Internal Endpoints -> Information Leakage Cascade
    for dbg_idx, d_path, d_name in debug_pages:
        combined = [(dbg_idx, d_path)] + [(idx, ep) for idx, ep, nm in exposed_admins]
        if combined:
            paths.append({
                'id': f'path_{len(paths)+1}',
                'name': 'Internal Recon Lead via Debug Info',
                'description': (
                    f"The debug page located at '{d_path}' reveals internal configurations and exposed admin panels."
                ),
                'steps': [step[0] for step in combined],
                'risk_score': 60
            })

    # 3️⃣ SQLi Leads to Credential Theft Enabling Access to Protected Services
    for sql_idx, s_path, s_name in sqli_points:
        combined_with_auth = [(sql_idx, s_path)] + [(a_i, ap) for a_i, ap, anm in auth_endpoints]
        if combined_with_auth:
            paths.append({
                'id': f'path_{len(paths)+1}',
                'name': 'Database Breach to Session Stealing',
                'description': (
                    f"SQL Injection at '{s_path}' combined with access to login endpoints allows credential leaks leading to impersonation attacks."
                ),
                'steps': [step[0] for step in combined_with_auth],
                'risk_score': 95
            })

    return paths
