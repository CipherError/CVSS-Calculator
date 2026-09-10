import requests
import json

def analyze_vulnerability(name, description):

    prompt = f"""
You are a cybersecurity expert.

Based on the vulnerability name and description determine:

1. CVSS v3.1 vector
2. CWE ID

Return ONLY JSON.

Example:

{{
"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
"cwe":"CWE-639"
}}

Vulnerability Name: {name}

Description: {description}
"""

    response = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model": "llama3",
            "prompt": prompt,
            "stream": False
        }
    )

    result = response.json()

    return result["response"]