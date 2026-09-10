import requests
import json
import re


def analyze_vulnerability(name, description):

    prompt = f"""
You are a cybersecurity expert.

Analyze the vulnerability.

Return ONLY JSON.

NO explanation.
NO extra text.

Format exactly:

{{
"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
"cwe":"CWE-639"
}}

Vulnerability Name:
{name}

Description:
{description}
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

    text = result["response"]

    # Extract JSON only
    match = re.search(r"\{[\s\S]*\}", text)

    if match:
        return match.group()

    return json.dumps({
        "cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cwe":"CWE-20"
    })