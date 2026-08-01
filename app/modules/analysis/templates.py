"""
===========================================================
Project : Sentinel AI
Module  : Finding Templates
File ID : ANALYSIS-TEMPLATE-001
Version : 1.0.0
===========================================================

Description:
Central repository of vulnerability templates used by
the Analysis Engine.

===========================================================
"""

from __future__ import annotations

# ===========================================================
# Finding Templates
# ===========================================================

TEMPLATE_DATABASE = {
    # =======================================================
    # Missing Security Headers
    # =======================================================
    "HDR-001": {
        "id": "HDR-001",
        "title": "Missing Content Security Policy",
        "severity": "Medium",
        "cvss": 5.3,
        "module": "headers",
        "description": ("Content-Security-Policy header is missing."),
        "impact": ("May increase the risk of Cross Site Scripting (XSS)."),
        "recommendation": ("Configure a strict Content-Security-Policy header."),
        "references": [
            "https://owasp.org/www-project-secure-headers/",
        ],
        "cwe": "CWE-693",
        "owasp": "A05:2021 Security Misconfiguration",
    },
    # =======================================================
    "HDR-002": {
        "id": "HDR-002",
        "title": "Missing X-Frame-Options",
        "severity": "Medium",
        "cvss": 4.8,
        "module": "headers",
        "description": ("X-Frame-Options header is missing."),
        "impact": ("Application may be vulnerable to Clickjacking."),
        "recommendation": ("Set X-Frame-Options to DENY or SAMEORIGIN."),
        "references": [
            "https://owasp.org/www-project-secure-headers/",
        ],
        "cwe": "CWE-1021",
        "owasp": "A05:2021 Security Misconfiguration",
    },
    # =======================================================
    "HDR-003": {
        "id": "HDR-003",
        "title": "Missing X-Content-Type-Options",
        "severity": "Low",
        "cvss": 3.1,
        "module": "headers",
        "description": ("X-Content-Type-Options header is missing."),
        "impact": ("Browser MIME sniffing may be enabled."),
        "recommendation": ("Set X-Content-Type-Options to nosniff."),
        "references": [
            "https://owasp.org/www-project-secure-headers/",
        ],
        "cwe": "CWE-16",
        "owasp": "A05:2021 Security Misconfiguration",
    },
    # =======================================================
    "HDR-004": {
        "id": "HDR-004",
        "title": "Missing Referrer Policy",
        "severity": "Low",
        "cvss": 2.9,
        "module": "headers",
        "description": ("Referrer-Policy header is missing."),
        "impact": ("Sensitive URLs may leak through Referer headers."),
        "recommendation": ("Configure Referrer-Policy."),
        "references": [
            "https://owasp.org/www-project-secure-headers/",
        ],
        "cwe": "CWE-200",
        "owasp": "A01:2021 Broken Access Control",
    },
    # =======================================================
    "HDR-005": {
        "id": "HDR-005",
        "title": "Missing Permissions Policy",
        "severity": "Low",
        "cvss": 2.7,
        "module": "headers",
        "description": ("Permissions-Policy header is missing."),
        "impact": ("Browser features are not restricted."),
        "recommendation": ("Configure Permissions-Policy."),
        "references": ["https://developer.mozilla.org/"],
        "cwe": "CWE-16",
        "owasp": "A05:2021 Security Misconfiguration",
    },
    # =======================================================
    # WAF
    # =======================================================
    "WAF-001": {
        "id": "WAF-001",
        "title": "Web Application Firewall Detected",
        "severity": "Info",
        "cvss": 0.0,
        "module": "waf",
        "description": ("A Web Application Firewall is protecting the target."),
        "impact": ("Security controls detected."),
        "recommendation": ("Take WAF behavior into account during testing."),
        "references": [],
        "cwe": None,
        "owasp": None,
    },
    "WAF-002": {
        "id": "WAF-002",
        "title": "No Web Application Firewall Detected",
        "severity": "Medium",
        "cvss": 4.0,
        "module": "waf",
        "description": ("No WAF detected."),
        "impact": ("Target may have reduced protection against attacks."),
        "recommendation": ("Deploy a Web Application Firewall."),
        "references": [],
        "cwe": None,
        "owasp": "A05:2021 Security Misconfiguration",
    },
    # =======================================================
    # JavaScript Secrets
    # =======================================================
    "JS-001": {
        "id": "JS-001",
        "title": "Sensitive Secret Found in JavaScript",
        "severity": "High",
        "cvss": 8.2,
        "module": "js_secrets",
        "description": (
            "Sensitive credentials or tokens were found inside JavaScript files."
        ),
        "impact": ("Attackers may abuse exposed secrets to gain unauthorized access."),
        "recommendation": (
            "Remove secrets from client-side JavaScript and store "
            "them securely on the server."
        ),
        "references": [
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        ],
        "cwe": "CWE-798",
        "owasp": "A02:2021 Cryptographic Failures",
    },
    # =======================================================
    # API Discovery
    # =======================================================
    "API-001": {
        "id": "API-001",
        "title": "API Endpoint Discovered",
        "severity": "Info",
        "cvss": 0.0,
        "module": "api",
        "description": ("API endpoint discovered during reconnaissance."),
        "impact": (
            "Endpoint should be reviewed for authentication and "
            "authorization weaknesses."
        ),
        "recommendation": (
            "Validate access controls and perform API security testing."
        ),
        "references": [
            "https://owasp.org/API-Security/",
        ],
        "cwe": None,
        "owasp": "API Security Top 10",
    },
    # =======================================================
    # Parameters
    # =======================================================
    "PARAM-001": {
        "id": "PARAM-001",
        "title": "Interesting HTTP Parameter Found",
        "severity": "Low",
        "cvss": 2.0,
        "module": "parameters",
        "description": ("Interesting request parameter discovered."),
        "impact": (
            "Parameters may be vulnerable to injection, IDOR, "
            "SSRF or Open Redirect attacks."
        ),
        "recommendation": ("Review parameter validation and authorization."),
        "references": [
            "https://owasp.org/Top10/",
        ],
        "cwe": "CWE-20",
        "owasp": "A03:2021 Injection",
    },
    # =======================================================
    # Technology
    # =======================================================
    "TECH-001": {
        "id": "TECH-001",
        "title": "Technology Identified",
        "severity": "Info",
        "cvss": 0.0,
        "module": "technology",
        "description": ("Technology fingerprint identified."),
        "impact": ("Technology identification helps prioritize known vulnerabilities."),
        "recommendation": ("Keep software updated with the latest security patches."),
        "references": [
            "https://owasp.org/Top10/",
        ],
        "cwe": None,
        "owasp": None,
    },
    # =======================================================
    # Future Templates
    # =======================================================
    "SSL-001": {
        "id": "SSL-001",
        "title": "Weak SSL Configuration",
        "severity": "High",
        "cvss": 7.5,
        "module": "ssl",
        "description": "",
        "impact": "",
        "recommendation": "",
        "references": [],
        "cwe": None,
        "owasp": None,
    },
    "DNS-001": {
        "id": "DNS-001",
        "title": "DNS Misconfiguration",
        "severity": "Medium",
        "cvss": 5.0,
        "module": "dns",
        "description": "",
        "impact": "",
        "recommendation": "",
        "references": [],
        "cwe": None,
        "owasp": None,
    },
    "PORT-001": {
        "id": "PORT-001",
        "title": "Open Service Detected",
        "severity": "Info",
        "cvss": 0.0,
        "module": "ports",
        "description": "",
        "impact": "",
        "recommendation": "",
        "references": [],
        "cwe": None,
        "owasp": None,
    },
    "SUBDOMAIN-001": {
        "id": "SUBDOMAIN-001",
        "title": "Subdomain Discovered",
        "severity": "Info",
        "cvss": 0.0,
        "module": "subdomains",
        "description": "",
        "impact": "",
        "recommendation": "",
        "references": [],
        "cwe": None,
        "owasp": None,
    },
    "NUCLEI-001": {
        "id": "NUCLEI-001",
        "title": "Nuclei Finding",
        "severity": "High",
        "cvss": 7.5,
        "module": "nuclei",
        "description": "",
        "impact": "",
        "recommendation": "",
        "references": [],
        "cwe": None,
        "owasp": None,
    },
    "SQLI-001": {
        "id": "SQLI-001",
        "title": "SQL Injection",
        "severity": "Critical",
        "cvss": 9.8,
        "module": "sqli",
        "description": "",
        "impact": "",
        "recommendation": "",
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
        ],
        "cwe": "CWE-89",
        "owasp": "A03:2021 Injection",
    },
    "XSS-001": {
        "id": "XSS-001",
        "title": "Cross Site Scripting",
        "severity": "High",
        "cvss": 8.0,
        "module": "xss",
        "description": "",
        "impact": "",
        "recommendation": "",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
        ],
        "cwe": "CWE-79",
        "owasp": "A03:2021 Injection",
    },
}
