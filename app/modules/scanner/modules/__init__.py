"""
===========================================================
Project : Sentinel AI
Module  : Scanner Modules
File ID : SCANNER-MODULES-INIT-001
Version : 2.0.0
===========================================================

Description:

Package initializer for scanner modules.

Exports:
- SQLiScanner
- XSSScanner
- BlindBooleanScanner
- ErrorBasedScanner
- TimeBasedScanner
- CommandInjectionScanner
- PathTraversalScanner
- SSRFScanner
- LoginBypassScanner
- FileUploadScanner
- IDORScanner
- CORSScanner
- CSRFScanner
- ClickjackingScanner
- LFIScanner
- RFIScanner
- SSIScanner
- SSTIScanner
- XXEInjectionScanner
- HostHeaderScanner
- OpenRedirectScanner
- PrototypePollutionScanner
- JWTHijackingScanner

===========================================================
"""

# ===========================================================
# SQL Injection
# ===========================================================

try:
    from app.modules.scanner.modules.sqli import SQLiScanner
except ImportError:
    # Fallback if sqli module is not available
    SQLiScanner = None

# ===========================================================
# XSS Scanner
# ===========================================================

try:
    from app.modules.scanner.modules.xss_scanner import LegacyXSSScanner, XSSScanner
except ImportError:
    XSSScanner = None
    LegacyXSSScanner = None

# ===========================================================
# Blind Injection
# ===========================================================

try:
    from app.modules.scanner.modules.blind_sqli import BlindSQLiScanner
except ImportError:
    BlindSQLiScanner = None

try:
    from app.modules.scanner.modules.blind_boolean import BlindBooleanScanner
except ImportError:
    BlindBooleanScanner = None

try:
    from app.modules.scanner.modules.blind_time import TimeBasedScanner
except ImportError:
    TimeBasedScanner = None

# ===========================================================
# Error Based
# ===========================================================

try:
    from app.modules.scanner.modules.error_sqli import ErrorBasedScanner
except ImportError:
    ErrorBasedScanner = None

# ===========================================================
# Injection Types
# ===========================================================

try:
    from app.modules.scanner.modules.cmd_injection import CommandInjectionScanner
except ImportError:
    CommandInjectionScanner = None

try:
    from app.modules.scanner.modules.path_traversal import PathTraversalScanner
except ImportError:
    PathTraversalScanner = None

# ===========================================================
# SSRF, LFI, RFI Scanners (Updated Imports)
# ===========================================================

try:
    from app.modules.scanner.modules.ssrf_scanner import SSRFScanner
except ImportError:
    try:
        from app.modules.scanner.modules.ssrf import SSRFScanner
    except ImportError:
        SSRFScanner = None

try:
    from app.modules.scanner.modules.lfi_scanner import LFIScanner
except ImportError:
    try:
        from app.modules.scanner.modules.lfi import LFIScanner
    except ImportError:
        LFIScanner = None

try:
    from app.modules.scanner.modules.rfi_scanner import RFIScanner
except ImportError:
    try:
        from app.modules.scanner.modules.rfi import RFIScanner
    except ImportError:
        RFIScanner = None

# ===========================================================
# XML & Template Injection
# ===========================================================

try:
    from app.modules.scanner.modules.xxe import XXEInjectionScanner
except ImportError:
    XXEInjectionScanner = None

try:
    from app.modules.scanner.modules.ssti import SSTIScanner
except ImportError:
    SSTIScanner = None

try:
    from app.modules.scanner.modules.ldap_injection import LDAPInjectionScanner
except ImportError:
    LDAPInjectionScanner = None

try:
    from app.modules.scanner.modules.nosql_injection import NoSQLInjectionScanner
except ImportError:
    NoSQLInjectionScanner = None

# ===========================================================
# Authentication & Authorization
# ===========================================================

try:
    from app.modules.scanner.modules.login_bypass import LoginBypassScanner
except ImportError:
    LoginBypassScanner = None

try:
    from app.modules.scanner.modules.idor import IDORScanner
except ImportError:
    IDORScanner = None

try:
    from app.modules.scanner.modules.jwt import JWTHijackingScanner
except ImportError:
    JWTHijackingScanner = None

# ===========================================================
# File & Upload
# ===========================================================

try:
    from app.modules.scanner.modules.file_upload import FileUploadScanner
except ImportError:
    FileUploadScanner = None

# ===========================================================
# Web Vulnerabilities
# ===========================================================

try:
    from app.modules.scanner.modules.cors import CORSScanner
except ImportError:
    CORSScanner = None

try:
    from app.modules.scanner.modules.csrf import CSRFScanner
except ImportError:
    CSRFScanner = None

try:
    from app.modules.scanner.modules.clickjacking import ClickjackingScanner
except ImportError:
    ClickjackingScanner = None

try:
    from app.modules.scanner.modules.host_header import HostHeaderScanner
except ImportError:
    HostHeaderScanner = None

try:
    from app.modules.scanner.modules.open_redirect import OpenRedirectScanner
except ImportError:
    OpenRedirectScanner = None

try:
    from app.modules.scanner.modules.prototype_pollution import (
        PrototypePollutionScanner,
    )
except ImportError:
    PrototypePollutionScanner = None

# ===========================================================
# Web Application Firewall
# ===========================================================

try:
    from app.modules.scanner.modules.waf_bypass import WAFBypassScanner
except ImportError:
    WAFBypassScanner = None

# ===========================================================
# Public API
# ===========================================================

__all__ = [
    "BlindBooleanScanner",
    # Blind Injection
    "BlindSQLiScanner",
    # Web Vulnerabilities
    "CORSScanner",
    "CSRFScanner",
    "ClickjackingScanner",
    # Injection Types
    "CommandInjectionScanner",
    # Error Based
    "ErrorBasedScanner",
    # File & Upload
    "FileUploadScanner",
    "HostHeaderScanner",
    "IDORScanner",
    "JWTHijackingScanner",
    "LDAPInjectionScanner",
    "LFIScanner",
    "LegacyXSSScanner",
    # Authentication
    "LoginBypassScanner",
    "NoSQLInjectionScanner",
    "OpenRedirectScanner",
    "PathTraversalScanner",
    "PrototypePollutionScanner",
    "RFIScanner",
    # SQL Injection
    "SQLiScanner",
    "SSRFScanner",
    "SSTIScanner",
    "TimeBasedScanner",
    # WAF
    "WAFBypassScanner",
    # XSS
    "XSSScanner",
    "XXEInjectionScanner",
]
