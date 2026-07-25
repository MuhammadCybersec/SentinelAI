# app/modules/scanner/signatures.py
"""
Oracle version and edition signatures for fingerprinting.
Phase 2: Oracle Version Fingerprinting
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Pattern
import re


@dataclass
class OracleVersionSignature:
    """Oracle version signature definition."""

    version: str
    display_name: str
    patterns: List[str]
    weight: int
    is_xe: bool = False


@dataclass
class OracleEditionSignature:
    """Oracle edition signature definition."""

    edition: str
    patterns: List[str]
    weight: int


class OracleSignatures:
    """Oracle version and edition signatures."""

    # ============================================================
    # Oracle Version Signatures
    # ============================================================

    VERSION_SIGNATURES: List[OracleVersionSignature] = [
        # Oracle 10g
        OracleVersionSignature(
            version="10g",
            display_name="Oracle 10g",
            patterns=[
                r"Oracle Database 10g",
                r"10\.\d+\.\d+\.\d+",
                r"10g Release",
                r"10\.2\.0",
                r"10\.1\.0",
            ],
            weight=30,
        ),
        # Oracle 11g
        OracleVersionSignature(
            version="11g",
            display_name="Oracle 11g",
            patterns=[
                r"Oracle Database 11g",
                r"11\.\d+\.\d+\.\d+",
                r"11g Release",
                r"11\.2\.0",
                r"11\.1\.0",
            ],
            weight=30,
        ),
        # Oracle 12c
        OracleVersionSignature(
            version="12c",
            display_name="Oracle 12c",
            patterns=[
                r"Oracle Database 12c",
                r"12\.\d+\.\d+\.\d+",
                r"12c Release",
                r"12\.2\.0",
                r"12\.1\.0",
            ],
            weight=30,
        ),
        # Oracle 18c
        OracleVersionSignature(
            version="18c",
            display_name="Oracle 18c",
            patterns=[
                r"Oracle Database 18c",
                r"18\.\d+\.\d+\.\d+",
                r"18c Release",
                r"18\.3\.0",
                r"18\.4\.0",
                r"18\.5\.0",
            ],
            weight=30,
        ),
        # Oracle 19c
        OracleVersionSignature(
            version="19c",
            display_name="Oracle 19c",
            patterns=[
                r"Oracle Database 19c",
                r"19\.\d+\.\d+\.\d+",
                r"19c Release",
                r"19\.3\.0",
                r"19\.4\.0",
                r"19\.5\.0",
                r"19\.6\.0",
                r"19\.7\.0",
                r"19\.8\.0",
                r"19\.9\.0",
                r"19\.10\.0",
                r"19\.11\.0",
                r"19\.12\.0",
                r"19\.13\.0",
                r"19\.14\.0",
                r"19\.15\.0",
                r"19\.16\.0",
                r"19\.17\.0",
                r"19\.18\.0",
                r"19\.19\.0",
                r"19\.20\.0",
            ],
            weight=30,
        ),
        # Oracle 21c
        OracleVersionSignature(
            version="21c",
            display_name="Oracle 21c",
            patterns=[
                r"Oracle Database 21c",
                r"21\.\d+\.\d+\.\d+",
                r"21c Release",
                r"21\.3\.0",
                r"21\.4\.0",
                r"21\.5\.0",
                r"21\.6\.0",
                r"21\.7\.0",
                r"21\.8\.0",
                r"21\.9\.0",
            ],
            weight=30,
        ),
        # Oracle XE (Express Edition)
        OracleVersionSignature(
            version="XE",
            display_name="Oracle XE",
            patterns=[
                r"Oracle Database XE",
                r"Express Edition",
                r"XE Release",
                r"Oracle XE",
                r"11g XE",
                r"18c XE",
                r"21c XE",
            ],
            weight=25,
            is_xe=True,
        ),
        # Oracle 23c (Future)
        OracleVersionSignature(
            version="23c",
            display_name="Oracle 23c",
            patterns=[
                r"Oracle Database 23c",
                r"23\.\d+\.\d+\.\d+",
                r"23c Release",
            ],
            weight=25,
        ),
    ]

    # ============================================================
    # Oracle Edition Signatures
    # ============================================================

    EDITION_SIGNATURES: List[OracleEditionSignature] = [
        # Enterprise Edition
        OracleEditionSignature(
            edition="Enterprise Edition",
            patterns=[
                r"Enterprise Edition",
                r"EE",
                r"Enterprise",
                r"Oracle Database.*Enterprise",
            ],
            weight=30,
        ),
        # Standard Edition
        OracleEditionSignature(
            edition="Standard Edition",
            patterns=[
                r"Standard Edition",
                r"SE",
                r"Standard",
                r"Oracle Database.*Standard",
            ],
            weight=25,
        ),
        # Express Edition (XE)
        OracleEditionSignature(
            edition="Express Edition",
            patterns=[
                r"Express Edition",
                r"XE",
                r"Express",
                r"Oracle Database.*Express",
                r"XE Release",
            ],
            weight=20,
        ),
        # Personal Edition
        OracleEditionSignature(
            edition="Personal Edition",
            patterns=[
                r"Personal Edition",
                r"PE",
                r"Personal",
            ],
            weight=15,
        ),
        # Lite Edition
        OracleEditionSignature(
            edition="Lite Edition",
            patterns=[
                r"Lite Edition",
                r"LE",
                r"Lite",
                r"Oracle Database.*Lite",
            ],
            weight=10,
        ),
    ]

    # ============================================================
    # Version Pattern Compilation
    # ============================================================

    @classmethod
    def get_version_patterns(cls) -> Dict[str, List[Pattern]]:
        """Compile all version patterns for efficient matching."""
        patterns = {}
        for sig in cls.VERSION_SIGNATURES:
            patterns[sig.version] = [re.compile(p, re.IGNORECASE) for p in sig.patterns]
        return patterns

    @classmethod
    def get_edition_patterns(cls) -> Dict[str, List[Pattern]]:
        """Compile all edition patterns for efficient matching."""
        patterns = {}
        for sig in cls.EDITION_SIGNATURES:
            patterns[sig.edition] = [re.compile(p, re.IGNORECASE) for p in sig.patterns]
        return patterns

    @classmethod
    def find_version_by_pattern(cls, text: str) -> List[OracleVersionSignature]:
        """
        Find all version signatures that match the given text.

        Args:
            text: Text to search for version patterns

        Returns:
            List[OracleVersionSignature]: Matching signatures
        """
        matches = []
        text_lower = text.lower()

        for sig in cls.VERSION_SIGNATURES:
            for pattern in sig.patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    matches.append(sig)
                    break

        return matches

    @classmethod
    def find_edition_by_pattern(cls, text: str) -> List[OracleEditionSignature]:
        """
        Find all edition signatures that match the given text.

        Args:
            text: Text to search for edition patterns

        Returns:
            List[OracleEditionSignature]: Matching signatures
        """
        matches = []
        text_lower = text.lower()

        for sig in cls.EDITION_SIGNATURES:
            for pattern in sig.patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    matches.append(sig)
                    break

        return matches

    @classmethod
    def get_all_versions(cls) -> List[str]:
        """Get list of all supported Oracle versions."""
        return [sig.version for sig in cls.VERSION_SIGNATURES]

    @classmethod
    def get_all_editions(cls) -> List[str]:
        """Get list of all supported Oracle editions."""
        return [sig.edition for sig in cls.EDITION_SIGNATURES]
