"""
===========================================================
Project : Sentinel AI
Module  : File Upload Scanner
File ID : SCANNER-UPLOAD-001
Version : 1.0.0
===========================================================

Description:
Insecure File Upload Scanner.

===========================================================
"""

from __future__ import annotations

from app.database.models.finding import Finding


class FileUploadScanner:
    """
    Detect insecure file upload vulnerabilities.
    """

    def __init__(self) -> None:

        self.name = "Insecure File Upload"

        self.severity = "Critical"

        self.test_files = [
            "shell.php",
            "shell.php5",
            "shell.phtml",
            "shell.jsp",
            "shell.asp",
            "shell.aspx",
            "shell.cgi",
            "shell.pl",
            "image.php.jpg",
            "test.svg",
            "payload.html",
        ]

    # =====================================================
    # Scan
    # =====================================================

    def scan(
        self,
        project_id: str,
        url: str,
    ) -> Finding | None:
        """
        Scan a single upload endpoint.
        """

        print(f"[File Upload] Scanning -> {url}")

        vulnerable = False

        detected_file = ""

        for file_name in self.test_files:
            # -------------------------------------------------
            # Future:
            # Upload test file
            # Verify upload success
            # Check execution
            # Verify MIME validation
            # -------------------------------------------------

            if False:
                vulnerable = True

                detected_file = file_name

                break

        if not vulnerable:
            return None

        return Finding(
            project_id=project_id,
            title="Insecure File Upload",
            description=("Potential insecure file upload vulnerability detected."),
            severity=self.severity,
            cvss=9.8,
            status="Open",
            module="File Upload Scanner",
            target=url,
            url=url,
            parameter="file",
            payload=detected_file,
            evidence="",
            recommendation=(
                "Validate file type, MIME type, extension, "
                "rename uploaded files, and store uploads "
                "outside the web root."
            ),
            reference=(
                "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
            ),
            cwe="CWE-434",
            owasp="A05:2021 Security Misconfiguration",
            cve="",
        )

    # =====================================================
    # Scanner Information
    # =====================================================

    def info(self) -> dict:

        return {
            "name": self.name,
            "severity": self.severity,
            "payloads": len(self.test_files),
            "type": "Active Scanner",
        }


# ============================================================
# Temporary Test
# ============================================================

if __name__ == "__main__":
    scanner = FileUploadScanner()

    result = scanner.scan(
        project_id="demo-project",
        url="https://example.com/upload",
    )

    print()

    if result is None:
        print("No File Upload Vulnerability Found")

    else:
        print(result)
