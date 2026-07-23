"""
===========================================================
Project : Sentinel AI
Module  : Form Parser
File ID : SCANNER-CORE-FORM-001
Version : 1.0.0
===========================================================

Description:
Pure HTML form parser. No HTTP requests.
Extracts forms, actions, methods, hidden fields, CSRF tokens.

Responsibilities (ONLY):
- Parse HTML
- Detect all forms
- Extract action, method, enctype
- Extract hidden inputs
- Detect CSRF token
- Detect username/password fields
- Resolve relative action URLs
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urljoin


@dataclass
class FormField:
    """Represents a form field."""

    name: str
    value: str = ""
    type: str = "text"
    is_hidden: bool = False


@dataclass
class ParsedForm:
    """Represents a parsed HTML form."""

    action: str = ""
    method: str = "GET"
    enctype: str = "application/x-www-form-urlencoded"
    fields: List[FormField] = field(default_factory=list)
    hidden_fields: Dict[str, str] = field(default_factory=dict)
    csrf_token: Optional[str] = None
    csrf_field_name: Optional[str] = None
    action_url: str = ""
    form_id: str = ""
    form_class: str = ""
    username_field: Optional[str] = None
    password_field: Optional[str] = None


class FormParser:
    """
    Pure HTML form parser. No HTTP requests.
    """

    # Common CSRF token names
    CSRF_PATTERNS = [
        "csrf",
        "csrf_token",
        "csrfmiddlewaretoken",
        "authenticity_token",
        "_token",
        "token",
        "xsrf",
        "xsrf_token",
        "csrf-token",
        "__csrf",
        "csrfToken",
        "CSRFToken",
        "form_token",
        "security_token",
    ]

    # Common username field names
    USERNAME_PATTERNS = [
        "username",
        "user",
        "email",
        "login",
        "user_name",
        "userid",
        "user_id",
        "uname",
        "name",
    ]

    # Common password field names
    PASSWORD_PATTERNS = [
        "password",
        "pass",
        "pwd",
        "userpass",
        "passwd",
        "password_",
        "password-confirm",
    ]

    def parse(self, html: str, base_url: str) -> List[ParsedForm]:
        """
        Parse all forms from HTML.

        Args:
            html: HTML content
            base_url: Base URL for resolving relative actions

        Returns:
            List of ParsedForm objects
        """
        forms = []

        form_pattern = re.compile(r"<form[^>]*>(.*?)</form>", re.DOTALL | re.IGNORECASE)

        for match in form_pattern.finditer(html):
            form_html = match.group(0)
            form_inner = match.group(1)

            parsed_form = self._parse_single_form(form_html, form_inner, base_url)
            if parsed_form:
                forms.append(parsed_form)

        return forms

    def _parse_single_form(
        self, form_html: str, form_inner: str, base_url: str
    ) -> Optional[ParsedForm]:
        """
        Parse a single form element.

        Args:
            form_html: Complete form HTML
            form_inner: Inner HTML of the form
            base_url: Base URL for resolving actions

        Returns:
            ParsedForm or None
        """
        parsed = ParsedForm()

        # Extract action
        action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.I)
        if action_match:
            parsed.action = action_match.group(1)
            parsed.action_url = urljoin(base_url, parsed.action)
        else:
            parsed.action_url = base_url

        # Extract method
        method_match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.I)
        if method_match:
            parsed.method = method_match.group(1).upper()
        else:
            parsed.method = "GET"

        # Extract enctype
        enctype_match = re.search(r'enctype=["\']([^"\']+)["\']', form_html, re.I)
        if enctype_match:
            parsed.enctype = enctype_match.group(1)

        # Extract id
        id_match = re.search(r'id=["\']([^"\']+)["\']', form_html, re.I)
        if id_match:
            parsed.form_id = id_match.group(1)

        # Extract class
        class_match = re.search(r'class=["\']([^"\']+)["\']', form_html, re.I)
        if class_match:
            parsed.form_class = class_match.group(1)

        # Extract all input fields
        input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', re.I)

        for input_match in input_pattern.finditer(form_inner):
            input_html = input_match.group(0)
            name = input_match.group(1)

            # Extract value
            value_match = re.search(r'value=["\']([^"\']*)["\']', input_html, re.I)
            value = value_match.group(1) if value_match else ""

            # Extract type
            type_match = re.search(r'type=["\']([^"\']+)["\']', input_html, re.I)
            input_type = type_match.group(1).lower() if type_match else "text"

            is_hidden = input_type == "hidden"

            field = FormField(
                name=name,
                value=value,
                type=input_type,
                is_hidden=is_hidden,
            )
            parsed.fields.append(field)

            if is_hidden:
                parsed.hidden_fields[name] = value

            # Detect username/password fields
            self._detect_login_fields(parsed, name, input_type)

        # Detect CSRF token
        self._detect_csrf(parsed)

        return parsed

    def _detect_csrf(self, parsed: ParsedForm) -> None:
        """Detect CSRF token from hidden fields."""
        for name, value in parsed.hidden_fields.items():
            name_lower = name.lower()
            for pattern in self.CSRF_PATTERNS:
                if pattern in name_lower:
                    parsed.csrf_token = value
                    parsed.csrf_field_name = name
                    return

    def _detect_login_fields(
        self, parsed: ParsedForm, name: str, input_type: str
    ) -> None:
        """Detect username and password fields."""
        name_lower = name.lower()

        # Username field
        if parsed.username_field is None:
            for pattern in self.USERNAME_PATTERNS:
                if pattern in name_lower:
                    parsed.username_field = name
                    break

        # Password field
        if input_type == "password" or parsed.password_field is None:
            for pattern in self.PASSWORD_PATTERNS:
                if pattern in name_lower:
                    parsed.password_field = name
                    break

    def extract_form_data(
        self, parsed_form: ParsedForm, additional_data: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """
        Extract form data for submission.

        Args:
            parsed_form: Parsed form
            additional_data: Additional data to include

        Returns:
            Dictionary of form data
        """
        data = {}
        data.update(parsed_form.hidden_fields)

        if additional_data:
            data.update(additional_data)

        return data


def create_form_parser() -> FormParser:
    """Create a FormParser instance."""
    return FormParser()
