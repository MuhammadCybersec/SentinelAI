"""
===========================================================
Project : Sentinel AI
Module  : Form Discovery
File ID : RECON-FORM-001
Version : 1.0.0
===========================================================
"""

from __future__ import annotations

from urllib.parse import urljoin

from bs4 import BeautifulSoup


def discover_forms(
    url: str,
    html: str,
    base_url: str | None = None,
) -> list[dict]:
    """
    Discover HTML forms and extract form details.

    Args:
        url: The page URL
        html: HTML content to parse
        base_url: Base URL for resolving relative actions

    Returns:
        List of form dictionaries with:
        - url: Page URL
        - action: Form action URL
        - method: GET or POST
        - inputs: List of input field names
        - fields: List of field details (name, type, value)
    """
    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")
    forms = []
    base = base_url or url

    for form in soup.find_all("form"):
        try:
            action = form.get("action", "")
            method = form.get("method", "").upper() or "GET"

            if action:
                action_url = urljoin(base, action)
            else:
                action_url = base

            inputs = []
            fields = []

            for input_tag in form.find_all(["input", "select", "textarea"]):
                field_name = input_tag.get("name", "")
                if not field_name:
                    continue

                field_type = input_tag.get("type", "").lower()

                # Handle select dropdown
                if input_tag.name == "select":
                    options = []
                    for option in input_tag.find_all("option"):
                        opt_value = option.get("value", "")
                        if opt_value or opt_value == "":
                            options.append(opt_value)
                    value = options[0] if options else ""
                    field_type = "select"
                elif input_tag.name == "textarea":
                    value = input_tag.get_text(strip=True)
                    field_type = "textarea"
                else:
                    value = input_tag.get("value", "")
                    if field_type in ("checkbox", "radio"):
                        value = input_tag.get("value", "on")

                fields.append(
                    {
                        "name": field_name,
                        "type": field_type,
                        "value": value,
                        "tag": input_tag.name,
                    }
                )
                inputs.append(field_name)

            if inputs:
                forms.append(
                    {
                        "url": url,
                        "action": action_url,
                        "method": method,
                        "inputs": inputs,
                        "fields": fields,
                    }
                )

        except Exception as e:
            print(f"[FORM ERROR] {e}")
            continue

    return forms


def extract_form_parameters(
    forms: list[dict],
) -> dict[str, list[str]]:
    """
    Extract all parameters from discovered forms.

    Args:
        forms: List of form dictionaries

    Returns:
        Dict mapping parameter name to list of URLs
    """
    params: dict[str, list[str]] = {}

    for form in forms:
        url = form.get("url", "")
        for input_name in form.get("inputs", []):
            if input_name not in params:
                params[input_name] = []
            if url not in params[input_name]:
                params[input_name].append(url)

    return params


# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":
    import requests

    print("=" * 60)
    print("Form Discovery Test")
    print("=" * 60)

    try:
        response = requests.get(test_url, timeout=10)
        if response.status_code == 200:
            forms = discover_forms(test_url, response.text)
            print(f"URL: {test_url}")
            print(f"Forms Found: {len(forms)}")

            for i, form in enumerate(forms, 1):
                print("-" * 40)
                print(f"Form #{i}")
                print(f"  Action: {form['action']}")
                print(f"  Method: {form['method']}")
                print(f"  Inputs: {form['inputs']}")
        else:
            print(f"Failed to fetch {test_url}: {response.status_code}")

    except Exception as e:
        print(f"[ERROR] {e}")
