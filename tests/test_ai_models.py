"""Unit tests for scanner.models.ai_report.

Verifies the validation, schema constraints, and sanitization hooks of the Pydantic models
used for structured AI security report sections.
"""

from scanner.models.ai_report import (
    AppContextModel,
    DependenciesSectionModel,
    FindingItem,
    FindingsSectionModel,
    InformationalItem,
    InformationalSectionModel,
    NetworkSectionModel,
    PermissionsSectionModel,
    VulnerabilitiesSectionModel,
    clean_code_snippet,
    is_dummy_code_snippet,
)


def test_is_dummy_code_snippet():
    """is_dummy_code_snippet correctly identifies empty, comment-only, and opt-out placeholders."""
    # Empty / whitespace
    assert is_dummy_code_snippet("") is True
    assert is_dummy_code_snippet("   \n\t  ") is True

    # Comment-only opt-out snippets
    assert is_dummy_code_snippet("// No direct fix available in application code.") is True
    assert is_dummy_code_snippet("// Implementation is in the third-party library") is True
    assert is_dummy_code_snippet("// Update com.esri:arcgis-maps-sdk to the latest version.") is True
    assert is_dummy_code_snippet("/* No direct fix available */") is True
    assert is_dummy_code_snippet("<!-- No direct fix available -->") is True

    # Plain-text opt-out without code
    assert is_dummy_code_snippet("No direct fix available in application code.") is True

    # Real code should NOT be marked as dummy
    assert is_dummy_code_snippet('android:allowBackup="false"') is False
    assert is_dummy_code_snippet("int x = 0;") is False
    assert is_dummy_code_snippet("Cipher c = Cipher.getInstance();") is False
    assert (
        is_dummy_code_snippet(
            '// Replace AES/ECB with AES/GCM\nCipher cipher = Cipher.getInstance("AES/GCM/NoPadding");'
        )
        is False
    )


def test_clean_code_snippet_discards_dummy_opt_out_snippets():
    """clean_code_snippet returns empty strings for comment-only or opt-out placeholders."""
    code, lang = clean_code_snippet("// No direct fix available in application code.", "java")
    assert code == ""
    assert lang == ""

    code, lang = clean_code_snippet(
        "```java\n// Implementation is in the third-party library\n// Update library\n```", "java"
    )
    assert code == ""
    assert lang == ""


def test_clean_code_snippet_helper():
    """clean_code_snippet strips markdown fences, detects language tags, and cleans whitespace."""
    # Raw code remains unchanged
    code, lang = clean_code_snippet('android:allowBackup="false"', "xml")
    assert code == 'android:allowBackup="false"'
    assert lang == "xml"

    # Single fenced block
    code, lang = clean_code_snippet("```java\nCipher c = Cipher.getInstance();\n```", "java")
    assert code == "Cipher c = Cipher.getInstance();"
    assert lang == "java"

    # Inferred language when empty
    code, lang = clean_code_snippet("```kotlin\nval x = 1\n```", "")
    assert code == "val x = 1"
    assert lang == "kotlin"

    # Nested fences
    code, lang = clean_code_snippet("```java\n```java\nint x = 0;\n```\n```", "java")
    assert code == "int x = 0;"
    assert lang == "java"

    # Stray closing fence
    code, lang = clean_code_snippet("int x = 0;\n```", "java")
    assert code == "int x = 0;"
    assert lang == "java"

    # Empty snippet
    code, lang = clean_code_snippet("   ", "")
    assert code == ""


def test_finding_item_auto_cleans_fenced_code_snippet():
    """FindingItem validator strips markdown fences and infers language tag."""
    raw_data = {
        "title": "Unsafe WebView",
        "risk": "High XSS risk.",
        "attack_vector": "Attacker injects JS.",
        "developer_intent": "Intended for fast loading.",
        "remediation": "Disable file access.",
        "code_snippet": "```java\nwebView.getSettings().setAllowFileAccess(false);\n```",
        "code_language": "",
        "sources": ["https://developer.android.com/guide/webapps/webview"],
    }
    item = FindingItem.model_validate(raw_data)
    assert item.code_snippet == "webView.getSettings().setAllowFileAccess(false);"
    assert item.code_language == "java"
    assert len(item.sources) == 1
    assert item.sources[0].url == "https://developer.android.com/guide/webapps/webview"


def test_finding_item_opts_out_of_dummy_code_snippet():
    """FindingItem validator sets code_snippet to None and clears language when model outputs dummy placeholder."""
    raw_data = {
        "title": "Insecure DES in third-party library",
        "risk": "Low - DES in NTLM.",
        "attack_vector": "Attacker intercepts network.",
        "developer_intent": "Legacy auth protocol.",
        "remediation": "Update the third-party library.",
        "code_snippet": "// No direct fix available in application code.\n// Update com.esri:arcgis-maps-sdk to the latest version.",
        "code_language": "java",
    }
    item = FindingItem.model_validate(raw_data)
    assert item.code_snippet is None
    assert item.code_language == ""


def test_findings_section_model_validation():
    """FindingsSectionModel parses lists of findings and handles no_findings flag."""
    section = FindingsSectionModel.model_validate(
        {
            "no_findings": False,
            "findings": [
                {
                    "title": "Cleartext Traffic",
                    "risk": "MITM risk.",
                    "code_snippet": 'android:usesCleartextTraffic="false"',
                    "code_language": "xml",
                }
            ],
            # Extra keys from local models are ignored cleanly
            "unexpected_model_key": "should_be_ignored",
        }
    )
    assert not section.no_findings
    assert len(section.findings) == 1
    assert section.findings[0].code_language == "xml"


def test_permissions_section_model():
    """PermissionsSectionModel handles permissions items and groups."""
    section = PermissionsSectionModel.model_validate(
        {
            "no_findings": False,
            "items": [
                {
                    "name": "android.permission.CAMERA",
                    "group": "runtime_requested",
                    "description": "Camera access for barcode scanning",
                    "verdict": "Safe (Expected)",
                    "rationale": "Required for scanning function.",
                    "sources": [{"url": "https://developer.android.com", "description": "Docs"}],
                }
            ],
        }
    )
    assert len(section.items) == 1
    assert section.items[0].name == "android.permission.CAMERA"
    assert section.items[0].sources[0].description == "Docs"


def test_dependencies_section_model():
    """DependenciesSectionModel parses dependency entries."""
    section = DependenciesSectionModel.model_validate(
        {
            "no_findings": False,
            "items": [
                {
                    "source_name": "com.squareup.okhttp3:okhttp",
                    "name": "OkHttp",
                    "version_used": "4.9.0",
                    "latest_version": "4.12.0",
                    "purpose": "HTTP client",
                    "vulnerabilities": "No known vulnerabilities found",
                }
            ],
        }
    )
    assert len(section.items) == 1
    assert section.items[0].version_used == "4.9.0"


def test_network_section_model():
    """NetworkSectionModel correctly categorizes domain items."""
    section = NetworkSectionModel.model_validate(
        {
            "no_findings": False,
            "cloud_services": [
                {
                    "domain": "api.example.com",
                    "assessment": "App backend",
                    "is_developer_code": True,
                }
            ],
            "trackers_and_ads": [],
            "other": [],
        }
    )
    assert len(section.cloud_services) == 1
    assert section.cloud_services[0].is_developer_code is True


def test_vulnerabilities_section_model():
    """VulnerabilitiesSectionModel validates OWASP vulnerability items."""
    section = VulnerabilitiesSectionModel.model_validate(
        {
            "no_findings": False,
            "summary": "Overall good posture.",
            "findings": [
                {
                    "owasp_id": "M10",
                    "owasp_category": "M10: Insufficient Cryptography",
                    "vulnerability": "Hardcoded Key",
                    "severity": "HIGH",
                    "cvss_score": 7.5,
                    "cwe": "CWE-321",
                }
            ],
        }
    )
    assert len(section.findings) == 1
    assert section.findings[0].cvss_score == 7.5


def test_informational_section_model():
    """InformationalSectionModel parses posture observations."""
    section = InformationalSectionModel.model_validate(
        {
            "no_findings": False,
            "items": [
                {
                    "finding": "Exported Activity",
                    "evidence": ["MainActivity"],
                    "detail": "Normal entry point.",
                    "recommendation": "Verify intent filters.",
                }
            ],
        }
    )
    assert len(section.items) == 1
    assert section.items[0].evidence == ["MainActivity"]


def test_informational_item_resilience():
    """InformationalItem accepts title alias and normalizes string evidence."""
    item = InformationalItem.model_validate(
        {
            "title": "Deep Link Intent",
            "evidence": "com.example://open",
            "detail": "Custom deep link scheme.",
            "recommendation": "Validate inputs.",
        }
    )
    assert item.finding == "Deep Link Intent"
    assert item.evidence == ["com.example://open"]


def test_informational_section_model_flexibility():
    """InformationalSectionModel accepts root lists and alternative finding keys."""
    # Test root list
    sec_list = InformationalSectionModel.model_validate(
        [
            {
                "title": "Root Detected",
                "evidence": ["/system/bin/su"],
                "detail": "Root check in code.",
                "recommendation": "Verify logic.",
            }
        ]
    )
    assert not sec_list.no_findings
    assert len(sec_list.items) == 1
    assert sec_list.items[0].finding == "Root Detected"

    # Test findings key alias
    sec_findings = InformationalSectionModel.model_validate(
        {
            "findings": [
                {
                    "finding": "DCL Detected",
                    "evidence": ["DexClassLoader"],
                }
            ]
        }
    )
    assert len(sec_findings.items) == 1
    assert sec_findings.items[0].finding == "DCL Detected"

    # Test observations key alias
    sec_obs = InformationalSectionModel.model_validate(
        {
            "observations": [
                {
                    "title": "Public Client ID",
                    "evidence": ["client-id-123"],
                }
            ]
        }
    )
    assert len(sec_obs.items) == 1
    assert sec_obs.items[0].finding == "Public Client ID"


def test_app_context_model():
    """AppContextModel validates application metadata and incidents."""
    ctx = AppContextModel.model_validate(
        {
            "app_name": "TestApp",
            "developer": "Acme Corp",
            "primary_purpose": "Testing",
            "status": "Active",
            "description": "A test application.",
            "security_incidents": [
                {
                    "summary": "Credential leak in 2023",
                    "date": "2023-01",
                    "relation": "backend",
                    "impact": "100 users",
                    "source_url": "https://news.example.com",
                }
            ],
            "sources": ["https://example.com"],
        }
    )
    assert ctx.app_name == "TestApp"
    assert len(ctx.security_incidents) == 1
    assert ctx.security_incidents[0].relation == "backend"
    assert len(ctx.sources) == 1
