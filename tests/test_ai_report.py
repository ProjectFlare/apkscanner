"""Unit tests for scanner.util.ai_report.

Tests the JSON-to-markdown renderers, scoring logic, data helpers,
and the main generate_ai_report() pipeline.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

import scanner.util.ai_report as ai_report
import scanner.web.scraper as scraper
from scanner.models.ai_report import FindingsSectionModel, InformationalSectionModel
from scanner.util.ai_prompt_templates import DEPENDENCIES_PROMPT_TEMPLATE
from scanner.util.ai_report import (
    SECTION_ATTEMPTS,
    EmptySectionResultError,
    _backfill_app_context_from_store,
    _clean_code_snippet,
    _cross_platform_coverage_caveat,
    _failed_section_placeholder,
    _fallback_maven_url,
    _filter_network_data,
    _format_numbered_steps,
    _format_playstore_metadata_block,
    _format_report_header,
    _incident_cutoff_date,
    _normalize_markdown,
    _parse_section_response,
    _prepare_sections_config,
    _query_dependencies_section_audit,
    _query_section_audit,
    _query_standard_section_audit,
    _render_app_context_json,
    _render_deps_json,
    _render_findings_json,
    _render_network_json,
    _render_security_incidents,
    _render_vulns_json,
    _reports_no_findings,
    _run_parallel,
    calculate_security_score,
    generate_ai_report,
    get_app_context,
    get_recommendation,
    get_security_grade,
    is_data_empty,
)
from scanner.util.tool_runner import BackendAPIError
from scanner.web.scraper import get_html, set_scraper_url


def _llm_opts(max_tool_iterations: int = 7) -> dict:
    """Builds the llm_opts dict the audit-path functions expect, with test defaults."""
    return {
        "model": "m",
        "openai_url": None,
        "search_func": MagicMock(),
        "max_tool_iterations": max_tool_iterations,
    }


def test_calculate_security_score_no_vulns():
    """Score should be 100.0 when there are no vulnerabilities."""
    assert calculate_security_score([]) == 100.0


def test_calculate_security_score_single_medium():
    """One MEDIUM vulnerability should deduct 10.0 points (score: 90.0)."""
    vulns = [{"owasp_id": "M3", "description": "Backup enabled", "severity": "MEDIUM"}]
    assert calculate_security_score(vulns) == 90.0


def test_calculate_security_score_multiple_unique():
    """Multiple unique severities deduct correctly (Medium -10, Low -5 -> score: 85.0)."""
    vulns = [
        {"owasp_id": "M3", "description": "Backup enabled", "severity": "MEDIUM"},
        {"owasp_id": "M7", "description": "No root detection", "severity": "LOW"},
    ]
    assert calculate_security_score(vulns) == 85.0


def test_calculate_security_score_critical_alone():
    """A CRITICAL vulnerability alone caps score at 40.0."""
    vulns = [{"owasp_id": "M1", "description": "Hardcoded keys", "severity": "CRITICAL"}]
    assert calculate_security_score(vulns) == 40.0


def test_calculate_security_score_critical_high():
    """CRITICAL and HIGH penalties compound deductions (100 - 60 - 35 = 5.0)."""
    vulns = [
        {"owasp_id": "M1", "description": "Hardcoded keys", "severity": "CRITICAL"},
        {"owasp_id": "M4", "description": "Cleartext allowed", "severity": "HIGH"},
    ]
    assert calculate_security_score(vulns) == 5.0


def test_calculate_security_score_high_alone():
    """A HIGH vulnerability alone caps score at 65.0."""
    vulns = [{"owasp_id": "M4", "description": "Cleartext allowed", "severity": "HIGH"}]
    assert calculate_security_score(vulns) == 65.0


def test_calculate_security_score_deduplicates():
    """Duplicate vulnerabilities (same owasp_id + description) are only counted once."""
    vuln = {"owasp_id": "M3", "description": "Backup enabled", "severity": "MEDIUM"}
    assert calculate_security_score([vuln, vuln]) == calculate_security_score([vuln])


def test_calculate_security_score_deepl_scenario():
    """DeepL scenario: 0 vulnerabilities, but exported components, custom schemes, and missing config."""
    scan_report = {
        "vulnerabilities": [],
        "informational": [
            {"type": "exported_components", "title": "Exported Components Without Permission", "evidence": ["act1"]},
            {"type": "custom_scheme_intents", "title": "Custom Scheme Deep Links", "evidence": ["deepl://app"]},
        ],
        "manifest_audit": {
            "security_flags": {
                "network_security_config_missing": True,
            }
        },
        "secrets": [],
    }
    # 100.0 - 5.0 (exported) - 5.0 (schemes) - 5.0 (missing config) = 85.0
    assert calculate_security_score(scan_report) == 85.0


def test_calculate_security_score_scan_report_all_hygiene():
    """Scan report with all hygiene deductions: exported, schemes, missing config, and non-public secret."""
    scan_report = {
        "vulnerabilities": [],
        "informational": [
            {"type": "exported_components", "title": "Exported Components Without Permission", "evidence": ["act1"]},
            {"type": "custom_scheme_intents", "title": "Custom Scheme Deep Links", "evidence": ["scheme://app"]},
        ],
        "manifest_audit": {
            "security_flags": {
                "network_security_config_missing": True,
            }
        },
        "secrets": [{"type": "aws_key", "value": "AKIA1234567890123456"}],
    }
    # 100.0 - 5 - 5 - 5 - 5 = 80.0
    assert calculate_security_score(scan_report) == 80.0


def test_calculate_security_score_zip_slip_hygiene():
    """Zip Slip in informational findings deducts 5.0 points as attack surface."""
    scan_report = {
        "vulnerabilities": [],
        "informational": [
            {
                "type": "zip_slip",
                "title": "Zip Slip Vulnerability (Archive Extraction)",
                "evidence": ["com.example.Unzip.extract"],
            }
        ],
    }
    # 100.0 - 5.0 (zip extraction) = 95.0
    assert calculate_security_score(scan_report) == 95.0


def test_calculate_security_score_informational_vulns_ignored():
    """Informational vulnerabilities (hardcoded_secrets, hardcoded_crypto_keys, zip_slip) are not deducted as HIGH."""
    vulns = [
        {"rule_id": "hardcoded_secrets", "title": "Hardcoded Secrets", "severity": "HIGH", "owasp_id": "M1"},
        {"rule_id": "hardcoded_crypto_keys", "title": "Hardcoded Symmetric Key", "severity": "HIGH", "owasp_id": "M1"},
        {"rule_id": "zip_slip", "title": "Zip Slip Vulnerability", "severity": "HIGH", "owasp_id": "M3"},
    ]
    # None of these should trigger -35 or high knockout
    assert calculate_security_score(vulns) == 100.0


def test_get_recommendation_informational_vulns_ignored():
    """Informational vulnerabilities do not trigger HIGH knockout in recommendations."""
    vulns = [
        {"rule_id": "hardcoded_secrets", "title": "Hardcoded Secrets", "severity": "HIGH"},
        {"rule_id": "hardcoded_crypto_keys", "title": "Hardcoded Symmetric Key", "severity": "HIGH"},
        {"rule_id": "zip_slip", "title": "Zip Slip", "severity": "HIGH"},
    ]
    plain, formatted = get_recommendation(95.0, vulns)
    assert plain == "Recommended"
    assert formatted == "Recommended"


def test_get_recommendation_boundaries():
    """get_recommendation maps scores and knockout triggers to plain words."""
    # Clean app >= 85
    plain, formatted = get_recommendation(100.0)
    assert plain == "Recommended"
    assert formatted == "Recommended"

    plain, formatted = get_recommendation(85.0)
    assert plain == "Recommended"
    assert formatted == "Recommended"

    # Partly recommended: 60 <= score < 85
    plain, formatted = get_recommendation(84.9)
    assert plain == "Partly recommended"
    assert formatted == "Partly recommended"

    plain, formatted = get_recommendation(60.0)
    assert plain == "Partly recommended"
    assert formatted == "Partly recommended"

    # High vulnerability triggers Partly recommended even if score >= 85
    plain, formatted = get_recommendation(90.0, [{"severity": "HIGH"}])
    assert plain == "Partly recommended"
    assert formatted == "Partly recommended"

    # Not recommended: score < 60
    plain, formatted = get_recommendation(59.9)
    assert plain == "Not recommended"
    assert formatted == "Not recommended"

    # Critical vulnerability triggers Not recommended
    plain, formatted = get_recommendation(80.0, [{"severity": "CRITICAL"}])
    assert plain == "Not recommended"
    assert formatted == "Not recommended"


def test_get_security_grade_boundaries():
    """Grade boundaries should map to correct letter grades."""
    assert get_security_grade(100.0) == "A"
    assert get_security_grade(90.0) == "A"
    assert get_security_grade(89.9) == "B"
    assert get_security_grade(80.0) == "B"
    assert get_security_grade(79.9) == "C"
    assert get_security_grade(70.0) == "C"
    assert get_security_grade(69.9) == "D"
    assert get_security_grade(60.0) == "D"
    assert get_security_grade(59.9) == "F"
    assert get_security_grade(10.0) == "F"


def test_is_data_empty_truthy_cases():
    """is_data_empty should return True for None, [], {}, and all-empty dicts."""
    assert is_data_empty(None) is True
    assert is_data_empty([]) is True
    assert is_data_empty({}) is True
    assert is_data_empty({"a": []}) is True
    assert is_data_empty({"a": {}}) is True


def test_is_data_empty_falsy_cases():
    """is_data_empty should return False for non-empty structures."""
    assert is_data_empty({"a": [{"b": []}]}) is False
    assert is_data_empty({"a": 1}) is False
    assert is_data_empty([1, 2]) is False


def test_parse_section_response_clean_json():
    """Clean JSON string is parsed correctly."""
    content = '{"no_findings": true, "findings": []}'
    result = _parse_section_response(content, FindingsSectionModel, "test")
    assert result == {"no_findings": True, "findings": []}


def test_parse_section_response_with_code_fence():
    """JSON wrapped in ```json ... ``` fences is parsed correctly."""
    content = '```json\n{"no_findings": false, "findings": []}\n```'
    result = _parse_section_response(content, FindingsSectionModel, "test")
    assert result is not None
    assert result["no_findings"] is False


def test_parse_section_response_with_thinking_tags():
    """Thinking tags are stripped before JSON is parsed."""
    content = '<think>some reasoning</think>\n{"no_findings": true, "findings": []}'
    result = _parse_section_response(content, FindingsSectionModel, "test")
    assert result is not None
    assert result["no_findings"] is True


def test_parse_section_response_malformed_returns_none():
    """Malformed JSON returns None without raising when no Instructor fallback is provided."""
    result = _parse_section_response("this is not JSON {{", FindingsSectionModel, "test")
    assert result is None


def test_parse_section_response_repairs_defects():
    """Defects like trailing commas or unescaped quotes are repaired in-process."""
    trailing = '{"no_findings": false, "findings": [],}'
    res = _parse_section_response(trailing, FindingsSectionModel, "test")
    assert res is not None
    assert res["no_findings"] is False


def test_parse_section_response_rejects_empty_salvage():
    """Invalid content returns None."""
    assert _parse_section_response("no json here at all", FindingsSectionModel, "test") is None


def test_parse_section_response_informational_flexible():
    """_parse_section_response parses root lists and title aliases for Informational sections directly."""
    raw_list_json = (
        "[\n"
        "  {\n"
        '    "title": "Exported Activity",\n'
        '    "evidence": "MainActivity",\n'
        '    "detail": "Standard entry point.",\n'
        '    "recommendation": "Check permissions."\n'
        "  }\n"
        "]"
    )
    result = _parse_section_response(raw_list_json, InformationalSectionModel, "Informational")
    assert result is not None
    assert not result["no_findings"]
    assert len(result["items"]) == 1
    assert result["items"][0]["finding"] == "Exported Activity"
    assert result["items"][0]["evidence"] == ["MainActivity"]


def test_render_findings_json_no_findings():
    """Renderer returns a 'no issues' placeholder when no_findings is True."""
    parsed = {"no_findings": True, "findings": []}
    result = _render_findings_json("## Test Section", parsed)
    assert "No security concerns" in result


def test_render_findings_json_with_findings():
    """Renderer produces a heading, risk, attack vector, and remediation block per finding."""
    parsed = {
        "no_findings": False,
        "findings": [
            {
                "title": "Allow Backup",
                "risk": "Data leakage risk.",
                "attack_vector": "Attacker with USB access.",
                "developer_intent": "Default setting left unchanged.",
                "remediation": "Set android:allowBackup='false'.",
                "code_snippet": 'android:allowBackup="false"',
                "sources": ["https://developer.android.com/guide/topics/manifest/application-element"],
            }
        ],
    }
    result = _render_findings_json("## 1. Manifest Audit", parsed)
    assert "Allow Backup" in result
    assert "Data leakage risk." in result
    assert "android:allowBackup" in result
    assert "```\n" in result


def test_render_findings_json_code_snippet_uses_language_tag_for_highlighting():
    """A code_language value is applied to the fenced code block so markdown renderers can
    syntax-highlight it, instead of always emitting a bare, unhighlighted fence."""
    parsed = {
        "no_findings": False,
        "findings": [
            {
                "title": "Cleartext Traffic",
                "risk": "MITM risk.",
                "remediation": "Disable cleartext traffic.",
                "code_snippet": 'android:usesCleartextTraffic="false"',
                "code_language": "xml",
            }
        ],
    }
    result = _render_findings_json("## 1. Manifest Audit", parsed)
    assert "```xml\n" in result


def test_clean_code_snippet_strips_fences_and_extracts_language():
    """_clean_code_snippet unwraps markdown fences, extracts language tag if missing, and handles nested fences."""
    # Raw code remains unchanged
    code, lang = _clean_code_snippet('android:allowBackup="false"', "xml")
    assert code == 'android:allowBackup="false"'
    assert lang == "xml"

    # Single fenced block with language tag
    code, lang = _clean_code_snippet("```java\nCipher c = Cipher.getInstance();\n```", "java")
    assert code == "Cipher c = Cipher.getInstance();"
    assert lang == "java"

    # Language inferred from fence tag when lang parameter is empty
    code, lang = _clean_code_snippet("```kotlin\nval secret = 42\n```", "")
    assert code == "val secret = 42"
    assert lang == "kotlin"

    # Bare fence without language tag
    code, lang = _clean_code_snippet("```\nint x = 0;\n```", "java")
    assert code == "int x = 0;"
    assert lang == "java"

    # Nested/doubled fences from confused models
    code, lang = _clean_code_snippet("```java\n```java\nint x = 0;\n```\n```", "java")
    assert code == "int x = 0;"
    assert lang == "java"

    # Stray closing fence
    code, lang = _clean_code_snippet("int x = 0;\n```", "java")
    assert code == "int x = 0;"
    assert lang == "java"

    # Unterminated opening fence
    code, lang = _clean_code_snippet("```java\nint x = 0;", "")
    assert code == "int x = 0;"
    assert lang == "java"

    # Whitespace only
    code, lang = _clean_code_snippet("   \n\t  ", "")
    assert code == ""


def test_render_findings_json_prevents_doubled_code_fences():
    """When a model wraps code_snippet in markdown fences, _render_findings_json emits exactly one fence."""
    parsed = {
        "no_findings": False,
        "findings": [
            {
                "title": "Unsafe WebView",
                "risk": "XSS risk.",
                "remediation": "Disable file access.",
                "code_snippet": "```java\nwebView.getSettings().setAllowFileAccess(false);\n```",
                "code_language": "java",
            }
        ],
    }
    result = _render_findings_json("## 7. Bytecode Audit", parsed)
    assert "```java\n```java" not in result
    assert "```\n```" not in result
    assert "```java\nwebView.getSettings().setAllowFileAccess(false);\n```" in result


def test_render_findings_json_omits_empty_opt_out_code_block():
    """When a finding opts out of code generation or has a dummy comment snippet, no code fence is rendered."""
    parsed = {
        "no_findings": False,
        "findings": [
            {
                "title": "Insecure DES in third-party library",
                "risk": "Low - DES in NTLM.",
                "remediation": "Update the third-party library to the latest version.",
                "code_snippet": "// No direct fix available in application code.\n// Update com.esri:arcgis-maps-sdk to the latest version.",
                "code_language": "java",
            },
            {
                "title": "Hardcoded HMAC in third-party library",
                "risk": "Low - key in AWS SDK.",
                "remediation": "Update the AWS Cognito SDK.",
                "code_snippet": None,
                "code_language": "",
            },
        ],
    }
    result = _render_findings_json("## 7. Bytecode Audit", parsed)
    assert "```" not in result
    assert "Update the third-party library" in result
    assert "Update the AWS Cognito SDK" in result


def test_normalize_markdown_collapses_doubled_code_fences():
    """_normalize_markdown collapses duplicated opening and closing code fences."""
    raw = (
        "## Section\n\n"
        "Some text.\n\n"
        "```java\n"
        "```java\n"
        'Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");\n'
        "```\n"
        "```\n"
    )
    normalized = _normalize_markdown(raw)
    assert "```java\n```java" not in normalized
    assert "```\n```" not in normalized
    assert '```java\nCipher cipher = Cipher.getInstance("AES/GCM/NoPadding");\n```' in normalized

    # Also handles empty fence followed by tagged fence
    raw_mixed = "```\n```kotlin\nval key = 123\n```\n```\n"
    normalized_mixed = _normalize_markdown(raw_mixed)
    assert "```kotlin\nval key = 123\n```" in normalized_mixed


def test_format_numbered_steps_splits_and_guards():
    """Inline numbered steps split onto their own lines; prose and version numbers are untouched."""
    # A real enumeration is split, one step per line.
    out = _format_numbered_steps("1. Rotate the key. 2. Restrict it. 3. Move it server-side.")
    assert out == "1. Rotate the key.\n2. Restrict it.\n3. Move it server-side."
    # Plain prose is returned unchanged.
    assert _format_numbered_steps("Rotate the key and move it server-side.") == (
        "Rotate the key and move it server-side."
    )
    # A trailing sentence number that is not a 1,2 sequence is not treated as a list.
    assert _format_numbered_steps("The app targets Android 12. It is fine.") == (
        "The app targets Android 12. It is fine."
    )
    # Version numbers inside prose are never broken.
    assert "\n" not in _format_numbered_steps("Upgrade okhttp to 4.12.0 to fix the issue.")
    # Parenthesized inline steps with intro text and commas are formatted cleanly without stray '('
    paren_text = (
        "An attacker would need to: (1) identify a code path in the NINA app that passes user-controlled "
        "data to LottieCompositionFactory, (2) craft a malicious archive containing entries with path traversal "
        "sequences (e.g., ../../malicious.file), (3) deliver the payload."
    )
    expected_paren = (
        "An attacker would need to:\n"
        "1. identify a code path in the NINA app that passes user-controlled data to LottieCompositionFactory\n"
        "2. craft a malicious archive containing entries with path traversal sequences (e.g., ../../malicious.file)\n"
        "3. deliver the payload."
    )
    assert _format_numbered_steps(paren_text) == expected_paren
    # Parenthesized steps with semicolons and 'and'
    semi_text = "The steps are: (1) step one; (2) step two; and (3) step three."
    expected_semi = "The steps are:\n1. step one\n2. step two\n3. step three."
    assert _format_numbered_steps(semi_text) == expected_semi
    # Trailing outer closing parens are cleaned up cleanly
    trailing_paren_text = "The steps are: (1) step one, (2) step two)"
    expected_trailing = "The steps are:\n1. step one\n2. step two"
    assert _format_numbered_steps(trailing_paren_text) == expected_trailing


def test_render_findings_json_formats_inline_enumeration():
    """A run-on numbered remediation renders as a real multi-line numbered list."""
    parsed = {
        "no_findings": False,
        "findings": [
            {
                "title": "Hardcoded Key",
                "risk": "Exposed.",
                "remediation": "1. Rotate the key. 2. Restrict the key. 3. Monitor usage.",
            }
        ],
    }
    result = _render_findings_json("## 6. Secrets", parsed, include_code=False)
    assert "1. Rotate the key.\n2. Restrict the key.\n3. Monitor usage." in result


def test_informational_section_is_llm_generated_list():
    """The Informational section is audited by the model (info_list renderer), not statically.

    It must carry its dedicated prompt template and its raw posture items as data, and
    must NOT fall back to a deterministic ``render_fn`` any more.
    """
    from scanner.util.ai_prompt_templates import INFORMATIONAL_PROMPT_TEMPLATE

    scan_report = {
        "informational": [
            {
                "type": "custom_scheme_intents",
                "title": "Custom Scheme Deep Links",
                "evidence": ["ecas:// in MainActivity"],
            }
        ]
    }
    sections = _prepare_sections_config(scan_report, {}, {})
    informational = next(s for s in sections if s["name"] == "Informational")

    assert informational.get("render_fn") is None
    assert informational["renderer"] == "info_list"
    assert informational["prompt_template"] is INFORMATIONAL_PROMPT_TEMPLATE
    assert informational["data"] == scan_report["informational"]


def test_filter_scan_report_propagates_manifest_error_and_v1_only():
    """A manifest parse failure and a v1-only signature both survive the report filtering."""
    from scanner.util.ai_report import _filter_scan_report

    scan_report = {
        "manifest_audit": {
            "security_flags": {"allow_backup": False, "debuggable": False},
            "error": "Failed to retrieve AndroidManifest XML from any APK: corrupt zip",
        },
        "signatures": {"v1_only_signature": True, "scheme_versions": ["v1"]},
    }
    filtered_manifest, filtered_signatures = _filter_scan_report(scan_report)
    assert filtered_manifest["analysis_error"].endswith("corrupt zip")
    assert filtered_signatures["v1_only_signature"] is True
    assert filtered_signatures["scheme_versions"] == ["v1"]


def test_filter_scan_report_streamlines_certificates():
    """When a signature finding is present, certificates are streamlined to security-relevant fields."""
    from scanner.util.ai_report import _filter_scan_report

    scan_report = {
        "signatures": {
            "has_weak_hash": True,
            "certificates": [
                {
                    "subject": "CN=Adobe Systems Incorporated",
                    "issuer": "CN=Adobe Systems Incorporated",
                    "serial_number": "1234567890",
                    "sha256_fingerprint": "AA:BB:CC:DD",
                    "sha1_fingerprint": "11:22:33:44",
                    "signature_algo": "SHA1withRSA",
                    "hash_algo": "SHA1",
                    "valid_from": "2010-01-01",
                    "valid_until": "2040-01-01",
                    "self_signed": True,
                }
            ],
        }
    }
    _, filtered_sigs = _filter_scan_report(scan_report)
    assert filtered_sigs["has_weak_hash"] is True
    certs = filtered_sigs["certificates"]
    assert len(certs) == 1
    cert = certs[0]
    assert cert["subject"] == "CN=Adobe Systems Incorporated"
    assert cert["signature_algo"] == "SHA1withRSA"
    assert cert["hash_algo"] == "SHA1"
    # Serial numbers, timestamps, and fingerprints are stripped to save prompt tokens
    assert "serial_number" not in cert
    assert "sha256_fingerprint" not in cert
    assert "valid_until" not in cert


def test_manifest_parse_failure_renders_deterministic_inconclusive_section():
    """A manifest parse failure must yield deterministic 'inconclusive' content instead of the
    misleading clean placeholder, bypassing the model entirely via static_content."""
    sections = _prepare_sections_config({}, {"analysis_error": "corrupt zip"}, {})
    manifest = next(s for s in sections if s["name"] == "Manifest Audit")

    static = manifest["static_content"]
    assert static.startswith("## 1. Manifest Audit")
    assert "inconclusive" in static
    assert "corrupt zip" in static
    assert "No security concerns" not in static

    # A healthy manifest section must not carry static content and still goes to the model.
    healthy = _prepare_sections_config({}, {"security_flags": {"debuggable": True}}, {})
    assert "static_content" not in next(s for s in healthy if s["name"] == "Manifest Audit")


def test_render_findings_json_suppresses_code_block_when_disabled():
    """With include_code=False (e.g. the Secrets section), no code block is rendered even if the
    model returned a code_snippet, while the textual remediation is still shown."""
    parsed = {
        "no_findings": False,
        "findings": [
            {
                "title": "Hardcoded API Key",
                "risk": "Key can be extracted.",
                "remediation": "Rotate the key and move it server-side.",
                "code_snippet": 'val key = System.getenv("API_KEY")',
                "code_language": "kotlin",
            }
        ],
    }
    result = _render_findings_json("## 6. Secrets", parsed, include_code=False)
    assert "Rotate the key and move it server-side." in result
    assert "```" not in result
    assert "System.getenv" not in result

    # Default keeps the code block for other sections.
    assert "```kotlin" in _render_findings_json("## 6. Secrets", parsed)


def test_render_deps_json_with_items():
    """Deps renderer shows version_used, latest_version, and vulnerabilities per dependency,
    grouped into Google SDK and independent third-party subsections."""
    parsed = {
        "no_findings": False,
        "google_sdk": [
            {
                "name": "com.google.android.gms:play-services-base",
                "version_used": "18.10.0",
                "latest_version": "18.11.0",
                "purpose": "Core Google Play services APIs.",
                "vulnerabilities": "No known vulnerabilities found.",
            }
        ],
        "independent": [
            {
                "name": "com.squareup.okhttp3:okhttp",
                "version_used": "4.9.0",
                "latest_version": "4.12.0",
                "purpose": "HTTP client.",
                "vulnerabilities": "CVE-2024-9999: CVSS 9.8 (CRITICAL) — Source: https://nvd.nist.gov",
                "sources": ["https://mvnrepository.com/artifact/com.squareup.okhttp3/okhttp"],
            }
        ],
    }
    result = _render_deps_json("## 5. Dependencies", parsed)
    assert "### Default Platform Services" in result
    assert "### Independent Third-Party Libraries" in result
    assert "play-services-base" in result
    assert "okhttp" in result
    assert "4.9.0" in result
    assert "4.12.0" in result
    assert "CVE-2024-9999" in result


def test_render_deps_json_omits_redundant_sources_bullet():
    """A dependency's source equals its 'Latest Available' link, so no separate Sources bullet is shown.

    This keeps the section consistent: previously the model echoed the same Maven URL into the
    'sources' array only sometimes, making the Sources line appear for some deps and not others.
    """
    parsed = {
        "no_findings": False,
        "independent": [
            {
                "name": "com.squareup.okhttp3:okhttp",
                "version_used": "4.9.0",
                "latest_version": "4.12.0",
                "latest_version_url": "https://mvnrepository.com/artifact/com.squareup.okhttp3/okhttp/4.12.0",
                "purpose": "HTTP client.",
                "vulnerabilities": "No known vulnerabilities found.",
                "sources": ["https://mvnrepository.com/artifact/com.squareup.okhttp3/okhttp"],
            }
        ],
    }
    result = _render_deps_json("## 5. Dependencies", parsed)
    # The latest version stays linked, but the duplicate per-dependency Sources bullet is gone.
    assert "**Latest Available**: [4.12.0]" in result
    assert "**Sources:**" not in result


def test_render_deps_json_no_findings_empty_groups():
    """Deps renderer falls back to the placeholder when both groups are empty."""
    result = _render_deps_json("## 5. Dependencies", {"no_findings": False, "google_sdk": [], "independent": []})
    assert "No third-party dependencies were identified" in result


def test_render_deps_json_with_unversioned_group():
    """Deps renderer shows a separate subsection for libraries with no resolved version,
    omitting redundant unknown/unassessed placeholder fields."""
    parsed = {
        "no_findings": False,
        "unversioned": [
            {
                "name": "io.ktor",
                "version_used": "unknown",
                "latest_version": "unknown",
                "purpose": "Kotlin HTTP client used for network requests.",
                "vulnerabilities": "Version unknown - not assessed",
            }
        ],
    }
    result = _render_deps_json("## 5. Dependencies", parsed)
    assert "### Additional Detected Libraries (Version Not Determined)" in result
    assert "io.ktor" in result
    assert "Kotlin HTTP client used for network requests." in result
    assert "Version Used" not in result
    assert "Latest Available" not in result
    assert "Security & Vulnerabilities" not in result


def test_render_deps_links_latest_version_to_provided_source():
    """Latest Available is a link to the model-provided latest_version_url when present."""
    parsed = {
        "no_findings": False,
        "independent": [
            {
                "name": "com.squareup.okhttp3:okhttp",
                "version_used": "4.9.0",
                "latest_version": "4.12.0",
                "latest_version_url": "https://maven.google.com/web/index.html#com.squareup.okhttp3:okhttp",
                "purpose": "HTTP client.",
                "vulnerabilities": "No known vulnerabilities found.",
            }
        ],
    }
    result = _render_deps_json("## 5. Dependencies", parsed)
    assert (
        "**Latest Available**: [4.12.0](https://maven.google.com/web/index.html#com.squareup.okhttp3:okhttp)" in result
    )


def test_render_deps_latest_version_falls_back_to_coordinate_link():
    """With no latest_version_url, a group:artifact name yields a deterministic mvnrepository link."""
    parsed = {
        "no_findings": False,
        "independent": [
            {
                "name": "com.squareup.okhttp3:okhttp",
                "version_used": "4.9.0",
                "latest_version": "4.12.0",
                "purpose": "HTTP client.",
                "vulnerabilities": "No known vulnerabilities found.",
            }
        ],
    }
    result = _render_deps_json("## 5. Dependencies", parsed)
    assert (
        "**Latest Available**: [4.12.0](https://mvnrepository.com/artifact/com.squareup.okhttp3/okhttp/4.12.0)"
        in result
    )


def test_render_deps_unknown_latest_version_is_not_linked():
    """An 'unknown' latest version is rendered as plain text, never a link."""
    parsed = {
        "no_findings": False,
        "independent": [
            {"name": "com.example:custom-lib", "version_used": "1.0", "latest_version": "unknown", "purpose": "Custom."}
        ],
    }
    result = _render_deps_json("## 5. Dependencies", parsed)
    assert "**Latest Available**: unknown" in result
    assert "[unknown]" not in result


def test_fallback_maven_url_edge_cases():
    """The fallback URL builder only fires for a real coordinate + concrete version."""
    assert _fallback_maven_url("com.squareup.okhttp3:okhttp", "4.12.0") == (
        "https://mvnrepository.com/artifact/com.squareup.okhttp3/okhttp/4.12.0"
    )
    assert _fallback_maven_url("io.ktor", "1.0.0") == ""  # not a group:artifact coordinate
    assert _fallback_maven_url("com.squareup.okhttp3:okhttp", "unknown") == ""
    assert _fallback_maven_url("a:b:c", "1.0.0") == ""  # too many colons


def test_render_app_context_json_renders_sources_as_links():
    """App context sources are rendered as markdown links, not inline plain text."""
    parsed = {
        "app_name": "EU Login",
        "developer": "European Union",
        "primary_purpose": "Scan a QR code to approve a login.",
        "play_store_url": "https://play.google.com/store/apps/details?id=eu.europa.ec.ecas",
        "official_website": None,
        "status": "Active",
        "description": "Authenticator app operated by scanning a QR code for two-factor authentication.",
        "sources": [
            {"url": "https://play.google.com/store/apps/details?id=eu.europa.ec.ecas", "description": "Play listing"},
            "https://trusted-digital-identity.europa.eu/index_en",
        ],
    }
    result = _render_app_context_json(parsed)
    assert "**Sources:**" in result
    assert "[play.google.com - Play listing](https://play.google.com/store/apps/details?id=eu.europa.ec.ecas)" in result
    assert "[trusted-digital-identity.europa.eu](https://trusted-digital-identity.europa.eu/index_en)" in result
    # Inline citation text must not leak into the description output.
    assert "[Source:" not in result


def _base_app_context() -> dict:
    """Minimal valid app-context parse for rendering tests."""
    return {
        "app_name": "Sample App",
        "developer": "Acme",
        "primary_purpose": "Does things.",
        "play_store_url": "https://play.google.com/store/apps/details?id=com.acme",
        "official_website": None,
        "status": "Active",
        "description": "A sample application.",
        "security_incidents": [],
        "sources": [],
    }


def test_render_app_context_json_renders_build_environment():
    """UI framework, processor architectures, and packaging are rendered as overview rows."""
    parsed = _base_app_context()
    env = {"ui_framework": "Native (Jetpack Compose)", "cpu_architecture": ["arm64-v8a", "armeabi-v7a"]}
    apk_metadata = {
        "split_apks": [
            {"name": "base.apk", "size_bytes": 1},
            {"name": "split_config.arm64_v8a.apk", "size_bytes": 1},
            {"name": "split_config.de.apk", "size_bytes": 1},
        ]
    }
    result = _render_app_context_json(parsed, env, apk_metadata)
    assert "| **UI Framework** | Native (Jetpack Compose) |" in result
    assert "| **Processor Architectures** | arm64-v8a, armeabi-v7a |" in result
    assert "| **Packaging** | Split APK (base + 2 configuration splits) |" in result
    # Native apps get no cross-platform coverage caveat.
    assert "Coverage note" not in result


def test_render_app_context_json_omits_app_name_row():
    """The app name is already a Report Details fact, so the overview table must not repeat it."""
    parsed = _base_app_context()
    result = _render_app_context_json(parsed, {"ui_framework": "Native"})
    assert "| **App Name** |" not in result
    assert "| **Packaging** | Single APK |" in result


def test_render_app_context_json_flutter_coverage_caveat():
    """Flutter apps surface an explicit DEX-coverage caveat."""
    parsed = _base_app_context()
    result = _render_app_context_json(parsed, {"ui_framework": "Flutter", "cpu_architecture": ["arm64-v8a"]})
    assert "Coverage note" in result
    assert "libapp.so" in result
    assert "Dependencies, Bytecode Audit, and Secrets" in result


def test_cross_platform_coverage_caveat_variants():
    """Caveat is emitted for Flutter/React Native and suppressed for native/unknown."""
    assert "libapp.so" in _cross_platform_coverage_caveat("Flutter")
    assert "index.android.bundle" in _cross_platform_coverage_caveat("React Native")
    assert _cross_platform_coverage_caveat("Native (Jetpack Compose)") == ""
    assert _cross_platform_coverage_caveat(None) == ""


def test_render_security_incidents_structured():
    """Structured incidents render with date, scope, impact, and a source link."""
    incidents = [
        {
            "summary": "Attackers exfiltrated user auth tokens.",
            "date": "2025-03",
            "relation": "backend",
            "impact": "Est. 10k users affected.",
            "source_url": "https://www.reuters.com/tech/breach",
        }
    ]
    result = _render_security_incidents(incidents)
    assert result.startswith("### Security Incidents & Publicity")
    assert "**2025-03** —" in result
    assert "scope: backend" in result
    assert "impact: Est. 10k users affected." in result
    assert "[source](https://www.reuters.com/tech/breach)" in result


def test_render_security_incidents_empty_and_non_list():
    """Empty or non-list values yield no section (the schema forces the structured list shape)."""
    assert _render_security_incidents([]) == ""
    assert _render_security_incidents(None) == ""
    assert _render_security_incidents("A breach happened in 2024.") == ""


def test_render_security_incidents_skips_incomplete_rows():
    """Incidents without a summary are dropped; a list of only-empties yields no section."""
    assert _render_security_incidents([{"date": "2025-01"}]) == ""


def test_incident_cutoff_date_from_scan_metadata():
    """Cutoff is the scan completion date minus two years, deterministically."""
    report = {"scan_metadata": {"scan_completed": "2026-07-15T14:26:45.193554+00:00"}}
    assert _incident_cutoff_date(report) == "2024-07-15"


def test_incident_cutoff_date_leap_day():
    """A Feb 29 completion date clamps to Feb 28 two years earlier."""
    report = {"scan_metadata": {"scan_completed": "2024-02-29T00:00:00+00:00"}}
    assert _incident_cutoff_date(report) == "2022-02-28"


def test_incident_cutoff_date_missing_metadata():
    """A missing/invalid timestamp still returns a valid YYYY-MM-DD string."""
    import re

    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", _incident_cutoff_date({}))
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", _incident_cutoff_date({"scan_metadata": {"scan_completed": "bad"}}))


def test_system_prompt_substitutes_report_date(monkeypatch):
    """The rendered system prompt carries the report's date, leaving no placeholder behind."""
    monkeypatch.setattr(ai_report, "_CURRENT_DATE", "2026-07-15")
    rendered = ai_report._system_prompt()
    assert "Today's date is 2026-07-15." in rendered
    assert "__CURRENT_DATE__" not in rendered


def test_system_prompt_falls_back_to_today_when_unset(monkeypatch):
    """Calling a section helper outside generate_ai_report still yields a real date."""
    import re

    monkeypatch.setattr(ai_report, "_CURRENT_DATE", None)
    assert re.search(r"Today's date is \d{4}-\d{2}-\d{2}\.", ai_report._system_prompt())


def test_query_dependencies_section_audit_chunks_and_boosts_iterations():
    """Dependencies are split into per-group chunks, each queried with a boosted iteration budget,
    and the resulting markdown preserves the google_sdk/independent grouping from the JSON."""
    google_sdk = {f"play-services-{i}": f"1.{i}.0" for i in range(8)}
    independent = {f"lib{i}": f"1.{i}.0" for i in range(6)}
    all_deps = {**google_sdk, **independent}
    section = {
        "heading": "## 5. Dependencies",
        "name": "Dependencies",
        "prompt_template": DEPENDENCIES_PROMPT_TEMPLATE,
        "data": {"exact_versions_found": {"third_party": {"google_sdk": google_sdk, "independent": independent}}},
    }

    seen_iterations = []

    def fake_agentic_query(**kwargs):
        seen_iterations.append(kwargs["max_iterations"])
        chunk_json = kwargs["prompt"]
        names_in_chunk = [name for name in all_deps if f'"{name}"' in chunk_json]
        items = [{"name": name, "version_used": all_deps[name], "purpose": "Test."} for name in names_in_chunk]
        return json.dumps({"no_findings": False, "items": items}), "", []

    with patch("scanner.util.ai_report.agentic_openai_query", side_effect=fake_agentic_query):
        markdown, _tool_log = _query_dependencies_section_audit(
            section=section,
            app_context_summary="ctx",
            llm_opts=_llm_opts(),
        )

    # Every dependency the model reported on must appear, under the correct group heading.
    assert all(name in markdown for name in all_deps)
    assert markdown.index("### Default Platform Services") < markdown.index("play-services-0")
    assert markdown.index("### Independent Third-Party Libraries") < markdown.index("lib0")
    # The chunk budget must exceed the low user-configured default so a large dependency list
    # is never starved of tool calls.
    assert all(it > 7 for it in seen_iterations)
    assert len(seen_iterations) > 1


def test_query_dependencies_section_audit_injects_known_facts():
    """Each versioned chunk carries what the scan already resolved: the latest published
    version and the OSV verdict per dependency directly in its dict, so the model never re-queries Maven or OSV
    for known versions."""
    third_party = {
        "com.squareup.okhttp3:okhttp": {
            "version_used": "4.9.0",
            "latest_version": "5.4.0",
            "latest_version_url": "https://mvnrepository.com/artifact/com.squareup.okhttp3/okhttp",
            "osv_findings": [
                {
                    "library": "com.squareup.okhttp3:okhttp",
                    "version": "4.9.0",
                    "cve_id": "CVE-2021-0341",
                    "summary": "Hostname verification bypass",
                    "details_url": "https://osv.dev/vulnerability/GHSA-example",
                }
            ],
        },
        "com.google.code.gson:gson": {
            "version_used": "2.13.2",
            "latest_version": "2.14.0",
            "latest_version_url": "https://mvnrepository.com/artifact/com.google.code.gson/gson",
            "osv_findings": [],
        },
    }
    section = {
        "heading": "## 5. Dependencies",
        "name": "Dependencies",
        "prompt_template": DEPENDENCIES_PROMPT_TEMPLATE,
        "data": {"third_party": third_party},
    }

    prompts = []

    def fake_agentic_query(**kwargs):
        prompts.append(kwargs["prompt"])
        items = [
            {"source_name": name, "name": name, "version_used": info["version_used"], "purpose": "Test."}
            for name, info in third_party.items()
            if f'"{name}"' in kwargs["prompt"]
        ]
        return json.dumps({"no_findings": False, "items": items}), "", []

    with patch("scanner.util.ai_report.agentic_openai_query", side_effect=fake_agentic_query):
        _query_dependencies_section_audit(section=section, app_context_summary="ctx", llm_opts=_llm_opts())

    combined = "\n".join(prompts)
    assert "CVE-2021-0341" in combined
    assert "https://osv.dev/vulnerability/GHSA-example" in combined
    assert "5.4.0" in combined


def test_query_dependencies_section_audit_lists_unassessed_deps_after_retries():
    """A dependency the model never assesses (even after every retry round) is still listed with
    a clear fallback note, never silently dropped from the report."""
    section = {
        "heading": "## 5. Dependencies",
        "name": "Dependencies",
        "prompt_template": DEPENDENCIES_PROMPT_TEMPLATE,
        "data": {"exact_versions_found": {"third_party": {"independent": {"okhttp": "5.3.2", "gson": "2.13.1"}}}},
    }

    # Model always returns empty -> both deps stay unassessed through every retry round.
    with patch("scanner.util.ai_report.agentic_openai_query", return_value=("", "", [])):
        markdown, _ = _query_dependencies_section_audit(
            section=section,
            app_context_summary="ctx",
            llm_opts=_llm_opts(),
        )

    # Both dependencies still appear, flagged as not individually assessed — never dropped.
    assert "okhttp" in markdown
    assert "gson" in markdown
    assert "not reviewed one by one by the AI model" in markdown
    assert "No third-party dependencies were identified" not in markdown


def test_query_dependencies_section_audit_retries_dropped_deps_through_the_model():
    """A dependency the model drops in the first round is re-submitted and actually assessed on a
    retry round, rather than falling back to a stub."""
    section = {
        "heading": "## 5. Dependencies",
        "name": "Dependencies",
        "prompt_template": DEPENDENCIES_PROMPT_TEMPLATE,
        "data": {"exact_versions_found": {"third_party": {"independent": {"okhttp": "5.3.2", "gson": "2.13.1"}}}},
    }

    calls = {"n": 0}

    def fake(**kwargs):
        calls["n"] += 1
        prompt = kwargs["prompt"]
        # First round assesses only okhttp (drops gson); the retry round assesses gson.
        if calls["n"] == 1:
            items = [
                {
                    "source_name": "okhttp",
                    "name": "com.squareup.okhttp3:okhttp",
                    "version_used": "5.3.2",
                    "purpose": "HTTP client.",
                    "vulnerabilities": "None.",
                }
            ]
        elif '"gson"' in prompt:
            items = [
                {
                    "source_name": "gson",
                    "name": "com.google.code.gson:gson",
                    "version_used": "2.13.1",
                    "purpose": "JSON serialization library.",
                    "vulnerabilities": "None.",
                }
            ]
        else:
            items = []
        return json.dumps({"no_findings": False, "items": items}), "", []

    with patch("scanner.util.ai_report.agentic_openai_query", side_effect=fake):
        markdown, _ = _query_dependencies_section_audit(
            section=section,
            app_context_summary="ctx",
            llm_opts=_llm_opts(),
        )

    # gson was assessed on retry (resolved coordinate + purpose), not stubbed as unassessed.
    assert "com.google.code.gson:gson" in markdown
    assert "JSON serialization library." in markdown
    assert "not reviewed one by one" not in markdown
    assert calls["n"] >= 2  # at least one retry round occurred


def test_query_dependencies_section_audit_includes_unversioned_group():
    """detected_libraries_version_unknown entries are chunked and rendered as their own group,
    alongside the versioned google_sdk/independent groups."""
    section = {
        "heading": "## 5. Dependencies",
        "name": "Dependencies",
        "prompt_template": DEPENDENCIES_PROMPT_TEMPLATE,
        "data": {
            "exact_versions_found": {"third_party": {"independent": {"okhttp": "5.3.2"}}},
            "detected_libraries_version_unknown": {"io.ktor": ["client", "http"]},
        },
    }

    def fake_agentic_query(**kwargs):
        chunk_json = kwargs["prompt"]
        if "io.ktor" in chunk_json:
            items = [{"name": "io.ktor", "version_used": "unknown", "purpose": "HTTP client."}]
        else:
            items = [{"name": "okhttp", "version_used": "5.3.2", "purpose": "HTTP client."}]
        return json.dumps({"no_findings": False, "items": items}), "", []

    with patch("scanner.util.ai_report.agentic_openai_query", side_effect=fake_agentic_query):
        markdown, _tool_log = _query_dependencies_section_audit(
            section=section,
            app_context_summary="ctx",
            llm_opts=_llm_opts(),
        )

    assert "### Additional Detected Libraries (Version Not Determined)" in markdown
    assert "io.ktor" in markdown
    assert "okhttp" in markdown
    assert "Version Used: unknown" not in markdown


def test_query_dependencies_section_audit_no_deps_returns_placeholder():
    """An empty dependencies dict short-circuits to the standard no-findings placeholder."""
    section = {"heading": "## 5. Dependencies", "name": "Dependencies", "data": {"exact_versions_found": {}}}
    markdown, tool_log = _query_dependencies_section_audit(
        section=section,
        app_context_summary="ctx",
        llm_opts=_llm_opts(),
    )
    assert "No third-party dependencies were identified" in markdown
    assert tool_log == []


def test_render_network_json_with_groups():
    """Network renderer groups domains into cloud_services, trackers, and other."""
    parsed = {
        "no_findings": False,
        "cloud_services": [
            {
                "domain": "api.example.com",
                "urls": ["https://api.example.com/v1"],
                "referencing_packages": ["com.example.app"],
                "assessment": "Developer backend.",
                "is_developer_code": True,
            }
        ],
        "trackers_and_ads": [],
        "other": [],
    }
    result = _render_network_json("## 8. Network", parsed)
    assert "api.example.com" in result
    assert "Cloud Services" in result
    assert "developer code" in result


def test_render_vulns_json_produces_table():
    """Vuln renderer produces an OWASP markdown table with severity and CVSS columns."""
    parsed = {
        "no_findings": False,
        "summary": "High risk app.",
        "findings": [
            {
                "masvs_id": "MASVS-STORAGE-1",
                "owasp_category": "M1: Improper Credential Usage",
                "vulnerability": "Hardcoded API key",
                "severity": "HIGH",
                "cvss_score": "7.5",
                "cwe": "CWE-798",
            }
        ],
    }
    result = _render_vulns_json("## 9. Vulnerabilities", parsed)
    assert "M1: Improper Credential Usage" in result
    assert "| MASVS ID | OWASP Category | Vulnerability | Severity | CVSS v3 | CWE |" in result
    assert "MASVS-STORAGE-1" in result
    assert "7.5" in result
    assert "CWE-798" in result
    assert "High risk app." in result


def test_render_vulns_json_renders_na_when_cvss_absent():
    """A finding with no CVSS score still renders the CVSS v3 column with an explicit 'N/A'."""
    parsed = {
        "no_findings": False,
        "findings": [
            {
                "masvs_id": "MASVS-NETWORK-1",
                "owasp_category": "M4: Insecure Communication",
                "vulnerability": "Cleartext traffic",
                "severity": "HIGH",
                "cvss_score": None,
                "cwe": "CWE-319",
            }
        ],
    }
    result = _render_vulns_json("## 9. Vulnerabilities", parsed)
    assert "CVSS v3" in result
    assert "| MASVS-NETWORK-1 | M4: Insecure Communication | Cleartext traffic | HIGH | N/A | CWE-319 |" in result


def test_query_section_audit_request_exception():
    """Section audit handles an Ollama connection error gracefully."""
    section = {
        "name": "Manifest Audit",
        "heading": "## 1. Manifest Audit",
        "renderer": "findings",
        "data": {"security_flags": {"allow_backup": True}},
        "guidelines": "some guidelines",
    }
    with patch("scanner.util.ai_report.agentic_openai_query", side_effect=requests.exceptions.ConnectionError("err")):
        result, _log = _query_section_audit(
            section=section,
            app_context_summary="context",
            model="model",
            search_func=MagicMock(),
            max_tool_iterations=10,
            openai_url="http://api/v1",
        )
    assert "Error" in result


def _make_mock_report() -> dict:
    return {
        "apk_metadata": {
            "apk_name": "test.apk",
            "app_name": "MyTestApp",
            "package": "com.test.app",
            "size": 1234567,
            "app_version_name": "1.2.3",
            "app_version_code": "123",
        },
        "manifest_audit": {"security_flags": {"allow_backup": True}},
        "security_checks": {"rooted_device_detection": []},
        "signatures": {"is_debug_signed": True, "certificates": [{"serial_number": "abc"}]},
        "permissions": {
            "runtime_requested": ["android.permission.CAMERA"],
            "install_time_or_system": [],
            "custom_or_third_party": [],
        },
        "dependencies": {
            "third_party": {
                "com.squareup.okhttp3:okhttp": {
                    "version_used": "4.9.0",
                    "latest_version": "5.0.0",
                    "osv_findings": [],
                }
            },
            "android_default": {},
        },
        "secrets": [{"name": "key", "type": "google_api", "value": "AIza123"}],
        "bytecode_audit": {"ssl_bypass": ["SomeClass"]},
        "network": {"categorized_domains": {"other": ["example.com"]}},
        "vulnerabilities": [{"owasp_id": "M1", "severity": "HIGH", "description": "Hardcoded key"}],
    }


def test_generate_ai_report_returns_markdown():
    """generate_ai_report returns a markdown string containing core report metadata."""
    mock_report = _make_mock_report()

    mock_agentic_response = (
        '{"no_findings": false, "findings": [{"title": "Test Finding", '
        '"risk": "r", "attack_vector": "a", "developer_intent": "d", '
        '"remediation": "fix", "sources": []}]}'
    )

    with (
        patch("scanner.util.ai_report.clear_tool_cache"),
        patch("scanner.util.ai_report.resolve_search_func", return_value=MagicMock()),
        patch("scanner.util.ai_report.get_app_context", return_value="App context text."),
        patch(
            "scanner.util.ai_report.agentic_openai_query",
            return_value=(mock_agentic_response, "", []),
        ),
    ):
        report = generate_ai_report(mock_report, "http://api/v1", model="test-model")

    assert "Mobile Application Security Assessment Report" in report
    assert "MyTestApp" in report
    assert "com.test.app" in report
    assert "1.2.3" in report
    assert "test-model" in report
    assert "test.apk" in report


def test_generate_ai_report_marks_failed_sections_in_the_report():
    """A section whose worker keeps raising is retried, then marked failed in the report.

    It must never be omitted or rendered as clean: a reader cannot tell a dropped section
    from an audited one, and "no concerns" on a failed section is an outright false negative.
    """
    mock_report = _make_mock_report()
    logged: list[str] = []
    attempts: list[int] = []

    def _always_fails(**kwargs):
        attempts.append(1)
        raise RuntimeError("backend exploded")

    with (
        patch("scanner.util.ai_report.clear_tool_cache"),
        patch("scanner.util.ai_report.resolve_search_func", return_value=MagicMock()),
        patch("scanner.util.ai_report.get_app_context", return_value="ctx"),
        patch("scanner.util.ai_report._query_section_audit", side_effect=_always_fails),
        patch("scanner.util.ai_report.logger.error", side_effect=logged.append),
    ):
        report = generate_ai_report(mock_report, "http://api/v1", model="test-model")

    assert "Mobile Application Security Assessment Report" in report
    assert "Section generation failed" in report
    assert "not an all-clear" in report
    assert any("failed after all attempts" in msg for msg in logged)
    # Every failing section is retried exactly SECTION_ATTEMPTS times, never more.
    assert len(attempts) % SECTION_ATTEMPTS == 0


def test_generate_ai_report_fails_fast_on_backend_api_error_in_app_context():
    """When app context generation hits a fatal BackendAPIError, report generation aborts immediately."""
    mock_report = _make_mock_report()
    with (
        patch("scanner.util.ai_report.clear_tool_cache"),
        patch("scanner.util.ai_report.resolve_search_func", return_value=MagicMock()),
        patch("scanner.util.ai_report._agentic_query", side_effect=BackendAPIError("504 Gateway Timeout")),
    ):
        with pytest.raises(BackendAPIError) as exc_info:
            generate_ai_report(mock_report, "http://api/v1", model="test-model")
    assert "504 Gateway Timeout" in str(exc_info.value)


def test_generate_ai_report_fails_fast_on_backend_api_error_in_section():
    """When a section query hits a fatal BackendAPIError, report generation aborts immediately without retrying."""
    mock_report = _make_mock_report()
    attempts: list[int] = []

    def _fails_backend(**kwargs):
        attempts.append(1)
        raise BackendAPIError("401 Unauthorized")

    with (
        patch("scanner.util.ai_report.clear_tool_cache"),
        patch("scanner.util.ai_report.resolve_search_func", return_value=MagicMock()),
        patch("scanner.util.ai_report.get_app_context", return_value="ctx"),
        patch("scanner.util.ai_report._query_section_audit", side_effect=_fails_backend),
    ):
        with pytest.raises(BackendAPIError) as exc_info:
            generate_ai_report(mock_report, "http://api/v1", model="test-model", concurrency=1)
    assert "401 Unauthorized" in str(exc_info.value)
    # BackendAPIError must not be retried across SECTION_ATTEMPTS rounds
    assert len(attempts) == 1


def test_run_parallel_raises_backend_api_error_immediately():
    """_run_parallel re-raises BackendAPIError immediately when a chunk fails."""

    def _failing_job(x):
        raise BackendAPIError("Read timed out")

    with pytest.raises(BackendAPIError) as exc_info:
        _run_parallel(_failing_job, [(1,), (2,)], concurrency=2, what="test chunk")
    assert "Read timed out" in str(exc_info.value)


def test_generate_ai_report_tool_call_counts_in_header():
    """Tool call counts accumulated across sections appear in the report header."""
    mock_report = _make_mock_report()
    tool_log = [
        {"tool_name": "web_search", "args": {"query": "q"}},
        {"tool_name": "lookup_nvd_cve", "args": {"cve_id": "CVE-X"}},
    ]

    with (
        patch("scanner.util.ai_report.clear_tool_cache"),
        patch("scanner.util.ai_report.resolve_search_func", return_value=MagicMock()),
        patch("scanner.util.ai_report.get_app_context", return_value="ctx"),
        patch(
            "scanner.util.ai_report.agentic_openai_query",
            return_value=('{"no_findings": true, "findings": []}', "", tool_log),
        ),
    ):
        report = generate_ai_report(mock_report, "http://api/v1", model="test-model")

    # Header must show tool call statistics
    assert "tool call" in report.lower()


def test_generate_ai_report_skips_empty_sections():
    """Sections with no data receive a placeholder and no agentic query is made for them."""
    mock_report = {
        "apk_metadata": {"apk_name": "empty.apk", "app_name": "EmptyApp", "package": "com.empty", "size": 100},
        "manifest_audit": {},
        "security_checks": {},
        "signatures": {},
        "permissions": {"runtime_requested": [], "install_time_or_system": [], "custom_or_third_party": []},
        "dependencies": {},
        "secrets": [],
        "bytecode_audit": {},
        "network": {},
        "vulnerabilities": [],
    }

    with (
        patch("scanner.util.ai_report.clear_tool_cache"),
        patch("scanner.util.ai_report.resolve_search_func", return_value=MagicMock()),
        patch("scanner.util.ai_report.get_app_context", return_value="No info."),
        patch("scanner.util.ai_report.agentic_openai_query", return_value=("", "", [])) as mock_query,
    ):
        report = generate_ai_report(mock_report, "http://api/v1", model="model")

    # All sections are empty — no agentic queries should be fired
    assert mock_query.call_count == 0
    assert "EmptyApp" in report


def test_get_app_context_empty_package():
    """Returns a generic placeholder when both package and apk_name are empty."""
    empty_report = {"apk_metadata": {"package": "", "apk_name": ""}}
    result = get_app_context(
        empty_report,
        model="model",
        search_func=MagicMock(),
        max_tool_iterations=5,
        openai_url="http://api/v1",
    )
    assert "Unknown Android application" in result


def test_get_app_context_agentic_call_with_valid_json():
    """Returns rendered markdown from a valid JSON agentic response."""
    report = {"apk_metadata": {"package": "com.test", "apk_name": "Test"}}
    mock_json = json.dumps(
        {
            "app_name": "Test App",
            "developer": "Test Corp",
            "primary_purpose": "Testing.",
            "play_store_url": "https://play.google.com/store/apps/details?id=com.test",
            "official_website": None,
            "status": "Active",
            "description": "A test app by Test Corp.",
        }
    )
    with patch("scanner.util.ai_report.agentic_openai_query", return_value=(mock_json, "", [])):
        result = get_app_context(
            report, model="m", search_func=MagicMock(), max_tool_iterations=5, openai_url="http://api/v1"
        )
    assert "| **Developer** | Test Corp |" in result
    assert "A test app by Test Corp." in result


def test_get_app_context_falls_back_to_apk_metadata_when_model_finds_nothing():
    """When the model returns its 'no information found' fallback, the app context is anchored to
    the APK's own metadata so the app is still identified instead of showing nothing."""
    report = {
        "apk_metadata": {
            "package": "eu.europa.ec.ecas",
            "apk_name": "ecas.apk",
            "app_name": "EU Login Mobile",
            "app_version_name": "2.1.0",
        }
    }
    no_info = json.dumps(
        {
            "app_name": None,
            "developer": None,
            "primary_purpose": "No information found.",
            "play_store_url": None,
            "status": "Unknown",
            "description": "No information about this application could be found online.",
            "security_incidents": [],
            "sources": [],
        }
    )
    with (
        patch("scanner.web.playstore.fetch_play_store_metadata", return_value=None),
        patch("scanner.util.ai_report.agentic_openai_query", return_value=(no_info, "", [])),
    ):
        result = get_app_context(
            report, model="m", search_func=MagicMock(), max_tool_iterations=5, openai_url="http://api/v1"
        )
    assert "EU Login Mobile" in result
    assert "No information about this application could be found online." not in result
    # Without a confirmed live listing, no constructed store link is rendered (it could 404).
    assert "play.google.com" not in result


def test_get_app_context_falls_back_on_agentic_exception():
    """If the agentic query raises, the app is still identified from APK metadata, not lost."""
    report = {"apk_metadata": {"package": "com.acme.app", "apk_name": "acme.apk", "app_name": "Acme"}}
    with patch("scanner.util.ai_report.agentic_openai_query", side_effect=RuntimeError("model down")):
        result = get_app_context(
            report, model="m", search_func=MagicMock(), max_tool_iterations=5, openai_url="http://api/v1"
        )
    assert "Acme" in result
    assert "com.acme.app" in result


def test_format_playstore_metadata_block_present_and_absent():
    """The prompt block lists the verified fields, or an explicit 'research it yourself' notice."""
    block = _format_playstore_metadata_block(
        {
            "package": "eu.europa.ec.ecas",
            "source": "https://play.google.com/store/apps/details?id=eu.europa.ec.ecas",
            "name": "EU Login",
            "developer": "European Union",
            "description": "Multi-factor authentication for EU applications.",
        }
    )
    assert "App Name: EU Login" in block
    assert "Developer: European Union" in block
    assert "Multi-factor authentication" in block

    absent = _format_playstore_metadata_block(None)
    assert "No Play Store metadata" in absent
    assert "yourself" in absent


def test_backfill_app_context_from_store_overrides_gaps_but_keeps_model_description():
    """Store data fills empty identity fields and replaces the 'no info' description, but a real
    model-written description is preserved."""
    store = {
        "package": "eu.europa.ec.ecas",
        "source": "https://play.google.com/store/apps/details?id=eu.europa.ec.ecas",
        "name": "EU Login",
        "developer": "European Union",
        "description": "Official EU multi-factor authentication app.",
    }

    # Empty model output: every field is backfilled from the store scrape.
    empty: dict = {"app_name": None, "description": "No information about this application could be found online."}
    _backfill_app_context_from_store(empty, store)
    assert empty["app_name"] == "EU Login"
    assert empty["developer"] == "European Union"
    assert empty["description"] == "Official EU multi-factor authentication app."
    assert empty["play_store_url"].endswith("id=eu.europa.ec.ecas")

    # Rich model output: the model's own name and description win over the store scrape.
    rich = {"app_name": "EU Login (Model)", "description": "A detailed, model-synthesised overview of the app."}
    _backfill_app_context_from_store(rich, store)
    assert rich["app_name"] == "EU Login (Model)"
    assert rich["description"] == "A detailed, model-synthesised overview of the app."
    # Developer was still missing, so it is filled from the store.
    assert rich["developer"] == "European Union"


def test_get_app_context_uses_prefetched_playstore_when_model_finds_nothing():
    """Even when the model emits its 'no info' fallback, the deterministic Play Store pre-fetch
    supplies the real name, developer, and description, so the overview is never a package stub."""
    report = {
        "apk_metadata": {
            "package": "eu.europa.ec.ecas",
            "apk_name": "ecas.apk",
            "app_name": "ecas",
            "app_version_name": "2.1.0",
        }
    }
    no_info = json.dumps(
        {
            "app_name": None,
            "developer": None,
            "description": "No information about this application could be found online.",
            "security_incidents": [],
            "sources": [],
        }
    )
    store = {
        "package": "eu.europa.ec.ecas",
        "source": "https://play.google.com/store/apps/details?id=eu.europa.ec.ecas",
        "name": "EU Login",
        "developer": "European Union",
        "description": "Official EU multi-factor authentication app used to sign in to EU services.",
    }
    with (
        patch("scanner.web.playstore.fetch_play_store_metadata", return_value=store),
        patch("scanner.util.ai_report.agentic_openai_query", return_value=(no_info, "", [])),
    ):
        result = get_app_context(
            report, model="m", search_func=MagicMock(), max_tool_iterations=5, openai_url="http://api/v1"
        )
    assert "European Union" in result
    # A live listing deterministically proves the app is distributed.
    assert "| **Status** | Active (listed on Google Play) |" in result
    # Description comes from the backfilled store metadata.
    assert "Official EU multi-factor authentication app" in result
    assert "No information about this application could be found online." not in result


def test_get_app_context_collects_tool_calls_into_out_param():
    """tool_calls_out is populated with the agentic query's tool_call_log entries, using the
    same 'tool_name' key produced by tool_runner, so callers can tally per-tool call counts."""
    report = {"apk_metadata": {"package": "com.test.toolcalls.unique", "apk_name": "Test"}}
    mock_json = json.dumps({"app_name": "Test App", "primary_purpose": "Testing."})
    tool_call_log = [{"tool_name": "lookup_play_store", "args": {"package_name": "com.test.toolcalls.unique"}}]
    tool_calls_out: list = []
    with patch("scanner.util.ai_report.agentic_openai_query", return_value=(mock_json, "", tool_call_log)):
        get_app_context(
            report,
            model="m",
            search_func=MagicMock(),
            max_tool_iterations=5,
            openai_url="http://api/v1",
            tool_calls_out=tool_calls_out,
        )
    assert tool_calls_out == tool_call_log
    assert tool_calls_out[0]["tool_name"] == "lookup_play_store"


def test_get_app_context_exception_handling():
    """Returns a fallback message when the agentic query raises an exception."""
    report = {"apk_metadata": {"package": "com.fail", "apk_name": "Fail"}}
    with patch("scanner.util.ai_report.agentic_openai_query", side_effect=Exception("Connection refused")):
        result = get_app_context(
            report, model="m", search_func=MagicMock(), max_tool_iterations=5, openai_url="http://api/v1"
        )
    assert "com.fail" in result or "No information" in result


def test_scraper_client():
    """Verifies that get_html routes queries through scraper API, and handles errors correctly."""
    orig_url = scraper.SCRAPER_URL
    try:
        set_scraper_url(None)
        with pytest.raises(ValueError, match=r"Scraper API URL is not configured\."):
            get_html("https://example.com")

        set_scraper_url("http://my-scraper.local")
        mock_scraper_response = MagicMock()
        mock_scraper_response.json.return_value = {"html": "Scraper content"}
        mock_scraper_response.status_code = 200

        with patch("requests.get", return_value=mock_scraper_response) as mock_get:
            html = get_html("https://example.com")
            assert html == "Scraper content"
            mock_get.assert_called_once()
            args, kwargs = mock_get.call_args
            assert args[0] == "http://my-scraper.local/scrape"
            assert kwargs["params"] == {"url": "https://example.com"}

        mock_error_response = MagicMock()
        mock_error_response.json.return_value = {"error": "Scraping failed"}
        mock_error_response.status_code = 200
        with patch("requests.get", return_value=mock_error_response):
            with pytest.raises(RuntimeError, match="Scraper API returned error: Scraping failed"):
                get_html("https://example.com")

        with patch("requests.get", side_effect=Exception("Connection timed out")):
            with pytest.raises(RuntimeError, match="Scraper API request failed: Connection timed out"):
                get_html("https://example.com")

        mock_invalid_response = MagicMock()
        mock_invalid_response.json.return_value = {"something_else": True}
        mock_invalid_response.status_code = 200
        with patch("requests.get", return_value=mock_invalid_response):
            with pytest.raises(RuntimeError, match=r"Scraper API response did not contain 'html' or 'error'\."):
                get_html("https://example.com")
    finally:
        scraper.SCRAPER_URL = orig_url


def test_format_report_header_basic():
    """_format_report_header includes all key metadata fields."""
    scan_report = {
        "apk_metadata": {
            "package": "com.example.app",
            "apk_name": "Target App",
            "app_name": "My App",
            "size": 1500000,
            "app_version_name": "1.0.0",
            "app_version_code": "1",
        }
    }
    header = _format_report_header(
        scan_report,
        security_score=100.0,
        security_grade="A",
        app_context_summary="App context summary.",
        model="qwen3.6:35b",
        duration_seconds=12.5,
        tool_call_counts={"web_search": 4, "lookup_nvd_cve": 2},
    )
    assert "My App" in header
    assert "com.example.app" in header
    assert "qwen3.6:35b" in header
    assert "web_search" in header
    assert "lookup_nvd_cve" in header
    assert "- **Recommendation**: Recommended" in header
    assert "- **Security Score**:" not in header
    assert "(Grade:" not in header


def test_format_report_header_zero_tool_calls_with_scraper():
    """_format_report_header reports active status with 0 tool calls when scraper is configured."""
    with patch("scanner.web.scraper.SCRAPER_URL", "http://localhost:8000"):
        header = _format_report_header(
            {},
            security_score=100.0,
            security_grade="A",
            app_context_summary="App context.",
            model="qwen3.6:35b",
            duration_seconds=1.0,
            tool_call_counts={},
        )
    assert "- **Threat Intelligence Search**: Active (qwen3.6:35b, 0 tool calls made)" in header


def test_format_report_header_zero_tool_calls_without_scraper():
    """_format_report_header reports active without scraper when scraper is unconfigured and 0 tool calls made."""
    with patch("scanner.web.scraper.SCRAPER_URL", None):
        header = _format_report_header(
            {},
            security_score=100.0,
            security_grade="A",
            app_context_summary="App context.",
            model="qwen3.6:35b",
            duration_seconds=1.0,
            tool_call_counts={},
        )
    assert "- **Threat Intelligence Search**: Active without web scraper (qwen3.6:35b, 0 tool calls made)" in header


def test_filter_network_data_basic():
    """_filter_network_data compresses categorized domains and attributes packages."""
    network = {
        "categorized_domains": {
            "cloud_services": ["firebase.google.com"],
            "trackers_and_ads": [],
            "other": ["carsync.de"],
        },
        "attributed_urls": {
            "de.vispiron.carsync": [
                "https://portal.carsync-log.de",
                "https://www.carsync.de/ueber-uns",
            ],
            "com.google.firebase": ["firebase.google.com/privacy"],
        },
    }
    filtered = _filter_network_data(network)
    assert "firebase.google.com" in [d["domain"] for d in filtered["cloud_services"]]
    assert "carsync.de" in [d["domain"] for d in filtered["other"]]

    # Check mapping
    firebase_entry = next(d for d in filtered["cloud_services"] if d["domain"] == "firebase.google.com")
    assert "com.google.firebase" in firebase_entry["referencing_packages"]
    assert "firebase.google.com/privacy" in firebase_entry["urls"]


def test_filter_network_data_caps_urls_per_domain():
    """A domain contributing hundreds of entries is sampled, not listed in full: the host is
    the security-relevant unit, and entries like 'type.googleapis.com/Foo' are protobuf type
    identifiers rather than request targets. Real request URLs (with a scheme) rank first."""
    many = [f"type.googleapis.com/Type{i}" for i in range(200)]
    network = {
        "categorized_domains": {"cloud_services": [], "trackers_and_ads": [], "other": ["type.googleapis.com"]},
        "attributed_urls": {"com.example": ["https://type.googleapis.com/real/endpoint", *many]},
    }
    entry = next(d for d in _filter_network_data(network)["other"] if d["domain"] == "type.googleapis.com")

    assert len(entry["urls"]) == 6
    assert entry["additional_url_count"] == 195
    # The one genuine request target is not buried behind the type identifiers.
    assert entry["urls"][0] == "https://type.googleapis.com/real/endpoint"

    # A domain within the cap keeps every URL and carries no omission count.
    small = {
        "categorized_domains": {"cloud_services": [], "trackers_and_ads": [], "other": ["api.example.com"]},
        "attributed_urls": {"com.example": ["https://api.example.com/a", "https://api.example.com/b"]},
    }
    entry_small = _filter_network_data(small)["other"][0]
    assert len(entry_small["urls"]) == 2
    assert "additional_url_count" not in entry_small


def test_render_network_json_reports_omitted_urls():
    """The rendered section states how many URLs were left out, so a sampled list is never
    mistaken for the app's complete network surface."""
    parsed = {
        "no_findings": False,
        "cloud_services": [],
        "trackers_and_ads": [],
        "other": [
            {
                "domain": "type.googleapis.com",
                "urls": ["type.googleapis.com/A", "type.googleapis.com/B"],
                "additional_url_count": 407,
                "assessment": "Protobuf type registry.",
            }
        ],
    }
    result = _render_network_json("## 8. Network", parsed)
    assert "(+407 more not listed)" in result
    assert "type.googleapis.com/A" in result


def test_filter_network_data_exclusions_and_limits():
    """_filter_network_data excludes boilerplate domains and limits output count."""
    network = {
        "categorized_domains": {
            "cloud_services": [],
            "trackers_and_ads": [],
            "other": [
                "w3.org",
                "schemas.microsoft.com",
                "kotlinlang.org",
                "d1.com",
                "d2.com",
                "d3.com",
                "d4.com",
                "d5.com",
                "d6.com",
                "d7.com",
                "d8.com",
                "d9.com",
                "d10.com",
                "d11.com",
                "d12.com",
                "d13.com",
                "d14.com",
                "d15.com",
                "d16.com",
                "d17.com",
                "d18.com",
                "d19.com",
                "d20.com",
                "d21.com",
                "d22.com",
            ],
        },
        "attributed_urls": {},
    }
    filtered = _filter_network_data(network)
    other_domains = [d["domain"] for d in filtered["other"]]

    # Boilerplate domains must be excluded
    assert "w3.org" not in other_domains
    assert "schemas.microsoft.com" not in other_domains

    # Must not be capped at 20 anymore (all 22 domains audited)
    assert len(other_domains) == 22
    assert "d1.com" in other_domains
    assert "d20.com" in other_domains
    assert "d22.com" in other_domains


def test_save_current_progress_writes_sections_to_disk(tmp_path):
    """save_current_progress writes the header and joined section bodies to the file."""
    from scanner.util.ai_report import save_current_progress

    report_file = tmp_path / "temp_report.md"
    header = "# Assessment Report\n- Model: test"
    sections = [
        "## 1. Manifest Audit\n\nThis is the manifest audit details with enough length to be valid.",
        "## 2. Security Capabilities\n\nThis is the security capabilities details with enough length to be valid. ---",
    ]

    save_current_progress(str(report_file), sections, header)

    content = report_file.read_text(encoding="utf-8")
    assert "This is the manifest audit details" in content
    assert "This is the security capabilities details" in content


def test_generate_ai_report_does_not_blindly_reuse_stale_report_file(tmp_path):
    """A pre-existing report file at ai_report_path must never be trusted just because a section
    heading happens to already be present in it — every section is genuinely re-audited. This
    guards against silently reusing stale content after the findings, prompt, or code changed."""
    from scanner.util.ai_report import generate_ai_report, save_current_progress

    report_file = tmp_path / "recovery_report.md"
    header = "# Assessment Report\n- Model: test"
    # Plant unrelated, stale text under the Manifest Audit heading — not a real cache entry.
    stale_sections = ["## 1. Manifest Audit\n\nThis is stale text unrelated to the current findings."]
    save_current_progress(str(report_file), stale_sections, header)

    mock_report = {
        "apk_metadata": {"package": "com.test.stale-recovery", "apk_name": "Test", "sizeBytes": 1000, "hash": "abc"},
        "manifest_audit": {"security_flags": {"allow_backup": True}},
        "security_checks": {},
        "signatures": {},
        "permissions": [],
        "dependencies": {},
        "secrets": [],
        "bytecode_audit": {},
        "network": {},
        "vulnerabilities": [],
    }

    with (
        patch("scanner.util.ai_report.clear_tool_cache"),
        patch("scanner.util.ai_report.resolve_search_func", return_value=MagicMock()),
        patch("scanner.util.ai_report.get_app_context", return_value="No info."),
        patch(
            "scanner.util.ai_report._query_section_audit",
            return_value=("## 1. Manifest Audit\n\nFreshly generated content.", []),
        ) as mock_query,
    ):
        report = generate_ai_report(mock_report, "http://api/v1", model="model", ai_report_path=str(report_file))

    # The stale file content is never trusted; the section is genuinely re-audited.
    assert mock_query.call_count >= 1
    assert "stale text unrelated" not in report
    assert "Freshly generated content" in report


def test_parse_section_response_instructor_fallback():
    """_parse_section_response invokes Instructor fallback when direct JSON validation fails."""
    from unittest.mock import MagicMock

    from scanner.models.ai_report import FindingItem, FindingsSectionModel
    from scanner.util.ai_report import _parse_section_response

    mock_client = MagicMock()
    mock_model_res = FindingsSectionModel(findings=[FindingItem(title="Recovered Finding", risk="High risk")])
    mock_client.chat.completions.create.return_value = mock_model_res

    with patch("scanner.util.ai_report.get_instructor_client", return_value=mock_client):
        res = _parse_section_response(
            content="This is not json at all, but plain markdown finding description",
            model_cls=FindingsSectionModel,
            section_name="TestSection",
            openai_url="http://api/v1",
            model="model",
        )
        assert res is not None
        findings = res.get("findings")
        assert isinstance(findings, list) and len(findings) > 0
        assert findings[0]["title"] == "Recovered Finding"
        mock_client.chat.completions.create.assert_called_once()


def test_update_incremental_report(tmp_path):
    """_update_incremental_report writes incremental progress files to disk."""
    import threading

    from scanner.util.ai_report import _update_incremental_report

    report_file = tmp_path / "incremental_progress.md"
    write_lock = threading.Lock()
    scan_report = {"apk_metadata": {"package": "com.test", "apk_name": "Test"}}
    results: list[str | None] = ["## 1. Section One\n\nResult content"]

    _update_incremental_report(
        ai_report_path=str(report_file),
        write_lock=write_lock,
        start_time=123456789.0,
        scan_report=scan_report,
        security_score=100.0,
        security_grade="A",
        app_context_summary="Context summary",
        model="model",
        total_tool_call_counts={"tool": 1},
        results=results,
    )

    assert report_file.exists()
    content = report_file.read_text(encoding="utf-8")
    assert "## 1. Section One" in content
    assert "Result content" in content


def test_audit_query_job_parses_response_and_collects_tool_log():
    """_audit_query_job runs the agentic query, parses the JSON, and returns the tool log."""
    from scanner.util.ai_report import _audit_query_job

    section = {"heading": "## 8. Network", "name": "Network", "guidelines": "", "data": {}}
    with patch(
        "scanner.util.ai_report.agentic_openai_query",
        return_value=('{"other": [{"domain": "test.com"}]}', "think", [{"tool_name": "search"}]),
    ):
        parsed, content, thinking, tool_log = _audit_query_job(
            "Network_chunk_1", section, "{}", "App Context", _llm_opts(max_tool_iterations=5)
        )
    assert parsed == {"other": [{"domain": "test.com"}]}
    assert "test.com" in content
    assert thinking == "think"
    assert len(tool_log) == 1
    assert tool_log[0]["tool_name"] == "search"


def test_query_network_section_audit():
    """_query_network_section_audit handles empty domain list and chunks properly."""
    from scanner.util.ai_report import _query_network_section_audit

    section = {
        "heading": "## 8. Network",
        "name": "Network",
        "data": {"cloud_services": [], "trackers_and_ads": [], "other": []},
    }

    # Scenario 1: Empty domains list
    markdown, tool_log = _query_network_section_audit(
        section=section,
        app_context_summary="Context",
        llm_opts=_llm_opts(max_tool_iterations=5),
    )
    assert "No active network domains" in markdown
    assert tool_log == []

    # Scenario 2: Chunks query
    section_with_data = {
        "heading": "## 8. Network",
        "name": "Network",
        "guidelines": "",
        "data": {
            "cloud_services": [{"domain": "service.com"}],
            "trackers_and_ads": [],
            "other": [],
        },
    }
    with patch(
        "scanner.util.ai_report.agentic_openai_query",
        return_value=(
            '{"cloud_services": [{"domain": "service.com", "is_developer_code": false}]}',
            "",
            [{"tool_name": "search"}],
        ),
    ):
        markdown, tool_log = _query_network_section_audit(
            section=section_with_data,
            app_context_summary="Context",
            llm_opts=_llm_opts(max_tool_iterations=5),
        )
        assert "service.com" in markdown
        assert len(tool_log) == 1


def test_query_network_section_audit_stubs_unassessed_domains():
    """A domain the model drops (or whose chunk fails) is stubbed, never silently deleted."""
    from scanner.util.ai_report import _query_network_section_audit

    section = {
        "heading": "## 8. Network",
        "name": "Network",
        "guidelines": "",
        "data": {
            "cloud_services": [{"domain": "assessed.com"}, {"domain": "dropped.com"}],
            "trackers_and_ads": [],
            "other": [],
        },
    }
    with patch(
        "scanner.util.ai_report.agentic_openai_query",
        return_value=('{"cloud_services": [{"domain": "assessed.com", "is_developer_code": true}]}', "", []),
    ):
        markdown, _tool_log = _query_network_section_audit(
            section=section,
            app_context_summary="Context",
            llm_opts=_llm_opts(max_tool_iterations=5),
        )

    assert "assessed.com" in markdown
    assert "dropped.com" in markdown
    assert "not reviewed by the AI model" in markdown
    # No fabricated origin claim for the stub entry: exactly one Origin line (the assessed one).
    assert markdown.count("**Origin**") == 1


def test_query_network_section_audit_retries_dropped_domains():
    """A domain the model drops in the first round is re-queried, so a flaky answer costs a
    retry instead of a permanent stub. Only the still-missing domains go into the retry."""
    from scanner.util.ai_report import _query_network_section_audit

    section = {
        "heading": "## 8. Network",
        "name": "Network",
        "guidelines": "",
        "data": {
            "cloud_services": [{"domain": "first.com"}, {"domain": "flaky.com"}],
            "trackers_and_ads": [],
            "other": [],
        },
    }

    calls: list[str] = []

    def fake_query(**kwargs):
        calls.append(kwargs["prompt"])
        # Round 1 assesses only first.com; the retry then covers flaky.com.
        if "flaky.com" in kwargs["prompt"] and len(calls) > 1:
            return '{"cloud_services": [{"domain": "flaky.com", "is_developer_code": false}]}', "", []
        return '{"cloud_services": [{"domain": "first.com", "is_developer_code": true}]}', "", []

    with patch("scanner.util.ai_report.agentic_openai_query", side_effect=fake_query):
        markdown, _tool_log = _query_network_section_audit(
            section=section, app_context_summary="ctx", llm_opts=_llm_opts(max_tool_iterations=5)
        )

    assert len(calls) > 1, "the dropped domain must trigger a retry round"
    assert "first.com" in markdown and "flaky.com" in markdown
    # Recovered on retry, so nothing is left stubbed.
    assert "not reviewed by the AI model" not in markdown
    # The retry re-queries only what is still missing, not the whole set again.
    assert "first.com" not in calls[-1]


def test_query_network_section_audit_is_input_driven():
    """The scan owns the domain inventory: a domain the model invents is not added to the
    report, and each detected domain appears exactly once even if echoed twice."""
    from scanner.util.ai_report import _query_network_section_audit

    section = {
        "heading": "## 8. Network",
        "name": "Network",
        "guidelines": "",
        "data": {"cloud_services": [{"domain": "real.com"}], "trackers_and_ads": [], "other": []},
    }
    response = (
        '{"cloud_services": [{"domain": "real.com", "assessment": "A"},'
        ' {"domain": "real.com", "assessment": "duplicate"},'
        ' {"domain": "hallucinated.com", "assessment": "invented"}]}'
    )
    with patch("scanner.util.ai_report.agentic_openai_query", return_value=(response, "", [])):
        markdown, _ = _query_network_section_audit(
            section=section, app_context_summary="ctx", llm_opts=_llm_opts(max_tool_iterations=5)
        )

    assert "hallucinated.com" not in markdown
    assert markdown.count("**real.com**") == 1


def test_query_standard_section_audit():
    """_query_standard_section_audit renders the parsed response and surfaces query errors."""
    from scanner.util.ai_report import _query_standard_section_audit

    section = {
        "name": "Secrets",
        "heading": "## 6. Secrets",
        "renderer": "findings",
        "guidelines": "",
        "data": {},
    }

    # Mock agentic query
    with patch(
        "scanner.util.ai_report.agentic_openai_query",
        return_value=(
            '{"findings": [{"title": "Hardcoded API Key", "risk": "api_key exposed"}]}',
            "think",
            [],
        ),
    ):
        markdown, tool_log = _query_standard_section_audit(
            section=section,
            app_context_summary="Context",
            llm_opts=_llm_opts(max_tool_iterations=5),
        )
        assert "Hardcoded API Key" in markdown
        assert tool_log == []

    # Timeout scenario: the error stays visible in the section instead of a silent clean result.
    with patch(
        "scanner.util.ai_report.agentic_openai_query", side_effect=requests.exceptions.Timeout("Request timed out")
    ):
        markdown, tool_log = _query_standard_section_audit(
            section=section,
            app_context_summary="Context",
            llm_opts=_llm_opts(max_tool_iterations=5),
        )
        assert "timed out" in markdown
        assert tool_log == []


def test_render_info_list_json_renders_labeled_bullet_blocks():
    """Informational items render as bold-title bullet blocks with one sub-bullet per evidence
    artifact, matching the Permissions/Dependencies list style instead of a table."""
    from scanner.util.ai_report import _render_info_list_json

    parsed = {
        "no_findings": False,
        "items": [
            {
                "finding": "Custom Scheme Deep Links",
                "evidence": ["ecas:// in MainActivity", "ecasenrolment:// in MainActivity"],
                "detail": "Deep links let the browser hand off authentication redirects to the app.",
                "recommendation": "Validate incoming intent data.",
                "sources": [{"url": "https://developer.android.com/training/app-links", "description": "Android docs"}],
            }
        ],
    }
    result = _render_info_list_json("## 2. Informational", parsed)
    assert "- **Custom Scheme Deep Links**" in result
    assert "  - **Evidence**:" in result
    assert "    - ecas:// in MainActivity" in result
    assert "    - ecasenrolment:// in MainActivity" in result
    assert "  - **Detail**: Deep links let the browser hand off" in result
    assert "  - **Recommendation**: Validate incoming intent data." in result
    assert "  - **Sources:** " in result
    assert "developer.android.com" in result
    # No table markup remains anywhere in the section.
    assert "| :---" not in result and "| **Finding**" not in result

    # Older model outputs may echo evidence as one string; it still renders as a sub-bullet.
    legacy = _render_info_list_json(
        "## 2. Informational",
        {"no_findings": False, "items": [{"finding": "Exported Components", "evidence": "Activity: MainActivity"}]},
    )
    assert "  - **Evidence**:" in legacy
    assert "    - Activity: MainActivity" in legacy

    empty = _render_info_list_json("## 2. Informational", {"no_findings": True, "items": []})
    assert "No items were identified" in empty


def test_render_permissions_json_groups_by_scan_data():
    """Permissions render under the same three groups as the JSON report; the static scan's own
    grouping wins over a wrong group echoed by the model, and unknown names fall back to the
    model's group."""
    from scanner.util.ai_report import _render_permissions_json

    permissions_data = {
        "runtime_requested": ["android.permission.CAMERA"],
        "install_time_or_system": ["android.permission.INTERNET"],
        "custom_or_third_party": ["com.example.CUSTOM"],
    }
    parsed = {
        "no_findings": False,
        "items": [
            # Model echoed the WRONG group; the scan data must override it.
            {"name": "android.permission.CAMERA", "group": "install_time_or_system", "description": "Camera access."},
            {
                "name": "android.permission.INTERNET",
                "group": "install_time_or_system",
                "description": "Network sockets.",
            },
            {"name": "com.example.CUSTOM", "group": "custom_or_third_party", "description": "Custom receiver guard."},
            # Not in the scan data and an invalid group: falls back to install-time.
            {"name": "android.permission.UNKNOWN", "group": "made_up", "description": "Mystery."},
        ],
    }
    result = _render_permissions_json("## 4. Permissions", parsed, permissions_data)

    runtime = result.index("### Runtime Requested Permissions (Dangerous)")
    install = result.index("### Install-time or System Permissions")
    custom = result.index("### Custom or Third-Party Permissions")
    assert runtime < install < custom
    assert runtime < result.index("android.permission.CAMERA") < install
    assert install < result.index("android.permission.INTERNET") < custom
    assert install < result.index("android.permission.UNKNOWN") < custom
    assert result.index("com.example.CUSTOM") > custom


def test_get_app_context_omits_store_link_for_unlisted_apps():
    """An app with no Play Store listing gets no constructed (dead) store link, and a null
    developer renders as 'Unknown' instead of 'None'."""
    report = {"apk_metadata": {"package": "de.example.internal", "apk_name": "internal.apk", "app_name": "Internal"}}
    no_info = json.dumps(
        {
            "app_name": "Internal",
            "developer": None,
            "primary_purpose": "No information found.",
            "play_store_url": None,
            "status": "Unknown",
            "description": "An internal enterprise Android application.",
            "security_incidents": [],
            "sources": [],
        }
    )
    with (
        patch("scanner.web.playstore.fetch_play_store_metadata", return_value=None),
        patch("scanner.util.ai_report.agentic_openai_query", return_value=(no_info, "", [])),
    ):
        result = get_app_context(
            report, model="m", search_func=MagicMock(), max_tool_iterations=5, openai_url="http://api/v1"
        )
    assert "play.google.com" not in result
    assert "| **Developer** | Unknown |" in result


def test_assemble_app_context_grounding_and_fallbacks():
    """_assemble_app_context backfills name, developer, and description from store metadata,
    falling back cleanly to local metadata when store metadata is missing."""
    from scanner.util.ai_report import _assemble_app_context

    store = {"name": "Adobe Scan", "developer": "Adobe Inc.", "description": "Pocket scanner."}
    parsed = _assemble_app_context({}, store, "Adobe Scan APK", "com.adobe.scan.android", "1.0")
    assert parsed["app_name"] == "Adobe Scan"
    assert parsed["developer"] == "Adobe Inc."
    assert parsed["description"] == "Pocket scanner."

    # Fallback to local package details when store metadata is None
    parsed_fallback = _assemble_app_context({}, None, "My App", "com.example.myapp", "2.0")
    assert parsed_fallback["app_name"] == "My App"
    assert "com.example.myapp" in parsed_fallback["description"]


def test_section_regenerations_counted_and_rendered_in_header():
    """Formatting fallbacks and dependency retry rounds are counted per section and shown
    below the tool-call line in Report Details, so weak sections are measurable."""
    from unittest.mock import MagicMock

    from scanner.models.ai_report import FindingsSectionModel
    from scanner.util.ai_report import (
        _parse_section_response,
        _record_section_regeneration,
        _reset_section_regenerations,
    )

    _reset_section_regenerations()
    header = _format_report_header({}, 100.0, "A", "ctx", "m", 1.0, {})
    assert "- **Section Regenerations**: none" in header

    # A formatting fallback counts once, chunked sections under their base section name.
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = FindingsSectionModel(findings=[])
    with patch("scanner.util.ai_report.get_instructor_client", return_value=mock_client):
        _parse_section_response("bad", FindingsSectionModel, "Vulnerabilities", "u", "m")
        _parse_section_response("bad", FindingsSectionModel, "Network_chunk_2", "u", "m")
    _record_section_regeneration("Dependencies")
    _record_section_regeneration("Dependencies")

    header = _format_report_header({}, 100.0, "A", "ctx", "m", 1.0, {})
    assert "- **Section Regenerations**: Dependencies: 2, Network: 1, Vulnerabilities: 1" in header
    _reset_section_regenerations()


def test_failed_section_placeholder_is_not_an_all_clear():
    """A generation failure must read as a failure, never as 'no concerns found'."""
    md = _failed_section_placeholder({"heading": "## 9. Vulnerabilities"}, RuntimeError("budget exhausted"))
    assert md.startswith("## 9. Vulnerabilities")
    assert "Section generation failed" in md
    assert "not assessed" in md
    assert "not an all-clear" in md
    assert "budget exhausted" in md
    # The clean-section wording must never appear in a failure notice.
    assert "No security concerns" not in md


def test_section_attempts_is_bounded():
    """Retries exist to ride out transient errors, not to hammer a deterministic failure."""
    assert SECTION_ATTEMPTS == 3


_LLM_OPTS = {"model": "m", "openai_url": "http://api/v1", "search_func": None, "max_tool_iterations": 5}


def test_reports_no_findings_matches_renderer_emptiness_rules():
    assert _reports_no_findings({"no_findings": True, "findings": []}) is True
    assert _reports_no_findings({"findings": [], "items": []}) is True
    assert _reports_no_findings({"findings": [{"vulnerability": "x"}]}) is False
    assert _reports_no_findings({"items": [{"finding": "y"}]}) is False


def test_standard_section_with_input_findings_rejects_empty_model_answer():
    """A well-formed 'nothing found' reply for non-empty input must fail, not render clean."""
    section = {
        "name": "Bytecode Audit",
        "heading": "## 7. Bytecode Audit",
        "data": {"zip_slip_detected": True, "zip_slip_evidence": ["Class 'a.b' extracts ZipEntry paths"]},
        "renderer": "findings",
    }
    empty_reply = ({"thinking": "looks fine", "no_findings": True, "findings": []}, "raw", "", [])
    with patch("scanner.util.ai_report._audit_query_job", return_value=empty_reply):
        with pytest.raises(EmptySectionResultError, match="Bytecode Audit"):
            _query_standard_section_audit(section, "ctx", _LLM_OPTS)


def test_standard_section_renders_normally_when_findings_are_present():
    section = {
        "name": "Vulnerabilities",
        "heading": "## 9. Vulnerabilities",
        "data": [{"owasp_id": "M4", "severity": "MEDIUM"}],
        "renderer": "vulns",
    }
    reply = (
        {
            "thinking": "t",
            "no_findings": False,
            "summary": "s",
            "findings": [
                {
                    "owasp_category": "M5: Insecure Communication",
                    "vulnerability": "Cleartext",
                    "severity": "MEDIUM",
                    "cvss_score": None,
                    "cwe": None,
                    "sources": [],
                }
            ],
        },
        "raw",
        "",
        [],
    )
    with patch("scanner.util.ai_report._audit_query_job", return_value=reply):
        result, _log = _query_standard_section_audit(section, "ctx", _LLM_OPTS)
    assert "Cleartext" in result
    assert "No security concerns" not in result


def test_canonical_source_helpers():
    """Canonical source helpers produce valid URLs for standard permissions, manifest flags, and CVEs."""
    from scanner.util.ai_report import (
        _canonical_cve_source,
        _canonical_finding_source,
        _canonical_permission_source,
        _render_permissions_json,
    )

    perm_src = _canonical_permission_source("android.permission.READ_EXTERNAL_STORAGE")
    assert perm_src is not None
    assert "developer.android.com" in perm_src["url"]
    assert "READ_EXTERNAL_STORAGE" in perm_src["url"]

    custom_src = _canonical_permission_source("com.example.CUSTOM_PERM")
    assert custom_src is None

    finding_src = _canonical_finding_source("1. allowBackup Enabled")
    assert finding_src is not None
    assert "autobackup" in finding_src["url"]

    cve_src = _canonical_cve_source("Vulnerability CVE-2024-12345 in lib")
    assert cve_src is not None
    assert "CVE-2024-12345" in cve_src["url"]
    assert "nvd.nist.gov" in cve_src["url"]

    # Test permissions rendering includes canonical source when model provides none
    parsed_perms = {
        "thinking": "t",
        "no_findings": False,
        "items": [
            {
                "name": "android.permission.CAMERA",
                "group": "runtime_requested",
                "description": "Camera access",
                "risk_assessment": "Safe - expected for QR scanning",
                "sources": [],
            }
        ],
    }
    rendered = _render_permissions_json("## 2. Permissions", parsed_perms)
    assert "developer.android.com/reference/android/Manifest.permission#CAMERA" in rendered


def test_extract_code_from_remediation_gradle():
    """_extract_code_from_remediation extracts unfenced Gradle signingConfigs and infers groovy."""
    from scanner.models.ai_report import _extract_code_from_remediation

    remediation = (
        "Re-sign the APK using modern config. In build.gradle, apply:\n\n"
        "android {\n"
        "    signingConfigs {\n"
        "        release {\n"
        "            v1SigningEnabled true\n"
        "            v2SigningEnabled true\n"
        "        }\n"
        "    }\n"
        "}\n\n"
        "Then verify with jarsigner."
    )
    code, lang, cleaned = _extract_code_from_remediation(remediation)
    assert code is not None
    assert "android {" in code
    assert "signingConfigs {" in code
    assert lang == "groovy"
    assert "In build.gradle, apply:" in cleaned
    assert "Then verify with jarsigner." in cleaned
    assert "android {" not in cleaned


def test_extract_code_from_remediation_xml():
    """_extract_code_from_remediation extracts XML blocks and sets language to xml."""
    from scanner.models.ai_report import _extract_code_from_remediation

    remediation = (
        "Update the manifest:\n\n"
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n'
        '    <application android:allowBackup="false" />\n'
        "</manifest>\n\n"
        "Save and rebuild."
    )
    code, lang, cleaned = _extract_code_from_remediation(remediation)
    assert code is not None
    assert "<manifest" in code
    assert lang == "xml"
    assert "Save and rebuild." in cleaned
    assert "<manifest" not in cleaned


def test_finding_item_auto_extracts_remediation_code():
    """FindingItem extracts code from remediation when code_snippet is not provided."""
    from scanner.models.ai_report import FindingItem

    data = {
        "title": "Weak Signature Algorithm",
        "risk": "High risk",
        "attack_vector": "Collision attack",
        "developer_intent": "Legacy build script",
        "remediation": (
            "Ensure the following signing configuration is set:\n\n"
            "android {\n"
            "    signingConfigs {\n"
            "        release {\n"
            "            v2SigningEnabled true\n"
            "        }\n"
            "    }\n"
            "}\n"
        ),
        "code_snippet": None,
    }
    item = FindingItem.model_validate(data)
    assert item.code_snippet is not None
    assert "signingConfigs {" in item.code_snippet
    assert item.code_language == "groovy"
    assert "android {" not in item.remediation


def test_filter_informational_data_retains_all_evidence():
    """_filter_informational_data preserves all evidence artifacts without [:5] slicing."""
    from scanner.util.ai_report import _filter_informational_data

    info = [
        {
            "type": "hardcoded_secrets",
            "title": "Hardcoded Secrets and API Keys",
            "evidence": [f"Secret_{i}" for i in range(12)],
        }
    ]
    filtered = _filter_informational_data(info)
    assert len(filtered) == 1
    assert len(filtered[0]["evidence"]) == 12


def test_render_info_list_json_reconciles_evidence_from_section_data():
    """_render_info_list_json reconciles evidence when model outputs only a single top item."""
    from scanner.util.ai_report import _render_info_list_json

    parsed = {
        "no_findings": False,
        "items": [
            {
                "finding": "Zip Slip Path Traversal",
                "evidence": ["Hc.l"],
                "detail": "Zip extraction path traversal",
                "recommendation": "Validate canonical path",
            }
        ],
    }
    section_data = [
        {
            "type": "zip_slip",
            "title": "Zip Slip Path Traversal",
            "evidence": [
                "Class 'Hc.l' method 'e' extracts ZipEntry...",
                "Class 'rg.i' method 'a' extracts ZipEntry...",
            ],
        }
    ]
    rendered = _render_info_list_json("## 2. Informational", parsed, section_data)
    assert "- **Zip Slip Path Traversal**" in rendered
    assert "    - Hc.l" in rendered
    assert "    - rg.i" in rendered


def test_secret_group_key():
    """_secret_group_key extracts a dynamic grouping key from code package or variable name."""
    from scanner.util.ai_report import _secret_group_key

    # DEX class
    assert _secret_group_key(
        {
            "type": "aes_hex_key",
            "source": "com.google.android.gms.internal.ads.TU-><clinit>",
            "name": "Hardcoded String Constant",
        }
    ) == ("aes_hex_key", "com.google.android.gms.internal.ads")

    # Resource name
    assert _secret_group_key(
        {
            "type": "aes_hex_key",
            "source": "resource string XML table",
            "name": "facebook_client_token_prod",
        }
    ) == ("aes_hex_key", "facebook_client_token")


def test_group_secrets_for_audit():
    """_group_secrets_for_audit dynamically clusters secrets by origin package and variable name."""
    from scanner.util.ai_report import _group_secrets_for_audit

    assert _group_secrets_for_audit(None) is None
    assert _group_secrets_for_audit([]) == []

    raw_secrets = [
        # DEX origin: same package and type -> must cluster
        {
            "type": "aes_hex_key",
            "value": "36864200e0eaf5284d884a0e77d31646",
            "name": "Hardcoded String Constant",
            "source": "com.google.android.gms.internal.ads.jV-><clinit>",
        },
        {
            "type": "aes_hex_key",
            "value": "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "name": "Hardcoded String Constant",
            "source": "com.google.android.gms.internal.ads.TU-><clinit>",
        },
        # XML origin: shared prefix -> must cluster
        {
            "type": "aes_hex_key",
            "value": "4f6120fcdf03207176582e74682a6c87",
            "name": "facebook_client_token_prod",
            "source": "resource string XML table",
        },
        {
            "type": "aes_hex_key",
            "value": "64acad2374eca48cb988bee0203f9d42",
            "name": "facebook_client_token_stage",
            "source": "resource string XML table",
        },
        # Distinct single item
        {
            "type": "google_oauth",
            "value": "827597488311-ltbba6ukaedt718mpr32djdft9dtjhvf.apps.googleusercontent.com",
            "name": "default_web_client_id",
            "source": "resource string XML table",
        },
        # Other origin
        {
            "type": "generic_secret",
            "value": "supersecretkey123456",
            "name": "Hardcoded String Constant",
            "source": "Asset File: config.txt",
        },
    ]

    grouped = _group_secrets_for_audit(raw_secrets)
    assert grouped is not None
    assert len(grouped) == 4

    # 1. DEX cluster
    dex_cluster = next(g for g in grouped if "com.google.android.gms.internal.ads" in g["source"])
    assert dex_cluster["count"] == 2
    assert "36864200e0eaf5284d884a0e77d31646" in dex_cluster["values"]
    assert "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" in dex_cluster["values"]

    # 2. XML prefix cluster
    xml_cluster = next(g for g in grouped if "facebook_client_token" in g["name"])
    assert xml_cluster["count"] == 2
    assert "4f6120fcdf03207176582e74682a6c87" in xml_cluster["values"]
    assert "64acad2374eca48cb988bee0203f9d42" in xml_cluster["values"]

    # 3. Single XML item
    oauth_item = next(g for g in grouped if g["type"] == "google_oauth")
    assert oauth_item["count"] == 1
    assert oauth_item["name"] == "default_web_client_id"

    # 4. Other origin item
    other_item = next(g for g in grouped if g["type"] == "generic_secret")
    assert other_item["count"] == 1
    assert other_item["value"] == "supersecretkey123456"
