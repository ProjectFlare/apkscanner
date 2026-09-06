"""Unit tests for scanner.util.ai_prompt_templates.

Guards the wording guarantees that keep AI report findings epistemically honest and
the security-incident research constrained to trusted, recent, material items.
"""

from scanner.util.ai_prompt_templates import (
    APP_CONTEXT_PROMPT_TEMPLATE,
    APP_CONTEXT_SCHEMA,
    BYTECODE_AUDIT_GUIDELINES,
    DEPENDENCIES_PROMPT_TEMPLATE,
    DEPS_SCHEMA,
    FINDINGS_SCHEMA,
    INFORMATIONAL_GUIDELINES,
    MANIFEST_AUDIT_GUIDELINES,
    SYSTEM_PROMPT_TEMPLATE,
    VULNERABILITIES_PROMPT_TEMPLATE,
)


def test_app_context_prompt_has_incident_gates_and_placeholders():
    """The incident research must be gated and parameterised by framework + cutoff date."""
    assert "__UI_FRAMEWORK__" in APP_CONTEXT_PROMPT_TEMPLATE
    assert "__INCIDENT_CUTOFF_DATE__" in APP_CONTEXT_PROMPT_TEMPLATE
    lowered = APP_CONTEXT_PROMPT_TEMPLATE.lower()
    assert "trusted source" in lowered
    assert "material" in lowered
    assert "adoption-risk" in lowered


def test_app_context_schema_uses_structured_incident_list():
    """security_incidents is a structured list, and the empty fallback is [] not null."""
    assert '"relation"' in APP_CONTEXT_SCHEMA
    assert '"impact"' in APP_CONTEXT_SCHEMA
    assert '"source_url"' in APP_CONTEXT_SCHEMA
    assert '"security_incidents": []' in APP_CONTEXT_SCHEMA


def test_system_prompt_recency_scope():
    """The two-year cap is scoped to incident news, not remediation/version research."""
    lowered = SYSTEM_PROMPT_TEMPLATE.lower()
    assert "most recent" in lowered
    assert "allowlist" in lowered


def test_system_prompt_dates_queries_and_bans_year_stuffing():
    """The model is told the current date and forbidden from baking a year into searches."""
    assert "__CURRENT_DATE__" in SYSTEM_PROMPT_TEMPLATE
    lowered = SYSTEM_PROMPT_TEMPLATE.lower()
    assert "training data is older" in lowered
    assert "never add a year or date to a web_search query" in lowered


def test_system_prompt_allows_flowing_prose_and_enforces_grounding():
    """Style is relaxed to natural prose report-wide, and evidence grounding is mandated."""
    lowered = SYSTEM_PROMPT_TEMPLATE.lower()
    # The old choppy 'short sentences' directive is gone; prose should flow naturally.
    assert "short sentences" not in lowered
    assert "flow" in lowered
    # Dashes stay banned even under the relaxed style.
    assert "en dashes" in lowered
    # Evidence-grounding guardrail: flags do not prove specific data exposure.
    assert "evidence grounding" in lowered
    assert "allowbackup" in lowered


def test_manifest_guidelines_ground_allowbackup_claims():
    """allowBackup guidance must curb invented data-exposure claims and note Keystore/biometric."""
    lowered = MANIFEST_AUDIT_GUIDELINES.lower()
    assert "allowbackup" in lowered
    assert "keystore" in lowered
    assert "biometric" in lowered
    assert "conditional" in lowered
    # The scoping mechanisms that narrow what is actually backed up are called out.
    assert "fullbackupcontent" in lowered or "dataextractionrules" in lowered


def test_findings_schema_risk_is_evidence_grounded():
    """The risk/attack_vector fields must forbid asserting specific unverified secrets."""
    lowered = FINDINGS_SCHEMA.lower()
    assert "grounded strictly in the evidence" in lowered
    assert "conditionally" in lowered


def test_findings_schema_and_bytecode_guidelines_require_raw_code():
    """The schema and guidelines must instruct the model to return raw code without markdown fences."""
    lowered_schema = FINDINGS_SCHEMA.lower()
    assert "raw code" in lowered_schema
    assert "do not wrap in markdown code fences" in lowered_schema
    lowered_guidelines = BYTECODE_AUDIT_GUIDELINES.lower()
    assert "raw code without markdown backticks" in lowered_guidelines


def test_vulnerabilities_prompt_preserves_owasp_categorization():
    """Vulnerabilities prompt instructs model to echo OWASP Mobile Top 10 category from findings."""
    assert "OWASP Mobile Top 10" in VULNERABILITIES_PROMPT_TEMPLATE


def test_bytecode_guidelines_report_false_positives_instead_of_hiding_them():
    """A likely false positive must be reported and explained, never silently dropped.

    The earlier "omit it" wording let a model return an empty Bytecode section for an app
    with four true detections. The policy now matches the vulnerabilities prompt: report
    everything, judge library-internal patterns from the evidence, and downgrade to LOW.
    """
    assert "Report every detection in the data; never drop one." in BYTECODE_AUDIT_GUIDELINES
    assert "LOW" in BYTECODE_AUDIT_GUIDELINES
    assert "omit" not in BYTECODE_AUDIT_GUIDELINES.lower()
    lowered = BYTECODE_AUDIT_GUIDELINES.lower()
    assert "rather than from any assumption" in lowered
    for name in ("tink", "conscrypt", "bouncycastle"):
        assert name not in lowered


def test_informational_guidelines_are_grounded_and_human():
    """Informational guidance asks for connected prose grounded in the item evidence."""
    lowered = INFORMATIONAL_GUIDELINES.lower()
    assert "informational" in lowered
    assert "evidence" in lowered
    # Must not affect the score and must guide handling of tooling artifacts.
    assert "score" in lowered
    assert "tooling" in lowered


def _all_public_templates() -> dict:
    """Collects every public string constant exported by the templates module."""
    import scanner.util.ai_prompt_templates as templates

    return {
        name: value for name, value in vars(templates).items() if not name.startswith("_") and isinstance(value, str)
    }


def test_templates_avoid_mirrorable_style_pitfalls():
    """No template may contain em/en dashes or the jargon 'benign': local models mirror the
    vocabulary and punctuation of their prompts, so banned output style must not appear in
    the prompt text itself."""
    for name, value in _all_public_templates().items():
        assert "—" not in value, f"{name} contains an em dash"
        assert "\u2013" not in value, f"{name} contains an en dash"
        assert "benign" not in value.lower(), f"{name} contains 'benign'"


def test_permissions_schema_carries_report_grouping():
    """The permissions schema echoes the JSON report's three grouping keys."""
    from scanner.util.ai_prompt_templates import PERMISSIONS_PROMPT_TEMPLATE, PERMISSIONS_SCHEMA

    for key in ("runtime_requested", "install_time_or_system", "custom_or_third_party"):
        assert key in PERMISSIONS_SCHEMA
        assert key in PERMISSIONS_PROMPT_TEMPLATE
    assert '"group"' in PERMISSIONS_SCHEMA


def test_informational_schema_matches_list_fields():
    """The informational schema provides the four rendered fields and stays app-context aware."""
    from scanner.util.ai_prompt_templates import INFORMATIONAL_PROMPT_TEMPLATE, INFORMATIONAL_SCHEMA

    for field in ('"finding"', '"evidence"', '"detail"', '"recommendation"'):
        assert field in INFORMATIONAL_SCHEMA
    assert "Application Context" in INFORMATIONAL_PROMPT_TEMPLATE
    lowered = INFORMATIONAL_PROMPT_TEMPLATE.lower()
    assert "score" in lowered
    assert "tooling" in lowered


def test_app_context_requires_neutral_rewritten_description():
    """The description must be rewritten neutrally instead of echoing store marketing copy."""
    lowered = APP_CONTEXT_SCHEMA.lower()
    assert "third-person" in lowered
    assert "marketing" in lowered
    assert "rhetorical questions" in lowered
    prompt_lowered = APP_CONTEXT_PROMPT_TEMPLATE.lower()
    assert "neutral" in prompt_lowered


def test_deps_prompt_uses_precomputed_known_facts():
    """The dependencies prompt trusts the precomputed facts for both the latest version and
    the OSV verdict, and tells the model not to issue redundant tool lookups."""
    from scanner.util.ai_prompt_templates import DEPENDENCIES_PROMPT_TEMPLATE, DEPS_SCHEMA

    assert "do NOT call lookup_maven_version or lookup_osv_vulnerabilities" in DEPENDENCIES_PROMPT_TEMPLATE
    assert "known_facts" in DEPS_SCHEMA


def test_deps_schema_forbids_cves_for_unknown_versions():
    """An unversioned library must be reported as unassessed, never from model memory.

    A CVE cannot be attributed without a version, and the earlier "historical
    vulnerabilities" wording produced confident CVE lines with wrong scores, wrong CWEs
    and wrong products for libraries the tools were never able to check.
    """
    assert "Version unknown - not assessed" in DEPS_SCHEMA
    assert "historically" not in DEPS_SCHEMA
    assert "NEVER state a CVE" in DEPS_SCHEMA


def test_dependencies_prompt_tells_model_not_to_recall_cves():
    """The instruction block must agree with the schema on unversioned dependencies."""
    assert "Version unknown - not assessed" in DEPENDENCIES_PROMPT_TEMPLATE
    assert "recalling one from memory" in DEPENDENCIES_PROMPT_TEMPLATE


def test_vulnerabilities_prompt_reports_false_positives_instead_of_hiding_them():
    """A likely false positive must be reported and explained, never silently dropped."""
    assert "Report every finding in the data; never drop one." in VULNERABILITIES_PROMPT_TEMPLATE
    assert "lower" in VULNERABILITIES_PROMPT_TEMPLATE and "LOW" in VULNERABILITIES_PROMPT_TEMPLATE


def test_vulnerabilities_prompt_does_not_preload_trusted_library_names():
    """Naming libraries as trustworthy up front biases the model before it reads the evidence."""
    for name in ("com.google.crypto.tink", "Conscrypt", "BouncyCastle"):
        assert name not in VULNERABILITIES_PROMPT_TEMPLATE
    assert "rather than from any assumption" in VULNERABILITIES_PROMPT_TEMPLATE


def test_signatures_schema_and_guidelines_include_code_snippet():
    """Signatures schema and guidelines must include code_snippet and code_language."""
    from scanner.util.ai_prompt_templates import SIGNATURES_GUIDELINES, SIGNATURES_SCHEMA

    assert '"code_snippet"' in SIGNATURES_SCHEMA
    assert '"code_language"' in SIGNATURES_SCHEMA
    assert "signingConfigs" in SIGNATURES_SCHEMA or "signingConfigs" in SIGNATURES_GUIDELINES
    assert "code_snippet" in SIGNATURES_GUIDELINES


def test_informational_schema_and_guidelines_request_all_evidence():
    """Informational schema and guidelines must instruct the model to report all evidence items."""
    from scanner.util.ai_prompt_templates import INFORMATIONAL_GUIDELINES, INFORMATIONAL_SCHEMA

    assert "All exact artifacts" in INFORMATIONAL_SCHEMA
    assert "never truncate" in INFORMATIONAL_GUIDELINES
