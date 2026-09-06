"""Pydantic data models for structured AI security report generation.

Defines type-safe schemas for each section of the automated security audit report,
complete with field-level normalization and validation (e.g. stripping markdown fences
from code snippets, normalizing source references, and providing fallback defaults).
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def is_dummy_code_snippet(snippet: str) -> bool:
    """Checks if a code snippet contains no actual code or is an opt-out comment placeholder.

    Identifies snippets that models emit when opting out of code generation (e.g. comments
    stating that a fix is not available in application code or is in a third-party library),
    allowing downstream renderers to omit empty/redundant code blocks.

    Args:
        snippet (str): Code snippet to inspect.

    Returns:
        bool: True if the snippet contains no executable code and should be discarded, False otherwise.
    """
    if not snippet or not snippet.strip():
        return True

    clean = snippet.strip()
    lines = [line.strip() for line in clean.splitlines() if line.strip()]
    if not lines:
        return True

    comment_prefixes = ("//", "/*", "*", "*/", "#", "<!--", "-->", ";")

    # Check for known opt-out disclaimer phrases used by models
    opt_out_indicators = (
        "no direct fix",
        "no fix available",
        "no direct code fix",
        "no code fix",
        "update the library",
        "update to the latest version",
        "third-party library",
        "third party library",
        "implementation is in",
        "not applicable",
        "cannot be fixed",
        "no code changes",
        "no code required",
    )
    lower = clean.lower()
    if any(phrase in lower for phrase in opt_out_indicators):
        code_lines = [line for line in lines if not any(line.startswith(p) for p in comment_prefixes)]
        if not code_lines or (len(code_lines) <= 2 and not any(ch in clean for ch in (";", "{", "}", "=", "<", ">"))):
            return True

    # Discard if 100% of non-empty lines are comments (a valid code fix must contain actual code)
    if all(any(line.startswith(p) for p in comment_prefixes) for line in lines):
        return True

    return False


def clean_code_snippet(snippet: str, lang: str = "") -> tuple[str, str]:
    """Strips markdown code fences and discards dummy/opt-out placeholder snippets.

    Local models frequently return ``code_snippet`` already wrapped in ```<lang> ... ``` fences,
    or output comment-only opt-out placeholders (e.g. ``// No direct fix available``).

    Args:
        snippet (str): Raw code snippet from the model response.
        lang (str): Optional language identifier from code_language.

    Returns:
        tuple[str, str]: Cleaned raw code snippet without enclosing fences, and language tag.
            If the snippet is empty or an opt-out placeholder, returns ("", "").
    """
    clean_snippet = snippet.strip()
    clean_lang = (lang or "").strip().lower()

    # Repeatedly unwrap outer markdown fences if the model wrapped the snippet in them
    while clean_snippet.startswith("```"):
        match = re.match(r"^```([a-zA-Z0-9_+-]*)[ \t]*\r?\n?(.*)", clean_snippet, re.DOTALL)
        if not match:
            break
        fence_lang, rest = match.groups()
        if fence_lang and not clean_lang:
            clean_lang = fence_lang.strip().lower()

        rest = rest.strip()
        if rest.endswith("```"):
            clean_snippet = rest[:-3].strip()
        else:
            clean_snippet = rest
            break

    # Strip any trailing stray closing fence left behind by unterminated model output
    if clean_snippet.endswith("```"):
        clean_snippet = clean_snippet[:-3].strip()

    if is_dummy_code_snippet(clean_snippet):
        return "", ""

    if not clean_lang:
        clean_lang = _infer_code_language(clean_snippet)

    return clean_snippet, clean_lang


def _infer_code_language(code: str) -> str:
    """Infers code snippet programming language from structural keywords.

    Args:
        code (str): Cleaned code snippet string.

    Returns:
        str: Lowercase language tag (e.g. 'xml', 'groovy', 'kotlin', 'java'), or empty string.
    """
    if not code:
        return ""
    if code.startswith("<") or "android:" in code or "</" in code:
        return "xml"
    if any(k in code for k in ("android {", "signingConfigs", "buildTypes", "dependencies {")):
        return "groovy"
    if any(k in code for k in ("fun ", "val ", "var ", "object :", "by lazy")):
        return "kotlin"
    if any(k in code for k in ("public class", "public void", "private void", "import java.")):
        return "java"
    return ""


def _extract_code_from_remediation(remediation: str) -> tuple[str | None, str, str]:
    """Detects and extracts embedded code blocks from remediation text when code_snippet is empty.

    Models occasionally include code blocks directly in the remediation narrative (either fenced
    in markdown or unfenced like Gradle configurations or XML manifests) instead of populating
    the code_snippet field.

    Args:
        remediation (str): Raw remediation text.

    Returns:
        tuple[str | None, str, str]: Extracted code snippet (or None), inferred language, and
            the cleaned remediation text without the extracted code block.
    """
    if not remediation:
        return None, "", remediation

    # 1. Check for fenced code block (```lang ... ```)
    fenced_match = re.search(r"```([a-zA-Z0-9_\-+]*)\r?\n(.*?)```", remediation, re.DOTALL)
    if fenced_match:
        code = fenced_match.group(2).strip()
        lang = fenced_match.group(1).strip().lower()
        cleaned = (
            remediation[: fenced_match.start()].rstrip() + "\n\n" + remediation[fenced_match.end() :].lstrip()
        ).strip()
        if not lang:
            lang = _infer_code_language(code)
        return code, lang, cleaned

    # 2. Check for multi-line XML blocks (<manifest...>, <application...>, etc.)
    xml_match = re.search(
        r"((?:^|\n)[ \t]*<(?:manifest|application|activity|service|receiver|provider|network-security-config|domain-config)[\s>].*?</(?:manifest|application|activity|service|receiver|provider|network-security-config|domain-config)>)",
        remediation,
        re.DOTALL,
    )
    if xml_match:
        code = xml_match.group(1).strip()
        cleaned = (remediation[: xml_match.start()].rstrip() + "\n\n" + remediation[xml_match.end() :].lstrip()).strip()
        return code, "xml", cleaned

    # 3. Check for brace-delimited blocks (Gradle signingConfigs/android, Java/Kotlin classes/methods)
    brace_patterns = [
        r"(?:^|\n)([ \t]*(?:android|signingConfigs|buildTypes|dependencies|plugins)\s*\{)",
        r"(?:^|\n)([ \t]*(?:fun|public\s+class|class|private\s+fun|public\s+void)\s+[A-Za-z0-9_]+[^{]*\{)",
    ]
    for pat in brace_patterns:
        bm = re.search(pat, remediation)
        if bm:
            start_pos = bm.start(1)
            sub = remediation[start_pos:]
            count = 0
            end_pos = None
            for idx, ch in enumerate(sub):
                if ch == "{":
                    count += 1
                elif ch == "}":
                    count -= 1
                    if count == 0:
                        end_pos = start_pos + idx + 1
                        break
            if end_pos is not None:
                code = remediation[start_pos:end_pos].strip()
                cleaned = (remediation[:start_pos].rstrip() + "\n\n" + remediation[end_pos:].lstrip()).strip()
                lang = _infer_code_language(code)
                return code, lang, cleaned

    return None, "", remediation


class BaseReportModel(BaseModel):
    """Base Pydantic model configuration for all AI report schemas."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class SourceItem(BaseReportModel):
    """Structured documentation or advisory citation."""

    url: str
    description: str = ""

    @field_validator("url", mode="before")
    @classmethod
    def sanitize_url(cls, v: Any) -> str:
        """Coerces the URL to a trimmed string."""
        return str(v).strip() if v else ""


def _normalize_sources_list(v: Any) -> list[dict[str, Any]]:
    """Normalizes heterogeneous sources lists (strings, dicts) into standard dicts."""
    if not isinstance(v, list):
        return []
    normalized: list[dict[str, Any]] = []
    for item in v:
        if isinstance(item, str) and item.strip():
            normalized.append({"url": item.strip(), "description": ""})
        elif isinstance(item, dict) and item.get("url"):
            normalized.append(item)
    return normalized


# ---------------------------------------------------------------------------
# Findings Section Models (Manifest, Bytecode, Security Checks, Secrets, Signatures)
# ---------------------------------------------------------------------------


class FindingItem(BaseReportModel):
    """Individual security finding in a standard findings section."""

    title: str = Field(description="Descriptive finding name referencing concrete artifact")
    risk: str = Field(description="Action-First severity impact verdict and technical explanation")
    attack_vector: str = Field(default="", description="Threat model, preconditions, and attacker steps")
    developer_intent: str = Field(default="", description="Engineering reason this was implemented")
    remediation: str = Field(default="", description="Actionable step-by-step remediation instructions")
    code_snippet: str | None = Field(
        default=None,
        description="Raw code fix without markdown fences, or None/null if no direct code fix applies",
    )
    code_language: str = Field(default="", description="Language tag for syntax highlighting")
    sources: list[SourceItem] = Field(default_factory=list, description="Authoritative reference URLs")

    @field_validator("sources", mode="before")
    @classmethod
    def normalize_sources(cls, v: Any) -> list[dict[str, Any]]:
        """Normalizes source links into structured items."""
        return _normalize_sources_list(v)

    @model_validator(mode="after")
    def sanitize_code_snippet(self) -> FindingItem:
        """Strips markdown fences from code_snippet, infers code_language, or extracts from remediation."""
        if not self.code_snippet and self.remediation:
            extracted_code, lang, clean_remediation = _extract_code_from_remediation(self.remediation)
            if extracted_code:
                self.code_snippet = extracted_code
                if lang and not self.code_language:
                    self.code_language = lang
                self.remediation = clean_remediation

        if self.code_snippet:
            cleaned_code, inferred_lang = clean_code_snippet(self.code_snippet, self.code_language)
            self.code_snippet = cleaned_code if cleaned_code else None
            if inferred_lang and not self.code_language:
                self.code_language = inferred_lang
            if not self.code_snippet:
                self.code_language = ""
        return self


class FindingsSectionModel(BaseReportModel):
    """Standard findings section schema (Manifest, Bytecode, Security Checks, etc.)."""

    no_findings: bool = False
    findings: list[FindingItem] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Permissions Section Models
# ---------------------------------------------------------------------------


class PermissionItem(BaseReportModel):
    """Detailed audit for a single requested permission."""

    name: str = Field(description="Exact permission identifier, e.g. android.permission.CAMERA")
    group: str = Field(
        default="custom_or_third_party",
        description="Permission classification: runtime_requested, install_time_or_system, or custom_or_third_party",
    )
    description: str = Field(default="", description="What the permission grants and where used")
    verdict: str = Field(default="Safe (Expected)", description="Postural assessment verdict")
    rationale: str = Field(default="", description="Technical justification based on verified purpose")
    sources: list[SourceItem] = Field(default_factory=list)

    @field_validator("sources", mode="before")
    @classmethod
    def normalize_sources(cls, v: Any) -> list[dict[str, Any]]:
        """Normalizes source links into structured items."""
        return _normalize_sources_list(v)


class PermissionsSectionModel(BaseReportModel):
    """Permissions audit section schema."""

    no_findings: bool = False
    items: list[PermissionItem] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Dependencies Section Models
# ---------------------------------------------------------------------------


class DependencyItem(BaseReportModel):
    """Dependency audit item."""

    source_name: str = Field(description="The exact dependency key from the findings")
    name: str = Field(description="Full Maven coordinate or library name")
    version_used: str = Field(default="unknown", description="Version detected in the application")
    latest_version: str = Field(default="unknown", description="Latest available release version")
    latest_version_url: str = Field(default="", description="URL of latest release documentation")
    purpose: str = Field(default="", description="Functionality and role in the application")
    vulnerabilities: str = Field(default="No known vulnerabilities found", description="CVE summary or status")


class DependenciesSectionModel(BaseReportModel):
    """Dependencies audit section schema."""

    no_findings: bool = False
    items: list[DependencyItem] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Network Section Models
# ---------------------------------------------------------------------------


class NetworkDomainItem(BaseReportModel):
    """Assessment of a single contacted network domain or endpoint."""

    domain: str = Field(description="Domain name from findings")
    assessment: str = Field(default="", description="Reputation assessment and justification")
    is_developer_code: bool = Field(default=False, description="Whether endpoint is app backend")
    sources: list[SourceItem] = Field(default_factory=list)

    @field_validator("sources", mode="before")
    @classmethod
    def normalize_sources(cls, v: Any) -> list[dict[str, Any]]:
        """Normalizes source links into structured items."""
        return _normalize_sources_list(v)


class NetworkSectionModel(BaseReportModel):
    """Network audit section schema."""

    no_findings: bool = False
    cloud_services: list[NetworkDomainItem] = Field(default_factory=list)
    trackers_and_ads: list[NetworkDomainItem] = Field(default_factory=list)
    other: list[NetworkDomainItem] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Vulnerabilities Section Models
# ---------------------------------------------------------------------------


class VulnerabilityFindingItem(BaseReportModel):
    """OWASP Mobile Top 10 mapped vulnerability finding."""

    owasp_id: str = Field(description="OWASP category ID, e.g. M1, M5, M10")
    owasp_category: str = Field(description="OWASP category name, e.g. M10: Insufficient Cryptography")
    vulnerability: str = Field(description="Descriptive vulnerability name")
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, or LOW")
    cvss_score: float | str | None = Field(default=None, description="CVSS base score")
    cwe: str | None = Field(default=None, description="CWE identifier and name")
    sources: list[SourceItem] = Field(default_factory=list)

    @field_validator("sources", mode="before")
    @classmethod
    def normalize_sources(cls, v: Any) -> list[dict[str, Any]]:
        """Normalizes source links into structured items."""
        return _normalize_sources_list(v)


class VulnerabilitiesSectionModel(BaseReportModel):
    """Vulnerabilities section schema."""

    no_findings: bool = False
    summary: str = Field(default="", description="Executive summary of posture")
    findings: list[VulnerabilityFindingItem] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Informational Section Models
# ---------------------------------------------------------------------------


class InformationalItem(BaseReportModel):
    """Single informational observation."""

    finding: str = Field(description="Observation title from findings")
    evidence: list[str] = Field(default_factory=list, description="Concrete artifacts, classes, or schemes")
    detail: str = Field(default="", description="Action-First posture verdict and explanation")
    recommendation: str = Field(default="", description="Verification steps or standard posture acknowledgment")
    sources: list[SourceItem] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def pre_validate_finding(cls, data: Any) -> Any:
        """Accepts 'title' as an alias for 'finding' if the model used standard finding schema keys."""
        if isinstance(data, dict):
            if not data.get("finding") and data.get("title"):
                data["finding"] = data["title"]
        return data

    @field_validator("evidence", mode="before")
    @classmethod
    def normalize_evidence(cls, v: Any) -> list[str]:
        """Normalizes evidence from either a single string or a list of items."""
        if isinstance(v, str):
            return [v] if v.strip() else []
        if isinstance(v, list):
            return [str(x) for x in v if str(x).strip()]
        return []

    @field_validator("sources", mode="before")
    @classmethod
    def normalize_sources(cls, v: Any) -> list[dict[str, Any]]:
        """Normalizes source links into structured items."""
        return _normalize_sources_list(v)


class InformationalSectionModel(BaseReportModel):
    """Informational observations section schema."""

    no_findings: bool = False
    items: list[InformationalItem] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def pre_validate_items(cls, data: Any) -> Any:
        """Tolerates root lists or alternative keys ('findings', 'observations') from local models."""
        if isinstance(data, list):
            return {"no_findings": len(data) == 0, "items": data}
        if isinstance(data, dict):
            if not data.get("items"):
                if data.get("findings"):
                    data["items"] = data["findings"]
                elif data.get("observations"):
                    data["items"] = data["observations"]
        return data


# ---------------------------------------------------------------------------
# Application Context Models
# ---------------------------------------------------------------------------


class SecurityIncident(BaseReportModel):
    """Historical security incident record."""

    summary: str = Field(description="Factual incident summary")
    date: str = Field(default="", description="Date in YYYY-MM or YYYY-MM-DD format")
    relation: str = Field(default="mobile_app", description="mobile_app, backend, or connected_infrastructure")
    impact: str = Field(default="", description="Affected users and adoption decision impact")
    source_url: str = Field(default="", description="Trusted news or advisory URL")


class AppContextModel(BaseReportModel):
    """Application overview and metadata schema."""

    app_name: str = Field(description="Application display name")
    developer: str | None = Field(default=None, description="Developer or company name")
    primary_purpose: str = Field(default="", description="Core function and category of the app")
    play_store_url: str | None = Field(default=None, description="Play Store URL")
    official_website: str | None = Field(default=None, description="Official website URL")
    status: str = Field(default="Unknown", description="Active, Discontinued, or Unknown")
    description: str = Field(default="", description="Neutral description of supported features and workflows")
    security_incidents: list[SecurityIncident] = Field(default_factory=list)
    sources: list[SourceItem] = Field(default_factory=list)

    @field_validator("sources", mode="before")
    @classmethod
    def normalize_sources(cls, v: Any) -> list[dict[str, Any]]:
        """Normalizes source links into structured items."""
        return _normalize_sources_list(v)
