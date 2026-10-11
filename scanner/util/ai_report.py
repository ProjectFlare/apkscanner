"""AI security report generation module for the APK static scanner.

Implements the agentic report generation pipeline using a local Ollama model
with native tool-calling support. The model is given five tools it can invoke
on demand during its reasoning loop (web_search, lookup_maven_version,
lookup_osv_vulnerabilities, lookup_nvd_cve, lookup_play_store) rather than
receiving pre-fetched context in the prompt.
"""

import concurrent.futures
import json
import re
import threading
import time
import urllib.parse
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import json_repair
from loguru import logger
from pydantic import BaseModel

from scanner.models.ai_report import (
    AppContextModel,
    DependenciesSectionModel,
    FindingsSectionModel,
    InformationalSectionModel,
    NetworkSectionModel,
    PermissionsSectionModel,
    VulnerabilitiesSectionModel,
    clean_code_snippet,
)
from scanner.scan_modules.dependencies import find_unversioned_third_party
from scanner.scan_modules.domains import normalize_domain_from_url
from scanner.util.ai_prompt_templates import (
    APP_CONTEXT_PROMPT_TEMPLATE,
    APP_CONTEXT_SCHEMA,
    BYTECODE_AUDIT_GUIDELINES,
    DEPENDENCIES_PROMPT_TEMPLATE,
    DEPS_SCHEMA,
    FINDINGS_SCHEMA,
    INFORMATIONAL_PROMPT_TEMPLATE,
    INFORMATIONAL_SCHEMA,
    MANIFEST_AUDIT_GUIDELINES,
    NETWORK_PROMPT_TEMPLATE,
    NETWORK_SCHEMA,
    PERMISSIONS_PROMPT_TEMPLATE,
    PERMISSIONS_SCHEMA,
    SECRETS_PROMPT_TEMPLATE,
    SECRETS_SCHEMA,
    SIGNATURES_GUIDELINES,
    SIGNATURES_SCHEMA,
    STANDARD_SECTION_PROMPT_TEMPLATE,
    SYSTEM_PROMPT_TEMPLATE,
    VULNERABILITIES_PROMPT_TEMPLATE,
    VULNS_SCHEMA,
)
from scanner.util.rules import IGNORED_AI_DOMAINS
from scanner.util.tool_runner import (
    OPENAI_DIRECT_MAX_TOKENS,
    BackendAPIError,
    ModelOutputTruncatedError,
    agentic_openai_query,
    clear_tool_cache,
    get_instructor_client,
    resolve_search_func,
)

# The model has no inherent notion of "now" and would otherwise fall back on its training cutoff,
# guessing stale years into search queries and version claims. The date is set once per report from
# the scan timestamp and read by every section worker thread, so it stays consistent across a run.
_CURRENT_DATE: str | None = None


def _system_prompt() -> str:
    """Renders the shared system prompt with the current report's date.

    Returns:
        str: The system prompt with today's date substituted in.
    """
    current = _CURRENT_DATE or datetime.now(UTC).strftime("%Y-%m-%d")
    return SYSTEM_PROMPT_TEMPLATE.replace("__CURRENT_DATE__", current)


def calculate_security_score(
    vulnerabilities_or_report: list[dict[str, Any]] | dict[str, Any],
) -> float:
    """Computes an objective security score from 0.0 to 100.0.

    Evaluates confirmed vulnerabilities using severity deductions and hard knockout
    ceilings, alongside one-time low deductions (-5.0 pts) for unverified attack surface
    indicators (unprotected exported components, unverified custom deep links, potential
    secrets, and missing network security configuration).

    Args:
        vulnerabilities_or_report (list[dict[str, Any]] | dict[str, Any]): Either a list
            of vulnerability dictionaries or the full scan report dictionary.

    Returns:
        float: Computed security score clamped to [0.0, 100.0] and rounded to one decimal place.
    """
    if isinstance(vulnerabilities_or_report, dict):
        scan_report = vulnerabilities_or_report
        vulnerabilities = scan_report.get("vulnerabilities", [])
    else:
        scan_report = None
        vulnerabilities = vulnerabilities_or_report

    score = 100.0
    deductions = 0.0

    # 1. Deductions for unverified attack surface and hygiene (one-time -5.0 pts each)
    if scan_report:
        # Check for unprotected exported components in informational findings
        informational = scan_report.get("informational", [])
        has_exported = any(
            item.get("type") == "exported_components" or "exported components" in item.get("title", "").lower()
            for item in informational
            if item.get("evidence")
        )
        if has_exported:
            deductions += 5.0

        # Check for unverified custom scheme deep links in informational findings
        has_custom_schemes = any(
            item.get("type") == "custom_scheme_intents" or "custom scheme" in item.get("title", "").lower()
            for item in informational
            if item.get("evidence")
        )
        if has_custom_schemes:
            deductions += 5.0

        # Check for missing network security configuration
        sec_flags = scan_report.get("manifest_audit", {}).get("security_flags", {})
        if sec_flags.get("network_security_config_missing", False):
            deductions += 5.0

        # Check for non-public secrets/API keys
        from scanner.util.rules import PUBLIC_CLIENT_TOKEN_TYPES

        raw_secrets = scan_report.get("secrets", [])
        has_secrets = any(s.get("type") not in PUBLIC_CLIENT_TOKEN_TYPES for s in raw_secrets)
        if has_secrets:
            deductions += 5.0

        # Check for archive extraction (Zip Slip attack surface)
        has_zip = any(
            item.get("type") == "zip_slip" or "zip slip" in item.get("title", "").lower()
            for item in informational
            if item.get("evidence")
        ) or bool(scan_report.get("bytecode_audit", {}).get("zip_slip"))
        if has_zip:
            deductions += 5.0

    # 2. Deductions for confirmed vulnerabilities
    has_critical = False
    has_high = False

    # Deduplicate findings by (owasp_id, title or description or rule_id)
    unique_vulns: dict[tuple, str] = {}
    for v in vulnerabilities:
        rule_id = str(v.get("rule_id") or "")
        title = str(v.get("title") or "").lower()
        if (
            rule_id in ("hardcoded_secrets", "hardcoded_crypto_keys", "zip_slip")
            or "hardcoded secret" in title
            or "hardcoded symmetric" in title
            or "zip slip" in title
        ):
            continue
        key = (v.get("owasp_id"), v.get("title") or v.get("description") or v.get("rule_id"))
        unique_vulns[key] = str(v.get("severity", "MEDIUM")).upper()

    for severity in unique_vulns.values():
        if severity == "INFORMATIONAL":
            continue
        elif severity == "CRITICAL":
            has_critical = True
            deductions += 60.0
        elif severity == "HIGH":
            has_high = True
            deductions += 35.0
        elif severity == "MEDIUM":
            deductions += 10.0
        elif severity == "LOW":
            deductions += 5.0
        else:
            deductions += 10.0

    score -= deductions

    # 3. Apply hard knockout ceilings
    if has_critical:
        score = min(score, 40.0)
    elif has_high:
        score = min(score, 65.0)

    return round(max(0.0, min(100.0, score)), 1)


def get_recommendation(
    score: float,
    vulnerabilities_or_report: list[dict[str, Any]] | dict[str, Any] | None = None,
) -> tuple[str, str]:
    """Determines the operational deployment recommendation based on security evaluation.

    Maps the numerical score and presence of critical/high vulnerabilities to a three-tier
    operational verdict formatted for workers, returning plain text recommendation strings.

    Args:
        score (float): The computed security score out of 100.0.
        vulnerabilities_or_report (list[dict[str, Any]] | dict[str, Any] | None): Optional
            vulnerability list or scan report to evaluate hard knockout triggers.

    Returns:
        tuple[str, str]: (plain_verdict, formatted_verdict) where both are plain text:
            - ("Recommended", "Recommended")
            - ("Partly recommended", "Partly recommended")
            - ("Not recommended", "Not recommended")
    """
    has_critical = False
    has_high = False
    if vulnerabilities_or_report is not None:
        if isinstance(vulnerabilities_or_report, dict):
            vulns = vulnerabilities_or_report.get("vulnerabilities", [])
        else:
            vulns = vulnerabilities_or_report
        for v in vulns:
            rule_id = str(v.get("rule_id") or "")
            title = str(v.get("title") or "").lower()
            if (
                rule_id in ("hardcoded_secrets", "hardcoded_crypto_keys", "zip_slip")
                or "hardcoded secret" in title
                or "hardcoded symmetric" in title
                or "zip slip" in title
            ):
                continue
            sev = str(v.get("severity", "")).upper()
            if sev == "CRITICAL":
                has_critical = True
            elif sev == "HIGH":
                has_high = True

    if score < 60.0 or has_critical:
        verdict = "Not recommended"
    elif score < 85.0 or has_high:
        verdict = "Partly recommended"
    else:
        verdict = "Recommended"

    return verdict, verdict


def get_security_grade(score: float) -> str:
    """Maps a numerical security score to a letter grade (A, B, C, D, F).

    Retained for backward compatibility with external consumers; the report
    presentation uses operational recommendations instead.

    Args:
        score (float): The security score out of 100.

    Returns:
        str: The letter grade.
    """
    if score >= 90.0:
        return "A"
    if score >= 80.0:
        return "B"
    if score >= 70.0:
        return "C"
    if score >= 60.0:
        return "D"
    return "F"


def is_data_empty(data) -> bool:
    """Safely checks if the provided data is empty or indicates no security findings.

    Args:
        data (any): The data structure (list or dict) to check.

    Returns:
        bool: True if the data is considered empty or has no findings, False otherwise.
    """
    if not data:
        return True
    if isinstance(data, dict):
        # If all values are False, empty lists, or empty dicts, the dictionary contains no findings
        if all(
            val is False or (isinstance(val, list) and not val) or (isinstance(val, dict) and not val)
            for val in data.values()
        ):
            return True
    return False


def _normalize_markdown(content: str) -> str:
    """Normalizes markdown for lint compliance.

    Collapses runs of blank lines, pads headings with blank lines, closes an
    unterminated code fence, and ensures a single trailing newline. This is all the
    post-processing the fully rendered report needs, since the section renderers
    emit clean markdown themselves.

    Args:
        content (str): Markdown content to normalize.

    Returns:
        str: Normalized markdown content.
    """
    content = re.sub(r"\n{3,}", "\n\n", content)

    # Ensure headings have a blank line before and after them
    content = re.sub(r"([^\n])\n(#+\s+[^\n]+)", r"\1\n\n\2", content)
    content = re.sub(r"(#+\s+[^\n]+)\n([^\n])", r"\1\n\n\2", content)

    # Collapse doubled opening code fences (e.g. "```java\n```java" -> "```java", "```\n```java" -> "```java")
    def _collapse_opening_fences(match: re.Match) -> str:
        lang1 = match.group(1).strip()
        lang2 = match.group(2).strip()
        lang = lang1 or lang2
        return f"```{lang}"

    while True:
        new_content = re.sub(
            r"^[ \t]{0,3}```([a-zA-Z0-9_+-]*)[ \t]*\r?\n[ \t]{0,3}```([a-zA-Z0-9_+-]*)[ \t]*$",
            _collapse_opening_fences,
            content,
            flags=re.MULTILINE,
        )
        if new_content == content:
            break
        content = new_content

    # Collapse doubled closing code fences (e.g. "```\n```" -> "```")
    while True:
        new_content = re.sub(
            r"^[ \t]{0,3}```[ \t]*\r?\n[ \t]{0,3}```[ \t]*$",
            "```",
            content,
            flags=re.MULTILINE,
        )
        if new_content == content:
            break
        content = new_content

    # Close an unterminated code fence (a model code_snippet may contain a stray ```)
    lines = content.splitlines()
    if sum(1 for line in lines if line.strip().startswith("```")) % 2:
        lines.append("```")
        content = "\n".join(lines)

    return content.strip() + "\n"


def _format_source_item(s) -> str:
    """Formats a source reference (string URL or dict with url/description) into a markdown link.

    Extracts the domain name and uses the description if available.
    """
    if isinstance(s, dict):
        url = s.get("url", "").strip()
        desc = s.get("description", "").strip()
    else:
        url = str(s).strip()
        desc = ""

    if not url:
        return ""

    domain = urllib.parse.urlparse(url).netloc or url
    if domain.startswith("www."):
        domain = domain[4:]

    if desc:
        return f"[{domain} - {desc}]({url})"
    return f"[{domain}]({url})"


def _sources_line(sources: object, prefix: str = "**Sources:** ", sep: str = " | ") -> str:
    """Formats a model-provided sources list into a single markdown line.

    Args:
        sources (object): The sources list from the parsed JSON (may be None or malformed).
        prefix (str): Text placed before the joined links.
        sep (str): Separator between links.

    Returns:
        str: The formatted line, or an empty string when no valid sources exist.
    """
    if not isinstance(sources, list):
        return ""
    links = [link for s in sources if s and (link := _format_source_item(s))]
    return prefix + sep.join(links) if links else ""


def _format_numbered_steps(text: str) -> str:
    """Puts an inline '1. ... 2. ... 3. ...' enumeration onto separate lines.

    Models often return multi-step remediation as one run-on string (e.g. '1. ... 2. ...' or
    '(1) ... (2) ...'), which markdown renders as a single line instead of a numbered list.
    This splits it into one line per step so it renders correctly, stripping preceding delimiters
    (such as commas, semicolons, 'and', or opening parentheses) while leaving ordinary prose
    and version numbers untouched.

    Args:
        text (str): The remediation or descriptive text.

    Returns:
        str: The text with each numbered step on its own line, or the original text unchanged.
    """
    if not text:
        return text
    # A number followed by '.' or ')' and a space marks a step; a preceding digit (e.g. in 1.2.3)
    # disqualifies it. Only reformat when the markers actually start a 1, 2, ... sequence.
    markers = [int(m) for m in re.findall(r"(?<!\d)(\d{1,2})[.)]\s", text)]
    if markers[:2] != [1, 2]:
        return text

    # Reformat step markers: replace preceding whitespace, commas, semicolons, 'and', and optional
    # opening parentheses before the step digit with a newline and standard step number format.
    result = re.sub(
        r"(?:\s*[,;]*\s*(?:and\s+)?\(?\s*|\s*)(?<!\d)(\d{1,2})[.)]\s+",
        lambda m: f"\n{m.group(1)}. ",
        text,
    ).strip()

    # Clean up unbalanced trailing closing parenthesis left over from parenthesized step lists
    if result.endswith(")") and result.count(")") > result.count("("):
        result = result[:-1].rstrip()
    elif result.endswith(").") and result.count(")") > result.count("("):
        result = result[:-2].rstrip() + "."

    return result


def _labeled_bullet(label: str, value: object) -> str:
    """Renders a '  - **label**: value' bullet, moving any numbered enumeration to indented lines.

    Keeps a plain value inline after the label, but when the value is a numbered list it is placed
    on its own indented lines so markdown renders a real sub-list instead of a run-on.

    Args:
        label (str): The bold label shown before the value.
        value (object): The value text.

    Returns:
        str: The markdown line(s) for the bullet.
    """
    formatted = _format_numbered_steps(str(value))
    if "\n" in formatted:
        steps = "\n".join(f"    {line}" for line in formatted.splitlines())
        return f"  - **{label}**:\n{steps}"
    return f"  - **{label}**: {formatted}"


def _canonical_finding_source(title: str) -> dict[str, str] | None:
    """Builds a canonical documentation reference for common Android security findings.

    Args:
        title (str): Finding title string.

    Returns:
        dict[str, str] | None: Canonical source dictionary or None.
    """
    lowered = title.lower()
    if "allowbackup" in lowered or "backup" in lowered:
        return {
            "url": "https://developer.android.com/guide/topics/data/autobackup",
            "description": "Android documentation on Auto Backup and data extraction rules",
        }
    if "usescleartexttraffic" in lowered or "cleartext" in lowered:
        return {
            "url": "https://developer.android.com/training/articles/security-config",
            "description": "Android Network Security Configuration guide",
        }
    if "debuggable" in lowered:
        return {
            "url": "https://developer.android.com/studio/publish/preparing#publishing-build",
            "description": "Android developer guide on debuggable application configurations",
        }
    return None


def _clean_code_snippet(snippet: str, lang: str = "") -> tuple[str, str]:
    """Strips markdown code fences and discards dummy/opt-out placeholder snippets.

    Args:
        snippet (str): Raw code snippet from the model response.
        lang (str): Optional language identifier from code_language.

    Returns:
        tuple[str, str]: Cleaned raw code snippet without enclosing fences, and language tag.
            If the snippet is empty or an opt-out placeholder, returns ("", "").
    """
    return clean_code_snippet(snippet, lang)


def _render_findings_json(section_heading: str, parsed: dict, include_code: bool = True) -> str:
    """Renders a structured findings JSON object into a markdown section.

    Args:
        section_heading (str): The markdown heading string (e.g. '## 1. Manifest Audit').
        parsed (dict): The parsed JSON object from the model.
        include_code (bool): Whether to render each finding's code snippet. Disabled for the
            Secrets section, where remediation is rotate/restrict/move-server-side rather than a
            copy-paste code change, so a code block adds noise.

    Returns:
        str: Markdown-formatted section content.
    """
    if parsed.get("no_findings") or not parsed.get("findings"):
        return f"{section_heading}\n\nNo security concerns or vulnerabilities were identified in this section."

    parts = [section_heading, ""]
    for idx, finding in enumerate(parsed["findings"], start=1):
        title = finding.get("title", "Finding")
        parts.append(f"### {idx}. {title}")
        parts.append("")

        if risk := finding.get("risk"):
            parts.append("#### What is the risk?")
            parts.append(_format_numbered_steps(risk))
            parts.append("")

        if vector := finding.get("attack_vector"):
            parts.append("#### What is the attack vector?")
            parts.append(_format_numbered_steps(vector))
            parts.append("")

        if intent := finding.get("developer_intent"):
            parts.append("#### Why is it possibly implemented like that?")
            parts.append(_format_numbered_steps(intent))
            parts.append("")

        if fix := finding.get("remediation"):
            parts.append("#### How can the developer fix it?")
            parts.append(_format_numbered_steps(fix))
            if include_code and (raw_snippet := finding.get("code_snippet")):
                snippet, lang = _clean_code_snippet(raw_snippet, finding.get("code_language") or "")
                if snippet:
                    parts.append(f"\n```{lang}\n{snippet}\n```")
            parts.append("")

        sources_list = list(finding.get("sources") or [])
        if not sources_list:
            canonical = _canonical_finding_source(title)
            if canonical:
                sources_list.append(canonical)
        if sources_line := _sources_line(sources_list):
            parts.append(sources_line)
            parts.append("")

    return "\n".join(parts)


def _render_info_list_json(
    section_heading: str,
    parsed: dict,
    section_data: list[dict] | None = None,
) -> str:
    """Renders the Informational observations as a bulleted list, one block per observation.

    Mirrors the Permissions/Dependencies style (bold title with labeled sub-bullets) instead
    of a table, because the prose-heavy Detail and Recommendation fields do not fit readable
    table cells.

    Args:
        section_heading (str): The markdown heading string.
        parsed (dict): The parsed JSON object from the model.
        section_data (list[dict] | None): Original findings data used to reconcile evidence.

    Returns:
        str: Markdown-formatted section content with one bullet block per observation.
    """
    items = parsed.get("items") or []
    if parsed.get("no_findings") or not items:
        return f"{section_heading}\n\nNo items were identified in this section."

    parts = [section_heading, ""]
    for item in items:
        finding_title = item.get("finding", "Observation")
        parts.append(f"- **{finding_title}**")
        # Evidence is a list of artifacts in the current schema, but older model outputs may
        # echo it as one string; render each artifact on its own sub-bullet either way.
        evidence = item.get("evidence")
        if isinstance(evidence, list):
            evidence_items = [str(e).strip() for e in evidence if str(e).strip()]
        else:
            evidence_items = [str(evidence).strip()] if str(evidence or "").strip() else []

        # Reconcile evidence artifacts with ground-truth findings data to ensure no evidence is dropped
        if section_data:
            lowered_title = finding_title.lower()
            matching_finding = None
            for entry in section_data:
                t = str(entry.get("title", "")).lower()
                typ = str(entry.get("type", "")).lower().replace("_", " ")
                if t in lowered_title or lowered_title in t or typ in lowered_title:
                    matching_finding = entry
                    break
            if matching_finding:
                source_ev = matching_finding.get("evidence", [])
                if isinstance(source_ev, list) and len(evidence_items) < len(source_ev):
                    extracted: list[str] = []
                    for s in source_ev:
                        s_str = str(s).strip()
                        m_zip = re.search(r"Class '([^']+)'", s_str)
                        if m_zip:
                            extracted.append(m_zip.group(1))
                            continue
                        m_sec = re.search(r"Value:\s*([a-zA-Z0-9_\-]+)", s_str)
                        if m_sec:
                            extracted.append(m_sec.group(1))
                            continue
                        extracted.append(s_str)
                    if len(extracted) > len(evidence_items):
                        evidence_items = extracted

        if evidence_items:
            parts.append("  - **Evidence**:")
            parts.extend(f"    - {artifact}" for artifact in evidence_items)
        if detail := item.get("detail"):
            parts.append(_labeled_bullet("Detail", detail))
        if recommendation := item.get("recommendation"):
            parts.append(_labeled_bullet("Recommendation", recommendation))
        if sources_line := _sources_line(item.get("sources"), prefix="  - **Sources:** "):
            parts.append(sources_line)
        parts.append("")

    return "\n".join(parts)


# Report subsection titles for the permission groups, mirroring the JSON report's grouping keys.
_PERMISSION_GROUP_TITLES: dict[str, str] = {
    "runtime_requested": "Runtime Requested Permissions (Dangerous)",
    "install_time_or_system": "Install-time or System Permissions",
    "custom_or_third_party": "Custom or Third-Party Permissions",
}


def _canonical_permission_source(perm_name: str) -> dict[str, str] | None:
    """Builds a canonical Android developer documentation reference for standard permissions.

    Args:
        perm_name (str): The permission identifier string.

    Returns:
        dict[str, str] | None: A source dict mapping 'url' and 'description', or None for custom permissions.
    """
    cleaned = perm_name.strip()
    if cleaned.startswith("android.permission."):
        short_name = cleaned.split(".")[-1]
        return {
            "url": f"https://developer.android.com/reference/android/Manifest.permission#{short_name}",
            "description": f"Android Manifest.permission.{short_name} reference",
        }
    return None


def _render_permissions_json(section_heading: str, parsed: dict, permissions_data: dict | None = None) -> str:
    """Renders the Permissions audit grouped the same way as the JSON scan report.

    The authoritative group for each permission is taken from the static scan's own
    grouping (``permissions_data``) when available; the model's echoed ``group`` field is
    only trusted for permissions the scan data does not cover.

    Args:
        section_heading (str): The markdown heading string.
        parsed (dict): The parsed JSON object from the model.
        permissions_data (dict | None): The scan report's ``permissions`` block with the
            ``runtime_requested``/``install_time_or_system``/``custom_or_third_party`` lists.

    Returns:
        str: Markdown-formatted section content with one subsection per permission group.
    """
    items = parsed.get("items") or []
    if parsed.get("no_findings") or not items:
        return f"{section_heading}\n\nNo items were identified in this section."

    scan_groups: dict[str, str] = {}
    for group_key in _PERMISSION_GROUP_TITLES:
        for permission in (permissions_data or {}).get(group_key) or []:
            scan_groups[str(permission)] = group_key

    grouped: dict[str, list[dict]] = {key: [] for key in _PERMISSION_GROUP_TITLES}
    for item in items:
        name = str(item.get("name", "")).strip()
        group = scan_groups.get(name) or str(item.get("group", "")).strip()
        if group not in grouped:
            group = "install_time_or_system"
        grouped[group].append(item)

    parts = [section_heading, ""]
    for group_key, title in _PERMISSION_GROUP_TITLES.items():
        if not grouped[group_key]:
            continue
        parts.append(f"### {title}")
        parts.append("")
        for item in grouped[group_key]:
            parts.append(f"- **{item.get('name', 'Permission')}**")
            if desc := item.get("description"):
                parts.append(_labeled_bullet("What it is", desc))
            if risk := item.get("risk_assessment"):
                parts.append(_labeled_bullet("Risk Assessment", risk))
            elif verdict := item.get("verdict"):
                rationale = str(item.get("rationale") or "").strip()
                full_risk = f"{verdict} - {rationale}" if rationale else str(verdict)
                parts.append(_labeled_bullet("Risk Assessment", full_risk))
            sources_list = list(item.get("sources") or [])
            perm_name = str(item.get("name", "")).strip()
            if not sources_list:
                canonical = _canonical_permission_source(perm_name)
                if canonical:
                    sources_list.append(canonical)
            if sources := [s for s in sources_list if s and _format_source_item(s)]:
                parts.append("  - **Sources:** " + " | ".join(_format_source_item(s) for s in sources))
            parts.append("")

    return "\n".join(parts)


def _fallback_maven_url(name: str, version: str) -> str:
    """Builds a canonical Maven artifact URL from a coordinate when the model omitted one.

    Serves as a deterministic fallback so the latest version can still be linked even if the
    model failed to copy the ``lookup_maven_version`` source URL into ``latest_version_url``.

    Args:
        name (str): The dependency name; a link is only built when it is a full
            ``group:artifact`` Maven coordinate.
        version (str): The resolved latest version.

    Returns:
        str: An mvnrepository.com artifact URL for the exact version, or an empty string if a
            coordinate or a concrete version is not available.
    """
    if version.strip().lower() in ("", "unknown"):
        return ""
    if name.count(":") != 1:
        return ""
    group, artifact = name.split(":")
    if not group or not artifact:
        return ""
    return f"https://mvnrepository.com/artifact/{group}/{artifact}/{version.strip()}"


def _render_dependency_item(parts: list[str], item: dict, *, is_unversioned: bool = False) -> None:
    """Appends a single rendered dependency bullet block to *parts* in place.

    Args:
        parts (list[str]): The markdown lines list being assembled (mutated in place).
        item (dict): A single dependency item dict from the model's output.
        is_unversioned (bool): Whether the dependency belongs to the unversioned group.
            When True, constant 'unknown' versions and vulnerability placeholders are omitted.
    """
    name = item.get("name", "Dependency")
    parts.append(f"- **{name}**")
    if not is_unversioned:
        if v := item.get("version_used"):
            parts.append(f"  - **Version Used**: {v}")
        if lv := item.get("latest_version"):
            # Link the latest version to the artifact page where it was found, when available.
            lv_url = (item.get("latest_version_url") or "").strip() or _fallback_maven_url(name, str(lv))
            if lv_url and str(lv).strip().lower() != "unknown":
                parts.append(f"  - **Latest Available**: [{lv}]({lv_url})")
            else:
                parts.append(f"  - **Latest Available**: {lv}")
    if p := item.get("purpose"):
        parts.append(_labeled_bullet("Purpose & Core Functionality", p))
    if not is_unversioned:
        if vl := item.get("vulnerabilities"):
            parts.append(_labeled_bullet("Security & Vulnerabilities", vl))
    # The per-dependency source is the Maven artifact page, which is already rendered as the
    # "Latest Available" link above, so a separate Sources bullet would only duplicate it and
    # appears inconsistently depending on whether the model echoed the URL twice. Omit it here.
    parts.append("")


def _render_deps_json(section_heading: str, parsed: dict) -> str:
    """Renders a structured dependencies JSON object into a markdown section.

    Mirrors the JSON scan report's dependency grouping: dependencies are split into a
    "Default Platform Services" group, an "Independent Third-Party Libraries" group, and an
    "Additional Detected Libraries" group for libraries whose version could not be resolved,
    so the markdown report's structure matches the underlying JSON one-to-one.

    Args:
        section_heading (str): The markdown heading string.
        parsed (dict): The parsed JSON object, with ``"google_sdk"``, ``"independent"``, and
            ``"unversioned"`` lists of dependency items.

    Returns:
        str: Markdown-formatted section content.
    """
    google_sdk_items = parsed.get("google_sdk") or []
    independent_items = parsed.get("independent") or []
    unversioned_items = parsed.get("unversioned") or []
    if parsed.get("no_findings") or not (google_sdk_items or independent_items or unversioned_items):
        return f"{section_heading}\n\nNo third-party dependencies were identified."

    parts = [section_heading, ""]

    if google_sdk_items:
        parts.append("### Default Platform Services")
        parts.append("")
        for item in google_sdk_items:
            _render_dependency_item(parts, item)

    if independent_items:
        parts.append("### Independent Third-Party Libraries")
        parts.append("")
        for item in independent_items:
            _render_dependency_item(parts, item)

    if unversioned_items:
        parts.append("### Additional Detected Libraries (Version Not Determined)")
        parts.append("")
        for item in unversioned_items:
            _render_dependency_item(parts, item, is_unversioned=True)

    return "\n".join(parts)


def _render_network_json(section_heading: str, parsed: dict) -> str:
    """Renders a structured network JSON object into a markdown section.

    Args:
        section_heading (str): The markdown heading string.
        parsed (dict): The parsed JSON object from the model.

    Returns:
        str: Markdown-formatted section content.
    """
    groups = (
        parsed.get("cloud_services") or [],
        parsed.get("trackers_and_ads") or [],
        parsed.get("other") or [],
    )
    # Guard on emptiness too: if every chunk failed, an unguarded render would emit a bare heading.
    if parsed.get("no_findings") or not any(groups):
        return f"{section_heading}\n\nNo network domains or URLs were identified."

    parts = [section_heading, ""]

    def render_group(heading: str, domains: list) -> None:
        if not domains:
            return
        parts.append(f"### {heading}")
        parts.append("")
        for d in domains:
            domain = d.get("domain", "")
            parts.append(f"- **{domain}**")
            if urls := d.get("urls"):
                listed = ", ".join(f"`{u}`" for u in urls)
                if extra := d.get("additional_url_count"):
                    listed += f" (+{extra} more not listed)"
                parts.append(f"  - **URLs**: {listed}")
            if pkgs := d.get("referencing_packages"):
                parts.append(f"  - **Referenced by**: {', '.join(f'`{p}`' for p in pkgs)}")
            # Unassessed stub entries carry no is_developer_code key; claiming an origin for
            # them would be a fabrication, so the line is only rendered for assessed domains.
            if "is_developer_code" in d:
                origin = "developer code" if d.get("is_developer_code") else "third-party dependency"
                parts.append(f"  - **Origin**: {origin}")
            if assessment := d.get("assessment"):
                parts.append(_labeled_bullet("Assessment", assessment))
            if sources_line := _sources_line(d.get("sources"), prefix="  - **Sources:** "):
                parts.append(sources_line)
            parts.append("")

    render_group("Cloud Services", groups[0])
    render_group("Trackers and Ads", groups[1])
    render_group("Other", groups[2])

    return "\n".join(parts)


def _canonical_cve_source(text: str) -> dict[str, str] | None:
    """Extracts a CVE identifier and returns a canonical NVD database reference.

    Args:
        text (str): Vulnerability name or description text.

    Returns:
        dict[str, str] | None: Canonical source dictionary or None.
    """
    match = re.search(r"CVE-\d{4}-\d+", text, re.IGNORECASE)
    if match:
        cve_id = match.group(0).upper()
        return {
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "description": f"National Vulnerability Database reference for {cve_id}",
        }
    return None


def _render_vulns_json(section_heading: str, parsed: dict) -> str:
    """Renders a structured vulnerabilities JSON object into a markdown section with an OWASP table.

    Args:
        section_heading (str): The markdown heading string.
        parsed (dict): The parsed JSON object from the model.

    Returns:
        str: Markdown-formatted section content.
    """
    findings = parsed.get("findings") or []
    if parsed.get("no_findings") or not findings:
        return f"{section_heading}\n\nNo vulnerabilities were identified."

    parts = [section_heading, ""]
    parts.append("| MASVS ID | OWASP Category | Vulnerability | Severity | CVSS v3 | CWE |")
    parts.append("|---|---|---|---|---|---|")

    for f in findings:
        masvs = f.get("masvs_id") or f.get("owasp_id") or "N/A"
        owasp = f.get("owasp_category", "")
        vuln = f.get("vulnerability", "")
        sev = f.get("severity", "")
        cvss = f.get("cvss_score") or "N/A"
        cwe = f.get("cwe") or "N/A"
        parts.append(f"| {masvs} | {owasp} | {vuln} | {sev} | {cvss} | {cwe} |")

    parts.append("")
    if summary := parsed.get("summary"):
        parts.append(_format_numbered_steps(summary))

    # Collect and display unique sources referenced by the vulnerabilities
    all_sources = []
    for f in findings:
        f_sources = list(f.get("sources") or [])
        if not f_sources:
            canonical = _canonical_cve_source(f.get("vulnerability", ""))
            if canonical:
                f_sources.append(canonical)
        for s in f_sources:
            if s and s not in all_sources:
                all_sources.append(s)
    if sources_line := _sources_line(all_sources):
        parts.append("")
        parts.append(sources_line)
        parts.append("")

    return "\n".join(parts)


def _cross_platform_coverage_caveat(ui_framework: str | None) -> str:
    """Returns a scope caveat when the app is built on a cross-platform framework.

    Flutter and React Native compile their business logic outside the Dalvik bytecode
    (into ``libapp.so`` or a JavaScript bundle respectively), so the DEX-based dependency,
    bytecode, and secret analyses only cover the Android host layer. Sparse findings in
    those sections therefore reflect limited visibility, not a clean bill of health.

    Args:
        ui_framework (str | None): Detected UI framework name.

    Returns:
        str: A markdown caveat line, or an empty string for native or unknown frameworks.
    """
    if not ui_framework:
        return ""
    lowered = ui_framework.lower()
    if "flutter" in lowered:
        location = "most of the app's code is built into a native file called `libapp.so`"
    elif "react native" in lowered:
        location = "most of the app's code ships as JavaScript inside `assets/index.android.bundle`"
    else:
        return ""
    return (
        f"> **Coverage note:** This is a {ui_framework} app, so {location}. This scan mainly reads the "
        "normal Android (Java and Kotlin) code, so it does not look inside that file. Because of this, the "
        "Dependencies, Bytecode Audit, and Secrets sections below only cover the Android part of the app. "
        "If they look almost empty, it is because the scan cannot see that code, not because the app is safe."
    )


_INCIDENT_RELATION_LABELS = {
    "mobile_app": "mobile app",
    "backend": "backend",
    "connected_infrastructure": "connected infrastructure",
}


def _render_security_incidents(incidents: object) -> str:
    """Renders the structured security-incidents list into a markdown block.

    Returns an empty string when there is nothing material to report, which is the
    expected outcome for most applications.

    Args:
        incidents (object): The ``security_incidents`` value from the app-context JSON — a
            list of ``{summary, date, relation, impact, source_url}`` dicts, or None.

    Returns:
        str: Markdown block headed by '### Security Incidents & Publicity', or an empty string.
    """
    if not incidents or not isinstance(incidents, list):
        return ""

    rows = []
    for inc in incidents:
        if not isinstance(inc, dict):
            continue
        summary = str(inc.get("summary", "")).strip()
        if not summary:
            continue
        date = str(inc.get("date", "")).strip()
        relation = _INCIDENT_RELATION_LABELS.get(str(inc.get("relation", "")).strip().lower())
        impact = str(inc.get("impact", "")).strip()
        source_url = str(inc.get("source_url", "")).strip()

        meta = []
        if relation:
            meta.append(f"scope: {relation}")
        if impact:
            meta.append(f"impact: {impact}")
        meta_str = f" ({'; '.join(meta)})" if meta else ""
        prefix = f"**{date}** — " if date else ""
        source_str = f" [source]({source_url})" if source_url else ""
        rows.append(f"- {prefix}{summary}{meta_str}{source_str}")

    if not rows:
        return ""
    return "### Security Incidents & Publicity\n" + "\n".join(rows)


def _format_packaging_overview(apk_metadata: dict | None) -> str:
    """Summarizes the APK packaging (single APK vs. split APK set) from the scan metadata.

    Args:
        apk_metadata (dict | None): The scan report's ``apk_metadata`` block, whose optional
            ``split_apks`` list holds one entry per APK inside the analyzed bundle.

    Returns:
        str: A short human-readable packaging summary, e.g.
            ``"Split APK (base + 3 configuration splits)"`` or ``"Single APK"``.
    """
    split_apks = (apk_metadata or {}).get("split_apks") or []
    config_splits = [s for s in split_apks if s.get("name", "").lower() != "base.apk"]
    if not config_splits:
        return "Single APK"
    plural = "s" if len(config_splits) != 1 else ""
    return f"Split APK (base + {len(config_splits)} configuration split{plural})"


def _render_app_context_json(
    parsed: dict, environment_details: dict | None = None, apk_metadata: dict | None = None
) -> str:
    """Renders a structured app context JSON object into the report's App Description markdown block.

    The app name is intentionally NOT repeated in the overview table because it is already a
    deterministic fact in the Report Details header above.

    Args:
        parsed (dict): The parsed JSON object from the model.
        environment_details (dict | None): The scan's ``environment_details`` block, providing
            ``ui_framework`` and ``cpu_architecture`` for the Build Environment rows and the
            cross-platform coverage caveat.
        apk_metadata (dict | None): The scan's ``apk_metadata`` block, providing the split-APK
            packaging overview.

    Returns:
        str: Markdown-formatted application context block.
    """
    env = environment_details or {}
    ui_framework = env.get("ui_framework")
    cpu_arch = env.get("cpu_architecture")

    lines = ["### Application Overview", ""]
    lines.append("| **Detail** | **Value** |")
    lines.append("| :--- | :--- |")
    lines.append(f"| **Developer** | {parsed.get('developer') or 'Unknown'} |")
    lines.append(f"| **Primary Purpose** | {parsed.get('primary_purpose', '')} |")
    if url := parsed.get("play_store_url"):
        lines.append(f"| **Google Play Link** | [Google Play Store]({url}) |")
    if website := parsed.get("official_website"):
        lines.append(f"| **Official Website** | [{website}]({website}) |")
    if ui_framework:
        lines.append(f"| **UI Framework** | {ui_framework} |")
    if cpu_arch:
        abis = ", ".join(cpu_arch) if isinstance(cpu_arch, list) else str(cpu_arch)
        lines.append(f"| **Processor Architectures** | {abis} |")
    lines.append(f"| **Packaging** | {_format_packaging_overview(apk_metadata)} |")
    lines.append(f"| **Status** | {parsed.get('status', 'Unknown')} |")

    if caveat := _cross_platform_coverage_caveat(ui_framework):
        lines.append("")
        lines.append(caveat)

    lines.append("")
    lines.append("### Description")
    lines.append(_format_numbered_steps(parsed.get("description", "")))

    if incidents_block := _render_security_incidents(parsed.get("security_incidents")):
        lines.append("")
        lines.append(incidents_block)

    if sources_line := _sources_line(parsed.get("sources")):
        lines.append("")
        lines.append(sources_line)

    return "\n".join(lines)


_SECTION_MODELS: dict[str, type[BaseModel]] = {
    "findings": FindingsSectionModel,
    "info_list": InformationalSectionModel,
    "permissions": PermissionsSectionModel,
    "deps": DependenciesSectionModel,
    "network": NetworkSectionModel,
    "vulns": VulnerabilitiesSectionModel,
    "app_context": AppContextModel,
}

_SCHEMA_TO_MODEL: dict[str, type[BaseModel]] = {
    NETWORK_SCHEMA: NetworkSectionModel,
    DEPS_SCHEMA: DependenciesSectionModel,
    PERMISSIONS_SCHEMA: PermissionsSectionModel,
    FINDINGS_SCHEMA: FindingsSectionModel,
    VULNS_SCHEMA: VulnerabilitiesSectionModel,
    INFORMATIONAL_SCHEMA: InformationalSectionModel,
    SECRETS_SCHEMA: FindingsSectionModel,
    SIGNATURES_SCHEMA: FindingsSectionModel,
    APP_CONTEXT_SCHEMA: AppContextModel,
}


def _get_section_model(
    chunk_section: dict | None = None,
    schema_str: str | None = None,
    label: str | None = None,
) -> type[BaseModel]:
    """Resolves the appropriate Pydantic model class for a report section.

    Args:
        chunk_section (dict | None): Section configuration dictionary.
        schema_str (str | None): JSON schema string used in the prompt.
        label (str | None): Label or section identifier.

    Returns:
        type[BaseModel]: Corresponding Pydantic model class.
    """
    if schema_str and schema_str in _SCHEMA_TO_MODEL:
        return _SCHEMA_TO_MODEL[schema_str]

    renderer = chunk_section.get("renderer") if chunk_section else None
    if renderer and renderer in _SECTION_MODELS:
        return _SECTION_MODELS[renderer]

    identifier = ""
    if chunk_section and chunk_section.get("name"):
        identifier = chunk_section["name"]
    elif label:
        identifier = label

    id_lower = identifier.lower()
    if "network" in id_lower:
        return NetworkSectionModel
    if "depend" in id_lower:
        return DependenciesSectionModel
    if "permission" in id_lower:
        return PermissionsSectionModel
    if "vuln" in id_lower:
        return VulnerabilitiesSectionModel
    if "overview" in id_lower or "info" in id_lower:
        return InformationalSectionModel

    return FindingsSectionModel


def _parse_section_response(
    content: str,
    model_cls: type[BaseModel],
    section_name: str,
    openai_url: str | None = None,
    model: str | None = None,
) -> dict | None:
    """Parses model response into a validated Pydantic model dictionary.

    First attempts direct Pydantic JSON validation (handling markdown code fences and balanced JSON).
    If that fails and OpenAI configuration is provided, uses Instructor to re-format the response
    into the required schema with automatic validation and error recovery.

    Args:
        content (str): The raw response content from the LLM.
        model_cls (type[BaseModel]): Target Pydantic model class.
        section_name (str): Section name for logging.
        openai_url (str | None): Base URL of OpenAI API for Instructor fallback.
        model (str | None): LLM model name for Instructor fallback.

    Returns:
        dict | None: The validated model dumped as dict, or None on failure.
    """
    clean_content = content.strip()
    if clean_content.startswith("```json"):
        clean_content = clean_content[7:]
    elif clean_content.startswith("```"):
        clean_content = clean_content[3:]
    if clean_content.endswith("```"):
        clean_content = clean_content[:-3]
    clean_content = clean_content.strip()

    # Direct validation attempt
    last_val_err: Exception | None = None
    try:
        validated = model_cls.model_validate_json(clean_content)
        return validated.model_dump(exclude_unset=True)
    except Exception as e:
        last_val_err = e

    # Try extracting outermost balanced JSON block
    start_idx = clean_content.find("{")
    end_idx = clean_content.rfind("}")
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        try:
            candidate = clean_content[start_idx : end_idx + 1]
            validated = model_cls.model_validate_json(candidate)
            return validated.model_dump(exclude_unset=True)
        except Exception as e:
            last_val_err = e

    # Tolerant json_repair fallback before making network call
    try:
        repaired_obj = json_repair.repair_json(clean_content, return_objects=True)
        if (isinstance(repaired_obj, dict) and repaired_obj) or (isinstance(repaired_obj, list) and repaired_obj):
            validated = model_cls.model_validate(repaired_obj)
            return validated.model_dump(exclude_unset=True)
    except Exception as e:
        last_val_err = e

    # Instructor self-correction fallback turn if model and endpoint are provided
    if openai_url and model:
        logger.info(
            f"Direct validation failed for '{section_name}' ({last_val_err}). Invoking Instructor formatting fallback..."
        )
        _record_section_regeneration(section_name.split("_")[0])
        try:
            inst_client = get_instructor_client(openai_url)
            repaired = inst_client.chat.completions.create(
                model=model,
                response_model=model_cls,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a strict data formatter. Convert the audit findings into the target JSON schema.",
                    },
                    {"role": "user", "content": content},
                ],
                max_tokens=OPENAI_DIRECT_MAX_TOKENS,
                max_retries=2,
            )
            return repaired.model_dump(exclude_unset=True)
        except Exception as format_err:
            logger.warning(f"Instructor formatting turn failed for '{section_name}': {format_err}")

    logger.warning(f"Failed to parse JSON response for section '{section_name}'. Raw: {content[:200]}")
    return None


def _filter_scan_report(scan_report: dict) -> tuple[dict, dict]:
    """Filters findings from the scan report to only contain security issues.

    Args:
        scan_report (dict): The original static analysis report.

    Returns:
        tuple[dict, dict]: Filtered manifest audit and signatures.
    """
    # Filter manifest_audit
    manifest_audit = scan_report.get("manifest_audit", {})
    filtered_manifest = {}
    if manifest_audit:
        # A manifest parse failure means every security flag is unevaluated, not clean. The
        # error is propagated so the report can mark the section inconclusive instead of
        # rendering the misleading "no security concerns" placeholder.
        if error := manifest_audit.get("error"):
            filtered_manifest["analysis_error"] = str(error)
        sec_flags = manifest_audit.get("security_flags", {})
        filtered_flags = {k: v for k, v in sec_flags.items() if v is True}
        if filtered_flags:
            filtered_manifest["security_flags"] = filtered_flags

        if target_sdk := scan_report.get("apk_metadata", {}).get("target_sdk_version"):
            filtered_manifest["target_sdk_version"] = target_sdk
        if "uses_cleartext_traffic" in sec_flags:
            filtered_manifest["uses_cleartext_traffic"] = sec_flags["uses_cleartext_traffic"]

        net_config = manifest_audit.get("network_security_config", {})
        filtered_net = {}
        if net_config:
            if net_config.get("global_cleartext") is True:
                filtered_net["global_cleartext"] = True
            domain_list = net_config.get("domain_cleartext_list", [])
            if domain_list:
                filtered_net["domain_cleartext_list"] = domain_list
            if net_config.get("trusts_user_certs") is True:
                filtered_net["trusts_user_certs"] = True
        if filtered_net:
            filtered_manifest["network_security_config"] = filtered_net

    # Filter signatures
    signatures = scan_report.get("signatures", {})
    filtered_signatures = {}
    if signatures:
        if signatures.get("is_debug_signed") is True:
            filtered_signatures["is_debug_signed"] = True
        if signatures.get("has_weak_hash") is True:
            filtered_signatures["has_weak_hash"] = True
        if signatures.get("v1_only_signature") is True:
            filtered_signatures["v1_only_signature"] = True
            filtered_signatures["scheme_versions"] = signatures.get("scheme_versions", [])
        mismatched = signatures.get("mismatched_splits", [])
        if mismatched:
            filtered_signatures["mismatched_splits"] = mismatched

        if filtered_signatures:
            certs = signatures.get("certificates", [])
            if certs:
                streamlined_certs = []
                for c in certs:
                    streamlined = {
                        "subject": c.get("subject"),
                        "signature_algo": c.get("signature_algo"),
                        "hash_algo": c.get("hash_algo"),
                    }
                    if c.get("issuer") and c.get("issuer") != c.get("subject"):
                        streamlined["issuer"] = c.get("issuer")
                    streamlined_certs.append(streamlined)
                filtered_signatures["certificates"] = streamlined_certs

    return filtered_manifest, filtered_signatures


# The security-relevant unit in the Network section is the host, not every path seen under
# it. A single domain can contribute hundreds of entries that are not even request targets
# (protobuf type identifiers such as "type.googleapis.com/ApiSettings" are the common case),
# which drowns the report and wastes prompt tokens without adding signal.
_MAX_URLS_PER_DOMAIN = 6


def _sample_domain_urls(urls: list[str]) -> tuple[list[str], int]:
    """Reduces a domain's URL list to a representative sample.

    URLs carrying an explicit scheme are listed first because they are actual request
    targets, whereas schemeless entries are usually type identifiers or bare host mentions.

    Args:
        urls (list[str]): Every distinct URL attributed to one domain, in scan order.

    Returns:
        tuple[list[str], int]: The retained sample and the number of URLs omitted.
    """
    if len(urls) <= _MAX_URLS_PER_DOMAIN:
        return urls, 0
    ranked = [u for u in urls if "://" in u] + [u for u in urls if "://" not in u]
    return ranked[:_MAX_URLS_PER_DOMAIN], len(urls) - _MAX_URLS_PER_DOMAIN


def _filter_network_data(network: dict) -> dict:
    """Compresses the network scan findings to save input tokens.

    Maps categorized domains to their referencing packages and matching URLs,
    eliminating raw namespace bloat.
    """
    if not network:
        return {}

    categorized = network.get("categorized_domains", {})
    attributed = network.get("attributed_urls", {})

    def _is_ignored(d: str) -> bool:
        d_lower = d.lower()
        if d_lower in IGNORED_AI_DOMAINS:
            return True
        for ign in IGNORED_AI_DOMAINS:
            if d_lower.endswith(f".{ign}"):
                return True
        return False

    # Ordered dicts (not sets) keep the URL/package lists deterministic across runs,
    # so the same APK always produces the same model input and rendered report.
    domain_to_info: dict[str, dict[str, dict]] = {}

    for pkg, urls in attributed.items():
        for url in urls:
            domain = normalize_domain_from_url(url)
            if domain:
                info = domain_to_info.setdefault(domain, {"packages": {}, "urls": {}})
                info["packages"][pkg] = None
                info["urls"][url] = None

    def _format_domain_list(domains):
        res = []
        for d in domains:
            if _is_ignored(d):
                continue
            d_norm = normalize_domain_from_url(d) or d.lower().strip()
            info = domain_to_info.get(d_norm)
            if not info and d != d_norm:
                info = domain_to_info.get(d)
            if not info:
                # Fallback: check matching subdomains or prefix variations
                for cand_domain, cand_info in domain_to_info.items():
                    if (
                        cand_domain == d_norm
                        or cand_domain.endswith(f".{d_norm}")
                        or d_norm.endswith(f".{cand_domain}")
                    ):
                        info = cand_info
                        break
            if not info:
                info = {"packages": {}, "urls": {}}

            kept, dropped = _sample_domain_urls(list(info["urls"]))
            entry = {"domain": d, "urls": kept, "referencing_packages": list(info["packages"])}
            if dropped:
                entry["additional_url_count"] = dropped
            res.append(entry)
        return res

    return {
        "cloud_services": _format_domain_list(categorized.get("cloud_services", [])),
        "trackers_and_ads": _format_domain_list(categorized.get("trackers_and_ads", [])),
        "other": _format_domain_list(categorized.get("other", [])),
    }


def _manifest_error_content(heading: str, error: str) -> str:
    """Builds the deterministic Manifest Audit content for a manifest parse failure.

    Args:
        heading (str): The markdown heading string for the section.
        error (str): The parse-failure message recorded by the manifest audit.

    Returns:
        str: Markdown content marking the section as inconclusive instead of clean.
    """
    return (
        f"{heading}\n\n"
        "**Analysis inconclusive - the Android manifest could not be parsed.**\n\n"
        f"- **Error**: {error}\n\n"
        "None of the manifest security flags (allowBackup, debuggable, cleartext traffic, "
        "network security configuration, legacy external storage) could be evaluated, so this "
        "section reflects an analysis failure rather than a clean result. Inspect the APK "
        "manually (for example with apktool or androguard) or re-run the scan on an intact "
        "APK file to obtain a conclusive manifest audit."
    )


def _compact_call_sites(sites: list[str]) -> list[str]:
    """Cleans deobfuscator tag noise and call suffixes from DEX call sites.

    Args:
        sites (list[str]): Raw list of call-site strings.

    Returns:
        list[str]: Cleaned, unique list of 'package.ClassName->methodName' strings.
    """
    cleaned: list[str] = []
    for site in sites:
        s = re.sub(r"\s*\[.*?\]", "", site)
        s = re.sub(r"\s*\(calls.*?\)", "", s)
        s = s.strip()
        if s and s not in cleaned:
            cleaned.append(s)
    return cleaned


def _filter_informational_data(info_list: list[dict] | None) -> list[dict]:
    """Condenses and cleans informational observations before prompt formatting.

    Args:
        info_list (list[dict] | None): Raw list of informational findings.

    Returns:
        list[dict]: Condensed list with deduplicated call sites.
    """
    if not info_list:
        return []
    condensed: list[dict] = []
    for item in info_list:
        ev = item.get("evidence", [])
        if isinstance(ev, list):
            cleaned_ev = _compact_call_sites(ev)
            item_copy = dict(item)
            item_copy["evidence"] = cleaned_ev
            condensed.append(item_copy)
        else:
            condensed.append(item)
    return condensed


def _secret_group_key(secret: dict[str, Any]) -> tuple[str, str]:
    """Extracts a simple grouping key from origin file/package or variable name."""
    sec_type = str(secret.get("type") or "").strip()
    source = str(secret.get("source") or "").strip()
    name = str(secret.get("name") or "").strip()

    if "->" in source:
        # DEX class origin: group by package namespace
        class_name = source.split(",")[0].split("->")[0].split("$")[0].strip()
        pkg = class_name.rsplit(".", 1)[0] if "." in class_name else class_name
        return (sec_type, pkg)

    # Resource or asset origin: group by common name prefix or full name
    prefix = name.rsplit("_", 1)[0] if "_" in name else name
    return (sec_type, prefix or source)


def _group_secrets_for_audit(secrets: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
    """Consolidates secrets sharing the same origin or variable name into single findings.

    Args:
        secrets (list[dict[str, Any]] | None): Raw list of secrets from static analysis.

    Returns:
        list[dict[str, Any]] | None: Grouped list of secrets, or None if input was None.
    """
    if not secrets:
        return secrets

    clusters: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for s in secrets:
        clusters[_secret_group_key(s)].append(s)

    grouped: list[dict[str, Any]] = []
    for items in clusters.values():
        values = [i["value"] for i in items if i.get("value")]
        if len(items) == 1:
            item = items[0]
            grouped.append(
                {
                    "type": item.get("type", "secret"),
                    "value": item.get("value", ""),
                    "values": values,
                    "name": item.get("name", "Hardcoded String Constant"),
                    "source": item.get("source", ""),
                    "count": 1,
                }
            )
        else:
            first = items[0]
            sec_type = first.get("type", "secret")
            sources = list(dict.fromkeys(i.get("source", "") for i in items if i.get("source")))
            names = list(dict.fromkeys(i.get("name", "") for i in items if i.get("name")))
            name = names[0] if len(names) == 1 else f"{names[0]} (and {len(names) - 1} related)"
            source = sources[0] if len(sources) == 1 else ", ".join(sources[:2])
            grouped.append(
                {
                    "type": sec_type,
                    "value": ", ".join(values),
                    "values": values,
                    "name": name,
                    "source": source,
                    "count": len(items),
                }
            )
    return grouped


def _prepare_sections_config(
    scan_report: dict,
    filtered_manifest: dict,
    filtered_signatures: dict,
) -> list[dict]:
    """Assembles the list of sections with their headings, data, guidelines, and renderer type.

    Args:
        scan_report (dict): The original static analysis report.
        filtered_manifest (dict): Filtered manifest audit dict.
        filtered_signatures (dict): Filtered signatures dict.

    Returns:
        list[dict]: Configurations for each report section.
    """
    # Filter dependencies
    dependencies = scan_report.get("dependencies", {})
    if "third_party" in dependencies and isinstance(dependencies["third_party"], dict):
        filtered_dependencies = dependencies["third_party"]
    else:
        # Legacy support
        third_party = dependencies.get("exact_versions_found", {}).get("third_party", {})
        google_sdk = third_party.get("google_sdk", {})
        independent = third_party.get("independent", {})
        unversioned = find_unversioned_third_party(dependencies.get("external_libraries", {}), third_party)
        if not google_sdk and not independent and not unversioned:
            filtered_dependencies = {}
        else:
            filtered_dependencies = {
                "exact_versions_found": {"third_party": {"google_sdk": google_sdk, "independent": independent}},
                "detected_libraries_version_unknown": unversioned,
                "osv_findings": dependencies.get("osv_findings"),
                "maven_latest": dependencies.get("maven_latest"),
            }

    # Filter bytecode_audit
    bytecode_audit = scan_report.get("bytecode_audit", {})
    filtered_bytecode = {}
    if bytecode_audit:
        for k, v in bytecode_audit.items():
            # Dynamic code loading is reported under the Informational section (attack surface,
            # not a confirmed weakness), so it is excluded from the scored Bytecode Audit here.
            if k == "dynamic_code_loading" or k.startswith("dynamic_code_loading"):
                continue
            if isinstance(v, list) and v:
                filtered_bytecode[k] = _compact_call_sites(v)[:5]
            elif k.endswith("_detected") and v is True:
                base = k[:-9]
                evidence_key = f"{base}_evidence"
                raw_ev = bytecode_audit.get(evidence_key, [])
                if isinstance(raw_ev, list) and raw_ev:
                    filtered_bytecode[base] = _compact_call_sites(raw_ev)[:5]

    # Filter network
    filtered_network = _filter_network_data(scan_report.get("network", {}))

    manifest_section = {
        "name": "Manifest Audit",
        "heading": "## 1. Manifest Audit",
        "data": filtered_manifest,
        "guidelines": MANIFEST_AUDIT_GUIDELINES,
        "renderer": "findings",
    }
    # A manifest parse failure is a tooling fact, not something for the model to reason
    # about: render a deterministic inconclusive warning instead of querying the LLM.
    if error := (filtered_manifest or {}).get("analysis_error"):
        manifest_section["static_content"] = _manifest_error_content("## 1. Manifest Audit", str(error))

    return [
        manifest_section,
        {
            "name": "Informational",
            "heading": "## 2. Informational",
            "data": _filter_informational_data(scan_report.get("informational")),
            "prompt_template": INFORMATIONAL_PROMPT_TEMPLATE,
            "renderer": "info_list",
        },
        {
            "name": "Signatures",
            "heading": "## 3. Signatures",
            "data": filtered_signatures,
            "guidelines": SIGNATURES_GUIDELINES,
            "schema": SIGNATURES_SCHEMA,
            "renderer": "findings",
        },
        {
            "name": "Permissions",
            "heading": "## 4. Permissions",
            "data": scan_report.get("permissions"),
            "prompt_template": PERMISSIONS_PROMPT_TEMPLATE,
            "renderer": "permissions",
        },
        {
            "name": "Dependencies",
            "heading": "## 5. Dependencies",
            "data": filtered_dependencies,
            "prompt_template": DEPENDENCIES_PROMPT_TEMPLATE,
            "renderer": "deps",
        },
        {
            "name": "Secrets",
            "heading": "## 6. Secrets",
            "data": _group_secrets_for_audit(scan_report.get("secrets")),
            "prompt_template": SECRETS_PROMPT_TEMPLATE,
            "schema": SECRETS_SCHEMA,
            "renderer": "findings",
            "include_code": False,
        },
        {
            "name": "Bytecode Audit",
            "heading": "## 7. Bytecode Audit",
            "data": filtered_bytecode,
            "guidelines": BYTECODE_AUDIT_GUIDELINES,
            "renderer": "findings",
        },
        {
            "name": "Network",
            "heading": "## 8. Network",
            "data": filtered_network,
            "prompt_template": NETWORK_PROMPT_TEMPLATE,
            "renderer": "network",
        },
        {
            "name": "Vulnerabilities",
            "heading": "## 9. Vulnerabilities",
            "data": scan_report.get("vulnerabilities"),
            "prompt_template": VULNERABILITIES_PROMPT_TEMPLATE,
            "renderer": "vulns",
        },
    ]


def _prepare_audit_prompt(section: dict, app_context_summary: str) -> str:
    """Formats the audit prompt for a section using templates.

    Args:
        section (dict): Configuration for the section to audit.
        app_context_summary (str): Summarized background context of the app.

    Returns:
        str: Formatted user prompt for Ollama.
    """
    data_json = json.dumps(section["data"], indent=2)

    custom_template = section.get("prompt_template")
    if custom_template:
        return custom_template.replace("__APP_CONTEXT__", app_context_summary).replace("__DATA_JSON__", data_json)
    base_template = STANDARD_SECTION_PROMPT_TEMPLATE
    if schema := section.get("schema"):
        base_template = base_template.replace(FINDINGS_SCHEMA, schema)
    return (
        base_template.replace("__SECTION_NAME__", section["name"])
        .replace("__APP_CONTEXT__", app_context_summary)
        .replace("__DATA_JSON__", data_json)
        .replace("__GUIDELINES__", section["guidelines"])
    )


# Audit response processing (JSON → markdown)


# Renderer and fallback-schema registry for the standard (non-chunked) sections. Network and
# Dependencies never reach this dispatch — they are routed to their own chunked audit paths.
_RENDERERS: dict[str, Callable[[str, dict, dict], str]] = {
    "findings": lambda heading, parsed, section: _render_findings_json(
        heading, parsed, section.get("include_code", True)
    ),
    "info_list": lambda heading, parsed, section: _render_info_list_json(heading, parsed, section.get("data")),
    "permissions": lambda heading, parsed, section: _render_permissions_json(heading, parsed, section.get("data")),
    "vulns": lambda heading, parsed, _section: _render_vulns_json(heading, parsed),
}

_RENDERER_SCHEMAS: dict[str, str] = {
    "findings": FINDINGS_SCHEMA,
    "info_list": INFORMATIONAL_SCHEMA,
    "permissions": PERMISSIONS_SCHEMA,
    "vulns": VULNS_SCHEMA,
}


# Per-section audit query


# Per-run counters of extra model turns needed per section (JSON formatting fallbacks and
# dependency retry rounds). Surfaced in the report header so the weak spots are measurable.
_section_regenerations: dict[str, int] = {}
_section_regenerations_lock = threading.Lock()


def _reset_section_regenerations() -> None:
    """Clears the per-run section regeneration counters at the start of a report run."""
    with _section_regenerations_lock:
        _section_regenerations.clear()


def _record_section_regeneration(section_name: str) -> None:
    """Counts one extra model turn (retry/fallback) for a section.

    Args:
        section_name (str): The report section that needed the extra turn.
    """
    with _section_regenerations_lock:
        _section_regenerations[section_name] = _section_regenerations.get(section_name, 0) + 1


SECTION_ATTEMPTS = 3


def _failed_section_placeholder(section: dict, error: Exception) -> str:
    """Renders an explicit failure notice for a section the model could not produce.

    Falling back to the usual "no concerns" placeholder would present a generation failure
    as a clean result and hide findings the static scan did detect, so a failed section is
    labelled as failed instead.

    Args:
        section (dict): The section config, providing its heading.
        error (Exception): The failure from the final attempt.

    Returns:
        str: Markdown for the failed section.
    """
    return (
        f"{section['heading']}\n\n"
        f"> **Section generation failed.** The model returned no usable response after "
        f"{SECTION_ATTEMPTS} attempts, so these findings were **not assessed**. This is a "
        f"generation failure, not an all-clear — consult the JSON scan report for the raw "
        f"findings.\n>\n"
        f"> Last error: `{error}`"
    )


def _format_section_regenerations() -> str:
    """Formats the per-section regeneration counters for the report header.

    Returns:
        str: A ``Section: count`` listing, or ``"none"`` when every section succeeded
            on its first attempt.
    """
    with _section_regenerations_lock:
        if not _section_regenerations:
            return "none"
        return ", ".join(f"{name}: {count}" for name, count in sorted(_section_regenerations.items()))


def _agentic_query(
    prompt: str,
    model: str,
    search_func: Callable,
    max_tool_iterations: int,
    openai_url: str,
) -> tuple[str, str, list[dict]]:
    """Runs one agentic audit query against the OpenAI-compatible backend.

    Args:
        prompt (str): The user-turn prompt content.
        model (str): The model name.
        search_func (Callable): The search function for web_search.
        max_tool_iterations (int): Maximum tool-call rounds.
        openai_url (str): Base URL of the OpenAI-compatible API.

    Returns:
        tuple[str, str, list[dict]]: The response content, thinking content, and tool log.
    """
    return agentic_openai_query(
        prompt=prompt,
        system_prompt=_system_prompt(),
        model=model,
        openai_url=openai_url,
        search_func=search_func,
        max_iterations=max_tool_iterations,
        format_json=False,
    )


def _run_parallel(fn: Callable, jobs: list[tuple], concurrency: int, what: str) -> list:
    """Runs jobs through ``fn`` in a bounded thread pool, collecting successful results.

    Args:
        fn (Callable): The function to run for each job.
        jobs (list[tuple]): One positional-argument tuple per job.
        concurrency (int): Maximum number of worker threads.
        what (str): Label used in the error log when a job raises.

    Returns:
        list: The results of all jobs that completed without raising, in completion order
            of the submitted futures.
    """
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(fn, *job) for job in jobs]
        for fut in futures:
            try:
                results.append(fut.result())
            except BackendAPIError as e:
                logger.error(f"Backend API failure during {what}: {e}. Aborting immediately.")
                executor.shutdown(wait=False, cancel_futures=True)
                raise
            except Exception as e:
                logger.error(f"Thread failed during {what}: {e}")
    return results


def _audit_query_job(
    label: str,
    chunk_section: dict,
    schema_str: str,
    app_context_summary: str,
    llm_opts: dict,
    replacements: dict[str, str] | None = None,
) -> tuple[dict | None, str, str, list[dict]]:
    """Runs one agentic audit over a section (or section chunk) and parses its JSON.

    This is the single query engine behind the standard, Network, and Dependencies audit
    paths: prepare the prompt, run the agentic loop, and recover invalid JSON through the
    formatting turn.

    Args:
        label (str): Log/telemetry label (e.g. ``"Network_chunk_2"``).
        chunk_section (dict): Section config whose ``data`` holds this job's input slice.
        schema_str (str): The JSON schema used by the formatting fallback.
        app_context_summary (str): Summarized background context of the app.
        llm_opts (dict): ``model``, ``openai_url``, ``search_func``, and
            ``max_tool_iterations`` for the query.
        replacements (dict[str, str] | None): Extra placeholder replacements applied to the
            prepared prompt (e.g. the dependency group label).

    Returns:
        tuple[dict | None, str, str, list[dict]]: The parsed JSON (None if unrecoverable),
            the raw response content, the thinking content, and the tool log.
    """
    prompt = _prepare_audit_prompt(chunk_section, app_context_summary)
    for placeholder, value in (replacements or {}).items():
        prompt = prompt.replace(placeholder, value)

    start = time.time()
    try:
        response_content, thinking_content, tool_log = _agentic_query(
            prompt,
            llm_opts["model"],
            llm_opts["search_func"],
            llm_opts["max_tool_iterations"],
            llm_opts["openai_url"],
        )
    except (ModelOutputTruncatedError, BackendAPIError):
        # Never swallowed: backend infrastructure failures and exhausted budgets produce no usable
        # analysis. They propagate immediately so the caller can retry or fail fast.
        raise
    except Exception as e:
        logger.error(f"Failed auditing {label}: {e}")
        return None, f"Error: {e}", "", []

    model_cls = _get_section_model(chunk_section=chunk_section, schema_str=schema_str, label=label)
    parsed = _parse_section_response(
        content=response_content,
        model_cls=model_cls,
        section_name=label,
        openai_url=llm_opts.get("openai_url"),
        model=llm_opts.get("model"),
    )

    logger.info(f"{label} completed in {time.time() - start:.2f}s ({len(tool_log)} tool calls).")
    return parsed, response_content, thinking_content, tool_log


_NETWORK_CATEGORIES = ("cloud_services", "trackers_and_ads", "other")


def _query_network_section_audit(
    section: dict,
    app_context_summary: str,
    llm_opts: dict,
    concurrency: int = 1,
) -> tuple[str, list[dict]]:
    """Handles chunking and querying of the Network section.

    The merge is input-driven: every detected domain appears in the rendered section exactly
    once — assessed by the model where possible, otherwise as a clearly labelled stub. A
    failed or unparseable chunk therefore shows up as unreviewed domains instead of silently
    deleting them from the report.

    Args:
        section (dict): Configuration for the section to audit.
        app_context_summary (str): Summarized background context of the app.
        llm_opts (dict): LLM query options (see :func:`_audit_query_job`).
        concurrency (int): Concurrency level for parallel sub-auditing.

    Returns:
        tuple[str, list[dict]]: Network report markdown and cumulative tool log.
    """
    network_data = section["data"]
    input_groups = {cat: sorted(network_data.get(cat, []), key=lambda x: x["domain"]) for cat in _NETWORK_CATEGORIES}
    all_domains = [(cat, item) for cat in _NETWORK_CATEGORIES for item in input_groups[cat]]

    if not all_domains:
        return f"{section['heading']}\n\nNo active network domains or endpoints were identified.", []

    def job(idx: int, chunk: dict) -> tuple[int, dict | None, list[dict]]:
        parsed, _content, _thinking, tool_log = _audit_query_job(
            f"Network_chunk_{idx}", {**section, "data": chunk}, NETWORK_SCHEMA, app_context_summary, llm_opts
        )
        return idx, parsed, tool_log

    # Model assessments indexed by domain, so a domain the model dropped can be detected and
    # re-queried. Chunks are kept small because a chunk that comes back unusable costs every
    # domain in it, and local models drop domains unpredictably from run to run.
    base_chunk_size = 8
    assessed: dict[str, dict] = {}
    all_tool_logs: list[dict] = []
    pending = list(all_domains)

    # One retry round, matching the Dependencies audit: a domain the model dropped twice
    # almost never lands in a third round, so further rounds only burn tokens.
    max_rounds = 2
    for round_num in range(1, max_rounds + 1):
        chunk_size = base_chunk_size if round_num == 1 else 4
        chunks = []
        for i in range(0, len(pending), chunk_size):
            chunk_dict: dict[str, list] = {cat: [] for cat in _NETWORK_CATEGORIES}
            for cat, item in pending[i : i + chunk_size]:
                chunk_dict[cat].append(item)
            chunks.append(chunk_dict)
        if not chunks:
            break

        if round_num == 1:
            logger.info(f"Splitting Network audit into {len(chunks)} chunk(s) (at most {chunk_size} domains each)...")
        else:
            _record_section_regeneration("Network")
            logger.info(
                f"Network retry round {round_num}/{max_rounds}: re-running {len(pending)} "
                f"domain(s) the model did not assess..."
            )

        for _idx, parsed, tool_log in _run_parallel(
            job, [(i, c) for i, c in enumerate(chunks, start=1)], concurrency, "network chunk audit"
        ):
            all_tool_logs.extend(tool_log)
            if not parsed:
                continue
            for cat in _NETWORK_CATEGORIES:
                for item in parsed.get(cat) or []:
                    if domain := str(item.get("domain", "")).strip().lower():
                        assessed.setdefault(domain, item)

        pending = [(cat, item) for cat, item in all_domains if item["domain"].strip().lower() not in assessed]
        if not pending:
            break

    # Assembled input-driven so every detected domain appears exactly once, in the category the
    # scan assigned it: the model supplies only the assessment, never the inventory. The scan
    # input is authoritative for URLs and referencing packages, so those cannot be mangled.
    merged_parsed: dict[str, list] = {cat: [] for cat in _NETWORK_CATEGORIES}
    unassessed = []
    for cat in _NETWORK_CATEGORIES:
        for item in input_groups[cat]:
            entry = assessed.get(item["domain"].strip().lower())
            if entry is None:
                unassessed.append(item["domain"])
                entry = {"domain": item["domain"], "assessment": "Found by the scan but not reviewed by the AI model."}
            entry["urls"] = item.get("urls", [])
            entry["referencing_packages"] = item.get("referencing_packages", [])
            if extra := item.get("additional_url_count"):
                entry["additional_url_count"] = extra
            merged_parsed[cat].append(entry)

    if unassessed:
        logger.warning(
            f"Network section: {len(unassessed)} domain(s) were not assessed by the model after "
            f"{max_rounds} rounds: {unassessed}"
        )

    return _render_network_json(section["heading"], merged_parsed), all_tool_logs


_DEP_GROUP_LABELS: dict[str, str] = {
    "google_sdk": (
        "These are official default platform services (Google Play services, Firebase, ML Kit, Play Core SDKs, "
        "Billing) bundled via Gradle, not general third-party libraries the app developer independently chose."
    ),
    "independent": (
        "These are third-party libraries the app developer chose independently of the Google Play ecosystem."
    ),
    "unversioned": (
        "These third-party libraries were detected in the DEX class pool but no exact version string could be "
        "extracted via metadata or bytecode analysis. Each entry lists the sub-module/package names detected "
        "instead of a version. Do NOT call lookup_maven_version or lookup_osv_vulnerabilities for these (both "
        "require a known version); instead use web_search to identify the library's general purpose and any "
        "well-known/critical vulnerabilities affecting it regardless of version."
    ),
}


def _dependency_index_keys(item: dict) -> set[str]:
    """Returns the lowercased names a dependency item can be reconciled on.

    Includes the echoed ``source_name``, the (possibly resolved) display ``name``, and the
    artifact segment of a Maven coordinate, so a detected dependency can be matched against the
    model's output even when the model renamed a bare artifact to a full ``group:artifact``.

    Args:
        item (dict): A dependency item from the model's output.

    Returns:
        set[str]: The set of lowercased keys the item can be looked up by.
    """
    keys: set[str] = set()
    for field in ("source_name", "name"):
        val = str(item.get(field) or "").strip().lower()
        if val:
            keys.add(val)
            if ":" in val:
                keys.add(val.split(":")[-1])
    return keys


def _categorize_third_party_deps(third_party: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Categorizes a third-party dependency dictionary into google_sdk, independent, and unversioned groups.

    Args:
        third_party (dict[str, Any]): Dictionary of third-party dependencies.

    Returns:
        dict[str, dict[str, Any]]: Mapping of group names to their respective dependencies.
    """
    from scanner.scan_modules.dependencies import _google_sdk_coordinate, _is_google_group

    google_sdk: dict[str, Any] = {}
    independent: dict[str, Any] = {}
    unversioned: dict[str, Any] = {}

    for name, details in sorted(third_party.items()):
        if not isinstance(details, dict):
            details = {
                "version_used": str(details),
                "latest_version": None,
                "latest_version_url": None,
                "osv_findings": [],
            }

        version = details.get("version_used")
        if version is None or str(version).strip().lower() in ("", "unknown", "null", "none"):
            unversioned[name] = details
        elif _is_google_group(name.split(":", 1)[0]) if ":" in name else _google_sdk_coordinate(name):
            google_sdk[name] = details
        else:
            independent[name] = details

    return {
        "google_sdk": google_sdk,
        "independent": independent,
        "unversioned": unversioned,
    }


def _dep_fallback_item(group: str, name: str, value: object) -> dict:
    """Builds a placeholder entry for a dependency the model never assessed.

    Used only as a last resort after the retry rounds so a detected dependency is never silently
    dropped from the report, while remaining clearly marked as not individually assessed.

    Args:
        group (str): The dependency group ('google_sdk', 'independent', or 'unversioned').
        name (str): The exact findings key for the dependency.
        value (object): The findings value (a dict or a version string).

    Returns:
        dict: A dependency item dict compatible with the deps renderer.
    """
    if isinstance(value, dict):
        version_used = str(value.get("version_used")) if value.get("version_used") else "unknown"
        latest_version = str(value.get("latest_version")) if value.get("latest_version") else "unknown"
        latest_url = str(value.get("latest_version_url") or "")
        osv_hits = value.get("osv_findings") or []
        vulns_text = (
            [f"{f.get('cve_id')}: {f.get('summary')} (details: {f.get('details_url')})" for f in osv_hits]
            if osv_hits
            else "No known vulnerabilities found for this version by the OSV.dev batch check"
            if version_used != "unknown"
            else "Version unknown - not assessed"
        )
    else:
        version_used = "unknown" if group == "unversioned" else str(value)
        latest_version = "unknown"
        latest_url = ""
        vulns_text = "Not checked by the model. Please check it by hand, for example on OSV.dev."

    return {
        "source_name": name,
        "name": name,
        "version_used": version_used,
        "latest_version": latest_version,
        "latest_version_url": latest_url,
        "purpose": "Found by the scan but not reviewed one by one by the AI model.",
        "vulnerabilities": vulns_text,
    }


def _query_dependencies_section_audit(
    section: dict,
    app_context_summary: str,
    llm_opts: dict,
    concurrency: int = 1,
) -> tuple[str, list[dict]]:
    """Handles chunking and querying of the Dependencies section.

    Each dependency requires several tool calls to research properly (Maven version lookup,
    OSV vulnerability lookup, and NVD lookups for any CVEs found). A single agentic run covering
    every dependency can exhaust the tool-call iteration budget before producing a final answer,
    which previously caused the model's response to come back empty for large dependency lists.
    Splitting into small chunks with a boosted per-chunk iteration budget lets the model actually
    finish researching and assessing every dependency.

    Args:
        section (dict): Configuration for the section to audit.
        app_context_summary (str): Summarized background context of the app.
        llm_opts (dict): LLM query options (see :func:`_audit_query_job`); its
            ``max_tool_iterations`` is treated as the baseline budget and boosted per chunk.
        concurrency (int): Concurrency level for parallel sub-auditing.

    Returns:
        tuple[str, list[dict]]: Dependencies report markdown (AI-assessed content only) and
            cumulative tool log.
    """
    raw_data = section.get("data", {})
    if "third_party" in raw_data and isinstance(raw_data["third_party"], dict):
        groups = _categorize_third_party_deps(raw_data["third_party"])
    elif isinstance(raw_data, dict) and any(k in raw_data for k in ("google_sdk", "independent", "unversioned")):
        groups = raw_data
    elif "exact_versions_found" in raw_data:
        tp_legacy = raw_data.get("exact_versions_found", {}).get("third_party", {})
        groups = {
            "google_sdk": tp_legacy.get("google_sdk", {}),
            "independent": tp_legacy.get("independent", {}),
            "unversioned": raw_data.get("detected_libraries_version_unknown", {}),
        }
    else:
        groups = _categorize_third_party_deps(raw_data)

    if not any(groups.values()):
        return f"{section['heading']}\n\nNo third-party dependencies were identified.", []

    base_chunk_size = 6
    # Give each chunk a generous iteration budget: every dependency needs at least one tool
    # call (Maven version lookup), plus headroom for CVE enrichment and web searches.
    chunk_opts = {**llm_opts, "max_tool_iterations": max(llm_opts["max_tool_iterations"], base_chunk_size * 4)}

    def job(group: str, idx: int, chunk: dict) -> tuple[str, dict | None, list[dict]]:
        data = chunk
        parsed, _content, _thinking, tool_log = _audit_query_job(
            f"Dependencies_{group}_chunk_{idx}",
            {**section, "data": data},
            DEPS_SCHEMA,
            app_context_summary,
            chunk_opts,
            replacements={"__DEP_GROUP_LABEL__": _DEP_GROUP_LABELS[group]},
        )
        return group, parsed, tool_log

    # Model assessments indexed per group by every name variant they can be matched on, so a
    # dropped dependency can be detected and re-queried until the model actually assesses it.
    model_items: dict[str, dict[str, dict]] = {group: {} for group in groups}
    all_tool_logs: list[dict] = []

    # Dependencies still awaiting a model assessment; starts as the full detected input set.
    # One retry round: a dependency the model dropped twice almost never appears in a third
    # round, so further rounds would only burn tokens before the fallback stub takes over.
    pending: dict[str, dict] = {group: dict(deps) for group, deps in groups.items()}
    max_rounds = 2
    for round_num in range(1, max_rounds + 1):
        # Smaller chunks on the retry round concentrate the tool-call budget on the few
        # stragglers the model dropped, which are usually the ambiguously named ones.
        chunk_size = base_chunk_size if round_num == 1 else 3
        chunk_jobs: list[tuple[str, int, dict]] = []
        for group, deps in pending.items():
            names = sorted(deps.keys())
            group_chunks = [
                {name: deps[name] for name in names[i : i + chunk_size]} for i in range(0, len(names), chunk_size)
            ]
            for i, c in enumerate(group_chunks, start=1):
                chunk_jobs.append((group, i, c))
        if not chunk_jobs:
            break

        if round_num == 1:
            logger.info(
                f"Splitting Dependencies audit into {len(chunk_jobs)} chunk(s) across "
                f"{sum(1 for g in groups.values() if g)} group(s) (at most {chunk_size} dependencies each, "
                f"{chunk_opts['max_tool_iterations']} iterations/chunk)..."
            )
        else:
            pending_total = sum(len(d) for d in pending.values())
            _record_section_regeneration("Dependencies")
            logger.info(
                f"Dependencies retry round {round_num}/{max_rounds}: re-running {pending_total} "
                f"dependency(ies) the model did not assess..."
            )

        for group, parsed_json, chunk_tool_log in _run_parallel(job, chunk_jobs, concurrency, "dependency chunk audit"):
            if parsed_json:
                for item in parsed_json.get("items") or []:
                    for key in _dependency_index_keys(item):
                        model_items[group].setdefault(key, item)
            all_tool_logs.extend(chunk_tool_log)

        # Anything still unmatched becomes the next round's workload.
        pending = {
            group: {name: value for name, value in deps.items() if model_items[group].get(name.strip().lower()) is None}
            for group, deps in groups.items()
        }
        if not any(pending.values()):
            break

    # Assemble the section input-driven so every detected dependency appears exactly once, using
    # the model's assessment where available and a clearly labelled fallback only as a last resort.
    merged_parsed: dict[str, list] = {group: [] for group in groups}
    unassessed: list[str] = []
    for group, deps in groups.items():
        for name in sorted(deps.keys()):
            item = model_items[group].get(name.strip().lower())
            if item is None:
                item = _dep_fallback_item(group, name, deps[name])
                unassessed.append(name)
            merged_parsed[group].append(item)

    if unassessed:
        logger.warning(
            f"Dependencies section: {len(unassessed)} dependency(ies) could not be assessed by the model after "
            f"{max_rounds} rounds and are listed with a fallback note: {sorted(unassessed)}"
        )

    final_markdown = _render_deps_json(section["heading"], merged_parsed)
    return final_markdown, all_tool_logs


class EmptySectionResultError(RuntimeError):
    """Raised when a section with findings in its input came back with none in its output.

    Standard sections only run when their input data is non-empty (empty inputs get a clean
    placeholder before any model call), so a well-formed answer reporting nothing means the
    model dropped every finding. Rendering it would present real scan results as a clean
    bill of health; raising instead routes the section through the retry-then-fail path.
    """


def _reports_no_findings(parsed: dict) -> bool:
    """Whether a parsed section response carries no findings at all.

    Mirrors the emptiness rules of the standard-section renderers: an explicit
    ``no_findings`` flag, or both content keys (``findings``/``items``) empty.

    Args:
        parsed (dict): The parsed JSON object from the model.

    Returns:
        bool: True if rendering this response would produce a "nothing found" section.
    """
    return bool(parsed.get("no_findings")) or (not parsed.get("findings") and not parsed.get("items"))


def _query_permissions_section_audit(
    section: dict,
    app_context_summary: str,
    llm_opts: dict,
    concurrency: int = 1,
) -> tuple[str, list[dict]]:
    """Handles chunking and querying of the Permissions section in small batches.

    Batches permissions (3-4 permissions per query) to avoid output token truncation
    and token limit exhaustion on large applications.

    Args:
        section (dict): Configuration for the section to audit.
        app_context_summary (str): Summarized background context of the app.
        llm_opts (dict): LLM query options.
        concurrency (int): Concurrency level for parallel sub-auditing.

    Returns:
        tuple[str, list[dict]]: Rendered permissions markdown and cumulative tool log.
    """
    perms_data = section.get("data") or {}
    groups = {
        "runtime_requested": perms_data.get("runtime_requested", []),
        "install_time_or_system": perms_data.get("install_time_or_system", []),
        "custom_or_third_party": perms_data.get("custom_or_third_party", []),
    }
    if not any(groups.values()):
        return f"{section['heading']}\n\nNo permissions were identified in this application.", []

    refs = perms_data.get("references", {})
    chunk_size = 4
    tasks = []

    for group_key, perm_list in groups.items():
        for i in range(0, len(perm_list), chunk_size):
            chunk = perm_list[i : i + chunk_size]
            chunk_items = []
            for p in chunk:
                raw_ref = refs.get(p, {})
                if isinstance(raw_ref, dict):
                    internal_sites = _compact_call_sites(raw_ref.get("app_internal", []))
                    third_party_sites = _compact_call_sites(raw_ref.get("third_party", []))
                    combined_sites = internal_sites[:2] + third_party_sites[:2]
                elif isinstance(raw_ref, list):
                    combined_sites = _compact_call_sites(raw_ref)[:3]
                    internal_sites = combined_sites
                    third_party_sites = []
                else:
                    combined_sites, internal_sites, third_party_sites = [], [], []

                chunk_items.append(
                    {
                        "permission": p,
                        "group": group_key,
                        "app_internal_call_sites": internal_sites[:3],
                        "third_party_call_sites": third_party_sites[:3],
                        "call_sites": combined_sites[:3],
                    }
                )
            tasks.append((group_key, chunk_items))

    def job(group_key: str, chunk_items: list[dict]) -> tuple[dict | None, list[dict]]:
        data_json = json.dumps(chunk_items, indent=2)
        custom_prompt = PERMISSIONS_PROMPT_TEMPLATE.replace("__APP_CONTEXT__", app_context_summary).replace(
            "__DATA_JSON__", data_json
        )
        parsed, _content, _thinking, tool_log = _audit_query_job(
            f"Permissions_{group_key}",
            {**section, "prompt_template": custom_prompt, "data": chunk_items},
            PERMISSIONS_SCHEMA,
            app_context_summary,
            llm_opts,
        )
        return parsed, tool_log

    jobs_args = [(g_key, items) for g_key, items in tasks]
    job_results = _run_parallel(job, jobs_args, max(1, concurrency), "Permissions audit")

    all_items: list[dict] = []
    all_tool_logs: list[dict] = []
    for parsed, tool_log in job_results:
        all_tool_logs.extend(tool_log)
        if parsed and parsed.get("items"):
            all_items.extend(parsed["items"])

    parsed_result = {"no_findings": len(all_items) == 0, "items": all_items}
    return _render_permissions_json(section["heading"], parsed_result, perms_data), all_tool_logs


def _query_standard_section_audit(
    section: dict,
    app_context_summary: str,
    llm_opts: dict,
) -> tuple[str, list[dict]]:
    """Queries a standard (non-chunked) section from the LLM model.

    Args:
        section (dict): Configuration for the section to audit.
        app_context_summary (str): Summarized background context of the app.
        llm_opts (dict): LLM query options (see :func:`_audit_query_job`).

    Returns:
        tuple[str, list[dict]]: Section report markdown and tool log.

    Raises:
        EmptySectionResultError: If the model reported no findings for non-empty input.
    """
    schema_str = section.get("schema") or _RENDERER_SCHEMAS.get(section.get("renderer", "findings"), FINDINGS_SCHEMA)
    parsed, response_content, _thinking_content, tool_call_log = _audit_query_job(
        section["name"], section, schema_str, app_context_summary, llm_opts
    )

    if parsed is not None:
        # Input/output sanity gate: this section only runs on non-empty input, so a reply
        # with zero findings means the model dropped everything (observed once as a
        # "No security concerns" Bytecode section for an app with four true detections).
        if _reports_no_findings(parsed):
            raise EmptySectionResultError(
                f"Model reported no findings for '{section['name']}' although the scan data "
                f"for this section is non-empty."
            )
        render = _RENDERERS.get(section.get("renderer", "findings"), _RENDERERS["findings"])
        return render(section["heading"], parsed, section), tool_call_log

    # JSON was unrecoverable — return clear error placeholder.
    return f"{section['heading']}\n\n*Error during automated AI analysis: {response_content}*", tool_call_log


def _query_section_audit(
    section: dict,
    app_context_summary: str,
    model: str,
    search_func: Callable,
    max_tool_iterations: int,
    openai_url: str,
    concurrency: int = 1,
) -> tuple[str, list[dict]]:
    """Routes a section to its audit strategy: chunked for Network/Dependencies/Permissions, direct otherwise.

    Args:
        section (dict): Configuration for the section to audit.
        app_context_summary (str): Summarized background context of the app.
        model (str): The model name.
        search_func (Callable): The search function for web_search.
        max_tool_iterations (int): Maximum tool rounds.
        openai_url (str): Base URL of the OpenAI-compatible API.
        concurrency (int): Concurrency level for parallel sub-auditing.

    Returns:
        tuple[str, list[dict]]: Section report markdown and tool log.
    """
    llm_opts = {
        "model": model,
        "openai_url": openai_url,
        "search_func": search_func,
        "max_tool_iterations": max_tool_iterations,
    }
    if section["name"] == "Network":
        return _query_network_section_audit(section, app_context_summary, llm_opts, concurrency)
    if section["name"] == "Dependencies":
        return _query_dependencies_section_audit(section, app_context_summary, llm_opts, concurrency)
    if section["name"] == "Permissions":
        return _query_permissions_section_audit(section, app_context_summary, llm_opts, concurrency)
    return _query_standard_section_audit(section, app_context_summary, llm_opts)


# App context generation


def _reference_datetime(scan_report: dict) -> datetime:
    """Resolves the point in time the report reasons from.

    Uses the scan's completion timestamp when available so every date derived from it is
    deterministic per report, falling back to the current UTC time.

    Args:
        scan_report (dict): The static scan report.

    Returns:
        datetime: The scan's completion time, or the current UTC time.
    """
    raw = scan_report.get("scan_metadata", {}).get("scan_completed")
    if raw:
        try:
            return datetime.fromisoformat(raw)
        except (ValueError, TypeError):
            pass
    return datetime.now(UTC)


def _incident_cutoff_date(scan_report: dict) -> str:
    """Computes the earliest acceptable date (report date minus two years) for incidents.

    The security-incidents research is limited to events on or after this date.

    Args:
        scan_report (dict): The static scan report.

    Returns:
        str: Cutoff date formatted as ``YYYY-MM-DD``.
    """
    ref = _reference_datetime(scan_report)
    try:
        cutoff = ref.replace(year=ref.year - 2)
    except ValueError:
        # Feb 29 has no counterpart in a non-leap year two years earlier; clamp to Feb 28.
        cutoff = ref.replace(month=2, day=28, year=ref.year - 2)
    return cutoff.strftime("%Y-%m-%d")


_NO_INFO_DESCRIPTION = "No information about this application could be found online."


def _assemble_app_context(
    parsed: dict,
    store_meta: dict | None,
    local_name: str,
    package: str,
    version_name: str | None,
) -> dict:
    """Grounds the parsed app context in the verified store scrape and APK metadata.

    Backfills the Play Store scrape wherever the model left gaps, then anchors to the APK's
    own metadata as the ultimate fallback so the report always identifies the app. Mutates
    and returns ``parsed``.

    Args:
        parsed (dict): The parsed app-context object from the model (may be empty).
        store_meta (dict | None): Structured Play Store metadata, or ``None`` if unavailable.
        local_name (str): App name derived from the APK's own metadata.
        package (str): The Android package ID.
        version_name (str | None): The app version name, if known.

    Returns:
        dict: The grounded app-context object.
    """
    _backfill_app_context_from_store(parsed, store_meta)
    if not parsed.get("app_name"):
        parsed["app_name"] = local_name
    description = (parsed.get("description") or "").strip()
    if not description or description == _NO_INFO_DESCRIPTION:
        parsed["description"] = _local_app_description(local_name, package, version_name)
    # Only force the constructed store URL when the scrape confirmed a live listing;
    # for unlisted apps (private/enterprise builds) the link would 404.
    if not parsed.get("play_store_url") and store_meta and store_meta.get("name") and package:
        parsed["play_store_url"] = f"https://play.google.com/store/apps/details?id={package}"
    return parsed


def _local_app_description(name: str, package: str, version: str | None) -> str:
    """Builds a plain-English app description from the APK's own metadata.

    Used as a guaranteed baseline so the report always identifies the app, even when the online
    Play Store and web lookups fail or return nothing.

    Args:
        name (str): The app name from the APK metadata.
        package (str): The Android package ID.
        version (str | None): The app version name, if known.

    Returns:
        str: A short description grounded only in the local package details.
    """
    ver = f" (version {version})" if version else ""
    return (
        f"{name}{ver}, Android package {package}. No extra public information about this app was found online, "
        "so this summary is based on the app's own package details."
    )


def _format_playstore_metadata_block(store_meta: dict | None) -> str:
    """Renders the pre-fetched Play Store metadata as a plain block for the app-context prompt.

    Args:
        store_meta (dict | None): Structured metadata from
            :func:`scanner.web.playstore.fetch_play_store_metadata`, or ``None``.

    Returns:
        str: A labelled metadata block, or an explicit "not available" notice so the model knows
            it must research the app itself instead of assuming the block was simply omitted.
    """
    if not store_meta or not (store_meta.get("name") or store_meta.get("description")):
        return (
            "No Play Store metadata could be retrieved for this package (the store page may not "
            "exist, or the scraper is unavailable). Research the app yourself using the tools."
        )

    lines = []
    if name := store_meta.get("name"):
        lines.append(f"App Name: {name}")
    if developer := store_meta.get("developer"):
        lines.append(f"Developer: {developer}")
    if description := store_meta.get("description"):
        lines.append(f"Description: {description}")
    if source := store_meta.get("source"):
        lines.append(f"Source: {source}")
    return "\n".join(lines)


def _backfill_app_context_from_store(parsed: dict, store_meta: dict | None) -> None:
    """Fills verified Play Store fields into the parsed app context wherever the model left gaps.

    The scraped store data is authoritative for the app's identity, so it overrides an empty
    ``app_name``/``developer`` and replaces a missing or sentinel 'no info' description. Mutates
    ``parsed`` in place.

    Args:
        parsed (dict): The parsed app-context object from the model (mutated in place).
        store_meta (dict | None): Structured Play Store metadata, or ``None`` if unavailable.
    """
    if not store_meta:
        return

    if not parsed.get("app_name") and store_meta.get("name"):
        parsed["app_name"] = store_meta["name"]
    if not parsed.get("developer") and store_meta.get("developer"):
        parsed["developer"] = store_meta["developer"]
    if store_meta.get("source") and not parsed.get("play_store_url"):
        parsed["play_store_url"] = store_meta["source"]

    current_desc = (parsed.get("description") or "").strip()
    if store_meta.get("description") and (not current_desc or current_desc == _NO_INFO_DESCRIPTION):
        parsed["description"] = store_meta["description"]

    # A live store listing is deterministic proof the app exists and is distributed.
    current_status = (parsed.get("status") or "").strip()
    if store_meta.get("name") and (not current_status or current_status.lower() == "unknown"):
        parsed["status"] = "Active (listed on Google Play)"


def get_app_context(
    scan_report: dict,
    model: str,
    search_func: Callable,
    max_tool_iterations: int,
    openai_url: str,
    tool_calls_out: list[dict] | None = None,
) -> str:
    """Generates an application overview by letting the model query the Play Store and web search.

    Args:
        scan_report (dict): The generated static scan report.
        model (str): Name of LLM model.
        search_func (Callable): Search function for web_search.
        max_tool_iterations (int): Maximum tool-call rounds.
        openai_url (str): Base URL of the OpenAI-compatible API.
        tool_calls_out (list[dict] | None): Optional output list to collect tool calls made.

    Returns:
        str: Generated application context markdown block.
    """
    metadata = scan_report.get("apk_metadata", {})
    package = metadata.get("package", "")
    apk_name = metadata.get("apk_name", "")

    if not package and not apk_name:
        return "Unknown Android application. No information about this application could be found online."

    environment_details = scan_report.get("environment_details", {})
    ui_framework = environment_details.get("ui_framework") or "Unknown"
    cutoff_date = _incident_cutoff_date(scan_report)

    # Reliable baseline from the APK's own metadata, so the app is always identified even when the
    # online Play Store / web lookups fail or return nothing.
    local_name = metadata.get("app_name") or apk_name
    if local_name.endswith(".apk"):
        local_name = local_name[:-4]
    local_name = local_name.strip() or "Unknown Android application"
    version_name = metadata.get("app_version_name")

    # Deterministically fetch the Play Store metadata in Python BEFORE the model runs. This
    # decouples the app's identity (name, developer, description) from the local model's flaky
    # tool-calling: the data is injected into the prompt as ground truth and also backfilled into
    # the parsed result, so the overview never collapses to a package-only stub when the store
    # page actually exists.
    from scanner.web.playstore import fetch_play_store_metadata

    store_meta: dict | None = None
    try:
        store_meta = fetch_play_store_metadata(package)
    except Exception as e:
        logger.warning(f"Play Store pre-fetch raised for {package}: {e}")
    playstore_block = _format_playstore_metadata_block(store_meta)

    logger.info(f"Gathering app context for {package} via agentic query...")
    prompt = (
        APP_CONTEXT_PROMPT_TEMPLATE.replace("__PACKAGE__", package)
        .replace("__KNOWN_APP_NAME__", local_name)
        .replace("__UI_FRAMEWORK__", ui_framework)
        .replace("__INCIDENT_CUTOFF_DATE__", cutoff_date)
        .replace("__PLAYSTORE_METADATA__", playstore_block)
    )

    try:
        response_content, _thinking_content, tool_call_log = _agentic_query(
            prompt, model, search_func, max_tool_iterations, openai_url
        )
        parsed = _parse_section_response(
            content=response_content,
            model_cls=AppContextModel,
            section_name="App Context",
            openai_url=openai_url,
            model=model,
        )

        if tool_calls_out is not None:
            tool_calls_out.extend(tool_call_log)

        if not isinstance(parsed, dict):
            parsed = {}
        parsed = _assemble_app_context(parsed, store_meta, local_name, package, version_name)
        return _render_app_context_json(parsed, environment_details, metadata)
    except BackendAPIError:
        raise
    except Exception as e:
        logger.warning(f"Failed to generate app context: {e}")
        # Even when the agentic query fails outright, prefer the verified store scrape over the
        # package-only stub so the overview still shows the real app identity and description.
        fallback = _assemble_app_context({}, store_meta, local_name, package, version_name)
        return _render_app_context_json(fallback, environment_details, metadata)


# Report header


def _format_report_header(
    scan_report: dict,
    security_score: float,
    security_grade: str,  # noqa: ARG001
    app_context_summary: str,
    model: str,
    duration_seconds: float,
    tool_call_counts: dict[str, int],
    recommendation: str = "",
) -> str:
    """Formats the standardized report metadata header.

    Args:
        scan_report (dict): The original static analysis report.
        security_score (float): Calculated numerical score out of 100.
        security_grade (str): Associated letter grade (retained for signature compatibility).
        app_context_summary (str): Summarized background context of the app.
        model (str): Name of LLM model.
        duration_seconds (float): Duration of execution.
        tool_call_counts (dict[str, int]): Per-tool call count breakdown.
        recommendation (str): Optional override for recommendation HTML string.

    Returns:
        str: Formatted markdown header string.
    """
    apk_metadata = scan_report.get("apk_metadata", {})
    apk_name = apk_metadata.get("apk_name", "Target App")
    app_name = apk_metadata.get("app_name") or apk_name
    if app_name.endswith(".apk"):
        app_name = app_name[:-4]

    package = apk_metadata.get("package", "Unknown")

    size_bytes = apk_metadata.get("size")
    if size_bytes:
        if size_bytes >= 1024 * 1024:
            size_str = f"{size_bytes / (1024 * 1024):.2f} MB ({size_bytes:,} bytes)"
        elif size_bytes >= 1024:
            size_str = f"{size_bytes / 1024:.2f} KB ({size_bytes:,} bytes)"
        else:
            size_str = f"{size_bytes} bytes"
    else:
        size_str = "Unknown"

    version_name = apk_metadata.get("app_version_name")
    version_code = apk_metadata.get("app_version_code")
    if version_name and version_code:
        version_str = f"{version_name} (Code: {version_code})"
    elif version_name:
        version_str = version_name
    elif version_code:
        version_str = f"Code: {version_code}"
    else:
        version_str = "Unknown"

    creation_date = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Format tool call summary
    from scanner.web.scraper import SCRAPER_URL

    total_calls = sum(tool_call_counts.values())
    if total_calls > 0:
        breakdown = ", ".join(f"{count}x {name}" for name, count in sorted(tool_call_counts.items()) if count > 0)
        search_status = f"Active ({model}, {total_calls} tool calls: {breakdown})"
    elif SCRAPER_URL:
        search_status = f"Active ({model}, 0 tool calls made)"
    else:
        search_status = f"Active without web scraper ({model}, 0 tool calls made)"

    if not recommendation:
        _, recommendation_styled = get_recommendation(security_score, vulnerabilities_or_report=scan_report)
    else:
        recommendation_styled = recommendation

    return (
        f"# Mobile Application Security Assessment Report - {app_name}\n\n"
        f"## Report Details\n"
        f"- **Recommendation**: {recommendation_styled}\n"
        f"- **App Name**: {app_name}\n"
        f"- **Package**: {package}\n"
        f"- **Version**: {version_str}\n"
        f"- **File Size**: {size_str}\n"
        f"- **Date of Creation**: {creation_date}\n"
        f"- **Target File**: {json.dumps(apk_name)}\n"
        f"- **Model Used**: {model}\n"
        f"- **AI Generation Time**: {duration_seconds:.2f} seconds\n"
        f"- **Threat Intelligence Search**: {search_status}\n"
        f"- **Section Regenerations**: {_format_section_regenerations()}\n\n"
        f"## App Description\n"
        f"{app_context_summary}\n\n"
        f"---\n"
    )


def _assemble_report(header: str, sections: list[str]) -> str:
    """Joins the report header and completed sections into the final normalized markdown.

    Args:
        header (str): The formatted report header block.
        sections (list[str]): The completed section markdown blocks, in report order.

    Returns:
        str: The normalized full report markdown.
    """
    if not sections:
        body = "\n## Security Audit Summary\n\nNo significant security concerns or risks were identified during this automated static analysis.\n"
    else:
        body = "\n\n---\n\n".join(sections)
    return _normalize_markdown(header + "\n" + body)


def save_current_progress(file_path: str, generated_sections: list[str], header: str) -> None:
    """Saves the report assembled so far to disk, overwriting any previous partial write.

    Write failures are logged and swallowed: an incremental snapshot is a convenience, and
    losing one must not abort a report run that is otherwise progressing.

    Args:
        file_path (str): Destination path for the partial Markdown report.
        generated_sections (list[str]): The section blocks completed so far, in report order.
        header (str): The formatted report header block.
    """
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(_assemble_report(header, generated_sections))
    except Exception as e:
        logger.warning(f"Failed to write incremental progress: {e}")


def _update_incremental_report(
    ai_report_path: str | None,
    write_lock: threading.Lock,
    start_time: float,
    scan_report: dict,
    security_score: float,
    security_grade: str,
    app_context_summary: str,
    model: str,
    total_tool_call_counts: dict[str, int],
    results: list[str | None],
) -> None:
    """Saves the current progress of report generation to disk if a path is provided.

    Args:
        ai_report_path (str | None): Optional path to write report progress incrementally.
        write_lock (threading.Lock): Thread lock for write operations.
        start_time (float): Start timestamp of the generation.
        scan_report (dict): Static scan report dictionary.
        security_score (float): Calculated security score.
        security_grade (str): Calculated security grade letter.
        app_context_summary (str): Compiled app context description.
        model (str): Name of the model.
        total_tool_call_counts (dict[str, int]): Tracked tool call counts.
        results (list[str | None]): Progress results list of section markdowns.
    """
    if ai_report_path:
        with write_lock:
            current_duration = time.time() - start_time
            header = _format_report_header(
                scan_report,
                security_score,
                security_grade,
                app_context_summary,
                model,
                current_duration,
                total_tool_call_counts,
            )
            completed = [r for r in results if r is not None]
            save_current_progress(ai_report_path, completed, header)


def generate_ai_report(
    scan_report: dict,
    openai_url: str,
    model: str = "qwen3.6:35b",
    max_tool_iterations: int = 10,
    ai_report_path: str | None = None,
    concurrency: int = 1,
) -> str:
    """Generates an AI assessment markdown report of the scanned APK.

    Uses the agentic tool-calling loop: the model calls tools on demand during
    its reasoning rather than receiving pre-fetched context in the prompt.
    Sections are audited in parallel using a thread pool executor.

    Args:
        scan_report (dict): The generated static scan report.
        model (str): The name of the local Ollama/OpenAI model to use.
        max_tool_iterations (int): Maximum tool-call rounds per section.
        openai_url (str): Base URL of the OpenAI-compatible API.
        ai_report_path (str | None): Optional path to write report progress incrementally.
        concurrency (int): Maximum number of concurrent section threads (default: 1).

    Returns:
        str: Generated Markdown report.
    """
    start_time = time.time()
    logger.info(f"Generating AI report using model '{model}' (agentic mode, concurrency: {concurrency})...")

    # Reset the in-session tool result cache and per-section retry counters for this run
    clear_tool_cache()
    _reset_section_regenerations()

    global _CURRENT_DATE
    _CURRENT_DATE = _reference_datetime(scan_report).strftime("%Y-%m-%d")

    # Resolve the web search function (DuckDuckGo via the scraper container)
    search_func = resolve_search_func()

    # Thread locks and shared accumulators
    counts_lock = threading.Lock()
    write_lock = threading.Lock()
    abort_event = threading.Event()
    total_tool_call_counts: dict[str, int] = {}

    # Generate the application context block first
    app_context_tool_calls = []
    app_context_summary = get_app_context(
        scan_report,
        model,
        search_func,
        max_tool_iterations,
        openai_url=openai_url,
        tool_calls_out=app_context_tool_calls,
    )
    for tc in app_context_tool_calls:
        tool_name = tc.get("tool_name")
        if tool_name:
            total_tool_call_counts[tool_name] = total_tool_call_counts.get(tool_name, 0) + 1
    logger.info("App context compiled.")

    # Remove safe items from raw static findings to focus LLM on risks
    filtered_manifest, filtered_signatures = _filter_scan_report(scan_report)

    # Assemble section configurations
    sections_config = _prepare_sections_config(scan_report, filtered_manifest, filtered_signatures)

    security_score = calculate_security_score(scan_report)
    security_grade = get_security_grade(security_score)

    total_sections = len(sections_config)
    results: list[str | None] = [None] * total_sections

    def save_progress() -> None:
        _update_incremental_report(
            ai_report_path,
            write_lock,
            start_time,
            scan_report,
            security_score,
            security_grade,
            app_context_summary,
            model,
            total_tool_call_counts,
            results,
        )

    def worker(idx: int, section: dict) -> None:
        if abort_event.is_set():
            return
        progress_prefix = f"[Progress {idx}/{total_sections}]"

        # 0. Deterministic sections (e.g. a manifest parse failure) bypass the model entirely.
        if static_content := section.get("static_content"):
            logger.info(f"{progress_prefix} Using deterministic content for '{section['name']}'.")
            results[idx - 1] = static_content
            save_progress()
            return

        # 1. Skip if empty
        if is_data_empty(section["data"]):
            logger.info(f"{progress_prefix} No findings in '{section['name']}'. Adding clean placeholder.")
            results[idx - 1] = (
                f"{section['heading']}\n\nNo security concerns or vulnerabilities were identified in this section."
            )
            save_progress()
            return

        # 2. Query LLM. A model that returned nothing usable three times over will not
        # succeed on a fourth, so the section is marked failed rather than rendered clean.
        logger.info(f"{progress_prefix} Auditing section '{section['name']}'...")
        for attempt in range(1, SECTION_ATTEMPTS + 1):
            try:
                section_result, section_tool_log = _query_section_audit(
                    section=section,
                    app_context_summary=app_context_summary,
                    model=model,
                    search_func=search_func,
                    max_tool_iterations=max_tool_iterations,
                    openai_url=openai_url,
                    concurrency=concurrency,
                )
                break
            except BackendAPIError:
                abort_event.set()
                raise
            except Exception as e:
                logger.warning(
                    f"{progress_prefix} Attempt {attempt}/{SECTION_ATTEMPTS} for '{section['name']}' failed: {e}"
                )
                if attempt == SECTION_ATTEMPTS:
                    logger.error(f"{progress_prefix} Section '{section['name']}' failed after all attempts.")
                    results[idx - 1] = _failed_section_placeholder(section, e)
                    save_progress()
                    return

        results[idx - 1] = section_result

        # Accumulate tool calls safely
        with counts_lock:
            for entry in section_tool_log:
                tool_name = str(entry.get("tool_name", "unknown"))
                total_tool_call_counts[tool_name] = total_tool_call_counts.get(tool_name, 0) + 1

        save_progress()

    # Execute sections concurrently. Each future is resolved individually so a section that
    # raises is logged with its name instead of silently disappearing from the final report.
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {
            executor.submit(worker, idx, section): section["name"]
            for idx, section in enumerate(sections_config, start=1)
        }
        for fut, section_name in futures.items():
            try:
                fut.result()
            except BackendAPIError as e:
                abort_event.set()
                logger.error(f"Backend API failure during '{section_name}': {e}. Aborting AI report generation.")
                executor.shutdown(wait=False, cancel_futures=True)
                raise
            except Exception as e:
                logger.error(f"Section '{section_name}' failed and was omitted from the report: {e}")

    header = _format_report_header(
        scan_report,
        security_score,
        security_grade,
        app_context_summary,
        model,
        time.time() - start_time,
        total_tool_call_counts,
    )
    return _assemble_report(header, [r for r in results if r is not None])
