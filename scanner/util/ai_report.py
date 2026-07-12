"""AI security report generation module for the APK static scanner.

Implements local Ollama integration and RAG via DuckDuckGo/Bing search queries.
"""

import json
import re
import time
import urllib.parse
from collections.abc import Callable
from datetime import UTC

import requests
from loguru import logger

from scanner.util.ai_prompt_templates import (
    APP_CONTEXT_PROMPT_TEMPLATE,
    BYTECODE_AUDIT_GUIDELINES,
    DEPENDENCIES_PROMPT_TEMPLATE,
    LIST_SECTION_PROMPT_TEMPLATE,
    MANIFEST_AUDIT_GUIDELINES,
    NETWORK_PROMPT_TEMPLATE,
    PERMISSIONS_PROMPT_TEMPLATE,
    SECRETS_PROMPT_TEMPLATE,
    SECURITY_CHECKS_GUIDELINES,
    SIGNATURES_GUIDELINES,
    STANDARD_SECTION_PROMPT_TEMPLATE,
    SYSTEM_PROMPT,
    VULNERABILITIES_PROMPT_TEMPLATE,
)


def search_ddg(query: str, max_results: int = 5) -> list[str]:
    """Queries DuckDuckGo HTML-only search and extracts result snippets and source URLs.

    Args:
        query (str): The search query to run.
        max_results (int): Maximum number of snippets to return.

    Returns:
        list[str]: A list of cleaned snippet strings with source URLs.
    """
    import html as html_lib

    from scanner.util.scraper import get_html

    url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote_plus(query)}"
    try:
        logger.debug(f"Executing web search: {query}")
        html_text = get_html(url)

        matches = re.finditer(r'<a\s+([^>]*?)href="([^"]+)"[^>]*>(.*?)</a>', html_text, re.DOTALL)
        cleaned_snippets = []
        for m in matches:
            tag_attrs = m.group(1)
            href = m.group(2)
            content = m.group(3)

            if "result__snippet" in tag_attrs:
                # Extract target URL if routed
                if "uddg=" in href:
                    parsed = urllib.parse.urlparse(href)
                    params = urllib.parse.parse_qs(parsed.query)
                    if "uddg" in params:
                        href = params["uddg"][0]

                clean = re.sub(r"<[^>]+>", "", content)
                clean = html_lib.unescape(clean)
                cleaned_snippets.append(f"{clean.strip()} (Source: {href})")

        return cleaned_snippets[:max_results]
    except Exception as e:
        logger.warning(f"DuckDuckGo search failed for query '{query}': {e}")
        return []


def search_bing(query: str, max_results: int = 5) -> list[str]:
    """Queries Bing search and extracts result snippets and source URLs.

    Args:
        query (str): The search query to run.
        max_results (int): Maximum number of snippets to return.

    Returns:
        list[str]: A list of cleaned snippet strings with source URLs.
    """
    import html as html_lib

    from scanner.util.scraper import get_html

    url = f"https://www.bing.com/search?q={urllib.parse.quote_plus(query)}"
    try:
        logger.debug(f"Executing Bing search: {query}")
        html = get_html(url)

        # Parse Bing results
        blocks = re.findall(r"<li[^>]*?class=\"b_algo\"[^>]*?>.*?</li>", html, re.DOTALL)
        cleaned_snippets = []
        for block in blocks:
            href_m = re.search(r"<h2[^>]*?>\s*<a[^>]*?href=\"([^\"]+)\"", block)
            p_m = re.search(r"<p[^>]*>(.*?)</p>", block, re.DOTALL)
            if href_m and p_m:
                href = href_m.group(1)
                snippet_html = p_m.group(1)
                clean = re.sub(r"<[^>]+>", "", snippet_html)
                clean = html_lib.unescape(clean)
                cleaned_snippets.append(f"{clean.strip()} (Source: {href})")

        if cleaned_snippets:
            return cleaned_snippets[:max_results]

        # Fallback to general paragraph extract if b_algo parsing didn't find anything
        snippets = re.findall(r"<p[^>]*>(.*?)</p>", html, re.DOTALL)
        cleaned_snippets = []
        for s in snippets:
            clean = re.sub(r"<[^>]+>", "", s)
            clean = html_lib.unescape(clean)
            clean = clean.strip()
            if len(clean) > 40 and not any(
                k in clean.lower() for k in ["microsoft", "privacy", "datenschutz", "bedingungen", "feedback"]
            ):
                cleaned_snippets.append(clean)

        return cleaned_snippets[:max_results]
    except Exception as e:
        logger.warning(f"Bing search failed for query '{query}': {e}")
        return []


def calculate_security_score(vulnerabilities: list[dict]) -> float:
    """Computes a security score from 0.0 to 100.0 based on unique vulnerability severities.

    Utilizes an exponential decay model where each unique vulnerability acts as a multiplier penalty:
    Score = 100 * prod_i (1 - w_i)

    Args:
        vulnerabilities (list[dict]): List of vulnerability dictionaries containing "owasp_id",
            "description", and "severity".

    Returns:
        float: Computed security score rounded to one decimal place.
    """
    if not vulnerabilities:
        return 100.0

    # Deduplicate findings by owasp_id and description to prevent double-counting
    unique_vulns = {}
    for v in vulnerabilities:
        key = (v.get("owasp_id"), v.get("description"))
        unique_vulns[key] = v.get("severity", "MEDIUM").upper()

    score = 100.0
    for severity in unique_vulns.values():
        if severity == "CRITICAL":
            w = 0.25
        elif severity == "HIGH":
            w = 0.15
        elif severity == "MEDIUM":
            w = 0.05
        elif severity == "LOW":
            w = 0.02
        else:
            w = 0.05
        score *= 1.0 - w

    return round(score, 1)


def get_security_grade(score: float) -> str:
    """Maps a numerical security score to a letter grade (A, B, C, D, F).

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


def _gather_vulnerability_search_context(vulnerabilities: list[dict], search_func) -> str:
    """Queries threat intelligence for top vulnerabilities found in the static scan.

    Args:
        vulnerabilities (list[dict]): List of vulnerabilities from the scan report.
        search_func (function): Search function to query DuckDuckGo or Bing.

    Returns:
        str: Formatted markdown string containing vulnerability search snippets.
    """
    vuln_results = []
    vuln_count = 0
    for v in vulnerabilities:
        if vuln_count >= 3:
            break
        desc = v.get("description", "")
        cat = v.get("category", "")
        cves = re.findall(r"\bCVE-\d{4}-\d+\b", str(v.get("evidence", [])) + desc)
        if cves:
            for cve in cves:
                if vuln_count >= 3:
                    break
                query = f"{cve} {cat} severity remediation"
                snippets = search_func(query, max_results=5)
                if snippets:
                    vuln_results.append(f"### Search for {cve}:\n" + "\n".join(f"- {s}" for s in snippets))
                    vuln_count += 1
        elif "crypto" in desc.lower() or "ssl" in desc.lower() or "webview" in desc.lower():
            query = f"Android security issue: {desc[:60]}"
            snippets = search_func(query, max_results=5)
            if snippets:
                vuln_results.append(f"### Search for '{desc[:50]}...':\n" + "\n".join(f"- {s}" for s in snippets))
                vuln_count += 1

    return "\n\n".join(vuln_results) if vuln_results else "No vulnerability search context was retrieved."


def _resolve_maven_coordinates(lib: str) -> tuple[str | None, str]:
    """Resolves Maven coordinates (group, artifact) from a library string name.

    Args:
        lib (str): The library name string.

    Returns:
        tuple[str | None, str]: A tuple containing the Maven group (or None) and the artifact name.
    """
    group, artifact = None, lib
    if ":" in lib:
        parts = lib.split(":")
        group, artifact = parts[0], parts[1]
    elif lib.startswith("androidxedparcelable_"):
        group, artifact = "androidx.versionedparcelable", lib.replace("androidxedparcelable_", "")
    elif lib.startswith("com.google.dagger_"):
        group, artifact = "com.google.dagger", lib.replace("com.google.dagger_", "")
    elif lib.startswith("play-services-"):
        group, artifact = "com.google.android.gms", lib
    elif lib.startswith("firebase-"):
        group, artifact = "com.google.firebase", lib
    elif lib == "google-gson":
        group, artifact = "com.google.code.gson", "gson"
    elif lib == "okhttp3":
        group, artifact = "com.squareup.okhttp3", "okhttp"
    return group, artifact


def _query_google_maven(group: str, artifact: str) -> tuple[str | None, str | None]:
    """Queries the Google Maven repository index for the latest version of a package.

    Args:
        group (str): Maven group ID.
        artifact (str): Maven artifact ID.

    Returns:
        tuple[str | None, str | None]: The latest version and repository link, or (None, None) if not found.
    """
    import xml.etree.ElementTree as ET

    if any(
        group.startswith(p) or group == p.rstrip(".")
        for p in ["androidx.", "com.google.android.", "com.google.firebase.", "com.android."]
    ):
        group_path = group.replace(".", "/")
        url = f"https://dl.google.com/dl/android/maven2/{group_path}/group-index.xml"
        try:
            res = requests.get(url, timeout=5.0)
            if res.status_code == 200:
                root = ET.fromstring(res.text)
                elem = root.find(artifact)
                if elem is not None:
                    versions_str = elem.attrib.get("versions", "")
                    if versions_str:
                        latest_ver = versions_str.split(",")[-1].strip()
                        src_link = "https://developer.android.com/jetpack/androidx/versions"
                        return latest_ver, src_link
        except Exception:
            pass
    return None, None


def _query_maven_central(group: str | None, artifact: str) -> tuple[str | None, str | None, str | None]:
    """Queries Maven Central API for package details and latest version.

    Args:
        group (str | None): Maven group ID.
        artifact (str): Maven artifact ID.

    Returns:
        tuple[str | None, str | None, str | None]: Latest version, source link, and resolved group ID.
    """
    latest_ver, src_link, resolved_group = None, None, group
    if group:
        url = f"https://search.maven.org/solrsearch/select?q=g:{group}+AND+a:{artifact}&rows=1&wt=json"
        try:
            res = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=5.0)
            if res.status_code == 200:
                docs = res.json().get("response", {}).get("docs", [])
                if docs:
                    latest_ver = docs[0].get("latestVersion")
                    src_link = f"https://mvnrepository.com/artifact/{group}/{artifact}"
                    return latest_ver, src_link, resolved_group
        except Exception:
            pass

    # Fallback to query by artifact only
    url = f"https://search.maven.org/solrsearch/select?q=a:{artifact}&rows=1&wt=json"
    try:
        res = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=5.0)
        if res.status_code == 200:
            docs = res.json().get("response", {}).get("docs", [])
            if docs:
                latest_ver = docs[0].get("latestVersion")
                found_g = docs[0].get("g")
                resolved_group = found_g
                src_link = f"https://mvnrepository.com/artifact/{found_g}/{artifact}"
    except Exception:
        pass

    return latest_ver, src_link, resolved_group


def _query_osv_dev(group: str, artifact: str, version: str) -> list[dict]:
    """Queries OSV.dev vulnerability database for a specific package version.

    Args:
        group (str): Maven group ID.
        artifact (str): Maven artifact ID.
        version (str): The version of the package.

    Returns:
        list[dict]: List of vulnerabilities returned by OSV.dev, or empty list.
    """
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": f"{group}:{artifact}", "ecosystem": "Maven"}, "version": version}
    try:
        res = requests.post(url, json=payload, timeout=5.0)
        if res.status_code == 200:
            return res.json().get("vulns", [])
    except Exception:
        pass
    return []


def _search_dependency_intel(group: str | None, lib: str, artifact: str, ver: str, current_search_func) -> list[str]:
    """Runs web search query fallback for dependencies and returns search snippets.

    Args:
        group (str | None): Maven group ID.
        lib (str): The original library name.
        artifact (str): Maven artifact ID.
        ver (str): Package version.
        current_search_func (function): The search function to use.

    Returns:
        list[str]: Snippets retrieved from search engine.
    """
    query = f"{group or lib}:{artifact} {ver} android library vulnerability latest version"
    snippets = current_search_func(query, max_results=5)

    # Self-healing rate limit fallback: if ddg fails, try Bing
    if not snippets and current_search_func == search_ddg:
        logger.warning(f"DuckDuckGo search returned empty for '{query}'. Attempting fallback to Bing...")
        snippets = search_bing(query, max_results=5)
    return snippets


def _gather_dependency_search_context(dependencies_data: dict, search_func) -> str:
    """Resolves coordinates, queries APIs, and performs web searches to get dependency info.

    Args:
        dependencies_data (dict): Dependencies dictionary from scan report.
        search_func (function): Search function to use for web fallback.

    Returns:
        str: Formatted markdown containing dependency analysis.
    """
    dep_results = []
    third_party = dependencies_data.get("exact_versions_found", {}).get("third_party", {})

    current_search_func = search_func
    for lib, ver in third_party.items():
        # Resolve Maven coordinates
        group, artifact = _resolve_maven_coordinates(lib)

        # Query repository details programmatically
        latest_ver, src_link = None, None
        if group:
            latest_ver, src_link = _query_google_maven(group, artifact)

        if not latest_ver:
            latest_ver, src_link, group = _query_maven_central(group, artifact)

        # Query OSV.dev vulnerabilities
        osv_vulns = []
        if group:
            osv_vulns = _query_osv_dev(group, artifact, ver)

        # Web search fallback if programmatic lookup fails or vulnerabilities exist
        snippets = []
        if not latest_ver or osv_vulns:
            snippets = _search_dependency_intel(group, lib, artifact, ver, current_search_func)
            if snippets and current_search_func == search_ddg and not any("(Source: " in s for s in snippets):
                current_search_func = search_bing
            time.sleep(0.5)

        # Compile info
        dep_info = []
        if latest_ver:
            dep_info.append(f"Latest version: {latest_ver} (Source: {src_link})")

        if osv_vulns:
            for v in osv_vulns:
                summary = v.get("summary", "Vulnerability found")
                vid = v.get("id")
                dep_info.append(f"Vulnerability: {vid} - {summary} (Source: https://osv.dev/vulnerability/{vid})")

        if snippets:
            for s in snippets:
                if "(Source: " in s:
                    dep_info.append(f"Threat Intel: {s}")

        dep_results.append(f"### Search for {lib}@{ver}:\n" + "\n".join(f"- {item}" for item in dep_info))

    return "\n\n".join(dep_results) if dep_results else "No dependency search context was retrieved."


def _gather_domain_search_context(network_data: dict, search_func) -> str:
    """Queries threat intelligence websites for top domains identified in the application.

    Args:
        network_data (dict): Network audit dictionary from scan report.
        search_func (function): Search function to query DuckDuckGo or Bing.

    Returns:
        str: Formatted markdown containing domain reputation snippets.
    """
    domain_results = []
    other_domains = network_data.get("categorized_domains", {}).get("other", [])
    domain_count = 0
    for domain in other_domains:
        if domain_count >= 2:
            break
        if domain in ["github.com", "google.com", "android.com", "w3.org", "example.com"]:
            continue
        query = f"{domain} threat intelligence reputation"
        snippets = search_func(query, max_results=5)
        if snippets:
            domain_results.append(f"### Search for domain {domain}:\n" + "\n".join(f"- {s}" for s in snippets))
            domain_count += 1

    return "\n\n".join(domain_results) if domain_results else "No domain search context was retrieved."


def gather_web_context(scan_report: dict, search_func=None) -> dict:
    """Extracts libraries, domains, and vulnerabilities to gather web search snippets.

    Args:
        scan_report (dict): The generated static scan report dictionary.
        search_func (function): The search function to use for scraping.

    Returns:
        dict: A dictionary containing compiled search snippets for vulnerabilities, dependencies, and domains.
    """
    if search_func is None:
        search_func = search_ddg

    context = {
        "vulnerabilities": "No vulnerability search context was retrieved.",
        "dependencies": "No dependency search context was retrieved.",
        "domains": "No domain search context was retrieved.",
    }

    # Query search engines for vulnerabilities, dependencies, and domains context
    vulnerabilities = scan_report.get("vulnerabilities", [])
    context["vulnerabilities"] = _gather_vulnerability_search_context(vulnerabilities, search_func)

    dependencies_data = scan_report.get("dependencies", {})
    context["dependencies"] = _gather_dependency_search_context(dependencies_data, search_func)

    network_data = scan_report.get("network", {})
    context["domains"] = _gather_domain_search_context(network_data, search_func)

    return context


def get_app_context(scan_report: dict, search_func, model: str, ollama_url: str) -> str:
    """Queries the web for app details based on metadata and generates a short 2-3 sentence summary.

    Args:
        scan_report (dict): The generated static scan report.
        search_func (function): The search function to query DuckDuckGo or Bing.
        model (str): Name of local Ollama model.
        ollama_url (str): HTTP URL of the local Ollama service.

    Returns:
        str: Generated application context summary in Markdown.
    """
    metadata = scan_report.get("apk_metadata", {})
    package = metadata.get("package", "")
    apk_name = metadata.get("apk_name", "")

    if not package and not apk_name:
        return "Unknown Android application. No information about this application could be found online."

    logger.info(f"Gathering online app metadata for {package}...")
    snippets = []

    # Query online databases and search engines for app context metadata
    play_query = f"site:play.google.com/store/apps/details?id={package}"
    snippets.extend(search_func(play_query, max_results=3))
    time.sleep(0.5)

    dev_query = f'"{package}" developer website documentation'
    snippets.extend(search_func(dev_query, max_results=3))
    time.sleep(0.5)

    status_query = f'"{package}" discontinued replaced shutdown'
    snippets.extend(search_func(status_query, max_results=2))

    # De-duplicate snippets
    seen = set()
    unique_snippets = []
    for s in snippets:
        if s not in seen:
            seen.add(s)
            unique_snippets.append(s)

    if not unique_snippets:
        return f"Android application with package '{package}'. No information about this application could be found online."

    context_text = "\n".join(f"- {s}" for s in unique_snippets)

    prompt = APP_CONTEXT_PROMPT_TEMPLATE.format(package=package, context_text=context_text)

    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "options": {"temperature": 0.2, "num_ctx": 8192, "num_predict": 1024},
    }

    try:
        response = requests.post(f"{ollama_url}/api/chat", json=payload, timeout=300)
        response.raise_for_status()
        summary = response.json().get("message", {}).get("content", "").strip()
        # Clean thinking tag if present (handling unclosed/truncated tags)
        for tag in ["think", "thinking", "thought"]:
            start_tag = f"<{tag}>"
            end_tag = f"</{tag}>"
            if start_tag in summary:
                if end_tag in summary:
                    summary = re.sub(rf"<{tag}>.*?</{tag}>", "", summary, flags=re.DOTALL).strip()
                else:
                    summary = summary.split(start_tag)[0].strip()
        return summary
    except Exception as e:
        logger.warning(f"Failed to generate app context summary: {e}")
        return f"Android application with package '{package}'. No information about this application could be found online."


def deduplicate_findings(content: str, reindex_numbers: bool = True) -> str:
    """Splits the content by level-3 headers (###), and de-duplicates finding blocks based on their heading title.

    Also re-indexes the finding numbers sequentially if they start with a digit (optional).

    Args:
        content (str): The raw report content to deduplicate.
        reindex_numbers (bool): Whether to reindex findings sequentially.

    Returns:
        str: Cleaned, deduplicated markdown content.
    """
    if "###" not in content:
        return content

    # Use negative lookbehind and lookahead to match exactly level-3 headers (###), avoiding level-4 headers (####)
    parts = re.split(r"(?<!\#)###(?!\#)", content)
    header_part = parts[0]

    seen_headings = set()
    deduped_parts = []

    for part in parts[1:]:
        lines = part.splitlines()
        if not lines:
            continue
        heading = lines[0].strip()

        # Strip number from the start of the heading to normalize
        norm_heading = re.sub(r"^\d+\s*[\.\:\-\)]\s*", "", heading).strip().lower()
        if not norm_heading:
            continue

        if norm_heading in seen_headings:
            continue
        seen_headings.add(norm_heading)
        deduped_parts.append(part)

    new_parts = [header_part]
    for idx, part in enumerate(deduped_parts, start=1):
        lines = part.splitlines()
        if not lines:
            continue
        heading = lines[0].strip()
        body = "\n".join(lines[1:])

        # Check if the heading starts with a number
        has_number_match = re.match(r"^(\d+)\s*[\.\:\-\)]\s*(.*)$", heading)
        if reindex_numbers and has_number_match:
            title = has_number_match.group(2).strip()
            new_heading = f"### {idx}. {title}"
        else:
            new_heading = f"### {heading}"

        new_parts.append(f"{new_heading}\n{body}")

    return "".join(new_parts)


def clean_markdown_report(content: str, strip_internal_rules: bool = True, reindex_numbers: bool = True) -> str:
    """Post-processes generated AI report content to comply with markdown lint standards.

    Args:
        content (str): Raw generated markdown content.
        strip_internal_rules (bool): If True, strips any horizontal rules (---) from the content.
        reindex_numbers (bool): If True, re-indexes finding numbers starting from 1.

    Returns:
        str: Sanitized and normalized markdown content.
    """
    # Strip DeepSeek R1/reasoning thinking blocks if present (handling unclosed/truncated tags)
    for tag in ["think", "thinking", "thought"]:
        start_tag = f"<{tag}>"
        end_tag = f"</{tag}>"
        if start_tag in content:
            if end_tag in content:
                content = re.sub(rf"<{tag}>.*?</{tag}>", "", content, flags=re.DOTALL).strip()
            else:
                content = content.split(start_tag)[0].strip()

    # Fix doubled/nested heading symbols (e.g. "#### ### Heading" -> "### Heading")
    content = re.sub(r"^\s*(#+)\s+(#+)\s*(.*)$", r"\2 \3", content, flags=re.MULTILINE)

    if strip_internal_rules:
        # Remove standard conclusion or summary sections/headings generated by LLMs at the end of sections
        content = re.sub(r"^\s*###?\s*Conclusion\b.*$", "", content, flags=re.MULTILINE | re.IGNORECASE | re.DOTALL)

        # Remove internal horizontal rules (---) that the model generated within sections
        content = re.sub(r"^\s*---+\s*$", "", content, flags=re.MULTILINE)

    # Fix nested markdown code block if LLM wrapped the whole thing
    content = content.strip()
    if content.startswith("```markdown"):
        content = content[11:]
    elif content.startswith("```"):
        content = content[3:]
    if content.endswith("```"):
        content = content[:-3]
    content = content.strip()

    # Remove lines containing system instructions or notes about NO_SECURITY_RISKS
    lines = content.splitlines()
    cleaned_lines = []
    for line in lines:
        stripped_line = line.strip().lower()
        if "no_security_risks" in stripped_line:
            # Skip if it looks like the prompt instructions or note
            if any(k in stripped_line for k in ["if no security risks", "note:", "exactly", "guideline", "evaluation"]):
                continue
            # Also skip standalone NO_SECURITY_RISKS when response has multiple lines (leakage)
            if (
                len(lines) > 2
                and stripped_line.replace("`", "").replace("'", "").replace('"', "") == "no_security_risks"
            ):
                continue
        cleaned_lines.append(line)
    content = "\n".join(cleaned_lines)

    # Normalize multiple consecutive blank lines to at most a single blank line
    content = re.sub(r"\n{3,}", "\n\n", content)

    # Ensure headings have a blank line before and after them
    content = re.sub(r"([^\n])\n(#+\s+[^\n]+)", r"\1\n\n\2", content)
    content = re.sub(r"(#+\s+[^\n]+)\n([^\n])", r"\1\n\n\2", content)

    # Normalize again in case we added redundant empty lines
    content = re.sub(r"\n{3,}", "\n\n", content)

    # Ensure all code blocks are closed 100%
    lines = content.splitlines()
    in_code_block = False
    for line in lines:
        if line.strip().startswith("```"):
            in_code_block = not in_code_block
    if in_code_block:
        lines.append("```")
        content = "\n".join(lines)

    # De-duplicate repeated findings & re-index numbers
    content = deduplicate_findings(content, reindex_numbers=reindex_numbers)

    # Ensure a single trailing newline
    content = content.strip() + "\n"
    return content


def _probe_search_status(use_websearch: bool) -> tuple[str, Callable]:
    """Probes search engine connections (DuckDuckGo/Bing) to check availability.

    Args:
        use_websearch (bool): Whether web search is requested.

    Returns:
        tuple[str, Callable]: A tuple of search status name and the search function.
    """
    search_status = "Disabled"
    search_func = search_ddg

    if not use_websearch:
        return search_status, search_func

    logger.info("Probing DuckDuckGo connection...")
    from scanner.util.scraper import get_html

    try:
        html_text = get_html("https://html.duckduckgo.com/")
        if "duckduckgo" in html_text.lower():
            search_status = "Available (DuckDuckGo)"
            search_func = search_ddg
        else:
            raise ValueError("Response does not look like DuckDuckGo")
    except Exception as e_ddg:
        logger.warning(f"DuckDuckGo probe failed: {e_ddg}. Attempting fallback to Bing...")
        try:
            html_text = get_html("https://www.bing.com/")
            if "bing" in html_text.lower() or "b_algo" in html_text or "class=" in html_text:
                search_status = "Available (Fallback to Bing)"
                search_func = search_bing
            else:
                raise ValueError("Response does not look like Bing")
        except Exception as e_bing:
            logger.warning(f"Bing probe failed: {e_bing}. Outgoing search queries are completely blocked.")
            search_status = "Unavailable (Offline / Blocked)"

    return search_status, search_func


def _filter_scan_report(scan_report: dict) -> tuple[dict, dict, dict]:
    """Filters findings from the scan report to only contain security issues.

    Args:
        scan_report (dict): The original static analysis report.

    Returns:
        tuple[dict, dict, dict]: Filtered manifest audit, security checks, and signatures.
    """
    # Filter manifest_audit
    manifest_audit = scan_report.get("manifest_audit", {})
    filtered_manifest = {}
    if manifest_audit:
        sec_flags = manifest_audit.get("security_flags", {})
        filtered_flags = {k: v for k, v in sec_flags.items() if v is True}
        if filtered_flags:
            filtered_manifest["security_flags"] = filtered_flags

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

    # Filter security_checks
    security_checks = scan_report.get("security_checks", {})
    filtered_security_checks = {}
    if security_checks:
        root_detect = security_checks.get("rooted_device_detection", {})
        if root_detect and root_detect.get("detection_missing") is True:
            filtered_security_checks["rooted_device_detection"] = root_detect

        static_analysis = security_checks.get("static_analysis", {})
        filtered_static = {}
        if static_analysis:
            if static_analysis.get("analysis_blocked") is True:
                filtered_static["analysis_blocked"] = True
            if static_analysis.get("packer_detected"):
                filtered_static["packer_detected"] = static_analysis["packer_detected"]
        if filtered_static:
            filtered_security_checks["static_analysis"] = filtered_static

    # Filter signatures
    signatures = scan_report.get("signatures", {})
    filtered_signatures = {}
    if signatures:
        if signatures.get("is_debug_signed") is True:
            filtered_signatures["is_debug_signed"] = True
        if signatures.get("has_weak_hash") is True:
            filtered_signatures["has_weak_hash"] = True
        if signatures.get("split_signatures_aligned") is False:
            filtered_signatures["split_signatures_aligned"] = False
        mismatched = signatures.get("mismatched_splits", [])
        if mismatched:
            filtered_signatures["mismatched_splits"] = mismatched

        if filtered_signatures:
            certs = signatures.get("certificates", [])
            if certs:
                filtered_signatures["certificates"] = certs

    return filtered_manifest, filtered_security_checks, filtered_signatures


def _prepare_sections_config(
    scan_report: dict,
    filtered_manifest: dict,
    filtered_security_checks: dict,
    filtered_signatures: dict,
    web_context_dict: dict,
) -> list[dict]:
    """Assembles the list of sections with their headings, data, guidelines, and templates.

    Args:
        scan_report (dict): The original static analysis report.
        filtered_manifest (dict): Filtered manifest audit dict.
        filtered_security_checks (dict): Filtered security checks dict.
        filtered_signatures (dict): Filtered signatures dict.
        web_context_dict (dict): Web context snippets for RAG.

    Returns:
        list[dict]: Configurations for each report section.
    """
    return [
        {
            "name": "Manifest Audit",
            "heading": "## 1. Manifest Audit",
            "data": filtered_manifest,
            "search_context": "No search context required.",
            "is_list": False,
            "guidelines": MANIFEST_AUDIT_GUIDELINES,
        },
        {
            "name": "Security Capabilities",
            "heading": "## 2. Security Capabilities",
            "data": {
                "security_checks": filtered_security_checks,
                "exported_components": [
                    v
                    for v in scan_report.get("vulnerabilities", [])
                    if v.get("owasp_id") == "M5" and "exported" in v.get("description", "").lower()
                ],
                "custom_scheme_intents": [
                    v for v in scan_report.get("vulnerabilities", []) if v.get("owasp_id") == "M8"
                ],
            },
            "search_context": "No search context required.",
            "is_list": False,
            "guidelines": SECURITY_CHECKS_GUIDELINES,
        },
        {
            "name": "Signatures",
            "heading": "## 3. Signatures",
            "data": filtered_signatures,
            "search_context": "No search context required.",
            "is_list": False,
            "guidelines": SIGNATURES_GUIDELINES,
        },
        {
            "name": "Permissions",
            "heading": "## 4. Permissions",
            "data": scan_report.get("permissions"),
            "search_context": "No search context required.",
            "is_list": True,
            "prompt_template": PERMISSIONS_PROMPT_TEMPLATE,
            "guidelines": "",
        },
        {
            "name": "Dependencies",
            "heading": "## 5. Dependencies",
            "data": scan_report.get("dependencies"),
            "search_context": web_context_dict["dependencies"],
            "is_list": True,
            "prompt_template": DEPENDENCIES_PROMPT_TEMPLATE,
            "guidelines": "",
        },
        {
            "name": "Secrets",
            "heading": "## 6. Secrets",
            "data": scan_report.get("secrets"),
            "search_context": "No search context required.",
            "is_list": False,
            "prompt_template": SECRETS_PROMPT_TEMPLATE,
            "guidelines": "",
        },
        {
            "name": "Bytecode Audit",
            "heading": "## 7. Bytecode Audit",
            "data": scan_report.get("bytecode_audit"),
            "search_context": "No search context required.",
            "is_list": False,
            "guidelines": BYTECODE_AUDIT_GUIDELINES,
        },
        {
            "name": "Network",
            "heading": "## 8. Network",
            "data": scan_report.get("network"),
            "search_context": web_context_dict["domains"],
            "is_list": True,
            "prompt_template": NETWORK_PROMPT_TEMPLATE,
            "guidelines": "",
        },
        {
            "name": "Vulnerabilities",
            "heading": "## 9. Vulnerabilities",
            "data": scan_report.get("vulnerabilities"),
            "search_context": web_context_dict["vulnerabilities"],
            "is_list": False,
            "prompt_template": VULNERABILITIES_PROMPT_TEMPLATE,
            "guidelines": "",
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
        return custom_template.format(
            app_context_summary=app_context_summary,
            data_json=data_json,
            search_context=section["search_context"],
        )
    if section.get("is_list"):
        return LIST_SECTION_PROMPT_TEMPLATE.format(
            section_name=section["name"],
            app_context_summary=app_context_summary,
            data_json=data_json,
            search_context=section["search_context"],
            section_guidelines=section["guidelines"],
        )
    return STANDARD_SECTION_PROMPT_TEMPLATE.format(
        section_name=section["name"],
        app_context_summary=app_context_summary,
        data_json=data_json,
        search_context=section["search_context"],
        section_guidelines=section["guidelines"],
    )


def _execute_ollama_query(prompt: str, model: str, ollama_url: str) -> tuple[str, str]:
    """Posts requests to local Ollama service.

    Args:
        prompt (str): User prompt payload.
        model (str): Name of LLM model.
        ollama_url (str): HTTP URL of the local Ollama service.

    Returns:
        tuple[str, str]: A tuple of response content and thinking content.
    """
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "options": {"temperature": 0.2, "num_ctx": 8192, "num_predict": 4096},
    }

    api_url = f"{ollama_url}/api/chat"
    response = requests.post(api_url, json=payload, timeout=600)
    response.raise_for_status()

    res_data = response.json()
    message_data = res_data.get("message", {})
    return message_data.get("content", "").strip(), message_data.get("thinking", "").strip()


def _process_audit_response(section: dict, response_content: str, thinking_content: str) -> str:
    """Processes, cleans, and sanitizes the LLM audit output response.

    Args:
        section (dict): Configuration for the audited section.
        response_content (str): Raw LLM response content.
        thinking_content (str): Raw LLM thinking content.

    Returns:
        str: Normalized section audit findings in Markdown.
    """
    # Fallback to extract findings from thinking if content is empty (due to length limits)
    if not response_content and thinking_content:
        header_match = re.search(r"^(#+\s+[^\n]+)", thinking_content, re.MULTILINE)
        if header_match:
            start_pos = header_match.start()
            response_content = thinking_content[start_pos:]
            logger.info("Content is empty. Extracted drafted markdown from thinking.")
        else:
            response_content = thinking_content

    # Clean thinking tag and markdown fencing
    cleaned_content = clean_markdown_report(response_content)

    # Check if it is a "no risks" indicator
    norm_content = cleaned_content.lower().replace("`", "").replace("'", "").replace('"', "").strip()
    if norm_content == "no_security_risks" or not norm_content:
        logger.info(f"No security risks identified for section '{section['name']}'. Adding clean section placeholder.")
        return f"{section['heading']}\n\nNo security concerns or vulnerabilities were identified in this section."

    # Strip only top-level (## or #) section headers the LLM may have generated
    lines = cleaned_content.splitlines()
    while lines:
        stripped = lines[0].strip()
        if not stripped or (stripped.startswith("##") and not stripped.startswith("###")):
            lines.pop(0)
        elif stripped.startswith("#") and not stripped.startswith("##"):
            lines.pop(0)
        else:
            break
    cleaned_body = "\n".join(lines).strip()

    if not cleaned_body:
        logger.info(
            f"Section '{section['name']}' body is empty after stripping headers. Adding clean section placeholder."
        )
        return f"{section['heading']}\n\nNo security concerns or vulnerabilities were identified in this section."

    # Prepend our standardized heading
    final_section = f"{section['heading']}\n\n{cleaned_body}"
    return clean_markdown_report(final_section)


def _query_section_audit(section: dict, app_context_summary: str, model: str, ollama_url: str) -> str:
    """Queries local Ollama using the appropriate prompt template to audit a section.

    Args:
        section (dict): Configuration for the section to audit.
        app_context_summary (str): Summarized background context of the app.
        model (str): The local Ollama model to use.
        ollama_url (str): The HTTP URL of the local Ollama service.

    Returns:
        str: Audited section markdown content.
    """
    formatted_prompt = _prepare_audit_prompt(section, app_context_summary)
    start_req_time = time.time()
    try:
        response_content, thinking_content = _execute_ollama_query(formatted_prompt, model, ollama_url)
        elapsed = time.time() - start_req_time
        logger.info(f"Ollama responded successfully in {elapsed:.2f} seconds.")
        return _process_audit_response(section, response_content, thinking_content)

    except requests.exceptions.Timeout:
        logger.error(f"Ollama request timed out after 600 seconds for section '{section['name']}'.")
        return f"{section['heading']}\n\nError: Audit query timed out."
    except requests.exceptions.RequestException as e:
        logger.error(f"Ollama request failed: {e}. Check if Ollama service is running at {ollama_url}.")
        return f"{section['heading']}\n\nError: Ollama query failed ({e})."
    except Exception as e:
        logger.error(f"Unexpected error auditing section '{section['name']}': {e}")
        return f"{section['heading']}\n\nError: Unexpected error during auditing ({e})."


def _format_report_header(
    scan_report: dict,
    security_score: float,
    security_grade: str,
    app_context_summary: str,
    model: str,
    duration_seconds: float,
    search_status: str,
) -> str:
    """Formats the standardized report metadata header.

    Args:
        scan_report (dict): The original static analysis report.
        security_score (float): Calculated numerical score out of 100.
        security_grade (str): Associated letter grade (A, B, C, D, F).
        app_context_summary (str): Summarized background context of the app.
        model (str): Name of LLM model.
        duration_seconds (float): Duration of execution.
        search_status (str): Status of search connection (e.g. Disabled, Available).

    Returns:
        str: Formatted markdown header string.
    """
    apk_metadata = scan_report.get("apk_metadata", {})
    apk_name = apk_metadata.get("apk_name", "Target App")
    app_name = apk_metadata.get("app_name") or apk_name
    if app_name.endswith(".apk"):
        app_name = app_name[:-4]

    package = apk_metadata.get("package", "Unknown")

    # Format size nicely
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

    # Format version nicely
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

    # Date of AI report creation
    from datetime import datetime

    creation_date = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    return (
        f"# Mobile Application Security Assessment Report - {app_name}\n\n"
        f"## Report Details\n"
        f"- **Security Score**: {security_score}/100 (Grade: {security_grade})\n"
        f"- **App Name**: {app_name}\n"
        f"- **Package**: {package}\n"
        f"- **Version**: {version_str}\n"
        f"- **File Size**: {size_str}\n"
        f"- **Date of Creation**: {creation_date}\n"
        f"- **Target File**: {json.dumps(apk_name)}\n"
        f"- **Model Used**: {model}\n"
        f"- **AI Generation Time**: {duration_seconds:.2f} seconds\n"
        f"- **Threat Intelligence Search**: {search_status}\n\n"
        f"## App Description\n"
        f"{app_context_summary}\n\n"
        f"---\n"
    )


def generate_ai_report(
    scan_report: dict,
    model: str = "deepseek-r1:14b",
    ollama_url: str = "http://127.0.0.1:11434",
    use_websearch: bool = True,
) -> str:
    """Generates an AI assessment markdown report of the scanned APK.

    Queries local Ollama using RAG and outputs the assessment.

    Args:
        scan_report (dict): The generated static scan report.
        model (str): The name of the local Ollama model to use.
        ollama_url (str): The HTTP URL of the local Ollama service.
        use_websearch (bool): Set to True to enable DuckDuckGo/Bing web search.

    Returns:
        str: Generated Markdown report.
    """
    start_time = time.time()

    logger.info(f"Generating AI report using model '{model}'...")

    # Probe search engine connection status and capabilities
    search_status, search_func = _probe_search_status(use_websearch)

    web_context_dict = {
        "vulnerabilities": "No vulnerability search context was retrieved.",
        "dependencies": "No dependency search context was retrieved.",
        "domains": "No domain search context was retrieved.",
    }

    if search_status != "Unavailable (Offline / Blocked)" and use_websearch:
        logger.info(f"Gathering web search context via {search_status}...")
        web_context_dict = gather_web_context(scan_report, search_func=search_func)

    # Perform pre-search to build background app details
    metadata_temp = scan_report.get("apk_metadata", {})
    package_temp = metadata_temp.get("package", "unknown")
    app_context_summary = f"Android application with package '{package_temp}'. No information about this application could be found online."
    if search_status != "Unavailable (Offline / Blocked)" and search_status != "Disabled":
        app_context_summary = get_app_context(scan_report, search_func, model, ollama_url)
    logger.info(f"App Context Overview compiled: {app_context_summary}")

    # Remove safe items from raw static findings to focus LLM focus on risks
    filtered_manifest, filtered_security_checks, filtered_signatures = _filter_scan_report(scan_report)

    # Assemble sections configurations
    sections_config = _prepare_sections_config(
        scan_report, filtered_manifest, filtered_security_checks, filtered_signatures, web_context_dict
    )

    # Run queries sequentially against local LLM service for each report section
    generated_sections = []
    total_sections = len(sections_config)
    for idx, section in enumerate(sections_config, start=1):
        progress_prefix = f"[Progress {idx}/{total_sections}]"

        # If the input data is empty, skip calling Ollama completely and append clean placeholder
        if is_data_empty(section["data"]):
            logger.info(
                f"{progress_prefix} No security findings in data for section '{section['name']}'. "
                "Adding clean section placeholder."
            )
            clean_message = (
                f"{section['heading']}\n\nNo security concerns or vulnerabilities were identified in this section."
            )
            generated_sections.append(clean_message)
            continue

        logger.info(f"{progress_prefix} Auditing section '{section['name']}'...")
        section_report = _query_section_audit(section, app_context_summary, model, ollama_url)
        generated_sections.append(section_report)

    # Merge sections and add the requested top-level header banner
    duration_seconds = time.time() - start_time

    vulnerabilities_list = scan_report.get("vulnerabilities", [])
    security_score = calculate_security_score(vulnerabilities_list)
    security_grade = get_security_grade(security_score)

    header = _format_report_header(
        scan_report,
        security_score,
        security_grade,
        app_context_summary,
        model,
        duration_seconds,
        search_status,
    )

    if not generated_sections:
        body = "\n## Security Audit Summary\n\nNo significant security concerns or risks were identified during this automated static analysis.\n"
    else:
        body = "\n\n---\n\n".join(generated_sections)

    final_report = header + "\n" + body
    return clean_markdown_report(final_report, strip_internal_rules=False, reindex_numbers=False)
