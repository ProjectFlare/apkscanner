"""Module for scanning the DEX file string pool and class annotations for HTTP/HTTPS URLs.

Attributes extracted URLs to their referencing library or application context.
"""

import re
from urllib.parse import urlparse, urlunparse

from scanner.util.rules import SCHEMA_KEYWORDS

# Pre-compile the URL regex patterns outside the extraction loops to maximize execution speed.
HTTP_REGEX = re.compile(r"https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s\"'>]*)?")
PATH_REGEX = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|de|co|us|uk|app|dev)(?::\d+)?/[^\s\"'>]+\b")


def _clean_and_filter_url(url):
    """Cleans control chars/null bytes from URLs and filters out schema/docs.

    Args:
        url (str): The raw URL string.

    Returns:
        str | None: Cleaned URL, or None if it should be skipped.
    """
    url_clean = url.strip().strip("\u0000").rstrip("#")

    # Exclude standard boilerplate namespaces and generic developer documentation links
    if any(k in url_clean for k in SCHEMA_KEYWORDS):
        return None

    # Normalize host-only URLs by removing the trailing slash
    if url_clean:
        try:
            parsed = urlparse(url_clean)
            if parsed.scheme in ("http", "https") and parsed.path == "/":
                url_clean = urlunparse(parsed._replace(path=""))
        except Exception:
            pass

    return url_clean if url_clean else None


OBFUSCATED_SEGMENT = re.compile(r"^[a-zA-Z]\d*$|^[a-zA-Z]\d+$")


def _is_obfuscated_package(clean_cls):
    """Checks if a package path segments list looks obfuscated by R8/Proguard.

    Args:
        clean_cls (list[str]): List of package path segments.

    Returns:
        bool: True if obfuscated, False otherwise.
    """
    if len(clean_cls) <= 1:
        return False

    pkg_segments = clean_cls[:-1]

    # If all package segments are short or match the obfuscation pattern
    if all(len(p) <= 2 or OBFUSCATED_SEGMENT.match(p) is not None for p in pkg_segments):
        return True

    return False


def _get_package_context(class_name: str) -> str:
    """Determines the package context string for a given DEX class name.

    Converts class structures like 'Lcom/example/Test;' to 'com.example.Test' package format,
    handling R8/Proguard obfuscation and fallback defaults.

    Args:
        class_name: The class name in DEX format (e.g., 'Lcom/example/Test;').

    Returns:
        The resolved package namespace or generic key (e.g., 'com.example.app').
    """
    clean_cls_raw = class_name[1:].rstrip(";").split("/")
    clean_cls = []
    for p in clean_cls_raw:
        clean_cls.extend(p.split("$"))

    if _is_obfuscated_package(clean_cls):
        return "obfuscated.classes"
    elif len(clean_cls_raw) >= 3:
        return f"{clean_cls_raw[0]}.{clean_cls_raw[1]}.{clean_cls_raw[2]}"
    elif len(clean_cls_raw) == 2:
        return f"{clean_cls_raw[0]}.{clean_cls_raw[1]}"
    else:
        return "app.internal"


def _filter_and_deduplicate_urls(matches: list[str]) -> set[str]:
    """Cleans, filters, and deduplicates extracted URLs.

    It removes duplicate schemeless matches if a corresponding schema-prefixed
    match exists (e.g. keeps 'https://example.com' and removes 'example.com').

    Args:
        matches: A list of raw URL strings.

    Returns:
        A set of cleaned, non-duplicate URL strings.
    """
    cleaned_matches = []
    for url in set(matches):
        url_clean = _clean_and_filter_url(url)
        if url_clean:
            cleaned_matches.append(url_clean)

    final_matches = set()
    for m in cleaned_matches:
        is_duplicate = False
        if not m.startswith(("http://", "https://")):
            for other in cleaned_matches:
                if other.startswith(("http://", "https://")) and other.endswith(m):
                    is_duplicate = True
                    break
        if not is_duplicate:
            final_matches.add(m)
    return final_matches


def _scan_string_pool(dx, attributed_urls: dict[str, set[str]]) -> None:
    """Scans the DEX string pool for HTTP/HTTPS URLs and attributes them to owners.

    Args:
        dx: Analysis object containing class information and strings.
        attributed_urls: Dictionary mapping owners to their set of attributed URLs.
    """
    for string_val in dx.get_strings():
        val = string_val.get_value()

        # If there is no '/' in the string, it cannot be a URL or path. Skip.
        if "/" not in val:
            continue

        matches = HTTP_REGEX.findall(val) + PATH_REGEX.findall(val)
        if not matches:
            continue

        xrefs = string_val.get_xref_from()
        owners = set()

        if xrefs:
            for xref in xrefs:
                try:
                    class_anal = xref[0]
                    pkg = _get_package_context(class_anal.name)
                    owners.add(pkg)
                except Exception:
                    owners.add("unresolved.context")
        else:
            owners.add("unreferenced.static_pool")

        final_matches = _filter_and_deduplicate_urls(matches)

        for url_clean in final_matches:
            for owner in owners:
                if owner not in attributed_urls:
                    attributed_urls[owner] = set()
                attributed_urls[owner].add(url_clean)


def _scan_class_annotations(dx, attributed_urls: dict[str, set[str]]) -> None:
    """Scans class annotations for URLs (common in Retrofit endpoints or HTTP libraries).

    Args:
        dx: Analysis object containing class information and strings.
        attributed_urls: Dictionary mapping owners to their set of attributed URLs.
    """
    for cls in dx.get_classes():
        if cls.is_external() or not hasattr(cls, "get_vm_class"):
            continue

        vm_class = cls.get_vm_class()
        if not vm_class:
            continue

        try:
            annotations = vm_class.get_annotations()
            if not annotations:
                continue

            pkg = _get_package_context(cls.name)
            ann_string = str(annotations)
            matches = HTTP_REGEX.findall(ann_string) + PATH_REGEX.findall(ann_string)

            if matches:
                final_matches = _filter_and_deduplicate_urls(matches)
                for url_clean in final_matches:
                    if pkg not in attributed_urls:
                        attributed_urls[pkg] = set()
                    attributed_urls[pkg].add(url_clean)
        except Exception:
            continue


def extract_urls(dx):
    """Extracts URLs from DEX string pools and class annotations.

    Attributes each URL to the package or third-party library context that references it.

    Args:
        dx: Analysis object containing class information and strings.

    Returns:
        dict[str, list[str]]: A mapping of owning package prefixes to sorted lists of
        attributed URLs.
    """
    attributed_urls = {}
    _scan_string_pool(dx, attributed_urls)
    _scan_class_annotations(dx, attributed_urls)
    return {owner: sorted(urls) for owner, urls in attributed_urls.items()}
