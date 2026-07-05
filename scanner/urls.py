# This module scans the DEX file string pool and class annotations
# for HTTP/HTTPS URLs and attributes them to the referencing library context.

import re
from urllib.parse import urlparse, urlunparse
from .rules import SCHEMA_KEYWORDS

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
            if parsed.scheme in ('http', 'https') and parsed.path == '/':
                url_clean = urlunparse(parsed._replace(path=''))
            elif not parsed.scheme and '/' in url_clean:
                if url_clean.endswith('/'):
                    url_clean = url_clean.rstrip('/')
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
    if not pkg_segments:
        return len(clean_cls[0]) <= 2 or OBFUSCATED_SEGMENT.match(clean_cls[0]) is not None
        
    # If all package segments are short or match the obfuscation pattern
    if all(len(p) <= 2 or OBFUSCATED_SEGMENT.match(p) is not None for p in pkg_segments):
        return True
        
    return False

def extract_urls(dx):
    """Extracts URLs from DEX string pools and class annotations.

    Attributes each URL to the package or third-party library context that references it.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Analysis object containing class
            information and strings.

    Returns:
        dict: A mapping of owning package prefixes to sorted lists of attributed URLs.
    """
    attributed_urls = {}
    
    # 1. Scan String Pool for URLs
    for string_val in dx.get_strings():
        val = string_val.get_value()
        
        # If there is no '/' in the string, it cannot be a URL or path. Skip.
        if "/" not in val:
            continue
            
        matches = HTTP_REGEX.findall(val) + PATH_REGEX.findall(val)
        if not matches:
            continue
            
        unique_matches = set(matches)
        xrefs = string_val.get_xref_from()
        owners = set()
        
        if xrefs:
            for xref in xrefs:
                try:
                    class_anal = xref[0]
                    class_name = class_anal.name
                    
                    # Convert Lcom/example/Test; structure into package syntax (com.example.Test)
                    clean_cls_raw = class_name[1:].rstrip(';').split('/')
                    clean_cls = []
                    for p in clean_cls_raw:
                        clean_cls.extend(p.split('$'))
                    
                    if _is_obfuscated_package(clean_cls):
                        pkg = "obfuscated.classes"
                    elif len(clean_cls_raw) >= 3:
                        pkg = f"{clean_cls_raw[0]}.{clean_cls_raw[1]}.{clean_cls_raw[2]}"
                    elif len(clean_cls_raw) == 2:
                        pkg = f"{clean_cls_raw[0]}.{clean_cls_raw[1]}"
                    else:
                        pkg = "app.internal"
                        
                    owners.add(pkg)
                except Exception:
                    owners.add("unresolved.context")
        else:
            owners.add("unreferenced.static_pool")

        # Clean, filter and deduplicate schemeless matches
        cleaned_matches = []
        for url in unique_matches:
            url_clean = _clean_and_filter_url(url)
            if url_clean:
                cleaned_matches.append(url_clean)
                
        final_matches = set()
        for m in cleaned_matches:
            is_duplicate = False
            if not m.startswith(('http://', 'https://')):
                for other in cleaned_matches:
                    if other.startswith(('http://', 'https://')) and other.endswith(m):
                        is_duplicate = True
                        break
            if not is_duplicate:
                final_matches.add(m)

        for url_clean in final_matches:
            for owner in owners:
                if owner not in attributed_urls:
                    attributed_urls[owner] = set()
                attributed_urls[owner].add(url_clean)
           
    # 2. Scan Class Annotations (common in Retrofit endpoints or modern HTTP libraries)
    for cls in dx.get_classes():
        if cls.is_external() or not hasattr(cls, 'get_vm_class'):
            continue
            
        vm_class = cls.get_vm_class()
        if not vm_class:
            continue
            
        try:
            annotations = vm_class.get_annotations()
            if not annotations:
                continue
                
            class_name = cls.name
            clean_cls_raw = class_name[1:].rstrip(';').split('/')
            clean_cls = []
            for p in clean_cls_raw:
                clean_cls.extend(p.split('$'))
                
            if _is_obfuscated_package(clean_cls):
                pkg = "obfuscated.classes"
            elif len(clean_cls_raw) >= 3:
                pkg = f"{clean_cls_raw[0]}.{clean_cls_raw[1]}.{clean_cls_raw[2]}"
            else:
                pkg = "app.internal"
                
            ann_string = str(annotations)
            matches = HTTP_REGEX.findall(ann_string) + PATH_REGEX.findall(ann_string)
            
            if matches:
                cleaned_matches = []
                for url in set(matches):
                    url_clean = _clean_and_filter_url(url)
                    if url_clean:
                        cleaned_matches.append(url_clean)
                
                final_matches = set()
                for m in cleaned_matches:
                    is_duplicate = False
                    if not m.startswith(('http://', 'https://')):
                        for other in cleaned_matches:
                            if other.startswith(('http://', 'https://')) and other.endswith(m):
                                is_duplicate = True
                                break
                    if not is_duplicate:
                        final_matches.add(m)

                for url_clean in final_matches:
                    if pkg not in attributed_urls:
                        attributed_urls[pkg] = set()
                    attributed_urls[pkg].add(url_clean)
        except Exception:
            continue

    return {owner: sorted(urls) for owner, urls in attributed_urls.items()}