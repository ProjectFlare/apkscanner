# This module scans the DEX file string pool and class annotations
# for HTTP/HTTPS URLs and attributes them to the referencing library context.

import re

# Pre-compile the URL regex patterns outside the extraction loops to maximize execution speed.
HTTP_REGEX = re.compile(r"https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s\"'>]*)?")
PATH_REGEX = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|de|co|us|uk|app|dev)(?::\d+)?/[^\s\"'>]+\b")

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
                    clean_cls = class_name[1:].rstrip(';').split('/')
                    
                    if len(clean_cls) >= 3:
                        pkg = f"{clean_cls[0]}.{clean_cls[1]}.{clean_cls[2]}"
                    elif len(clean_cls) == 2:
                        pkg = f"{clean_cls[0]}.{clean_cls[1]}"
                    else:
                        pkg = "app.internal"
                        
                    owners.add(pkg)
                except Exception:
                    owners.add("unresolved.context")
        else:
            owners.add("unreferenced.static_pool")

        for url in unique_matches:
            for owner in owners:
                if owner not in attributed_urls:
                    attributed_urls[owner] = set()
                attributed_urls[owner].add(url)
           
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
            clean_cls = class_name[1:].rstrip(';').split('/')
            if len(clean_cls) >= 3:
                pkg = f"{clean_cls[0]}.{clean_cls[1]}.{clean_cls[2]}"
            else:
                pkg = "app.internal"
                
            ann_string = str(annotations)
            matches = HTTP_REGEX.findall(ann_string) + PATH_REGEX.findall(ann_string)
            
            if matches:
                for url in set(matches):
                    if pkg not in attributed_urls:
                        attributed_urls[pkg] = set()
                    attributed_urls[pkg].add(url)
        except Exception:
            continue

    return {owner: sorted(urls) for owner, urls in attributed_urls.items()}