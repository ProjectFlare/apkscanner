# This module extracts third-party external libraries and their version details
# from compile-time classes inside the DEX bytecode and packaging metadata.

import re

from packaging.version import InvalidVersion, parse as parse_version

# Regexp to match obfuscated submodules (e.g. single character or a letter followed by digits)
OBFUSCATED_SUBMODULE = re.compile(r"^[a-zA-Z]\d+$|^[a-zA-Z]$")

# Pre-compiled regex patterns to extract versions of popular custom libraries from DEX strings
VERSION_PATTERNS = [
    # name/version (e.g. okhttp/4.12.0 or datatransport/3.3.0)
    re.compile(r"\b(okhttp|retrofit|ktor|datatransport|jackson|gson)/(\d+\.\d+\.\d+[-a-z\d\.]*)", re.IGNORECASE),
    # name:version (e.g. firebase-sessions:1.1.0)
    re.compile(r"\b(firebase-[a-z\d_\-\.]+):(\d+\.\d+\.\d+)", re.IGNORECASE),
    # Name (version) (e.g. Mixpanel (8.0.2) or GSON (2.11.0))
    re.compile(r"\b(mixpanel|gson)\s*\(?(\d+\.\d+\.\d+)\)?", re.IGNORECASE),
    # SDK/version (e.g. Crashlytics Android SDK/19.4.1)
    re.compile(r"\b(Crashlytics Android SDK)/(\d+\.\d+\.\d+)", re.IGNORECASE),
    # Maven coordinate @@ version
    re.compile(r"\b([a-zA-Z0-9_\-\.]+:[a-zA-Z0-9_\-\.]+)@@(\d+\.\d+\.\d+)")
]

NAME_MAPPINGS = {
    "okhttp": "okhttp3",
    "retrofit": "retrofit2",
    "ktor": "ktor-client",
    "datatransport": "google-datatransport",
    "gson": "google-gson",
    "crashlytics android sdk": "firebase-crashlytics-sdk",
    "mixpanel": "mixpanel-android"
}

def _is_newer_version(new_ver: str, old_ver: str) -> bool:
    """Safely compares two version strings to determine if new_ver is newer than old_ver.

    Uses packaging.version if available and falls back to a custom numeric tuple comparison
    if parsing fails or throws InvalidVersion.
    """
    try:
        return parse_version(new_ver) > parse_version(old_ver)
    except InvalidVersion:
        def version_key(v):
            parts = []
            for part in re.split(r'[-.]', v):
                if part.isdigit():
                    parts.append((0, int(part)))
                else:
                    parts.append((1, part))
            return parts
        try:
            return version_key(new_ver) > version_key(old_ver)
        except TypeError:
            return new_ver > old_ver

def extract_dependencies(apk, dx):
    """Scans compile-time classes and META-INF to detect third-party library dependencies.

    Inspects all class namespaces, ignoring standard Android/Kotlin SDK modules,
    and extracts library versions from packaging property files or the DEX string pool.

    Args:
        apk (androguard.core.apk.APK): The parsed APK object.
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.

    Returns:
        dict: A dictionary containing:
            - external_libraries (dict): Map of root library package to its submodules.
            - exact_versions_found (dict): Classified library version mappings (system vs third_party).
    """
    raw_packages = set()
    
    # Namespaces to skip to avoid reporting basic system or runtime boilerplate libraries
    ignore_prefixes = (
        "Landroid/", "Landroidx/", "Ljava/", "Ljavax/", "Lkotlin/", 
        "Lkotlinx/", "Ldalvik/", "Llibcore/", "Lsun/", "Lorg/apache/", 
        "Lorg/xml/", "Lorg/w3c/", "Lorg/json/", "Lorg/intellij/", "Lorg/jetbrains/"
    )
    
    # Extract only unique package path substrings to avoid processing 
    # redundant class strings in large multidex packages
    for cls in dx.get_classes():
        name = cls.name
        if name.startswith("L") and not name.startswith(ignore_prefixes):
            last_slash = name.rfind('/')
            if last_slash > 1:
                pkg_path = name[1:last_slash]
                raw_packages.add(pkg_path)

    packages = set()
    for pkg_path in raw_packages:
        clean_name = pkg_path.replace('/', '.')
        parts = clean_name.split(".")
        
        if len(parts) >= 2:
            # Skip if package segments are heavily compressed via R8 or Proguard obfuscation (e.g. La.b.c)
            if len(parts[0]) <= 2 and len(parts[1]) <= 2:
                continue
                
            # Skip segments containing obfuscated non-alphanumeric characters
            if any(not p.isalnum() and '_' not in p for p in parts[:2]):
                continue

            packages.add(clean_name)

    grouped_deps = {}
    
    # Common TLDs ignored as grouping root names
    tlds = {"com", "org", "net", "io", "de", "co", "us", "uk", "app", "dev", "gov", "edu", "info"}

    # Group submodules under library roots (e.g., com.google.gson -> com.google: gson)
    for pkg in sorted(packages):
        parts = pkg.split(".")
        root_key = pkg
        sub_module = "core"
        
        for i, part in enumerate(parts):
            if part in tlds:
                continue
            else:
                root_key = ".".join(parts[:i+1])
                
                if i + 1 < len(parts):
                    sub_module = parts[i+1]
                break
                
        # Filter out obfuscated sub-modules (e.g. single characters or letter + digit combinations)
        if OBFUSCATED_SUBMODULE.match(sub_module):
            sub_module = "core"
                
        if root_key not in grouped_deps:
            grouped_deps[root_key] = set()
        grouped_deps[root_key].add(sub_module)
        
    grouped_deps = {k: sorted(v) for k, v in grouped_deps.items()}

    versions = {}
    # Iterate through build metadata files packaged inside META-INF/ directory to extract versions
    for filename in apk.get_files():
        if filename.startswith("META-INF/") and filename.endswith("pom.properties"):
            try:
                data = apk.get_file(filename).decode('utf-8', errors='ignore')
                for line in data.splitlines():
                    if line.startswith("version="):
                        version = line.split("=")[1].strip()
                        parts = filename.split("/")
                        if len(parts) >= 4:
                            versions[f"{parts[2]}:{parts[3]}"] = version
            except Exception:
                pass
        # Read androidx/jetpack version descriptors
        elif filename.startswith("META-INF/") and filename.endswith(".version"):
            try:
                lib_name = filename.split("/")[-1].replace(".version", "")
                data = apk.get_file(filename).decode('utf-8', errors='ignore').strip()
                if data:
                    versions[lib_name] = data
            except Exception:
                pass
                
    for string_val in dx.get_strings():
        val = string_val.get_value()
        for pat in VERSION_PATTERNS:
            match = pat.search(val)
            if match:
                raw_name = match.group(1).lower()
                version_str = match.group(2)
                mapped_name = NAME_MAPPINGS.get(raw_name, raw_name)
                if mapped_name in versions:
                    if _is_newer_version(version_str, versions[mapped_name]):
                        versions[mapped_name] = version_str
                else:
                    versions[mapped_name] = version_str

    # Resolve anonymous version files based on class pool footprint
    class_names = {cls.name for cls in dx.get_classes()}
    if "library" in versions:
        if any("Lcom/yubico/yubikit" in name for name in class_names):
            versions["yubikit"] = versions.pop("library")

    # Classify exact versions into system and third_party sections
    system_prefixes = (
        "androidx.", "com.google.android.", "kotlinx_coroutines", 
        "android.", "com.android."
    )
    
    classified_versions = {
        "system": {},
        "third_party": {}
    }
    
    for lib_name, version in versions.items():
        # Exclude placeholders and unconfirmed indicators
        if not version or "unconfirmed" in version or "unreferenced" in version or "property 'version'" in version:
            continue
            
        if lib_name.startswith(system_prefixes):
            classified_versions["system"][lib_name] = version
        else:
            classified_versions["third_party"][lib_name] = version

    return {
        "external_libraries": grouped_deps,
        "exact_versions_found": classified_versions
    }