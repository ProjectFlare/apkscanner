"""Module for extracting third-party external libraries and their version details.

Analyzes compile-time classes inside the DEX bytecode and packaging metadata to identify
third-party library dependencies, group them under their root package names, and resolve
exact version strings from META-INF property files and the DEX string pool.
"""

import re
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from loguru import logger
from packaging.version import InvalidVersion
from packaging.version import parse as parse_version

from scanner.util.rules import MAVEN_MAPPING, MAVEN_PREFIXES, OBFUSCATED_SUBMODULE, VERSION_PATTERNS

# Precompiled regex patterns for version splitting and name tokenization
_VERSION_SPLIT_RE = re.compile(r"[-.]")
_TOKEN_SPLIT_RE = re.compile(r"[.:_-]")

# Common top-level domains skipped when determining the library root key
_TLDS = {"com", "org", "net", "io", "de", "co", "us", "uk", "app", "dev", "gov", "edu", "info"}

# Prefixes that identify system / SDK DEX namespaces excluded from third-party reporting
_SYSTEM_DEX_PREFIXES: tuple[str, ...] = (
    "Landroid/",
    "Landroidx/",
    "Ljava/",
    "Ljavax/",
    "Lkotlin/",
    "Lkotlinx/",
    "Ldalvik/",
    "Llibcore/",
    "Lsun/",
    "Lorg/apache/",
    "Lorg/xml/",
    "Lorg/w3c/",
    "Lorg/json/",
    "Lorg/intellij/",
    "Lorg/jetbrains/",
)

# Version string prefixes that identify system / Google platform libraries
_SYSTEM_VERSION_PREFIXES: tuple[str, ...] = (
    "androidx.",
    "com.google.android.",
    "kotlinx_coroutines",
    "android.",
    "com.android.",
)

# Maven groups that constitute the Google Play/Firebase/ML Kit/Play Core SDK ecosystem.
# A full coordinate under one of these groups (e.g. from a META-INF pom.properties file)
# is classified as google_sdk regardless of how it was extracted, so the same artifact
# never shows up twice under two spellings in different buckets.
_GOOGLE_SDK_GROUPS: frozenset[str] = frozenset(
    {
        "com.google.android.gms",
        "com.google.firebase",
        "com.google.mlkit",
        "com.google.android.play",
        "com.google.android.datatransport",
        "com.google.android.odml",
        "com.google.android.ump",
        "com.android.billingclient",
    }
)

# Bare artifact names too generic to attribute from the name alone (e.g. "common", "image").
# They are only mapped to their verified Google coordinates when the .properties file carries
# Google's "client=" fingerprint; otherwise they fall through to the "independent" bucket.
_GOOGLE_FINGERPRINT_COORDINATES: dict[str, str] = {
    "common": "com.google.mlkit:common",
    "core-common": "com.google.android.play:core-common",
    "image": "com.google.android.odml:image",
}


def _is_google_group(group: str) -> bool:
    """Whether a Maven group belongs to the Google SDK ecosystem.

    Args:
        group (str): A lowercase Maven group ID.

    Returns:
        bool: True for known Google SDK groups.
    """
    return group in _GOOGLE_SDK_GROUPS or group.startswith("com.google.android.libraries.")


def _google_sdk_coordinate(lib_name: str) -> str | None:
    """Resolves a library key to its Google SDK Maven coordinate, or None when not Google.

    Resolution delegates to the canonical tables in :mod:`scanner.util.rules`
    (``MAVEN_MAPPING`` exact names, ``MAVEN_PREFIXES`` artifact families) so the scan and
    the OSV vulnerability lookup agree on one coordinate per artifact. A full coordinate
    input is accepted as-is when its group is a Google SDK group.

    Args:
        lib_name (str): A library key — a bare artifact name or ``group:artifact`` form.

    Returns:
        str | None: The full Google SDK coordinate, the unchanged name for Google
            artifacts without a verified coordinate (e.g. "crashlytics android sdk" DEX
            strings not present in the mapping), or ``None`` for non-Google libraries.
    """
    lower = lib_name.lower()
    if ":" in lower:
        return lib_name if _is_google_group(lower.split(":", 1)[0]) else None
    mapped = MAVEN_MAPPING.get(lower)
    if mapped and _is_google_group(mapped.split(":", 1)[0]):
        return mapped
    for prefix, group in MAVEN_PREFIXES.items():
        if lower.startswith(prefix):
            return f"{group}:{lower}"
    if "crashlytics" in lower:
        return lib_name
    return None


def _version_key(v: str) -> list[tuple[int, int | str]]:
    """Converts a version string into a comparable list of (kind, value) tuples.

    Each segment of the version string is turned into a tuple where numeric
    segments get kind ``0`` (so they sort before non-numeric ones) and string
    segments get kind ``1``.  This allows mixed versions such as ``1.10-beta``
    to be ordered correctly.

    Args:
        v (str): A version string, e.g. ``"1.10-beta"`` or ``"3.0.0"``.

    Returns:
        list[tuple[int, int | str]]: Comparable representation of the version.
    """
    parts: list[tuple[int, int | str]] = []
    for segment in _VERSION_SPLIT_RE.split(v):
        if segment.isdigit():
            parts.append((0, int(segment)))
        else:
            parts.append((1, segment))
    return parts


def _is_newer_version(new_ver: str, old_ver: str) -> bool:
    """Safely compares two version strings and returns ``True`` if *new_ver* is newer.

    Tries ``packaging.version`` first and falls back to :func:`_version_key`
    tuple comparison when the version string is non-PEP 440 compliant.

    Args:
        new_ver (str): The candidate version string.
        old_ver (str): The baseline version string.

    Returns:
        bool: ``True`` if *new_ver* is strictly greater than *old_ver*.
    """
    try:
        return parse_version(new_ver) > parse_version(old_ver)
    except InvalidVersion:
        # The (kind, value) encoding keeps int-int and str-str comparisons type-safe.
        return _version_key(new_ver) > _version_key(old_ver)


def _resolve_app_package(apk_list: Sequence) -> str | None:
    """Returns the base package name of the first APK that reports one.

    Args:
        apk_list (Sequence): One or more parsed APK objects.

    Returns:
        str | None: The package name string, or ``None`` if unavailable.
    """
    for apk_obj in apk_list:
        try:
            pkg = apk_obj.get_package()
            if pkg and isinstance(pkg, str):
                return pkg
        except Exception:
            pass
    return None


def _build_ignore_prefixes(package_name: str | None) -> tuple[str, ...]:
    """Builds a tuple of DEX namespace prefixes to exclude from analysis.

    Always excludes standard Android / Kotlin / Java SDK namespaces.  When
    *package_name* is provided the app's own package (and up to its first two
    or three dot-separated segments) is added so that app-internal classes are
    not reported as third-party libraries.

    Args:
        package_name (str | None): The app's base package name, e.g. ``"com.example.app"``.

    Returns:
        tuple[str, ...]: Prefix strings in DEX notation (e.g. ``"Lcom/example/"``).
    """
    prefixes: list[str] = list(_SYSTEM_DEX_PREFIXES)
    if package_name:
        prefixes.append("L" + package_name.replace(".", "/") + "/")
        parts = package_name.split(".")
        if len(parts) >= 3:
            prefixes.append("L" + "/".join(parts[:3]) + "/")
        elif len(parts) >= 2:
            prefixes.append("L" + "/".join(parts[:2]) + "/")
    return tuple(prefixes)


def _collect_raw_packages(dx: Any, ignore_prefixes: tuple[str, ...]) -> set[str]:
    """Gathers unique, non-obfuscated package path strings from the DEX class pool.

    Only classes actually defined in the APK's own DEX files are considered
    (``get_internal_classes()``): externally referenced classes (platform APIs like
    ``org.xmlpull``) are merely mentioned by the bytecode, not bundled, and would
    otherwise be reported as phantom third-party dependencies. Packages where the
    first two segments are two characters or fewer (R8/ProGuard minification) or
    contain non-alphanumeric characters are dropped.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
        ignore_prefixes (tuple[str, ...]): DEX namespace prefixes to skip.

    Returns:
        set[str]: Dot-separated package names, e.g. ``{"com.google.gson.internal"}``.
    """
    raw_packages: set[str] = set()
    for cls in dx.get_internal_classes():
        name = cls.name
        if name.startswith("L") and not name.startswith(ignore_prefixes):
            last_slash = name.rfind("/")
            if last_slash > 1:
                raw_packages.add(name[1:last_slash])

    packages: set[str] = set()
    for pkg_path in raw_packages:
        clean_name = pkg_path.replace("/", ".")
        parts = clean_name.split(".")
        if len(parts) < 2:
            continue
        # Skip packages where both leading segments are heavily minified by R8/ProGuard
        if len(parts[0]) <= 2 and len(parts[1]) <= 2:
            continue
        # Skip if leading segments contain non-alphanumeric characters (obfuscation artifact)
        if any(not p.isalnum() and "_" not in p for p in parts[:2]):
            continue
        packages.add(clean_name)

    return packages


def _group_packages(packages: set[str]) -> dict[str, list[str]]:
    """Groups dot-separated package names under a common library root key.

    The first meaningful (non-TLD) segment of a package path becomes the root
    key.  The segment immediately following is recorded as a sub-module name,
    defaulting to ``"core"`` when absent or when it matches the obfuscated
    sub-module pattern.

    Example::

        "com.google.gson.internal"  ->  root="com.google",  sub_module="gson"
        "org.jsoup"                 ->  root="org.jsoup",   sub_module="core"

    Args:
        packages (set[str]): Dot-separated package name strings.

    Returns:
        dict[str, list[str]]: Mapping from root key to sorted list of sub-module names.
    """
    grouped: dict[str, set[str]] = {}
    for pkg in sorted(packages):
        parts = pkg.split(".")
        root_key = pkg
        sub_module = "core"

        for i, part in enumerate(parts):
            if part in _TLDS:
                continue
            root_key = ".".join(parts[: i + 1])
            if i + 1 < len(parts):
                sub_module = parts[i + 1]
            break

        # Replace obfuscated sub-module names with the generic "core" label
        if OBFUSCATED_SUBMODULE.match(sub_module):
            sub_module = "core"

        grouped.setdefault(root_key, set()).add(sub_module)

    return {k: sorted(v) for k, v in grouped.items()}


def _extract_versions_from_metadata(apk_list: Sequence[Any]) -> dict[str, str]:
    """Reads library version strings from META-INF and asset property files.

    Three file types are handled:

    * ``META-INF/.../pom.properties`` - Maven build descriptors (``groupId:artifactId`` key).
    * ``META-INF/.../*.version``      - AndroidX / Jetpack single-line version files.
    * ``*.properties`` (non META-INF) - General property files, e.g. ``play-services-*.properties``.

    Args:
        apk_list (Sequence[Any]): One or more parsed APK objects.

    Returns:
        dict[str, str]: Mapping from library name / coordinate to its version string.
    """
    versions: dict[str, str] = {}
    for apk_obj in apk_list:
        for filename in apk_obj.get_files():
            if filename.startswith("META-INF/") and filename.endswith("pom.properties"):
                _parse_pom_properties(apk_obj, filename, versions)
            elif filename.startswith("META-INF/") and filename.endswith(".version"):
                _parse_version_file(apk_obj, filename, versions)
            elif filename.endswith(".properties") and not filename.startswith("META-INF/"):
                _parse_general_properties(apk_obj, filename, versions)
    return versions


def _parse_pom_properties(apk_obj: Any, filename: str, versions: dict[str, str]) -> None:
    """Extracts the version from a Maven ``pom.properties`` file in META-INF.

    The library key is derived from the directory structure:
    ``META-INF/maven/<groupId>/<artifactId>/pom.properties`` -> ``"groupId:artifactId"``.

    Args:
        apk_obj: A parsed APK object exposing ``get_file()``.
        filename (str): Path of the file inside the APK archive.
        versions (dict[str, str]): Mutable mapping updated in place.
    """
    try:
        data = apk_obj.get_file(filename).decode("utf-8", errors="ignore")
        for line in data.splitlines():
            if line.startswith("version="):
                version = line.split("=")[1].strip()
                path_parts = filename.split("/")
                if len(path_parts) >= 4:
                    versions[f"{path_parts[2]}:{path_parts[3]}"] = version
                break
    except Exception:
        pass


def _parse_version_file(apk_obj: Any, filename: str, versions: dict[str, str]) -> None:
    """Reads a single-line AndroidX / Jetpack ``.version`` file from META-INF.

    The library name is the filename stem (without the ``.version`` extension).

    Args:
        apk_obj: A parsed APK object exposing ``get_file()``.
        filename (str): Path of the file inside the APK archive.
        versions (dict[str, str]): Mutable mapping updated in place.
    """
    try:
        # removesuffix (not replace) so names containing ".version" elsewhere, such as
        # "androidx.versionedparcelable_versionedparcelable.version", are not mangled.
        lib_name = filename.split("/")[-1].removesuffix(".version")
        data = apk_obj.get_file(filename).decode("utf-8", errors="ignore").strip()
        if data:
            versions[lib_name] = data
    except Exception:
        pass


def _parse_general_properties(apk_obj: Any, filename: str, versions: dict[str, str]) -> None:
    """Extracts the ``version=`` value from a general ``.properties`` asset file.

    Typically used for Play Services property files such as
    ``play-services-base.properties``. Files carrying Google's SDK fingerprint (a
    ``client=`` line naming the artifact) with a bare artifact name are renamed to
    their verified full Maven coordinate so they are not misreported as
    unidentifiable independent libraries; too-generic names (e.g. ``common``) are
    only attributed with that fingerprint present.

    Args:
        apk_obj: A parsed APK object exposing ``get_file()``.
        filename (str): Path of the file inside the APK archive.
        versions (dict[str, str]): Mutable mapping updated in place.
    """
    try:
        lib_name = filename.split("/")[-1].removesuffix(".properties")
        data = apk_obj.get_file(filename).decode("utf-8", errors="ignore")
        version = None
        is_google_client_format = False
        for line in data.splitlines():
            if line.startswith("version="):
                version = line.split("=")[1].strip()
            elif line.startswith("client="):
                is_google_client_format = True
        if version is None:
            return
        if is_google_client_format:
            fingerprint_coord = _GOOGLE_FINGERPRINT_COORDINATES.get(lib_name.lower())
            lib_name = fingerprint_coord or _google_sdk_coordinate(lib_name) or lib_name
        versions[lib_name] = version
    except Exception:
        pass


def _extract_versions_from_strings(dx: Any, versions: dict[str, str]) -> None:
    """Augments *versions* with library version strings found in the DEX string pool.

    Iterates over all string constants in the DEX, applies each pattern in
    :data:`~scanner.util.rules.VERSION_PATTERNS`, and keeps only the highest version
    seen for each library name (using :func:`_is_newer_version`).

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
        versions (dict[str, str]): Mutable mapping updated in place.
    """
    for string_val in dx.get_strings():
        val = string_val.get_value()
        for pat in VERSION_PATTERNS:
            match = pat.search(val)
            if match:
                lib_name = match.group(1).lower()
                version_str = match.group(2)
                if lib_name in versions:
                    if _is_newer_version(version_str, versions[lib_name]):
                        versions[lib_name] = version_str
                else:
                    versions[lib_name] = version_str


def _resolve_anonymous_version_files(dx: Any, versions: dict[str, str]) -> None:
    """Renames ambiguous version keys to their correct library names.

    Some property files use a generic filename (e.g. ``"library.version"``) that
    only becomes meaningful when cross-referenced with the DEX class pool.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
        versions (dict[str, str]): Mutable mapping updated in place.
    """
    class_names = {cls.name for cls in dx.get_classes()}
    if "library" in versions:
        if any("Lcom/yubico/yubikit" in name for name in class_names):
            versions["yubikit"] = versions.pop("library")


def _classify_versions(versions: dict[str, str]) -> dict[str, Any]:
    """Splits a flat version mapping into ``system`` and ``third_party`` groups.

    Entries whose key starts with a known system prefix (e.g. ``"androidx."``,
    ``"com.google.android."``) are placed in the ``system`` bucket. All others go into
    ``third_party``, further split into ``google_sdk`` (official Play services, Firebase,
    ML Kit, and Play Core SDK modules) and ``independent`` (libraries the developer chose
    independently of the Google Play ecosystem, e.g. OkHttp, Dagger, Gson). Placeholder
    values such as ``"unconfirmed"`` or ``"unreferenced"`` are silently dropped.

    Args:
        versions (dict[str, str]): Raw library-to-version mapping.

    Returns:
        dict[str, Any]: A dict with a ``"system"`` sub-dict and a ``"third_party"`` sub-dict
            containing ``"google_sdk"`` and ``"independent"`` sub-dicts.
    """
    classified: dict[str, dict[str, Any]] = {"system": {}, "third_party": {"google_sdk": {}, "independent": {}}}
    google_sdk = classified["third_party"]["google_sdk"]

    def _put_google_sdk(name: str, version: str) -> None:
        # The same artifact can be extracted from several sources (a Google .properties
        # file and a META-INF pom.properties); keep the highest version seen.
        existing = google_sdk.get(name)
        if existing is None or _is_newer_version(version, existing):
            google_sdk[name] = version

    for lib_name, version in versions.items():
        if not version or any(token in version for token in ("unconfirmed", "unreferenced", "property 'version'")):
            continue
        # Google SDK resolution runs before the system prefixes: e.g.
        # "com.google.android.play:core-common" would otherwise match the
        # "com.google.android." system prefix and vanish from the third-party report.
        if coordinate := _google_sdk_coordinate(lib_name):
            _put_google_sdk(coordinate, version)
        elif lib_name.startswith(_SYSTEM_VERSION_PREFIXES):
            classified["system"][lib_name] = version
        else:
            classified["third_party"]["independent"][lib_name] = version
    return classified


def _lib_name_tokens(name: str) -> set[str]:
    """Splits a library key into lowercase identifier tokens for cross-referencing.

    Args:
        name (str): A library root key (e.g. ``"io.ktor"``) or version-entry key
            (e.g. ``"com.squareup.okhttp3:okhttp"``).

    Returns:
        set[str]: The non-TLD segments of the name, e.g. ``{"squareup", "okhttp3", "okhttp"}``.
    """
    tokens = {t for t in _TOKEN_SPLIT_RE.split(name.lower()) if t and t not in _TLDS}
    # Also match numeric-suffix name variants (okhttp3 <-> okhttp) on the same identifier.
    tokens |= {stripped for t in tokens if (stripped := t.rstrip("0123456789"))}
    return tokens or {name.lower()}


def find_unversioned_third_party(
    external_libraries: dict[str, list[str]], third_party: dict[str, Any]
) -> dict[str, list[str]]:
    """Finds libraries detected in the DEX class pool that have no resolved version.

    ``external_libraries`` is a coarse, version-less grouping of every third-party
    namespace seen in the DEX class pool (see :func:`_group_packages`), while
    ``exact_versions_found.third_party`` only contains the subset whose version could
    be pinned via META-INF metadata or a DEX string constant. This cross-references the
    two so libraries present in the former but absent from the latter (e.g. Ktor,
    LeakCanary, BouncyCastle, Conscrypt, RootBeer) are not silently dropped from the AI
    report just because no version string was extracted.

    Args:
        external_libraries (dict[str, list[str]]): Root key -> sorted sub-module list, as returned by
            :func:`_group_packages`.
        third_party (dict[str, Any]): The ``exact_versions_found.third_party`` dict, with
            ``"google_sdk"`` and ``"independent"`` sub-dicts.

    Returns:
        dict[str, list[str]]: Mapping from library root key to its sorted list of detected sub-module
            names, containing only entries with no matching versioned dependency.
    """
    # Segment-level matching (shared identifier token), not substring matching: a substring
    # test lets a short root like "ru" match inside unrelated coordinates and silently drop
    # a genuinely detected library from the report.
    versioned_token_sets = [_lib_name_tokens(name) for name in flatten_third_party(third_party)]

    unversioned: dict[str, list[str]] = {}
    for root_key, sub_modules in external_libraries.items():
        tokens = _lib_name_tokens(root_key)
        if any(tokens & versioned for versioned in versioned_token_sets):
            continue
        unversioned[root_key] = sub_modules
    return unversioned


def flatten_third_party(third_party: dict[str, Any]) -> dict[str, str]:
    """Flattens third-party sub-buckets or unified dictionaries into one name-to-version mapping.

    Used by consumers (e.g. OSV vulnerability scanning) that need to check every third-party
    dependency for known CVEs regardless of how it was structured.

    Args:
        third_party (dict[str, Any]): The third-party dictionary with either ``"google_sdk"`` /
            ``"independent"`` sub-dicts, direct ``name -> version`` strings, or unified
            ``name -> {"version_used": ...}`` objects.

    Returns:
        dict[str, str]: A single flat mapping of library name to version string.
    """
    flat: dict[str, str] = {}
    if "google_sdk" in third_party or "independent" in third_party:
        flat.update(third_party.get("google_sdk", {}))
        flat.update(third_party.get("independent", {}))
    else:
        for k, v in third_party.items():
            if isinstance(v, str):
                flat[k] = v
            elif isinstance(v, dict) and v.get("version_used"):
                flat[k] = str(v["version_used"])
    return flat


def resolve_latest_versions(third_party: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Resolves the latest published version for every third-party dependency, in parallel.

    Doing this once at scan time replaces the per-dependency ``lookup_maven_version`` call
    the report model would otherwise have to make for each entry, which was the single
    largest source of tool traffic and the one weaker models routinely skipped, leaving
    every dependency reported as version "unknown".

    Args:
        third_party (dict[str, Any]): The third-party dependency mapping.

    Returns:
        dict[str, dict[str, str]]: Mapping of the detected dependency name to ``{"latest_version", "source_url"}``
            for every name that resolved. Unresolvable names are omitted so the report layer
            can tell "not looked up" apart from "looked up and unknown".
    """
    from scanner.scan_modules.vulnerabilities import resolve_maven_coordinate
    from scanner.web.lookups import resolve_latest_version

    names = sorted(flatten_third_party(third_party))
    if not names:
        return {}

    def _resolve(name: str) -> tuple[str, dict[str, str]] | None:
        coordinate = resolve_maven_coordinate(name)
        if not coordinate or coordinate.count(":") != 1:
            return None
        group, artifact = coordinate.split(":")
        try:
            hit = resolve_latest_version(group, artifact)
        except Exception:
            return None
        return (name, {"latest_version": hit[0], "source_url": hit[1]}) if hit else None

    logger.info(f"Resolving latest versions for {len(names)} third-party dependencies...")
    resolved: dict[str, dict[str, str]] = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        for result in pool.map(_resolve, names):
            if result:
                resolved[result[0]] = result[1]
    logger.info(f"Resolved {len(resolved)}/{len(names)} dependency versions.")
    return resolved


def flatten_for_osv(deps_input: dict[str, Any]) -> dict[str, str]:
    """Merges the system and third-party versioned dependencies into one mapping for OSV scanning.

    System libraries (AndroidX, Play Services base modules, Kotlin coroutines) are kept out
    of the AI dependency report to avoid flooding it, but they still carry pinned versions
    that can have published advisories, so the CVE check covers them too.

    Args:
        deps_input (dict[str, Any]): Dictionary containing either ``system`` and ``third_party``
            mappings, an ``exact_versions_found`` structure, or unified report mappings.

    Returns:
        dict[str, str]: A single flat mapping of library name to version string.
    """
    flat: dict[str, str] = {}
    if "system" in deps_input and isinstance(deps_input["system"], dict):
        flat.update(deps_input["system"])
        if isinstance(deps_input.get("third_party"), dict):
            flat.update(flatten_third_party(deps_input["third_party"]))
    elif "exact_versions_found" in deps_input:
        exact = deps_input["exact_versions_found"]
        flat.update(exact.get("system", {}))
        flat.update(flatten_third_party(exact.get("third_party", {})))
    elif "third_party" in deps_input and isinstance(deps_input["third_party"], dict):
        for k, v in deps_input["third_party"].items():
            if isinstance(v, dict) and v.get("version_used"):
                flat[k] = str(v["version_used"])
            elif isinstance(v, str):
                flat[k] = v
        for k, v in deps_input.get("android_default", {}).items():
            if isinstance(v, dict) and v.get("version_used"):
                flat[k] = str(v["version_used"])
            elif isinstance(v, str):
                flat[k] = v
    return flat


def assemble_dependencies(
    raw_deps: dict[str, Any],
    osv_findings: list[dict[str, Any]],
    maven_latest: dict[str, dict[str, str]],
) -> dict[str, Any]:
    """Assembles unified third_party and android_default dependency dictionaries.

    Attaches pinned versions, latest Maven versions, and specific OSV CVE findings
    directly to each individual dependency.

    Args:
        raw_deps (dict[str, Any]): The raw dependency extraction dictionary containing
            ``"system"``, ``"third_party"``, and ``"unversioned"`` mappings.
        osv_findings (list[dict[str, Any]]): All OSV vulnerability hits from the batched query.
        maven_latest (dict[str, dict[str, str]]): Latest Maven version lookups for third-party libs.

    Returns:
        dict[str, Any]: Dictionary containing ``"third_party"`` and ``"android_default"`` mappings.
    """
    from scanner.scan_modules.vulnerabilities import resolve_maven_coordinate

    # Index OSV findings by (coordinate, version)
    osv_by_target: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for finding in osv_findings:
        lib = str(finding.get("library", ""))
        ver = str(finding.get("version", ""))
        osv_by_target.setdefault((lib, ver), []).append(finding)

    # 1. Build third_party dict
    third_party: dict[str, dict[str, Any]] = {}

    # Versioned third-party libraries
    versioned_tp = flatten_third_party(raw_deps.get("third_party", {}))
    for name, version in sorted(versioned_tp.items()):
        coord = resolve_maven_coordinate(name) or name
        hits = osv_by_target.get((coord, str(version)), [])
        latest_info = maven_latest.get(name, {})
        third_party[name] = {
            "version_used": version,
            "latest_version": latest_info.get("latest_version"),
            "latest_version_url": latest_info.get("source_url"),
            "osv_findings": hits,
        }

    # Unversioned third-party libraries from DEX bytecode namespaces
    unversioned = raw_deps.get("unversioned", {})
    for root_key, sub_modules in sorted(unversioned.items()):
        lib_name = f"{root_key}:{sub_modules[0]}" if len(sub_modules) == 1 else root_key
        if lib_name not in third_party:
            third_party[lib_name] = {
                "version_used": None,
                "latest_version": None,
                "latest_version_url": None,
                "osv_findings": [],
            }

    # 2. Build android_default dict
    android_default: dict[str, dict[str, Any]] = {}
    system_deps = raw_deps.get("system", {})
    for name, version in sorted(system_deps.items()):
        coord = resolve_maven_coordinate(name) or name
        hits = osv_by_target.get((coord, str(version)), [])
        android_default[name] = {
            "version_used": version,
            "osv_findings": hits,
        }

    return {
        "third_party": third_party,
        "android_default": android_default,
    }


def extract_dependencies(apk: Any, dx: Any) -> dict[str, Any]:
    """Scans compile-time classes and META-INF metadata to detect third-party libraries.

    Delegates to a set of focused private helpers that each handle one stage of
    the pipeline:

    1. Resolve the app's own package name to exclude internal classes.
    2. Build the DEX namespace ignore-prefix list.
    3. Collect and filter raw package paths from the DEX class pool.
    4. Group package paths under library root keys with sub-module labels.
    5. Extract exact version strings from property files and the DEX string pool.
    6. Classify versions into ``system`` and ``third_party`` (``google_sdk``/``independent``) buckets.

    Args:
        apk (androguard.core.apk.APK | list[androguard.core.apk.APK]): The parsed APK
            object or list of split APK objects.
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.

    Returns:
        dict[str, Any]: A dictionary containing classified dependency mappings.
    """
    apk_list = apk if isinstance(apk, (list, tuple)) else [apk]

    package_name = _resolve_app_package(apk_list)
    ignore_prefixes = _build_ignore_prefixes(package_name)
    packages = _collect_raw_packages(dx, ignore_prefixes)
    grouped_deps = _group_packages(packages)

    versions = _extract_versions_from_metadata(apk_list)
    _extract_versions_from_strings(dx, versions)
    _resolve_anonymous_version_files(dx, versions)
    classified_versions = _classify_versions(versions)

    unversioned = find_unversioned_third_party(grouped_deps, classified_versions["third_party"])
    flat_tp = flatten_third_party(classified_versions["third_party"])

    return {
        "external_libraries": grouped_deps,
        "exact_versions_found": classified_versions,
        "system": classified_versions["system"],
        "third_party": flat_tp,
        "unversioned": unversioned,
    }
