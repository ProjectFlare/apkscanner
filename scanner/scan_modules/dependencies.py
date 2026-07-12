"""Module for extracting third-party external libraries and their version details.

Analyzes compile-time classes inside the DEX bytecode and packaging metadata to identify
third-party library dependencies, group them under their root package names, and resolve
exact version strings from META-INF property files and the DEX string pool.
"""

import re
from collections.abc import Sequence

from packaging.version import InvalidVersion
from packaging.version import parse as parse_version

from scanner.util.rules import OBFUSCATED_SUBMODULE, VERSION_PATTERNS

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


def _version_key(v: str) -> list:
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
    parts = []
    for segment in re.split(r"[-.]", v):
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
        try:
            return _version_key(new_ver) > _version_key(old_ver)
        except TypeError:
            # Last resort: lexicographic comparison
            return new_ver > old_ver


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


def _collect_raw_packages(dx, ignore_prefixes: tuple[str, ...]) -> set:
    """Gathers unique, non-obfuscated package path strings from the DEX class pool.

    Only classes whose DEX descriptor starts with ``"L"`` and does not match
    any *ignore_prefixes* are considered.  Packages where the first two
    segments are two characters or fewer (R8/ProGuard minification) or
    contain non-alphanumeric characters are dropped.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
        ignore_prefixes (tuple[str, ...]): DEX namespace prefixes to skip.

    Returns:
        set[str]: Dot-separated package names, e.g. ``{"com.google.gson.internal"}``.
    """
    raw_packages: set[str] = set()
    for cls in dx.get_classes():
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


def _group_packages(packages: set) -> dict:
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
    grouped: dict[str, set] = {}
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


def _extract_versions_from_metadata(apk_list: Sequence) -> dict:
    """Reads library version strings from META-INF and asset property files.

    Three file types are handled:

    * ``META-INF/.../pom.properties`` - Maven build descriptors (``groupId:artifactId`` key).
    * ``META-INF/.../*.version``      - AndroidX / Jetpack single-line version files.
    * ``*.properties`` (non META-INF) - General property files, e.g. ``play-services-*.properties``.

    Args:
        apk_list (Sequence): One or more parsed APK objects.

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


def _parse_pom_properties(apk_obj, filename: str, versions: dict) -> None:
    """Extracts the version from a Maven ``pom.properties`` file in META-INF.

    The library key is derived from the directory structure:
    ``META-INF/maven/<groupId>/<artifactId>/pom.properties`` -> ``"groupId:artifactId"``.

    Args:
        apk_obj: A parsed APK object exposing ``get_file()``.
        filename (str): Path of the file inside the APK archive.
        versions (dict): Mutable mapping updated in place.
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


def _parse_version_file(apk_obj, filename: str, versions: dict) -> None:
    """Reads a single-line AndroidX / Jetpack ``.version`` file from META-INF.

    The library name is the filename stem (without the ``.version`` extension).

    Args:
        apk_obj: A parsed APK object exposing ``get_file()``.
        filename (str): Path of the file inside the APK archive.
        versions (dict): Mutable mapping updated in place.
    """
    try:
        lib_name = filename.split("/")[-1].replace(".version", "")
        data = apk_obj.get_file(filename).decode("utf-8", errors="ignore").strip()
        if data:
            versions[lib_name] = data
    except Exception:
        pass


def _parse_general_properties(apk_obj, filename: str, versions: dict) -> None:
    """Extracts the ``version=`` value from a general ``.properties`` asset file.

    Typically used for Play Services property files such as
    ``play-services-base.properties``.

    Args:
        apk_obj: A parsed APK object exposing ``get_file()``.
        filename (str): Path of the file inside the APK archive.
        versions (dict): Mutable mapping updated in place.
    """
    try:
        lib_name = filename.split("/")[-1].replace(".properties", "")
        data = apk_obj.get_file(filename).decode("utf-8", errors="ignore")
        for line in data.splitlines():
            if line.startswith("version="):
                versions[lib_name] = line.split("=")[1].strip()
                break
    except Exception:
        pass


def _extract_versions_from_strings(dx, versions: dict) -> None:
    """Augments *versions* with library version strings found in the DEX string pool.

    Iterates over all string constants in the DEX, applies each pattern in
    :data:`~scanner.util.rules.VERSION_PATTERNS`, and keeps only the highest version
    seen for each library name (using :func:`_is_newer_version`).

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
        versions (dict): Mutable mapping updated in place.
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


def _resolve_anonymous_version_files(dx, versions: dict) -> None:
    """Renames ambiguous version keys to their correct library names.

    Some property files use a generic filename (e.g. ``"library.version"``) that
    only becomes meaningful when cross-referenced with the DEX class pool.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
        versions (dict): Mutable mapping updated in place.
    """
    class_names = {cls.name for cls in dx.get_classes()}
    if "library" in versions:
        if any("Lcom/yubico/yubikit" in name for name in class_names):
            versions["yubikit"] = versions.pop("library")


def _classify_versions(versions: dict) -> dict:
    """Splits a flat version mapping into ``system`` and ``third_party`` groups.

    Entries whose key starts with a known system prefix (e.g. ``"androidx."``,
    ``"com.google.android."``) are placed in the ``system`` bucket; all others
    go into ``third_party``.  Placeholder values such as ``"unconfirmed"`` or
    ``"unreferenced"`` are silently dropped.

    Args:
        versions (dict[str, str]): Raw library-to-version mapping.

    Returns:
        dict: A dict with ``"system"`` and ``"third_party"`` sub-dicts.
    """
    classified: dict[str, dict] = {"system": {}, "third_party": {}}
    for lib_name, version in versions.items():
        if not version or any(token in version for token in ("unconfirmed", "unreferenced", "property 'version'")):
            continue
        bucket = "system" if lib_name.startswith(_SYSTEM_VERSION_PREFIXES) else "third_party"
        classified[bucket][lib_name] = version
    return classified


def extract_dependencies(apk, dx):
    """Scans compile-time classes and META-INF metadata to detect third-party libraries.

    Delegates to a set of focused private helpers that each handle one stage of
    the pipeline:

    1. Resolve the app's own package name to exclude internal classes.
    2. Build the DEX namespace ignore-prefix list.
    3. Collect and filter raw package paths from the DEX class pool.
    4. Group package paths under library root keys with sub-module labels.
    5. Extract exact version strings from property files and the DEX string pool.
    6. Classify versions into ``system`` and ``third_party`` buckets.

    Args:
        apk (androguard.core.apk.APK | list[androguard.core.apk.APK]): The parsed APK
            object or list of split APK objects.
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.

    Returns:
        dict: A dictionary with two keys:

            * ``"external_libraries"`` (*dict*) - Mapping from root library package to a
              sorted list of its detected sub-module names.
            * ``"exact_versions_found"`` (*dict*) - Classified version mappings with
              ``"system"`` and ``"third_party"`` sub-dicts.
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

    return {"external_libraries": grouped_deps, "exact_versions_found": classified_versions}
