"""Module for extracting requested permissions from the APK and classifying them.

Groups permissions into runtime, install-time/system, or custom categories, performs bytecode
cross-referencing (XREFs) for privacy SDK attribution, and detects declared-but-unused permissions.
"""

from typing import Any

from scanner.util.rules import OS_LEVEL_PERMISSIONS, RUNTIME_PERMISSIONS


def _get_package_name(apks: list[Any]) -> str:
    """Retrieves the primary package name from the APK objects.

    Args:
        apks (list[Any]): List of APK objects.

    Returns:
        str: Package name or empty string if not found.
    """
    for apk in apks:
        try:
            pkg = apk.get_package()
            if pkg:
                return str(pkg)
        except Exception:
            continue
    return ""


def _attribute_call_sites(package_name: str, call_sites: list[str]) -> dict[str, list[str]]:
    """Attributes permission call sites to app-internal code versus third-party SDKs.

    Args:
        package_name (str): The root package name of the scanned application.
        call_sites (list[str]): List of 'ClassName->methodName' call locations.

    Returns:
        dict[str, list[str]]: Mapping containing 'app_internal' and 'third_party' call site lists.
    """
    internal_sites: list[str] = []
    third_party_sites: list[str] = []

    for site in sorted(set(call_sites)):
        cls_name = site.split("->")[0]
        if package_name and cls_name.startswith(package_name):
            internal_sites.append(site)
        else:
            third_party_sites.append(site)

    return {
        "app_internal": internal_sites,
        "third_party": third_party_sites,
    }


def _find_declared_but_unused(
    sorted_perms: list[str],
    referenced_perms: set[str],
) -> list[str]:
    """Identifies declared permissions lacking bytecode references while excluding OS-level permissions.

    Args:
        sorted_perms (list[str]): Sorted list of all declared permissions.
        referenced_perms (set[str]): Set of permissions that have bytecode XREF references.

    Returns:
        list[str]: List of dormant / over-privileged permission names.
    """
    dormant: list[str] = []

    for perm in sorted_perms:
        if perm in referenced_perms or perm in OS_LEVEL_PERMISSIONS:
            continue
        dormant.append(perm)

    return dormant


def extract_permissions(apks: Any, dx: Any = None) -> dict[str, Any]:
    """Extracts permissions from the APK objects and classifies them into categories.

    Also uses Dalvik bytecode analysis (XREFs) to attribute usage to app-internal code
    versus third-party SDKs, and identifies declared-but-unused permissions without dropping them.

    The categories are:
    - runtime_requested: Dangerous permissions requiring explicit runtime user approval.
    - install_time_or_system: Normal/signature permissions granted automatically.
    - custom_or_third_party: Custom permissions defined by the app or third-party SDKs.
    - references: Mapping of permissions to their app-internal and third-party call site locations.
    - declared_but_unused: List of permissions declared in manifest with zero bytecode usage.

    Args:
        apks (APK or list): A single parsed APK object or a list of split APK objects.
        dx (androguard.core.analysis.analysis.Analysis, optional): Analysis object containing
            class and string pool analysis data.

    Returns:
        dict[str, Any]: A dictionary containing classified permissions, references,
            and declared-but-unused findings.
    """
    if not isinstance(apks, list):
        apks = [apks]

    raw_permissions: set[str] = set()
    for apk in apks:
        try:
            raw_permissions.update(apk.get_permissions())
        except Exception:
            pass

    categorized: dict[str, Any] = {
        "runtime_requested": [],
        "install_time_or_system": [],
        "custom_or_third_party": [],
        "references": {},
        "declared_but_unused": [],
    }

    sorted_perms = sorted(raw_permissions)

    for perm in sorted_perms:
        # Permissions not starting with android or com.android are categorized as custom/third-party
        if not perm.startswith("android.permission.") and not perm.startswith("com.android."):
            categorized["custom_or_third_party"].append(perm)
        elif perm in RUNTIME_PERMISSIONS:
            categorized["runtime_requested"].append(perm)
        else:
            categorized["install_time_or_system"].append(perm)

    # Resolve bytecode references using a single pass over dx string pool XREFs
    if dx:
        pkg_name = _get_package_name(apks)
        target_perms = set(sorted_perms)
        raw_refs: dict[str, list[str]] = {}

        for s in dx.get_strings():
            val = s.get_value()
            if val in target_perms:
                refs_list = raw_refs.setdefault(val, [])
                for class_ana, method_ana in s.get_xref_from():
                    class_name = class_ana.name
                    if class_name.startswith("L") and class_name.endswith(";"):
                        class_name = class_name[1:-1].replace("/", ".")
                    refs_list.append(f"{class_name}->{method_ana.name}")

        for perm, refs_list in raw_refs.items():
            if refs_list:
                cleaned_sites = sorted(set(refs_list))
                categorized["references"][perm] = _attribute_call_sites(pkg_name, cleaned_sites)

        categorized["declared_but_unused"] = _find_declared_but_unused(
            sorted_perms, set(categorized["references"].keys())
        )

    return categorized
