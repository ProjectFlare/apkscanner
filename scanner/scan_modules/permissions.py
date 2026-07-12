"""Module for extracting requested permissions from the APK and classifying them.

Groups permissions into runtime, install-time/system, or custom categories, and performs bytecode cross-referencing (XREFs) to find usage.
"""

from scanner.util.rules import RUNTIME_PERMISSIONS


def extract_permissions(apks, dx=None):
    """Extracts permissions from the APK objects and classifies them into categories.

    Also uses Dalvik bytecode analysis (XREFs) to identify which classes and methods
    reference each permission.

    The categories are:
    - runtime_requested: Dangerous permissions requiring explicit runtime user approval.
    - install_time_or_system: Normal/signature permissions granted automatically.
    - custom_or_third_party: Custom permissions defined by the app or third-party SDKs.
    - references: Mapping of permissions to the list of class->method locations where they are used.

    Args:
        apks (APK or list): A single parsed APK object or a list of split APK objects.
        dx (androguard.core.analysis.analysis.Analysis, optional): Analysis object containing
            class and string pool analysis data.

    Returns:
        dict: A dictionary containing lists of sorted permissions:
            - runtime_requested (list[str]): List of runtime permissions.
            - install_time_or_system (list[str]): List of install-time or system permissions.
            - custom_or_third_party (list[str]): List of custom/third-party permissions.
            - references (dict[str, list[str]]): Mapping of permissions to their code usages.
    """
    if not isinstance(apks, list):
        apks = [apks]

    raw_permissions = set()
    for apk in apks:
        try:
            raw_permissions.update(apk.get_permissions())
        except Exception:
            pass

    categorized = {"runtime_requested": [], "install_time_or_system": [], "custom_or_third_party": [], "references": {}}

    sorted_perms = sorted(raw_permissions)

    for perm in sorted_perms:
        # Permissions not starting with android or com.android are categorized as custom/third-party
        if not perm.startswith("android.permission.") and not perm.startswith("com.android."):
            categorized["custom_or_third_party"].append(perm)
        elif perm in RUNTIME_PERMISSIONS:
            categorized["runtime_requested"].append(perm)
        else:
            categorized["install_time_or_system"].append(perm)

    # Resolve bytecode references using dx string pool XREFs
    if dx:
        for perm in sorted_perms:
            refs = []
            for s in dx.get_strings():
                if s.get_value() == perm:
                    for class_ana, method_ana in s.get_xref_from():
                        class_name = class_ana.name
                        if class_name.startswith("L") and class_name.endswith(";"):
                            class_name = class_name[1:-1].replace("/", ".")
                        refs.append(f"{class_name}->{method_ana.name}")
            if refs:
                categorized["references"][perm] = sorted(set(refs))

    return categorized
