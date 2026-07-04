# This module extracts requested permissions from the APK and classifies them
# into runtime, install-time/system, or custom categories.

from .rules import RUNTIME_PERMISSIONS

def extract_permissions(apk):
    """Extracts permissions from the APK object and classifies them into categories.

    The categories are:
    - runtime_requested: Dangerous permissions requiring explicit runtime user approval.
    - install_time_or_system: Normal/signature permissions granted automatically.
    - custom_or_third_party: Custom permissions defined by the app or third-party SDKs.

    Args:
        apk (androguard.core.apk.APK): The parsed APK object from Androguard.

    Returns:
        dict: A dictionary containing lists of sorted permissions:
            - runtime_requested (list[str]): List of runtime permissions.
            - install_time_or_system (list[str]): List of install-time or system permissions.
            - custom_or_third_party (list[str]): List of custom/third-party permissions.
    """
    raw_permissions = apk.get_permissions()
    
    categorized = {
        "runtime_requested": [],
        "install_time_or_system": [],
        "custom_or_third_party": []
    }
    
    for perm in sorted(raw_permissions):
        # Permissions not starting with android or com.android are categorized as custom/third-party
        if not perm.startswith("android.permission.") and not perm.startswith("com.android."):
            categorized["custom_or_third_party"].append(perm)
        elif perm in RUNTIME_PERMISSIONS:
            categorized["runtime_requested"].append(perm)
        else:
            categorized["install_time_or_system"].append(perm)
            
    return categorized