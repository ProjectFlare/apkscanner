# This module extracts requested permissions from the APK and classifies them
# into runtime, install-time/system, or custom categories.

from .rules import RUNTIME_PERMISSIONS

def extract_permissions(apks):
    """Extracts permissions from the APK objects and classifies them into categories.

    The categories are:
    - runtime_requested: Dangerous permissions requiring explicit runtime user approval.
    - install_time_or_system: Normal/signature permissions granted automatically.
    - custom_or_third_party: Custom permissions defined by the app or third-party SDKs.

    Args:
        apks (APK or list): A single parsed APK object or a list of split APK objects.

    Returns:
        dict: A dictionary containing lists of sorted permissions:
            - runtime_requested (list[str]): List of runtime permissions.
            - install_time_or_system (list[str]): List of install-time or system permissions.
            - custom_or_third_party (list[str]): List of custom/third-party permissions.
    """
    if not isinstance(apks, list):
        apks = [apks]
        
    raw_permissions = set()
    for apk in apks:
        try:
            raw_permissions.update(apk.get_permissions())
        except Exception:
            pass
    
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