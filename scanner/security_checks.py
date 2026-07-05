# This module evaluates security capabilities of the APK, including detecting
# root checks and auditing if the application allows static analysis (e.g., packing detection).

import os
import re
from loguru import logger

# Pre-compiled packer signatures to optimize detection loops
PACKER_SIGNATURES = {
    "Qihoo 360 / Jiagu": {
        "libs": [
            re.compile(r"libjiagu\.so", re.IGNORECASE),
            re.compile(r"libjiagu_a64\.so", re.IGNORECASE),
            re.compile(r"libjiagu_x86\.so", re.IGNORECASE)
        ],
        "classes": ["com/qihoo", "com/qihoo360"]
    },
    "Tencent Legu / Shell": {
        "libs": [
            re.compile(r"libtxlog\.so", re.IGNORECASE),
            re.compile(r"libshell\.so", re.IGNORECASE),
            re.compile(r"libtup\.so", re.IGNORECASE)
        ],
        "classes": ["com/tencent/StubShell"]
    },
    "Bangcle / SecApk": {
        "libs": [
            re.compile(r"libsecapk\.so", re.IGNORECASE),
            re.compile(r"libsecexe\.so", re.IGNORECASE)
        ],
        "classes": ["com/secapk", "com/bangcle"]
    },
    "SecShell": {
        "libs": [re.compile(r"libsecshell\.so", re.IGNORECASE)],
        "classes": ["com/secshell"]
    },
    "Ali Shield": {
        "libs": [
            re.compile(r"libmobisecy\.so", re.IGNORECASE),
            re.compile(r"libfakejni\.so", re.IGNORECASE)
        ],
        "classes": ["com/ali/mobisecy"]
    },
    "Baidu Protect": {
        "libs": [re.compile(r"libbaiduprotect\.so", re.IGNORECASE)],
        "classes": ["com/baidu/protect"]
    },
    "IJiami": {
        "libs": [
            re.compile(r"libegis\.so", re.IGNORECASE),
            re.compile(r"libegisboot\.so", re.IGNORECASE)
        ],
        "classes": []
    }
}

# String pool indicators indicating potential root detection mechanisms
ROOT_STRINGS = {
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/su",
    "/system/bin/.ext", "/system/usr/we-need-root/su-backup",
    "/system/app/Superuser.apk", "supersu", "KingoUser.apk",
    "SuperSU-v2.82.zip", "magisk", "test-keys", "/system/xbin/daemonsu"
}

def _check_root_detection(dx):
    """Checks DEX classes and string pool for rooted device detection indicators.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): The multidex Analysis object.

    Returns:
        set[str]: A set of detected root-related signatures.
    """
    root_indicators = set()
    
    # Check classes for RootBeer
    try:
        for cls in dx.get_classes():
            if "scottyab/rootbeer" in cls.name:
                root_indicators.add("Scottyab RootBeer library classes detected")
                break
    except Exception as e:
        logger.warning(f"Error checking classes for root detection: {str(e)}")
        
    # Check string pool for root signatures
    try:
        for string_val in dx.get_strings():
            val = string_val.get_value()
            for root_str in ROOT_STRINGS:
                if root_str in val:
                    root_indicators.add(f"Root-related string signature found: '{root_str}'")
    except Exception as e:
        logger.warning(f"Error scanning string pool for root detection: {str(e)}")
        
    return root_indicators

def _detect_packer(apks, dx):
    """Scans native library files and class package names for known packers.

    Args:
        apks (list[APK]): List of APK objects in the split ZIP.
        dx (androguard.core.analysis.analysis.Analysis): The multidex Analysis object.

    Returns:
        str | None: The name of the detected packer and details, or None.
    """
    # 1. Check files inside the APKs for packer native libraries using pre-compiled regexes
    try:
        for apk_obj in apks:
            apk_files = apk_obj.get_files()
            for file_path in apk_files:
                file_name = os.path.basename(file_path)
                for packer_name, sigs in PACKER_SIGNATURES.items():
                    for lib_pat in sigs["libs"]:
                        if lib_pat.search(file_name):
                            return f"{packer_name} (detected via native library '{file_name}')"
    except Exception as e:
        logger.warning(f"Error checking APK files for packers: {str(e)}")
        
    # 2. Check class path names for packer package signatures
    try:
        for cls in dx.get_classes():
            class_name = cls.name
            for packer_name, sigs in PACKER_SIGNATURES.items():
                for class_pat in sigs["classes"]:
                    if class_pat in class_name:
                        return f"{packer_name} (detected via class '{class_name}')"
    except Exception as e:
        logger.warning(f"Error checking classes for packers: {str(e)}")
        
    return None

def analyze_security_checks(apks, dx):
    """Evaluates the APK for security-related capabilities (root detection and anti-static analysis).

    Checks whether the application implements rooted device detection mechanisms
    and determines whether the application allows static analysis (e.g. checks if packed).

    Args:
        apks (APK or list): A single parsed APK object or list of split APK objects.
        dx (androguard.core.analysis.analysis.Analysis): The multidex Analysis object.

    Returns:
        dict: A report containing the security status flags:
            - rooted_device_detection (bool): True if root detection signatures are detected.
            - allows_static_analysis (bool): False if a packer/protector or empty classes are detected.
            - details (dict): Metadata about identified packer or root indicators.
    """
    security_report = {
        "rooted_device_detection": {
            "detection_missing": True,
            "indicators": []
        },
        "static_analysis": {
            "analysis_blocked": False,
            "packer_detected": None
        }
    }
    
    if not isinstance(apks, list):
        apks = [apks]
    
    # 1. ROOTED DEVICE DETECTION CHECK
    root_indicators = _check_root_detection(dx)
    if root_indicators:
        security_report["rooted_device_detection"]["detection_missing"] = False
        security_report["rooted_device_detection"]["indicators"] = sorted(root_indicators)
        
    # 2. ALLOWS STATIC ANALYSIS CHECK
    # Check if there are DEX files parsed successfully
    if not dx or not dx.get_classes():
        security_report["static_analysis"]["analysis_blocked"] = True
        security_report["static_analysis"]["packer_detected"] = "No DEX files or classes could be parsed (empty or invalid APK)."
        return security_report
        
    detected_packer = _detect_packer(apks, dx)
    if detected_packer:
        security_report["static_analysis"]["analysis_blocked"] = True
        security_report["static_analysis"]["packer_detected"] = detected_packer
        
    return security_report
