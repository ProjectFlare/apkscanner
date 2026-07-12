"""Module for evaluating security capabilities of the APK.

Includes detecting root checks and auditing if the application allows static analysis (e.g., packing detection).
"""

import os

from loguru import logger

from scanner.util.rules import PACKER_SIGNATURES, ROOT_STRINGS


def _check_rootbeer_classes(dx) -> bool:
    """Checks DEX classes for the presence of RootBeer library classes.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): The multidex Analysis object.

    Returns:
        bool: True if RootBeer library classes are detected, False otherwise.
    """
    if not dx:
        return False
    try:
        for cls in dx.get_classes():
            if "scottyab/rootbeer" in cls.name:
                return True
    except Exception as e:
        logger.warning(f"Error checking classes for RootBeer: {e!s}")
    return False


def _scan_string_pool_for_root(dx) -> set[str]:
    """Scans the DEX string pool for signatures indicating root checks.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): The multidex Analysis object.

    Returns:
        set[str]: A set of detected root-related string signatures.
    """
    root_indicators = set()
    if not dx:
        return root_indicators
    try:
        for string_val in dx.get_strings():
            val = string_val.get_value()
            for root_str in ROOT_STRINGS:
                if root_str in val:
                    root_indicators.add(f"Root-related string signature found: '{root_str}'")
    except Exception as e:
        logger.warning(f"Error scanning string pool for root detection: {e!s}")
    return root_indicators


def _check_root_detection(dx) -> set[str]:
    """Checks DEX classes and string pool for rooted device detection indicators.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): The multidex Analysis object.

    Returns:
        set[str]: A set of detected root-related signatures.
    """
    root_indicators = set()

    if _check_rootbeer_classes(dx):
        root_indicators.add("Scottyab RootBeer library classes detected")

    root_indicators.update(_scan_string_pool_for_root(dx))

    return root_indicators


def _detect_packer_via_libs(apks) -> str | None:
    """Scans native library files of APKs for signatures of known packers.

    Args:
        apks (list[APK]): List of APK objects in the split ZIP.

    Returns:
        str | None: Details of the detected packer if found, otherwise None.
    """
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
        logger.warning(f"Error checking APK files for packers: {e!s}")
    return None


def _detect_packer_via_classes(dx) -> str | None:
    """Scans package names of classes in DEX for signatures of known packers.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): The multidex Analysis object.

    Returns:
        str | None: Details of the detected packer if found, otherwise None.
    """
    if not dx:
        return None
    try:
        for cls in dx.get_classes():
            class_name = cls.name
            for packer_name, sigs in PACKER_SIGNATURES.items():
                for class_pat in sigs["classes"]:
                    if class_pat in class_name:
                        return f"{packer_name} (detected via class '{class_name}')"
    except Exception as e:
        logger.warning(f"Error checking classes for packers: {e!s}")
    return None


def _detect_packer(apks, dx) -> str | None:
    """Scans native library files and class package names for known packers.

    Args:
        apks (list[APK]): List of APK objects in the split ZIP.
        dx (androguard.core.analysis.analysis.Analysis): The multidex Analysis object.

    Returns:
        str | None: The name of the detected packer and details, or None.
    """
    packer_via_lib = _detect_packer_via_libs(apks)
    if packer_via_lib:
        return packer_via_lib

    return _detect_packer_via_classes(dx)


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
        "rooted_device_detection": {"detection_missing": True, "indicators": []},
        "static_analysis": {"analysis_blocked": False, "packer_detected": None},
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
        security_report["static_analysis"]["packer_detected"] = (
            "No DEX files or classes could be parsed (empty or invalid APK)."
        )
        return security_report

    detected_packer = _detect_packer(apks, dx)
    if detected_packer:
        security_report["static_analysis"]["analysis_blocked"] = True
        security_report["static_analysis"]["packer_detected"] = detected_packer

    return security_report
