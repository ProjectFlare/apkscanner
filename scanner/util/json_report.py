"""Assembles and post-processes the structured JSON scan report.

Provides helpers for computing file hashes, running all scanner sub-modules
and collecting their output into a single report dictionary, and applying
heuristic deobfuscation to the assembled result.
"""

import hashlib
import logging
import os
from datetime import UTC, datetime

from scanner.scan_modules.architecture import analyze_cpu_architecture, analyze_ui_framework
from scanner.scan_modules.bytecode_audit import analyze_bytecode
from scanner.scan_modules.deobfuscator import Deobfuscator
from scanner.scan_modules.dependencies import extract_dependencies
from scanner.scan_modules.domains import extract_domains
from scanner.scan_modules.manifest import analyze_manifest_security
from scanner.scan_modules.permissions import extract_permissions
from scanner.scan_modules.secrets import extract_secrets
from scanner.scan_modules.security_checks import analyze_security_checks
from scanner.scan_modules.signatures import audit_signatures
from scanner.scan_modules.urls import extract_urls


def calculate_hashes(filepath):
    """Computes cryptographic hashes (SHA256, SHA1, MD5) for a given file.

    Args:
        filepath (str): Path to the target binary file.

    Returns:
        dict: A dictionary mapping hash names (``sha256``, ``sha1``, ``md5``) to their hex digests.
    """
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)

    return {"sha256": sha256.hexdigest(), "sha1": sha1.hexdigest(), "md5": md5.hexdigest()}


def build_scan_report(apk, apk_objects, dx, target_path, scan_start):
    """Executes all feature-extraction and security-analysis modules.

    Runs every scanner sub-module and assembles the results into the top-level
    report dictionary.  Deobfuscation and vulnerability mapping are **not**
    performed here; they are applied by the caller after this function returns.

    Args:
        apk (androguard.core.apk.APK): Primary parsed APK object.
        apk_objects (list[androguard.core.apk.APK]): All APK split objects.
        dx (androguard.core.analysis.analysis.Analysis): Fully linked analysis context.
        target_path (str): Original file-system path to the APK/ZIP (used for metadata).
        scan_start (datetime): UTC timestamp recorded before analysis began.

    Returns:
        dict: The assembled scan report, without vulnerability or deobfuscation data.
    """
    scan_end = datetime.now(UTC)
    found_urls = extract_urls(dx)

    try:
        app_name = apk.get_app_name()
    except Exception:
        app_name = None

    return {
        "scan_metadata": {
            "scan_started": scan_start.isoformat(),
            "scan_completed": scan_end.isoformat(),
            "duration_seconds": (scan_end - scan_start).total_seconds(),
        },
        "apk_metadata": {
            "apk_name": os.path.basename(target_path),
            "package": apk.get_package(),
            "app_name": app_name,
            "size": os.path.getsize(target_path),
            "app_version_name": apk.get_androidversion_name(),
            "app_version_code": apk.get_androidversion_code(),
            "min_sdk_version": apk.get_min_sdk_version(),
            "target_sdk_version": apk.get_target_sdk_version(),
            "hashes": calculate_hashes(target_path),
        },
        "signatures": audit_signatures(apk_objects),
        "environment_details": {
            "ui_framework": analyze_ui_framework(apk_objects, dx),
            "cpu_architecture": analyze_cpu_architecture(apk_objects),
        },
        "manifest_audit": analyze_manifest_security(apk_objects),
        "security_checks": analyze_security_checks(apk_objects, dx),
        "permissions": extract_permissions(apk_objects, dx),
        "dependencies": extract_dependencies(apk_objects, dx),
        "secrets": extract_secrets(dx, apk_objects),
        "bytecode_audit": analyze_bytecode(dx),
        "network": {
            "attributed_urls": found_urls,
            "categorized_domains": extract_domains(found_urls),
        },
    }


def apply_deobfuscation(report, dx, package_name):
    """Runs heuristic deobfuscation over the assembled report in-place.

    Failures are logged as warnings and do not interrupt the scan.

    Args:
        report (dict): The assembled scan report to mutate.
        dx (androguard.core.analysis.analysis.Analysis): The linked analysis context.
        package_name (str): The APK's package name, used to focus deobfuscation heuristics.
    """
    try:
        deobf = Deobfuscator(dx, package_name)
        deobf.deobfuscate_report(report)
    except Exception as deobf_err:
        logging.warning(f"Deobfuscation failed: {deobf_err!s}")
