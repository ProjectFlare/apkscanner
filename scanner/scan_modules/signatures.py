"""Module for auditing the APK developer signing certificates and signature schemes.

Checks for self-signed status, debug signers, and signature algorithm strengths, and
records certificate parameters such as the validity period in the report.
"""

import datetime
import os
from collections.abc import Sequence
from typing import Any

from loguru import logger


def _parse_single_certificate(cert: Any) -> dict[str, Any]:
    """Parses a single certificate object into a details dictionary.

    Args:
        cert: The certificate object to parse.

    Returns:
        dict: A dictionary containing certificate parameters.
    """
    cert_details: dict[str, Any] = {}

    # Format subject & issuer names cleanly
    try:
        cert_details["subject"] = cert.subject.human_friendly
    except Exception:
        cert_details["subject"] = str(cert.subject)

    try:
        cert_details["issuer"] = cert.issuer.human_friendly
    except Exception:
        cert_details["issuer"] = str(cert.issuer)

    cert_details["serial_number"] = str(cert.serial_number)
    cert_details["sha256_fingerprint"] = getattr(cert, "sha256_fingerprint", "Unknown")
    cert_details["sha1_fingerprint"] = getattr(cert, "sha1_fingerprint", "Unknown")
    cert_details["signature_algo"] = getattr(cert, "signature_algo", "Unknown")
    cert_details["hash_algo"] = getattr(cert, "hash_algo", "Unknown")

    # Check validity ranges
    if hasattr(cert, "not_valid_before") and isinstance(cert.not_valid_before, datetime.datetime):
        cert_details["valid_from"] = cert.not_valid_before.isoformat()
    else:
        cert_details["valid_from"] = str(getattr(cert, "not_valid_before", "Unknown"))

    if hasattr(cert, "not_valid_after") and isinstance(cert.not_valid_after, datetime.datetime):
        cert_details["valid_until"] = cert.not_valid_after.isoformat()
    else:
        cert_details["valid_until"] = str(getattr(cert, "not_valid_after", "Unknown"))

    # Check if self-signed
    self_signed = getattr(cert, "self_signed", "Unknown")
    if isinstance(self_signed, bool):
        cert_details["self_signed"] = self_signed
    else:
        cert_details["self_signed"] = str(self_signed) == "maybe" or str(self_signed) == "True"

    return cert_details


def _audit_certificates(base_apk: Any) -> tuple[list[dict[str, Any]], bool, bool]:
    """Audits base APK certificates for vulnerability indicators.

    Extracts certificate parameters and checks for debug certs and weak hash algos.

    Args:
        base_apk: The base APK object.

    Returns:
        tuple[list[dict], bool, bool]: A tuple containing:
            - certs_list (list[dict]): Details of each certificate found.
            - is_debug_signed (bool): True if signed with a debug certificate.
            - has_weak_hash (bool): True if signed with MD5 or SHA1.
    """
    certs_list: list[dict[str, Any]] = []
    is_debug_signed = False
    has_weak_hash = False

    try:
        certs = base_apk.get_certificates()
        for cert in certs:
            cert_details = _parse_single_certificate(cert)

            # Evaluate vulnerabilities
            subj_lower = cert_details["subject"].lower()
            iss_lower = cert_details["issuer"].lower()
            if "android debug" in subj_lower or "android debug" in iss_lower or "o=android" in subj_lower:
                is_debug_signed = True

            hash_algo = cert_details["hash_algo"].lower()
            if hash_algo in ["md5", "sha1"]:
                has_weak_hash = True

            certs_list.append(cert_details)
    except Exception as e:
        logger.warning(f"Failed to extract certificate details: {e!s}")

    return certs_list, is_debug_signed, has_weak_hash


def _audit_split_alignment(apks: Sequence[Any], base_apk: Any) -> list[str]:
    """Audits signature alignment across all split APKs compared to base APK.

    Args:
        apks (Sequence[Any]): A list of parsed APK objects.
        base_apk: The base APK object (first element of apks).

    Returns:
        list[str]: List of mismatching split filenames.
    """
    mismatched_splits: list[str] = []

    base_fingerprints: set[str] = set()
    try:
        base_certs = base_apk.get_certificates()
        for cert in base_certs:
            fingerprint = getattr(cert, "sha256_fingerprint", "Unknown")
            if fingerprint != "Unknown":
                base_fingerprints.add(fingerprint.strip().replace(" ", "").lower())
    except Exception as e:
        logger.warning(f"Failed to extract base APK certificate fingerprints: {e!s}")

    splits = [apk for apk in apks if apk != base_apk]
    for i, split_apk in enumerate(splits):
        split_name = getattr(split_apk, "filename", None)
        if split_name:
            split_name = os.path.basename(split_name)
        else:
            split_name = f"split_{i + 1}.apk"

        try:
            if not split_apk.is_signed():
                mismatched_splits.append(f"{split_name} (unsigned)")
                continue

            split_certs = split_apk.get_certificates()
            if not split_certs:
                mismatched_splits.append(f"{split_name} (no certificates)")
                continue

            split_fingerprints: set[str] = set()
            for cert in split_certs:
                fingerprint = getattr(cert, "sha256_fingerprint", "Unknown")
                if fingerprint != "Unknown":
                    split_fingerprints.add(fingerprint.strip().replace(" ", "").lower())

            if split_fingerprints != base_fingerprints:
                mismatched_splits.append(f"{split_name} (signature mismatch)")
        except Exception as e:
            mismatched_splits.append(f"{split_name} (failed to read signature: {e!s})")
            logger.warning(f"Failed to audit split APK signature for {split_name}: {e!s}")

    return mismatched_splits


def audit_signatures(apks: Any) -> dict[str, Any]:
    """Audits the cryptographic signatures and certificates of the APK objects.

    Checks the APK signature schemes (v1, v2, v3) and parses the developer
    certificate parameters including subject, issuer, validity period, and hashing
    algorithms. Identifies weak signature hashes, debug cert usage, and APKs relying
    solely on the legacy v1 (JAR) signature scheme.

    Args:
        apks (APK or list): A single parsed APK object or a list of split APK objects.

    Returns:
        dict: A dictionary containing certificate audits and signing configurations:
            - scheme_versions (list[str]): List of active signature versions (e.g. ["v1", "v2"]).
            - v1_only_signature (bool): True if only the legacy v1 (JAR) scheme is active.
            - certificates (list[dict]): Details of each signing certificate found.
            - is_debug_signed (bool): True if signed with a debug certificate.
            - has_weak_hash (bool): True if signed with a weak algorithm (MD5/SHA1).
            - mismatched_splits (list[str]): List of mismatching split filenames.
    """
    if not isinstance(apks, list):
        apks = [apks]

    report: dict[str, Any] = {
        "scheme_versions": [],
        "v1_only_signature": False,
        "certificates": [],
        "is_debug_signed": False,
        "has_weak_hash": False,
        "mismatched_splits": [],
    }

    if not apks:
        return report

    # Enforce signature verification on the base APK
    base_apk = apks[0]
    for apk in apks:
        try:
            xml_root = apk.get_android_manifest_xml()
            if xml_root is not None and "split" not in xml_root.attrib:
                base_apk = apk
                break
            if "base.apk" in getattr(apk, "filename", "").lower():
                base_apk = apk
                break
        except Exception:
            pass

    # Audit signature schemes
    if base_apk.is_signed_v1():
        report["scheme_versions"].append("v1")
    if base_apk.is_signed_v2():
        report["scheme_versions"].append("v2")
    if base_apk.is_signed_v3():
        report["scheme_versions"].append("v3")

    # v1 (JAR) signing alone provides no whole-file integrity and is vulnerable to the
    # Janus vulnerability (CVE-2017-13156) on Android 5.0-8.1; v2/v3 schemes prevent it.
    report["v1_only_signature"] = report["scheme_versions"] == ["v1"]

    # Extract and audit certificate details
    certs_list, is_debug, has_weak = _audit_certificates(base_apk)
    report["certificates"] = certs_list
    report["is_debug_signed"] = is_debug
    report["has_weak_hash"] = has_weak

    # Audit signature alignment across split APKs
    if len(apks) > 1:
        report["mismatched_splits"] = _audit_split_alignment(apks, base_apk)

    return report
