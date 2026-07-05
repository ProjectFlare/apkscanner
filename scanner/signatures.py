# This module audits the APK developer signing certificates and signature schemes.
# It checks for certificate expiration, self-signed status, debug signers,
# and signature algorithm strengths.

import os
import datetime
from loguru import logger

def audit_signatures(apks):
    """Audits the cryptographic signatures and certificates of the APK objects.

    Checks the APK signature schemes (v1, v2, v3) and parses the developer
    certificate parameters including subject, issuer, validity period, and hashing
    algorithms. Identifies weak signature hashes or debug cert usage.

    Args:
        apks (APK or list): A single parsed APK object or a list of split APK objects.

    Returns:
        dict: A dictionary containing certificate audits and signing configurations:
            - scheme_versions (list[str]): List of active signature versions (e.g. ["v1", "v2"]).
            - certificates (list[dict]): Details of each signing certificate found.
            - is_debug_signed (bool): True if signed with a debug certificate.
            - has_weak_hash (bool): True if signed with a weak algorithm (MD5/SHA1).
            - split_signatures_aligned (bool): True if all split APK signatures align.
            - mismatched_splits (list[str]): List of mismatching split filenames.
    """
    if not isinstance(apks, list):
        apks = [apks]

    report = {
        "scheme_versions": [],
        "certificates": [],
        "is_debug_signed": False,
        "has_weak_hash": False,
        "split_signatures_aligned": True,
        "mismatched_splits": []
    }

    if not apks:
        return report

    # Enforce signature verification on the base APK (usually the first object)
    base_apk = apks[0]
    
    # Audit signature schemes
    if base_apk.is_signed_v1():
        report["scheme_versions"].append("v1")
    if base_apk.is_signed_v2():
        report["scheme_versions"].append("v2")
    if base_apk.is_signed_v3():
        report["scheme_versions"].append("v3")

    try:
        certs = base_apk.get_certificates()
        for cert in certs:
            cert_details = {}
            
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

            # Evaluate vulnerabilities
            subj_lower = cert_details["subject"].lower()
            iss_lower = cert_details["issuer"].lower()
            if "android debug" in subj_lower or "android debug" in iss_lower or "o=android" in subj_lower:
                report["is_debug_signed"] = True
                
            hash_algo = cert_details["hash_algo"].lower()
            if hash_algo in ["md5", "sha1"]:
                report["has_weak_hash"] = True

            report["certificates"].append(cert_details)

    except Exception as e:
        logger.warning(f"Failed to extract certificate details: {str(e)}")

    # Audit signature alignment across split APKs
    if len(apks) > 1:
        base_fingerprints = set()
        try:
            base_certs = base_apk.get_certificates()
            for cert in base_certs:
                fingerprint = getattr(cert, "sha256_fingerprint", "Unknown")
                if fingerprint != "Unknown":
                    base_fingerprints.add(fingerprint.strip().replace(" ", "").lower())
        except Exception as e:
            logger.warning(f"Failed to extract base APK certificate fingerprints: {str(e)}")

        for i, split_apk in enumerate(apks[1:]):
            split_name = getattr(split_apk, "filename", None)
            if split_name:
                split_name = os.path.basename(split_name)
            else:
                split_name = f"split_{i+1}.apk"

            try:
                if not split_apk.is_signed():
                    report["split_signatures_aligned"] = False
                    report["mismatched_splits"].append(f"{split_name} (unsigned)")
                    continue

                split_certs = split_apk.get_certificates()
                if not split_certs:
                    report["split_signatures_aligned"] = False
                    report["mismatched_splits"].append(f"{split_name} (no certificates)")
                    continue

                split_fingerprints = set()
                for cert in split_certs:
                    fingerprint = getattr(cert, "sha256_fingerprint", "Unknown")
                    if fingerprint != "Unknown":
                        split_fingerprints.add(fingerprint.strip().replace(" ", "").lower())

                if split_fingerprints != base_fingerprints:
                    report["split_signatures_aligned"] = False
                    report["mismatched_splits"].append(f"{split_name} (signature mismatch)")
            except Exception as e:
                report["split_signatures_aligned"] = False
                report["mismatched_splits"].append(f"{split_name} (failed to read signature: {str(e)})")
                logger.warning(f"Failed to audit split APK signature for {split_name}: {str(e)}")

    return report
