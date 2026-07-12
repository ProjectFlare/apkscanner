"""Unit tests for the APK signature auditing scanner module."""

from unittest.mock import MagicMock

from scanner.scan_modules.signatures import audit_signatures


def test_audit_signatures():
    """Verifies that audit_signatures correctly parses certificates and sets flags."""
    mock_cert = MagicMock()
    mock_cert.subject.human_friendly = "CN=Android Debug, O=Android, C=US"
    mock_cert.issuer.human_friendly = "CN=Android Debug, O=Android, C=US"
    mock_cert.serial_number = 12345
    mock_cert.sha256_fingerprint = "AA:BB:CC"
    mock_cert.sha1_fingerprint = "DD:EE"
    mock_cert.signature_algo = "sha256WithRSAEncryption"
    mock_cert.hash_algo = "sha256"
    mock_cert.self_signed = True

    mock_apk = MagicMock()
    mock_apk.is_signed_v1.return_value = True
    mock_apk.is_signed_v2.return_value = True
    mock_apk.is_signed_v3.return_value = False
    mock_apk.get_certificates.return_value = [mock_cert]

    result = audit_signatures([mock_apk])

    assert "v1" in result["scheme_versions"]
    assert "v2" in result["scheme_versions"]
    assert "v3" not in result["scheme_versions"]
    assert result["is_debug_signed"] is True
    assert result["has_weak_hash"] is False
    assert len(result["certificates"]) == 1
    assert result["certificates"][0]["serial_number"] == "12345"


def test_split_signatures_alignment():
    """Verifies split APK signature alignment validation logic."""
    # Case 1: Base + split signed with the same cert
    mock_cert_base = MagicMock()
    mock_cert_base.subject.human_friendly = "CN=App, O=Developer"
    mock_cert_base.issuer.human_friendly = "CN=App, O=Developer"
    mock_cert_base.serial_number = 123
    mock_cert_base.sha256_fingerprint = "AA BB CC"
    mock_cert_base.sha1_fingerprint = "DD EE"
    mock_cert_base.signature_algo = "sha256"
    mock_cert_base.hash_algo = "sha256"

    mock_apk_base = MagicMock()
    mock_apk_base.is_signed_v1.return_value = True
    mock_apk_base.is_signed_v2.return_value = False
    mock_apk_base.is_signed_v3.return_value = False
    mock_apk_base.get_certificates.return_value = [mock_cert_base]
    mock_apk_base.filename = "base.apk"

    mock_cert_split = MagicMock()
    mock_cert_split.sha256_fingerprint = "AA BB CC"
    mock_apk_split = MagicMock()
    mock_apk_split.is_signed.return_value = True
    mock_apk_split.get_certificates.return_value = [mock_cert_split]
    mock_apk_split.filename = "split_config.apk"

    result_aligned = audit_signatures([mock_apk_base, mock_apk_split])
    assert result_aligned["split_signatures_aligned"] is True
    assert len(result_aligned["mismatched_splits"]) == 0

    # Case 2: Base + split signed with different cert
    mock_cert_mismatch = MagicMock()
    mock_cert_mismatch.sha256_fingerprint = "XX YY ZZ"
    mock_apk_mismatch = MagicMock()
    mock_apk_mismatch.is_signed.return_value = True
    mock_apk_mismatch.get_certificates.return_value = [mock_cert_mismatch]
    mock_apk_mismatch.filename = "split_mismatch.apk"

    result_mismatched = audit_signatures([mock_apk_base, mock_apk_mismatch])
    assert result_mismatched["split_signatures_aligned"] is False
    assert "split_mismatch.apk (signature mismatch)" in result_mismatched["mismatched_splits"]

    # Case 3: Base + unsigned split
    mock_apk_unsigned = MagicMock()
    mock_apk_unsigned.is_signed.return_value = False
    mock_apk_unsigned.filename = "split_unsigned.apk"

    result_unsigned = audit_signatures([mock_apk_base, mock_apk_unsigned])
    assert result_unsigned["split_signatures_aligned"] is False
    assert "split_unsigned.apk (unsigned)" in result_unsigned["mismatched_splits"]


def test_signature_helpers():
    """Verifies private helper functions in scanner.signatures module."""
    import datetime
    from unittest.mock import PropertyMock

    from scanner.scan_modules.signatures import (
        _audit_certificates,
        _audit_split_alignment,
        _parse_single_certificate,
    )

    # Test _parse_single_certificate with subject/issuer raising exceptions
    mock_cert = MagicMock()
    mock_cert.subject = MagicMock()
    type(mock_cert.subject).human_friendly = PropertyMock(side_effect=Exception("no human friendly"))
    mock_cert.subject.__str__.return_value = "Raw Subject"

    mock_cert.issuer = MagicMock()
    type(mock_cert.issuer).human_friendly = PropertyMock(side_effect=Exception("no human friendly"))
    mock_cert.issuer.__str__.return_value = "Raw Issuer"

    mock_cert.serial_number = 9999
    mock_cert.sha256_fingerprint = "11:22:33"
    mock_cert.sha1_fingerprint = "44:55"
    mock_cert.signature_algo = "sha256"
    mock_cert.hash_algo = "md5"
    mock_cert.self_signed = "maybe"
    mock_cert.not_valid_before = "invalid_date_string"
    mock_cert.not_valid_after = "invalid_date_string"

    details = _parse_single_certificate(mock_cert)
    assert details["subject"] == "Raw Subject"
    assert details["issuer"] == "Raw Issuer"
    assert details["serial_number"] == "9999"
    assert details["sha256_fingerprint"] == "11:22:33"
    assert details["sha1_fingerprint"] == "44:55"
    assert details["signature_algo"] == "sha256"
    assert details["hash_algo"] == "md5"
    assert details["valid_from"] == "invalid_date_string"
    assert details["valid_until"] == "invalid_date_string"
    assert details["self_signed"] is True

    # Test self_signed as actual bool
    mock_cert_bool = MagicMock()
    mock_cert_bool.subject.human_friendly = "Sub"
    mock_cert_bool.issuer.human_friendly = "Iss"
    mock_cert_bool.serial_number = 111
    mock_cert_bool.self_signed = False
    details_bool = _parse_single_certificate(mock_cert_bool)
    assert details_bool["self_signed"] is False

    # Test self_signed as custom string not maybe/True
    mock_cert_str = MagicMock()
    mock_cert_str.subject.human_friendly = "Sub"
    mock_cert_str.issuer.human_friendly = "Iss"
    mock_cert_str.serial_number = 111
    mock_cert_str.self_signed = "false_string"
    details_str = _parse_single_certificate(mock_cert_str)
    assert details_str["self_signed"] is False

    # Test validity ranges with datetime objects
    mock_cert_dt = MagicMock()
    mock_cert_dt.subject.human_friendly = "Sub"
    mock_cert_dt.issuer.human_friendly = "Iss"
    mock_cert_dt.serial_number = 222
    mock_cert_dt.not_valid_before = datetime.datetime(2020, 1, 1, 12, 0, 0)
    mock_cert_dt.not_valid_after = datetime.datetime(2030, 1, 1, 12, 0, 0)
    details_dt = _parse_single_certificate(mock_cert_dt)
    assert details_dt["valid_from"] == "2020-01-01T12:00:00"
    assert details_dt["valid_until"] == "2030-01-01T12:00:00"

    # Test _audit_certificates handling exceptions
    mock_apk_err = MagicMock()
    mock_apk_err.get_certificates.side_effect = Exception("Failed to get certs")
    certs_list, is_debug, has_weak = _audit_certificates(mock_apk_err)
    assert certs_list == []
    assert is_debug is False
    assert has_weak is False

    # Test _audit_split_alignment handling base_apk certificate extraction failure
    mock_base_apk_err = MagicMock()
    mock_base_apk_err.get_certificates.side_effect = Exception("failed base certs")
    mock_split_apk = MagicMock()
    mock_split_apk.filename = None
    mock_split_apk.is_signed.return_value = True
    mock_split_apk.get_certificates.return_value = []

    aligned, mismatched = _audit_split_alignment([mock_base_apk_err, mock_split_apk], mock_base_apk_err)
    assert aligned is False
    assert "split_1.apk (no certificates)" in mismatched

    # Test weak hash and debug signature paths
    mock_weak_cert = MagicMock()
    mock_weak_cert.subject.human_friendly = "CN=Android Debug, O=Android"
    mock_weak_cert.issuer.human_friendly = "CN=Android Debug, O=Android"
    mock_weak_cert.serial_number = 456
    mock_weak_cert.hash_algo = "SHA1"
    mock_weak_cert.not_valid_before = datetime.datetime(2020, 1, 1, 12, 0, 0)
    mock_weak_cert.not_valid_after = datetime.datetime(2030, 1, 1, 12, 0, 0)
    mock_weak_cert.self_signed = True
    mock_apk_weak = MagicMock()
    mock_apk_weak.get_certificates.return_value = [mock_weak_cert]

    certs_list, is_debug, has_weak = _audit_certificates(mock_apk_weak)
    assert is_debug is True
    assert has_weak is True
    assert len(certs_list) == 1

    # Test audit_split_alignment handling split_apk exception
    mock_base = MagicMock()
    mock_base.get_certificates.return_value = []
    mock_split_except = MagicMock()
    mock_split_except.is_signed.side_effect = Exception("failed read signature")
    mock_split_except.filename = "split_exception.apk"

    aligned, mismatched = _audit_split_alignment([mock_base, mock_split_except], mock_base)
    assert aligned is False
    assert "split_exception.apk (failed to read signature: failed read signature)" in mismatched

    # Test audit_signatures with single APK (non-list input) and v3 signature scheme
    mock_apk_single = MagicMock()
    mock_apk_single.is_signed_v1.return_value = False
    mock_apk_single.is_signed_v2.return_value = False
    mock_apk_single.is_signed_v3.return_value = True
    mock_apk_single.get_certificates.return_value = []
    res_single = audit_signatures(mock_apk_single)
    assert "v3" in res_single["scheme_versions"]
    assert res_single["is_debug_signed"] is False

    # Test audit_signatures with empty list input
    res_empty = audit_signatures([])
    assert res_empty["scheme_versions"] == []
