"""Unit tests for the JSON report creation and deobfuscation helper utility module."""

import hashlib
import logging as stdlib_logging
from datetime import UTC, datetime
from unittest.mock import MagicMock

from scanner.util.json_report import (
    apply_deobfuscation,
    build_scan_report,
    calculate_hashes,
)


def test_calculate_hashes(tmp_path):
    """Verifies SHA256, SHA1 and MD5 digests are computed correctly."""
    data = b"hello world"
    f = tmp_path / "sample.bin"
    f.write_bytes(data)

    result = calculate_hashes(str(f))

    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert result["sha1"] == hashlib.sha1(data).hexdigest()
    assert result["md5"] == hashlib.md5(data).hexdigest()


def test_calculate_hashes_large_file(tmp_path):
    """Verifies that chunked reading produces correct hashes for multi-chunk files."""
    # Write more than one 8 192-byte chunk to exercise the while loop.
    data = b"x" * 20_000
    f = tmp_path / "big.bin"
    f.write_bytes(data)

    result = calculate_hashes(str(f))
    assert result["sha256"] == hashlib.sha256(data).hexdigest()


def test_apply_deobfuscation_success(monkeypatch):
    """Verifies apply_deobfuscation calls Deobfuscator and mutates the report."""
    mock_deobf = MagicMock()
    monkeypatch.setattr("scanner.util.json_report.Deobfuscator", lambda dx, pkg: mock_deobf)

    report = {"apk_metadata": {"package": "com.example"}}
    apply_deobfuscation(report, MagicMock(), "com.example")

    mock_deobf.deobfuscate_report.assert_called_once_with(report)


def test_apply_deobfuscation_failure_is_logged(monkeypatch, caplog):
    """Verifies apply_deobfuscation logs a warning and does not raise on failure."""
    monkeypatch.setattr("scanner.util.json_report.Deobfuscator", MagicMock(side_effect=RuntimeError("obf crash")))

    with caplog.at_level(stdlib_logging.WARNING, logger="scanner.util.json_report"):
        apply_deobfuscation({}, MagicMock(), "com.example")

    assert any("Deobfuscation failed" in m for m in caplog.messages)


def test_build_scan_report_returns_report_shape(monkeypatch, tmp_path):
    """Verifies build_scan_report assembles a report dict with all expected top-level keys."""
    MOD = "scanner.util.json_report"
    monkeypatch.setattr(f"{MOD}.extract_urls", lambda dx: {"lib": ["http://example.com"]})
    monkeypatch.setattr(f"{MOD}.audit_signatures", lambda apk_objects: {"schemes": []})
    monkeypatch.setattr(f"{MOD}.analyze_ui_framework", lambda apk_objects, dx: "compose")
    monkeypatch.setattr(f"{MOD}.analyze_cpu_architecture", lambda apk_objects: ["arm64-v8a"])
    monkeypatch.setattr(f"{MOD}.analyze_manifest_security", lambda apk_objects: {"issues": []})
    monkeypatch.setattr(f"{MOD}.analyze_security_checks", lambda apk_objects, dx: {"root_detection": False})
    monkeypatch.setattr(f"{MOD}.extract_permissions", lambda apk_objects, dx: {"runtime_requested": []})
    monkeypatch.setattr(f"{MOD}.extract_dependencies", lambda apk_objects, dx: [])
    monkeypatch.setattr(f"{MOD}.extract_secrets", lambda dx, apk_objects: [])
    monkeypatch.setattr(f"{MOD}.analyze_bytecode", lambda dx: {"findings": []})
    monkeypatch.setattr(
        f"{MOD}.extract_domains",
        lambda urls: {"cloud_services": [], "trackers_and_ads": [], "other": []},
    )
    monkeypatch.setattr(f"{MOD}.calculate_hashes", lambda path: {"sha256": "abc", "sha1": "def", "md5": "ghi"})

    apk_file = tmp_path / "app.apk"
    apk_file.write_bytes(b"dummy")

    mock_apk = MagicMock()
    mock_apk.get_package.return_value = "com.example"
    mock_apk.get_app_name.return_value = "Example App"
    mock_apk.get_androidversion_name.return_value = "1.0"
    mock_apk.get_androidversion_code.return_value = "1"
    mock_apk.get_min_sdk_version.return_value = "21"
    mock_apk.get_target_sdk_version.return_value = "33"

    report = build_scan_report(mock_apk, [mock_apk], MagicMock(), str(apk_file), datetime.now(UTC))

    required_keys = {
        "scan_metadata",
        "apk_metadata",
        "signatures",
        "environment_details",
        "manifest_audit",
        "security_checks",
        "permissions",
        "dependencies",
        "secrets",
        "bytecode_audit",
        "network",
    }
    assert required_keys.issubset(report.keys())
    assert report["apk_metadata"]["package"] == "com.example"


def test_build_scan_report_app_name_exception(monkeypatch, tmp_path):
    """Verifies build_scan_report sets app_name to None when get_app_name raises."""
    MOD = "scanner.util.json_report"
    for attr in (
        "extract_urls",
        "audit_signatures",
        "analyze_ui_framework",
        "analyze_cpu_architecture",
        "analyze_manifest_security",
        "analyze_security_checks",
        "extract_permissions",
        "extract_dependencies",
        "extract_secrets",
        "analyze_bytecode",
        "extract_domains",
        "calculate_hashes",
    ):
        monkeypatch.setattr(f"{MOD}.{attr}", MagicMock(return_value={}))

    apk_file = tmp_path / "app.apk"
    apk_file.write_bytes(b"dummy")

    mock_apk = MagicMock()
    mock_apk.get_app_name.side_effect = Exception("no name")
    mock_apk.get_package.return_value = "com.example"

    report = build_scan_report(mock_apk, [mock_apk], MagicMock(), str(apk_file), datetime.now(UTC))
    assert report["apk_metadata"]["app_name"] is None
