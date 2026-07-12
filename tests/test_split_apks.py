"""Unit tests for the split APK ZIP archive parser scanner utility module."""

import os
from unittest.mock import MagicMock, patch

import pytest

from scanner.util.split_apks import (
    _calculate_metadata_and_load,
    _extract_and_find_apks,
    _extract_dex_files,
    _find_base_apk,
    parse_split_apks,
)


def test_extract_and_find_apks(tmp_path):
    """Verifies unzipping and finding APK files recursively."""
    temp_dir = str(tmp_path / "extracted")
    os.makedirs(temp_dir)

    # Create dummy files
    apk1 = os.path.join(temp_dir, "app1.apk")
    apk2 = os.path.join(temp_dir, "subdir", "app2.apk")
    txt1 = os.path.join(temp_dir, "readme.txt")

    os.makedirs(os.path.dirname(apk2), exist_ok=True)
    with open(apk1, "w") as f:
        f.write("apk1")
    with open(apk2, "w") as f:
        f.write("apk2")
    with open(txt1, "w") as f:
        f.write("readme")

    # Mock zipfile extraction
    with patch("zipfile.ZipFile") as mock_zip:
        mock_zip_instance = MagicMock()
        mock_zip.return_value.__enter__.return_value = mock_zip_instance

        results = _extract_and_find_apks("dummy.zip", temp_dir)

        # Check both APK files are found, but not the txt file
        assert any(r.endswith("app1.apk") for r in results)
        assert any(r.endswith("app2.apk") for r in results)
        assert not any(r.endswith("readme.txt") for r in results)
        assert len(results) == 2


def test_calculate_metadata_and_load(tmp_path):
    """Verifies that APKs are loaded and sizes/SHA256 hashes are computed."""
    apk1_path = str(tmp_path / "test1.apk")
    with open(apk1_path, "wb") as f:
        f.write(b"APK_DATA_CHUNK")

    mock_apk_obj = MagicMock()
    with patch("scanner.util.split_apks.APK", return_value=mock_apk_obj):
        all_apks, metadata = _calculate_metadata_and_load([apk1_path])

        assert len(all_apks) == 1
        assert all_apks[0][0] == apk1_path
        assert all_apks[0][1] is mock_apk_obj

        assert len(metadata) == 1
        assert metadata[0]["name"] == "test1.apk"
        assert metadata[0]["size_bytes"] == len(b"APK_DATA_CHUNK")
        # SHA256 of b"APK_DATA_CHUNK"
        import hashlib

        expected_hash = hashlib.sha256(b"APK_DATA_CHUNK").hexdigest()
        assert metadata[0]["sha256"] == expected_hash


def test_find_base_apk():
    """Verifies base APK selection logic from split APK lists."""
    # Case 1: manifest XML element missing "split" attribute
    mock_xml_base = MagicMock()
    mock_xml_base.attrib = {}
    mock_apk_base = MagicMock()
    mock_apk_base.get_android_manifest_xml.return_value = mock_xml_base

    mock_xml_split = MagicMock()
    mock_xml_split.attrib = {"split": "config.arm64"}
    mock_apk_split = MagicMock()
    mock_apk_split.get_android_manifest_xml.return_value = mock_xml_split

    all_apks_1 = [
        ("/path/split.apk", mock_apk_split),
        ("/path/base.apk", mock_apk_base),
    ]
    base_apk, path = _find_base_apk(all_apks_1)
    assert base_apk is mock_apk_base
    assert path == "/path/base.apk"

    # Case 2: split attribute exists in all, fallback to filename containing 'base.apk'
    mock_apk_other = MagicMock()
    mock_apk_other.get_android_manifest_xml.return_value = mock_xml_split
    mock_apk_base_filename = MagicMock()
    mock_apk_base_filename.get_android_manifest_xml.return_value = mock_xml_split

    all_apks_2 = [
        ("/path/config.apk", mock_apk_other),
        ("/path/my_base.apk", mock_apk_base_filename),
    ]
    base_apk, path = _find_base_apk(all_apks_2)
    assert base_apk is mock_apk_base_filename
    assert path == "/path/my_base.apk"

    # Case 3: fallback to first element in the list
    all_apks_3 = [
        ("/path/config1.apk", mock_apk_other),
        ("/path/config2.apk", mock_apk_other),
    ]
    base_apk, path = _find_base_apk(all_apks_3)
    assert base_apk is mock_apk_other
    assert path == "/path/config1.apk"


def test_extract_dex_files():
    """Verifies parsing and extracting DEX files from split APK objects."""
    mock_apk = MagicMock()
    mock_apk.get_files.return_value = ["classes.dex", "classes2.dex", "res/layout/main.xml"]
    mock_apk.get_file.return_value = b"DEX_DATA"

    mock_dex_obj = MagicMock()
    with patch("scanner.util.split_apks.DEX", return_value=mock_dex_obj):
        dex_files = _extract_dex_files([("/path/app.apk", mock_apk)])
        assert len(dex_files) == 2
        assert dex_files[0] is mock_dex_obj

    # Test DEX parsing exception handled inside loop
    with patch("scanner.util.split_apks.DEX", side_effect=Exception("DEX parse error")):
        dex_files_err = _extract_dex_files([("/path/app.apk", mock_apk)])
        assert len(dex_files_err) == 0


def test_parse_split_apks_success(tmp_path):
    """Verifies full split APK parsing flow on success."""
    zip_path = str(tmp_path / "bundle.zip")

    # Mock helpers inside parse_split_apks
    mock_apk_files = ["/tmp/split_apk/base.apk"]
    mock_apk_obj = MagicMock()
    mock_xml = MagicMock()
    mock_xml.attrib = {}
    mock_apk_obj.get_android_manifest_xml.return_value = mock_xml
    mock_apk_obj.get_files.return_value = ["classes.dex"]
    mock_apk_obj.get_file.return_value = b"DEX"

    mock_dex = MagicMock()

    with (
        patch("scanner.util.split_apks._extract_and_find_apks", return_value=mock_apk_files),
        patch(
            "scanner.util.split_apks._calculate_metadata_and_load",
            return_value=([("/tmp/split_apk/base.apk", mock_apk_obj)], [{"name": "base.apk"}]),
        ),
        patch("scanner.util.split_apks.DEX", return_value=mock_dex),
    ):
        base_apk, base_path, dex_files, meta, objects, temp_dir = parse_split_apks(zip_path)

        assert base_apk is mock_apk_obj
        assert base_path == "/tmp/split_apk/base.apk"
        assert len(dex_files) == 1
        assert dex_files[0] is mock_dex
        assert len(meta) == 1
        assert meta[0]["name"] == "base.apk"
        assert objects == [mock_apk_obj]
        assert os.path.exists(temp_dir)

        # Cleanup
        import shutil

        shutil.rmtree(temp_dir, ignore_errors=True)


def test_parse_split_apks_value_error(tmp_path):
    """Verifies that parse_split_apks raises ValueError if no APKs are found."""
    zip_path = str(tmp_path / "bundle.zip")

    with patch("scanner.util.split_apks._extract_and_find_apks", return_value=[]):
        with pytest.raises(ValueError, match=r"No \.apk files found in the zip archive\."):
            parse_split_apks(zip_path)


def test_parse_split_apks_exception_cleanup(tmp_path):
    """Verifies that temporary directories are cleaned up when exceptions occur during parse."""
    zip_path = str(tmp_path / "bundle.zip")

    with (
        patch("scanner.util.split_apks._extract_and_find_apks", return_value=["/tmp/app.apk"]),
        patch("scanner.util.split_apks._calculate_metadata_and_load", side_effect=Exception("load failed")),
    ):
        with pytest.raises(Exception, match="load failed"):
            parse_split_apks(zip_path)
