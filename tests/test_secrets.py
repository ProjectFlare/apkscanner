"""Unit tests for the secrets extraction scanner module."""

from unittest.mock import MagicMock

from scanner.scan_modules.secrets import extract_secrets


def test_extract_secrets():
    """Verifies that secrets are identified from the DEX string pool."""
    mock_class_ana = MagicMock()
    mock_class_ana.name = "Lcom/example/MyClass;"
    mock_method_ana = MagicMock()
    mock_method_ana.name = "myMethod"

    mock_string_1 = MagicMock()
    mock_string_1.get_value.return_value = "AIzaXyA1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q"  # Google API key
    mock_string_1.get_xref_from.return_value = [(mock_class_ana, mock_method_ana)]

    mock_string_2 = MagicMock()
    mock_string_2.get_value.return_value = "AKIAIOSFODNN7EXAMPLE"  # AWS key
    mock_string_2.get_xref_from.return_value = []

    mock_string_3 = MagicMock()
    mock_string_3.get_value.return_value = "short_str"  # Short non-secret

    mock_dx = MagicMock()
    mock_dx.get_strings.return_value = [mock_string_1, mock_string_2, mock_string_3]

    result = extract_secrets(mock_dx)

    types = [secret["type"] for secret in result]
    assert "google_api" in types
    assert "aws_key" in types
    assert len(result) == 2

    # Check source formatting
    google_secret = next(s for s in result if s["type"] == "google_api")
    assert google_secret["source"] == "com.example.MyClass->myMethod"


def test_extract_secrets_with_apks():
    """Verifies that secrets are extracted from APK resource tables and assets, and deduplicated."""
    mock_dx = MagicMock()
    mock_dx.get_strings.return_value = []

    mock_apk = MagicMock()

    xml_data = (
        b"<resources>"
        b'  <string name="google_api_key">AIzaXyA1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q</string>'
        b'  <string name="short_val">too_short</string>'
        b'  <string name="aws_key_res">AKIAIOSFODNN7EXAMPLE</string>'
        b"</resources>"
    )
    mock_res = MagicMock()
    mock_res.get_strings_resources.return_value = xml_data
    mock_apk.get_android_resources.return_value = mock_res

    mock_apk.get_files.return_value = [
        "assets/config.properties",
        "res/raw/secrets.txt",
        "assets/large.txt",
        "assets/binary.png",
    ]

    def mock_get_file(filename):
        if filename == "assets/config.properties":
            return b"google_key = AIzaXyA1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q\n"
        elif filename == "res/raw/secrets.txt":
            return b"aws: AKIAIOSFODNN7EXAMPLE\nother_line = brief"
        elif filename == "assets/large.txt":
            return b"A" * (1024 * 1024 + 10)
        return None

    mock_apk.get_file.side_effect = mock_get_file

    result = extract_secrets(mock_dx, apks=mock_apk)

    assert len(result) == 2
    types = {secret["type"] for secret in result}
    assert "google_api" in types
    assert "aws_key" in types

    google_secret = next(s for s in result if s["type"] == "google_api")
    assert google_secret["name"] == "google_api_key"
    assert google_secret["source"] == "resource string XML table"

    aws_secret = next(s for s in result if s["type"] == "aws_key")
    assert aws_secret["name"] == "aws_key_res"
    assert aws_secret["source"] == "resource string XML table"


def test_extract_secrets_exception_handling():
    """Verifies that secrets extraction handles exceptions gracefully in resources and assets."""
    mock_dx = MagicMock()
    mock_dx.get_strings.return_value = []

    mock_apk = MagicMock()
    mock_apk.get_android_resources.side_effect = Exception("Resource error")
    mock_apk.get_files.side_effect = Exception("Files error")

    result = extract_secrets(mock_dx, apks=[mock_apk])
    assert result == []


def test_extract_secrets_file_exception():
    """Verifies that file reading exceptions are caught and don't halt overall scanning."""
    mock_dx = MagicMock()
    mock_dx.get_strings.return_value = []

    mock_apk = MagicMock()
    mock_apk.get_android_resources.return_value = None
    mock_apk.get_files.return_value = ["assets/ok.properties", "assets/bad.properties"]

    def mock_get_file(filename):
        if filename == "assets/ok.properties":
            return b"google_key = AIzaXyA1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q"
        raise Exception("Read error")

    mock_apk.get_file.side_effect = mock_get_file

    result = extract_secrets(mock_dx, apks=mock_apk)
    assert len(result) == 1
    assert result[0]["type"] == "google_api"
