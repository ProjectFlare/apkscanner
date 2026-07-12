"""Unit tests for the URL extraction scanner module."""

from unittest.mock import MagicMock, patch

from scanner.scan_modules.urls import extract_urls


def test_extract_urls():
    """Verifies URL extraction from string pool and annotations, including host normalization and obfuscation grouping."""
    mock_string_1 = MagicMock()
    mock_string_1.get_value.return_value = "https://my-backend.com/api/v1"
    mock_string_2 = MagicMock()
    mock_string_2.get_value.return_value = "https://my-backend.com/"
    mock_string_3 = MagicMock()
    mock_string_3.get_value.return_value = "https://square.github.io/wire/wire_compiler/#kotlin"

    # Mock XREFs to attribute owner
    mock_class_anal = MagicMock()
    mock_class_anal.name = "Lcom/mycompany/app/NetworkHelper;"
    mock_string_1.get_xref_from.return_value = [(mock_class_anal, 0)]
    mock_string_2.get_xref_from.return_value = [(mock_class_anal, 0)]

    mock_obf_class = MagicMock()
    mock_obf_class.name = "Lwi/r;"
    mock_string_3.get_xref_from.return_value = [(mock_obf_class, 0)]

    mock_dx = MagicMock()
    mock_dx.get_strings.return_value = [mock_string_1, mock_string_2, mock_string_3]
    mock_dx.get_classes.return_value = []  # Empty classes for annotation scanning

    result = extract_urls(mock_dx)

    assert "com.mycompany.app" in result
    assert "https://my-backend.com/api/v1" in result["com.mycompany.app"]
    # Trailing slash must be stripped for host-only URLs
    assert "https://my-backend.com" in result["com.mycompany.app"]
    assert "https://my-backend.com/" not in result["com.mycompany.app"]
    # Obfuscated package classes must be grouped under a generic key
    assert "obfuscated.classes" in result
    assert "https://square.github.io/wire/wire_compiler/#kotlin" in result["obfuscated.classes"]
    assert "wi.r" not in result


def test_extract_urls_with_annotations():
    """Verifies URL extraction from class annotations, including host normalization."""
    mock_cls = MagicMock()
    mock_cls.is_external.return_value = False

    mock_vm_class = MagicMock()
    mock_vm_class.get_annotations.return_value = [
        '@retrofit2.http.GET(value="https://api.my-backend.com/v1/users")',
        '@retrofit2.http.POST(value="https://api.my-backend.com/")',
    ]
    mock_cls.get_vm_class.return_value = mock_vm_class
    mock_cls.name = "Lcom/mycompany/app/MyApi;"

    mock_dx = MagicMock()
    mock_dx.get_strings.return_value = []
    mock_dx.get_classes.return_value = [mock_cls]

    result = extract_urls(mock_dx)

    assert "com.mycompany.app" in result
    assert "https://api.my-backend.com/v1/users" in result["com.mycompany.app"]
    # Trailing slash must be stripped for host-only URLs
    assert "https://api.my-backend.com" in result["com.mycompany.app"]
    assert "https://api.my-backend.com/" not in result["com.mycompany.app"]


def test_extract_urls_edge_cases():
    """Verifies edge cases in URL extraction to achieve full code coverage."""
    # 1. String pool edge cases
    # String without '/' (should be skipped)
    mock_string_no_slash = MagicMock()
    mock_string_no_slash.get_value.return_value = "no_slash_string"

    # String with '/' but no match
    mock_string_no_match = MagicMock()
    mock_string_no_match.get_value.return_value = "some/path/without/urls"

    # String that matches schema keyword (e.g. schemas.android.com)
    mock_string_schema_keyword = MagicMock()
    mock_string_schema_keyword.get_value.return_value = "http://schemas.android.com/apk/res/android"
    mock_string_schema_keyword.get_xref_from.return_value = []

    # Schemeless URL ending with slash
    mock_string_schemeless_slash = MagicMock()
    mock_string_schemeless_slash.get_value.return_value = "my-backend.org/somepath/"
    mock_string_schemeless_slash.get_xref_from.return_value = []

    # String with xref that fails class name attribute check (causes exception)
    mock_string_class_exception = MagicMock()
    mock_string_class_exception.get_value.return_value = "https://class-exception.com"
    mock_string_class_exception.get_xref_from.return_value = [()]

    # String with 2-segment package name
    mock_string_two_segments = MagicMock()
    mock_string_two_segments.get_value.return_value = "https://two-segments.com"
    mock_class_2_seg = MagicMock()
    mock_class_2_seg.name = "Lfoo/Bar;"
    mock_string_two_segments.get_xref_from.return_value = [(mock_class_2_seg, 0)]

    # String with 1-segment package name (goes to app.internal)
    mock_string_one_segment = MagicMock()
    mock_string_one_segment.get_value.return_value = "https://one-segment.com"
    mock_class_1_seg = MagicMock()
    mock_class_1_seg.name = "LBar;"
    mock_string_one_segment.get_xref_from.return_value = [(mock_class_1_seg, 0)]

    # Obfuscated package check with short list (length <= 1)
    mock_string_obf_short = MagicMock()
    mock_string_obf_short.get_value.return_value = "https://obf-short.com"
    mock_class_obf_short = MagicMock()
    mock_class_obf_short.name = "Lwi/r;"
    mock_string_obf_short.get_xref_from.return_value = [(mock_class_obf_short, 0)]

    mock_dx = MagicMock()
    mock_dx.get_strings.return_value = [
        mock_string_no_slash,
        mock_string_no_match,
        mock_string_schema_keyword,
        mock_string_schemeless_slash,
        mock_string_class_exception,
        mock_string_two_segments,
        mock_string_one_segment,
        mock_string_obf_short,
    ]

    # 2. Annotation scan edge cases
    # External class (should be skipped)
    mock_cls_external = MagicMock()
    mock_cls_external.is_external.return_value = True

    # Class without get_vm_class method
    mock_cls_no_method = MagicMock()
    mock_cls_no_method.is_external.return_value = False
    del mock_cls_no_method.get_vm_class

    # Class returning None for get_vm_class
    mock_cls_vm_none = MagicMock()
    mock_cls_vm_none.is_external.return_value = False
    mock_cls_vm_none.get_vm_class.return_value = None

    # Class with empty annotations list
    mock_cls_empty_annotations = MagicMock()
    mock_cls_empty_annotations.is_external.return_value = False
    mock_vm_empty = MagicMock()
    mock_vm_empty.get_annotations.return_value = []
    mock_cls_empty_annotations.get_vm_class.return_value = mock_vm_empty

    # Class raising exception on get_annotations
    mock_cls_exception = MagicMock()
    mock_cls_exception.is_external.return_value = False
    mock_vm_exc = MagicMock()
    mock_vm_exc.get_annotations.side_effect = Exception("annotations fail")
    mock_cls_exception.get_vm_class.return_value = mock_vm_exc
    mock_cls_exception.name = "Lcom/example/api/ExcApi;"

    mock_dx.get_classes.return_value = [
        mock_cls_external,
        mock_cls_no_method,
        mock_cls_vm_none,
        mock_cls_empty_annotations,
        mock_cls_exception,
    ]

    result = extract_urls(mock_dx)

    # Check that we handled the edge cases properly
    assert "unreferenced.static_pool" in result
    assert "my-backend.org/somepath" in result["unreferenced.static_pool"]
    assert "unresolved.context" in result
    assert "https://class-exception.com" in result["unresolved.context"]
    assert "foo.Bar" in result
    assert "https://two-segments.com" in result["foo.Bar"]
    assert "app.internal" in result
    assert "https://one-segment.com" in result["app.internal"]
    assert "obfuscated.classes" in result
    assert "https://obf-short.com" in result["obfuscated.classes"]

    # Verify that skipped items are indeed not present
    assert "schemas.android.com" not in result
    assert "no_slash_string" not in result
    assert "some/path/without/urls" not in result

    # 3. Trigger Exception in _clean_and_filter_url's urlparse block
    with patch("scanner.scan_modules.urls.urlparse", side_effect=Exception("mock parse error")):
        mock_string_err = MagicMock()
        mock_string_err.get_value.return_value = "https://trigger-error.com"
        mock_string_err.get_xref_from.return_value = []
        mock_dx_err = MagicMock()
        mock_dx_err.get_strings.return_value = [mock_string_err]
        mock_dx_err.get_classes.return_value = []
        result_err = extract_urls(mock_dx_err)
        assert "unreferenced.static_pool" in result_err
        assert "https://trigger-error.com" in result_err["unreferenced.static_pool"]
