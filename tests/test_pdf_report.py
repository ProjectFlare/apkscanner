"""Unit tests for scanner.util.pdf_report and PDF integration in main.py.

Tests Markdown-to-PDF compilation, anchor resolution, styling,
CLI argument handling, and error conditions.
"""

import os
from unittest.mock import patch

import pytest

from scanner.util.pdf_report import (
    convert_markdown_file_to_pdf,
    extract_report_title,
    generate_pdf_from_markdown,
    get_report_css,
    prepare_markdown_for_pdf,
    slugify,
)


def test_slugify_basic():
    """Verifies that strings are properly converted to lowercase hyphenated slugs."""
    assert slugify("Simple Heading") == "simple-heading"
    assert slugify("1. Missing Root Detection!") == "1-missing-root-detection"
    assert slugify("  Extra   Spaces  -- ") == "extra-spaces"
    assert slugify("Special @#$% Characters") == "special-characters"


def test_extract_report_title_h1():
    """Extracts top-level header text correctly and cleans HTML."""
    md = "# Security Report for Sample App <a id='sample'></a>\n\nSome body text."
    assert extract_report_title(md) == "Security Report for Sample App"


def test_extract_report_title_fallback():
    """Falls back to default title when no H1 exists in markdown."""
    md = "## Subtitle Only\n\nSome body text."
    assert extract_report_title(md) == "Mobile Application Security Assessment Report"


def test_prepare_markdown_for_pdf_anchors():
    """Ensures heading anchors and fallback links are properly injected."""
    md_content = """# App Security Report

## 1. Vulnerabilities

| Vulnerability | Link |
| --- | --- |
| Insecure Storage | [Details](#insecure-storage) |
| Missing Root | [Details](#missing-root) |
| Missing Match | [Details](#completely-unmatched-target) |

### 1. Insecure Storage
Details here.

### 2. Missing Root Detection
Details here.
"""
    prepared = prepare_markdown_for_pdf(md_content)
    # Check that heading anchors are injected
    assert '<a id="1-insecure-storage"></a>' in prepared
    assert '<a id="insecure-storage"></a>' in prepared
    assert '<a id="2-missing-root-detection"></a>' in prepared
    assert '<a id="missing-root-detection"></a>' in prepared

    # Check fallback anchor for unresolved link target
    assert '<a id="completely-unmatched-target"></a>' in prepared


def test_get_report_css():
    """Verifies that the report stylesheet contains expected selectors."""
    css = get_report_css()
    assert "body" in css
    assert "table" in css
    assert "th" in css
    assert "td" in css
    assert "pre" in css
    assert "code" in css


def test_generate_pdf_from_markdown_success(tmp_path):
    """Generates a valid PDF file from markdown content."""
    md = """# Mobile Application Security Assessment Report - TestApp

## Summary
The application was scanned and evaluated.

| OWASP Category | Severity | Description |
| --- | --- | --- |
| M1 | HIGH | Hardcoded API Key |

```java
public void test() {
    System.out.println("hello");
}
```
"""
    output_pdf = str(tmp_path / "test_report.pdf")
    res_path = generate_pdf_from_markdown(md, output_pdf)

    assert os.path.isfile(res_path)
    assert res_path == os.path.abspath(output_pdf)
    assert os.path.getsize(res_path) > 0


def test_generate_pdf_from_markdown_empty_error():
    """Raises ValueError when attempting to generate PDF from empty string."""
    with pytest.raises(ValueError, match="empty Markdown"):
        generate_pdf_from_markdown("   ", "dummy.pdf")


def test_generate_pdf_creates_parent_dir(tmp_path):
    """Creates nested parent directories if they do not already exist."""
    nested_dir = tmp_path / "nested" / "reports"
    output_pdf = str(nested_dir / "deep_report.pdf")

    generate_pdf_from_markdown("# Test Title\n\nContent", output_pdf)
    assert os.path.isfile(output_pdf)


def test_convert_markdown_file_to_pdf_default_path(tmp_path):
    """Converts file to PDF using default <basename>.pdf destination."""
    md_file = tmp_path / "assessment_report.md"
    md_file.write_text("# Report\n\nTest content", encoding="utf-8")

    result_pdf = convert_markdown_file_to_pdf(str(md_file))
    expected_pdf = str(tmp_path / "assessment_report.pdf")

    assert os.path.isfile(expected_pdf)
    assert result_pdf == os.path.abspath(expected_pdf)


def test_convert_markdown_file_to_pdf_custom_path(tmp_path):
    """Converts file to PDF using specified custom output path."""
    md_file = tmp_path / "assessment_report.md"
    md_file.write_text("# Report\n\nCustom content", encoding="utf-8")
    custom_pdf = str(tmp_path / "custom_name.pdf")

    result_pdf = convert_markdown_file_to_pdf(str(md_file), custom_pdf)
    assert os.path.isfile(custom_pdf)
    assert result_pdf == os.path.abspath(custom_pdf)


def test_convert_markdown_file_not_found():
    """Raises FileNotFoundError if target markdown file does not exist."""
    with pytest.raises(FileNotFoundError, match="Target markdown file not found"):
        convert_markdown_file_to_pdf("non_existent_report.md")


def test_main_cli_standalone_markdown_success(tmp_path):
    """Tests main() CLI execution for standalone .md to .pdf conversion."""
    md_file = tmp_path / "test_standalone.md"
    md_file.write_text("# Standalone Report\n\nSome findings", encoding="utf-8")
    pdf_file = tmp_path / "test_standalone.pdf"

    from main import main

    test_args = ["main.py", str(md_file), "--pdf"]
    with patch("sys.argv", test_args):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

    assert os.path.isfile(pdf_file)


def test_main_cli_standalone_markdown_missing_pdf_flag(tmp_path):
    """Fails with parser error if a .md file is passed without --pdf."""
    md_file = tmp_path / "test_standalone.md"
    md_file.write_text("# Standalone Report", encoding="utf-8")

    from main import main

    test_args = ["main.py", str(md_file)]
    with patch("sys.argv", test_args):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 2


def test_main_cli_standalone_markdown_file_not_found():
    """Exits with code 1 if the target .md file does not exist."""
    from main import main

    test_args = ["main.py", "does_not_exist.md", "--pdf"]
    with patch("sys.argv", test_args):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1


def test_main_cli_standalone_markdown_conversion_error(tmp_path):
    """Exits with code 1 if conversion raises an unexpected error."""
    md_file = tmp_path / "broken.md"
    md_file.write_text("# Broken", encoding="utf-8")

    from main import main

    test_args = ["main.py", str(md_file), "--pdf"]
    with patch("sys.argv", test_args):
        with patch("main.convert_markdown_file_to_pdf", side_effect=RuntimeError("PDF engine crashed")):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1


def test_handle_ai_only_generates_pdf(tmp_path):
    """Verifies that _handle_ai_only creates both .md and .pdf when args.pdf is True."""
    import json
    from unittest.mock import MagicMock

    from main import _handle_ai_only

    json_report = tmp_path / "scan.json"
    json_report.write_text(json.dumps({"app_name": "Demo"}), encoding="utf-8")
    md_output = tmp_path / "scan_ai.md"
    pdf_output = tmp_path / "scan_ai.pdf"

    args = MagicMock()
    args.apk_path = str(json_report)
    args.ai_report = str(md_output)
    args.ai_model = "test-model"
    args.max_tool_iterations = 3
    args.openai_url = "http://localhost:11434/v1"
    args.ai_concurrency = 1
    args.pdf = True

    with patch("main.generate_ai_report", return_value="# AI Assessment\n\nNo issues found."):
        with pytest.raises(SystemExit) as exc_info:
            _handle_ai_only(args)
        assert exc_info.value.code == 0

    assert os.path.isfile(md_output)
    assert os.path.isfile(pdf_output)


def test_write_ai_report_generates_pdf(tmp_path):
    """Verifies that _write_ai_report creates both .md and .pdf when args.pdf is True."""
    from unittest.mock import MagicMock

    from main import _write_ai_report

    md_output = tmp_path / "app_ai.md"
    pdf_output = tmp_path / "app_ai.pdf"

    args = MagicMock()
    args.ai_report = str(md_output)
    args.ai_model = "test-model"
    args.max_tool_iterations = 3
    args.openai_url = "http://localhost:11434/v1"
    args.ai_concurrency = 1
    args.pdf = True

    with patch("main.generate_ai_report", return_value="# Live Scan Report\n\nAudit complete."):
        _write_ai_report({"metadata": {}}, args)

    assert os.path.isfile(md_output)
    assert os.path.isfile(pdf_output)
