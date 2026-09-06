"""PDF report generation module for the APK static scanner.

Converts Markdown-formatted security assessment reports into structured,
styled PDF documents with native bookmarks, tables, and typography.
"""

import os
import re
from typing import cast

import pymupdf
from loguru import logger
from markdown_pdf import MarkdownPdf, Section


def slugify(text: str) -> str:
    """Converts heading text into a URL- and anchor-compatible slug.

    Args:
        text (str): Raw heading or text string.

    Returns:
        str: Lowercase, hyphen-delimited slug string.
    """
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s-]", "", text)
    return re.sub(r"[\s]+", "-", text).strip("-")


def extract_report_title(markdown_content: str) -> str:
    """Extracts the first top-level header (H1) from Markdown content.

    Args:
        markdown_content (str): Raw Markdown string.

    Returns:
        str: Extracted document title, or a default security report title.
    """
    match = re.search(r"^#\s+(.+)$", markdown_content, re.MULTILINE)
    if match:
        title = match.group(1).strip()
        # Remove any embedded HTML tags or anchor markup from the title line
        return re.sub(r"<[^>]+>", "", title).strip()
    return "Mobile Application Security Assessment Report"


def prepare_markdown_for_pdf(markdown_content: str) -> str:
    """Injects anchor IDs and resolves internal link destinations.

    PyMuPDF strictly requires every internal link (#destination) to have an
    exact matching element id in the document. This function injects anchor tags
    for all markdown headings and adds fallback anchors for any unresolved links
    to guarantee link resolution never fails.

    Args:
        markdown_content (str): The original Markdown report text.

    Returns:
        str: Preprocessed Markdown with explicit anchor tags attached to headings.
    """
    existing_anchors = set(re.findall(r"<a\s+id=[\'\"]([^\'\"]+)[\'\"]", markdown_content))
    target_links = set(re.findall(r"\[[^\]]+\]\(#([^\)]+)\)", markdown_content))

    lines = markdown_content.split("\n")
    processed_lines: list[str] = []

    # Map headings to slugs and inject anchors
    for line in lines:
        heading_match = re.match(r"^(#{1,6})\s+(.+)$", line)
        if heading_match:
            level, heading_text = heading_match.groups()
            raw_slug = slugify(heading_text)
            # Also create a slug without leading numbers (e.g. '1. Missing Root' -> 'missing-root')
            clean_heading_text = re.sub(r"^\d+\.\s*", "", heading_text)
            clean_slug = slugify(clean_heading_text)

            anchors: list[str] = []
            if raw_slug and raw_slug not in existing_anchors:
                anchors.append(f'<a id="{raw_slug}"></a>')
                existing_anchors.add(raw_slug)
            if clean_slug and clean_slug not in existing_anchors:
                anchors.append(f'<a id="{clean_slug}"></a>')
                existing_anchors.add(clean_slug)

            anchor_suffix = (" " + " ".join(anchors)) if anchors else ""
            processed_lines.append(f"{level} {heading_text}{anchor_suffix}".rstrip())
        else:
            processed_lines.append(line)

    # For any remaining target link without a matching anchor, inject fallback anchors
    unresolved_targets = target_links - existing_anchors
    if unresolved_targets:
        fallback_anchor_str = " ".join(f'<a id="{target}"></a>' for target in sorted(unresolved_targets))
        processed_lines.append(f"\n{fallback_anchor_str}")

    return "\n".join(processed_lines)


def get_report_css() -> str:
    """Returns the CSS stylesheet tailored for mobile security assessment reports.

    Returns:
        str: CSS styling for body typography, headers, tables, code blocks, and blockquotes.
    """
    return """
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 9.5pt;
    line-height: 1.5;
    color: #1e293b;
}
h1 {
    font-size: 18pt;
    color: #0f172a;
    border-bottom: 2px solid #2563eb;
    padding-bottom: 4px;
    margin-bottom: 14px;
}
h2 {
    font-size: 13pt;
    color: #1e40af;
    border-bottom: 1px solid #e2e8f0;
    padding-bottom: 3px;
    margin-top: 18px;
    margin-bottom: 8px;
}
h3 {
    font-size: 11pt;
    color: #0f172a;
    margin-top: 14px;
    margin-bottom: 6px;
}
h4 {
    font-size: 9.5pt;
    color: #475569;
    font-style: italic;
    margin-top: 8px;
    margin-bottom: 4px;
}
table {
    border-collapse: collapse;
    width: 100%;
    margin-top: 8px;
    margin-bottom: 12px;
    font-size: 8.5pt;
}
th {
    color: #0f172a;
    font-weight: bold;
    border: 1px solid #cbd5e1;
    border-bottom: 2px solid #2563eb;
    padding: 6px 8px;
    text-align: left;
}
td {
    border: 1px solid #e2e8f0;
    padding: 5px 8px;
    vertical-align: top;
}
code {
    font-family: SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    font-size: 8.5pt;
    background-color: #f1f5f9;
    color: #0f172a;
    padding: 1px 3px;
    border-radius: 3px;
}
pre {
    border: 1px solid #e2e8f0;
    border-radius: 4px;
    padding: 8px 10px;
    margin-top: 6px;
    margin-bottom: 10px;
    font-size: 8pt;
    line-height: 1.4;
}
pre code {
    background-color: transparent;
    padding: 0;
}
blockquote {
    border-left: 3px solid #2563eb;
    margin: 8px 0;
    padding: 4px 10px;
    color: #475569;
}
hr {
    border: 0;
    border-top: 1px solid #e2e8f0;
    margin: 16px 0;
}
a {
    color: #2563eb;
    text-decoration: none;
}
"""


def generate_pdf_from_markdown(
    markdown_content: str,
    output_pdf_path: str,
    title: str | None = None,
) -> str:
    """Renders a Markdown report string to a PDF file on disk.

    Args:
        markdown_content (str): The Markdown content of the report.
        output_pdf_path (str): Destination file path for the generated PDF.
        title (str | None): Optional title to store in the PDF document metadata.
            If None, the title is extracted from the first H1 header in markdown_content.

    Returns:
        str: The absolute path of the generated PDF file.

    Raises:
        ValueError: If markdown_content is empty.
    """
    if not markdown_content or not markdown_content.strip():
        raise ValueError("Cannot generate PDF from empty Markdown content.")

    doc_title = title or extract_report_title(markdown_content)

    # Ensure parent output directory exists
    parent_dir = os.path.dirname(os.path.abspath(output_pdf_path))
    if parent_dir and not os.path.exists(parent_dir):
        os.makedirs(parent_dir, exist_ok=True)

    prepared_markdown = prepare_markdown_for_pdf(markdown_content)

    pdf = MarkdownPdf(toc_level=3, optimize=True)
    pdf.meta["title"] = doc_title
    pdf.meta["author"] = "APK Scanner"
    pdf.meta["creator"] = "APK Scanner Security Pipeline"

    # Use an empty in-memory Archive instead of a filesystem directory path.
    # Passing a directory path triggers fz_mount_multi_archive / fz_open_directory
    # in MuPDF, which causes a C-level segmentation fault under Python coverage tracing on macOS.
    pdf.add_section(
        Section(prepared_markdown, paper_size="A4", root=cast(str, pymupdf.Archive())),
        user_css=get_report_css(),
    )
    pdf.save(output_pdf_path)

    logger.info(f"PDF report successfully created: {output_pdf_path}")
    return os.path.abspath(output_pdf_path)


def convert_markdown_file_to_pdf(
    markdown_file_path: str,
    output_pdf_path: str | None = None,
) -> str:
    """Reads a Markdown file from disk and converts it to a styled PDF report.

    Args:
        markdown_file_path (str): Path to the existing .md report file.
        output_pdf_path (str | None): Destination path for the PDF. If omitted,
            defaults to the same path with the .pdf extension.

    Returns:
        str: The absolute path of the generated PDF file.

    Raises:
        FileNotFoundError: If the input markdown_file_path does not exist.
    """
    if not os.path.isfile(markdown_file_path):
        raise FileNotFoundError(f"Target markdown file not found: {markdown_file_path}")

    with open(markdown_file_path, encoding="utf-8") as f:
        markdown_content = f.read()

    if not output_pdf_path:
        base_path, _ = os.path.splitext(markdown_file_path)
        output_pdf_path = f"{base_path}.pdf"

    return generate_pdf_from_markdown(markdown_content, output_pdf_path)
