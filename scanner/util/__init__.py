"""Utility functions and helper modules for the APK static scanner.

Provides archive extraction, rules management, LLM tool execution,
and database update routines.
"""

from scanner.util.pdf_report import convert_markdown_file_to_pdf, generate_pdf_from_markdown
from scanner.util.rules import load_dynamic_rules
from scanner.util.split_apks import parse_split_apks
from scanner.util.tool_runner import (
    agentic_openai_query,
    clear_tool_cache,
    query_llm_direct,
    set_thinking_enabled,
)
from scanner.util.update_rules import update_rules_db

__all__ = [
    "agentic_openai_query",
    "clear_tool_cache",
    "convert_markdown_file_to_pdf",
    "generate_pdf_from_markdown",
    "load_dynamic_rules",
    "parse_split_apks",
    "query_llm_direct",
    "set_thinking_enabled",
    "update_rules_db",
]
