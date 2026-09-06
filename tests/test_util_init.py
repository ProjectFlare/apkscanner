"""Unit tests for scanner.util package exports.

Verifies that __all__ defines all public entry points and that they are directly
accessible from the scanner.util namespace.
"""

import scanner.util


def test_util_package_exports():
    """scanner.util exports all primary utility functions in __all__."""
    expected_exports = [
        "agentic_openai_query",
        "clear_tool_cache",
        "load_dynamic_rules",
        "parse_split_apks",
        "query_llm_direct",
        "set_thinking_enabled",
        "update_rules_db",
    ]
    for export in expected_exports:
        assert export in scanner.util.__all__
        assert hasattr(scanner.util, export)
        assert getattr(scanner.util, export) is not None
