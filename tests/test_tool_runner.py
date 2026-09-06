"""Unit tests for scanner.util.tool_runner.

Covers the in-run tool-result dedup store, retry with exponential backoff
(including non-retryable bot-block failures), the execute_tool_call dispatcher,
search function resolution, and the agentic OpenAI-compatible query loop.
"""

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from scanner.util.tool_runner import (
    _TOOL_CACHE,
    ALL_TOOLS,
    OPENAI_MAX_TOKENS,
    SEARCH_RESULT_LIMIT,
    BackendAPIError,
    ModelOutputTruncatedError,
    _openai_headers,
    _query_openai_direct,
    agentic_openai_query,
    clear_tool_cache,
    execute_tool_call,
    is_cached_tool_call,
    resolve_search_func,
    set_api_key,
    set_request_timeouts,
    set_thinking_enabled,
)
from scanner.web.search import SearchBlockedError


def _make_tool_call(name: str, args: dict) -> dict:
    return {"function": {"name": name, "arguments": args}}


def test_clear_tool_cache_resets_dict():
    """Populating and then clearing the dedup store leaves it empty."""
    _TOOL_CACHE[("web_search", (("query", "test"),))] = "some result"
    clear_tool_cache()
    assert len(_TOOL_CACHE) == 0


def test_tool_cache_hit_skips_network_call():
    """A second identical tool call is served from the dedup store without a network call."""
    clear_tool_cache()

    fake_search = MagicMock(return_value=["snippet1"])
    # First call — populates cache
    result1 = execute_tool_call("web_search", {"query": "okhttp vulnerability"}, fake_search)
    # Second call — must hit cache
    result2 = execute_tool_call("web_search", {"query": "okhttp vulnerability"}, fake_search)

    assert result1 == result2
    # search_func should only have been invoked once despite two execute_tool_call calls
    assert fake_search.call_count == 1


def test_is_cached_tool_call_reports_hit_only_after_first_execution():
    """The cache probe is False before the first call and True only for a repeat."""
    clear_tool_cache()
    fake_search = MagicMock(return_value=["snippet"])
    args = {"query": "okhttp vulnerability"}

    assert is_cached_tool_call("web_search", args) is False
    execute_tool_call("web_search", args, fake_search)
    assert is_cached_tool_call("web_search", args) is True
    assert is_cached_tool_call("web_search", {"query": "something else"}) is False


def test_tool_cache_miss_different_args():
    """Two calls with different arguments each make their own network call."""
    clear_tool_cache()

    fake_search = MagicMock(return_value=["snippet"])
    execute_tool_call("web_search", {"query": "query A"}, fake_search)
    execute_tool_call("web_search", {"query": "query B"}, fake_search)

    assert fake_search.call_count == 2


def test_retry_succeeds_on_second_attempt():
    """A tool implementation that fails once then succeeds returns the success value."""
    clear_tool_cache()

    calls = [0]

    def flaky_search(q, max_results=5):
        calls[0] += 1
        if calls[0] == 1:
            raise RuntimeError("temporary failure")
        return ["result"]

    # Patch time.sleep so the test doesn't actually wait
    with patch("scanner.util.tool_runner.time.sleep"):
        result = execute_tool_call("web_search", {"query": "retry test"}, flaky_search)

    assert "result" in result
    assert calls[0] == 2


def test_retry_exhausted_returns_error_string():
    """A tool that always fails returns a graceful error string after max retries."""
    clear_tool_cache()

    broken_search = MagicMock(side_effect=RuntimeError("always down"))
    with patch("scanner.util.tool_runner.time.sleep"):
        result = execute_tool_call("web_search", {"query": "broken"}, broken_search)

    assert "failed" in result.lower()
    # Must NOT raise — result must be a string
    assert isinstance(result, str)


def test_retry_does_not_cache_failed_result():
    """A result that required all retries to fail must not be stored in the dedup store."""
    clear_tool_cache()

    broken_search = MagicMock(side_effect=RuntimeError("down"))
    with patch("scanner.util.tool_runner.time.sleep"):
        execute_tool_call("web_search", {"query": "cache fail test"}, broken_search)

    key = ("web_search", (("query", "cache fail test"),))
    assert key not in _TOOL_CACHE


def test_bot_block_is_not_retried():
    """A SearchBlockedError fails immediately — retrying a bot check only worsens the block."""
    clear_tool_cache()

    blocked_search = MagicMock(side_effect=SearchBlockedError("bot check served"))
    with patch("scanner.util.tool_runner.time.sleep") as mock_sleep:
        result = execute_tool_call("web_search", {"query": "blocked"}, blocked_search)

    assert blocked_search.call_count == 1
    mock_sleep.assert_not_called()
    assert "failed" in result.lower()
    assert isinstance(result, str)


def test_unconfigured_scraper_is_not_retried():
    """A ValueError (no scraper URL configured) fails immediately without backoff."""
    clear_tool_cache()

    unconfigured_search = MagicMock(side_effect=ValueError("Scraper API URL is not configured."))
    with patch("scanner.util.tool_runner.time.sleep") as mock_sleep:
        result = execute_tool_call("web_search", {"query": "no scraper"}, unconfigured_search)

    assert unconfigured_search.call_count == 1
    mock_sleep.assert_not_called()
    assert "failed" in result.lower()


def test_execute_tool_call_web_search_formats_snippets():
    """web_search result contains formatted snippet text."""
    clear_tool_cache()
    fake_search = MagicMock(return_value=["CVE-2024-1234 critical vuln (Source: https://nvd.nist.gov)"])
    result = execute_tool_call("web_search", {"query": "okhttp cve"}, fake_search)
    assert "CVE-2024-1234" in result


def test_execute_tool_call_web_search_empty():
    """web_search with no results returns a 'no results' message."""
    clear_tool_cache()
    result = execute_tool_call("web_search", {"query": "obscure query"}, MagicMock(return_value=[]))
    assert "no results" in result.lower()


def test_execute_tool_call_dispatches_lookup_tools():
    """Each lookup tool name dispatches to its scanner.web implementation."""
    clear_tool_cache()
    with patch("scanner.util.tool_runner.lookup_maven_version", return_value="Latest version: 1.0") as mock_maven:
        result = execute_tool_call("lookup_maven_version", {"group": "g", "artifact": "a"}, MagicMock())
    mock_maven.assert_called_once_with("g", "a")
    assert "Latest version" in result

    with patch("scanner.util.tool_runner.lookup_osv_vulnerabilities", return_value="No known vulns") as mock_osv:
        result = execute_tool_call("lookup_osv_vulnerabilities", {"package": "g:a", "version": "1.0"}, MagicMock())
    mock_osv.assert_called_once_with("g:a", "1.0")
    assert "No known vulns" in result

    with patch("scanner.util.tool_runner.lookup_nvd_cve", return_value="CVSS 9.8") as mock_nvd:
        result = execute_tool_call("lookup_nvd_cve", {"cve_id": "CVE-2024-1"}, MagicMock())
    mock_nvd.assert_called_once_with("CVE-2024-1")
    assert "CVSS 9.8" in result


def test_execute_tool_call_lookup_play_store():
    """lookup_play_store dispatches to the scanner.web implementation."""
    clear_tool_cache()
    with patch("scanner.util.tool_runner.lookup_play_store") as mock_impl:
        mock_impl.return_value = "App Name: Example App\nDeveloper: Example Dev Ltd"
        result = execute_tool_call("lookup_play_store", {"package_id": "com.example.app"}, MagicMock())
    assert "Example App" in result or "Developer" in result


def test_execute_tool_call_lookup_play_store_scraper_error():
    """lookup_play_store returns a graceful error string when the scraper raises."""
    clear_tool_cache()
    with patch("scanner.util.tool_runner.lookup_play_store", side_effect=RuntimeError("scraper down")):
        with patch("scanner.util.tool_runner.time.sleep"):
            result = execute_tool_call("lookup_play_store", {"package_id": "com.fail.app"}, MagicMock())
    assert "failed" in result.lower() or "error" in result.lower()


def test_execute_tool_call_unknown_tool_returns_error_string():
    """An unrecognised tool name returns a graceful error string without raising."""
    clear_tool_cache()
    result = execute_tool_call("nonexistent_tool", {"arg": "val"}, MagicMock())
    assert "unknown tool" in result.lower()
    assert isinstance(result, str)


def test_resolve_search_func_returns_ddg():
    """resolve_search_func always returns the DuckDuckGo search regardless of scraper state."""
    with patch("scanner.web.scraper.SCRAPER_URL", "http://localhost:8000"):
        assert resolve_search_func().__name__ == "search_ddg"
    with patch("scanner.web.scraper.SCRAPER_URL", None):
        assert resolve_search_func().__name__ == "search_ddg"


def test_all_tools_contains_five_tools():
    """ALL_TOOLS must define exactly five tools."""
    assert len(ALL_TOOLS) == 5


def test_all_tools_names():
    """ALL_TOOLS must contain the five expected tool names."""
    names = {t["function"]["name"] for t in ALL_TOOLS}
    assert names == {
        "web_search",
        "lookup_maven_version",
        "lookup_osv_vulnerabilities",
        "lookup_nvd_cve",
        "lookup_play_store",
    }


def test_all_tools_required_fields():
    """Each tool must have type, function, description, parameters, and required fields."""
    for tool in ALL_TOOLS:
        assert tool["type"] == "function"
        fn = tool["function"]
        assert "name" in fn
        assert fn.get("description")
        assert "parameters" in fn
        params = fn["parameters"]
        assert "required" in params
        assert len(params["required"]) > 0


def _make_openai_response(content: str = "", tool_calls: list | None = None, thinking: str = "") -> MagicMock:
    """Builds a mock non-streaming OpenAI JSON response."""
    msg: dict[str, Any] = {"content": content, "role": "assistant"}
    if tool_calls:
        msg["tool_calls"] = tool_calls
    if thinking:
        msg["reasoning_content"] = thinking
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"choices": [{"message": msg}]}
    return mock_resp


def test_agentic_openai_loop_no_tool_calls_returns_content():
    """When the OpenAI API returns plain content, the loop terminates immediately."""
    clear_tool_cache()
    plain_response = _make_openai_response(content='{"no_findings": true, "findings": []}')
    with patch("requests.post", return_value=plain_response) as mock_post:
        content, _thinking, log = agentic_openai_query(
            prompt="audit this",
            system_prompt="system",
            model="qwen",
            openai_url="http://localhost:12345/v1",
            search_func=MagicMock(),
        )
    assert mock_post.call_count == 1
    assert "no_findings" in content
    assert log == []


def test_agentic_openai_loop_single_tool_call_then_content():
    """The OpenAI loop makes a tool call in round 1 and then returns content in round 2."""
    clear_tool_cache()
    round1 = _make_openai_response(
        tool_calls=[
            {
                "id": "call_1",
                "type": "function",
                "function": {"name": "web_search", "arguments": '{"query": "okhttp cve"}'},
            }
        ]
    )
    round2 = _make_openai_response(content='{"no_findings": false, "findings": [{"title": "Vuln"}]}')
    fake_search = MagicMock(return_value=["some snippet"])

    with patch("requests.post", side_effect=[round1, round2]) as mock_post:
        content, _, log = agentic_openai_query(
            prompt="p",
            system_prompt="s",
            model="qwen",
            openai_url="http://localhost:12345/v1",
            search_func=fake_search,
        )

    assert mock_post.call_count == 2
    assert len(log) == 1
    assert log[0]["tool_name"] == "web_search"
    assert "findings" in content


def test_agentic_openai_loop_stream_callback_receives_tokens():
    """Tokens emitted by the streaming OpenAI endpoint are forwarded to the callback."""
    clear_tool_cache()
    chunks = [
        "data: " + json.dumps({"choices": [{"delta": {"content": "hello "}}]}),
        "data: " + json.dumps({"choices": [{"delta": {"content": "world"}}]}),
        "data: [DONE]",
    ]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.iter_lines.return_value = [c.encode() for c in chunks]

    received: list[str] = []

    def callback(chunk: str) -> None:
        received.append(chunk)

    with patch("requests.post", return_value=mock_resp):
        agentic_openai_query(
            prompt="p",
            system_prompt="s",
            model="qwen",
            openai_url="http://localhost:12345/v1",
            search_func=MagicMock(),
            stream_callback=callback,
        )

    full_text = "".join(received)
    assert "hello" in full_text
    assert "world" in full_text


def test_agentic_loop_forces_a_final_answer_when_budget_runs_out():
    """A model that keeps calling tools must still produce an answer: the last pass withholds
    the tools so it has to write its findings from what it already gathered, instead of the
    whole chunk being discarded (which previously dropped entire batches of findings)."""
    clear_tool_cache()
    payloads: list[dict] = []

    def post(url, json: dict, headers=None, timeout=None, stream=None):
        payloads.append(json)
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        # Tools offered -> keep researching; tools withheld -> deliver the final answer.
        if "tools" in json:
            message = {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"id": "c1", "type": "function", "function": {"name": "web_search", "arguments": '{"query":"x"}'}}
                ],
            }
        else:
            message = {"role": "assistant", "content": '{"items": ["salvaged"]}'}
        resp.json.return_value = {"choices": [{"message": message, "finish_reason": "stop"}]}
        return resp

    with patch("requests.post", side_effect=post):
        content, _thinking, _log = agentic_openai_query(
            prompt="p",
            system_prompt="s",
            model="qwen",
            openai_url="http://localhost:12345/v1",
            search_func=MagicMock(return_value=["result"]),
            max_iterations=3,
        )

    assert content == '{"items": ["salvaged"]}'
    # Only the closing pass withholds the tools; every earlier one still offers them.
    assert [("tools" in p) for p in payloads] == [True, True, True, False]
    # The model is told the budget is gone before that closing pass, not left to guess.
    assert any(
        m.get("role") == "user" and "no tool calls left" in m.get("content", "") for m in payloads[-1]["messages"]
    )


def test_agentic_loop_still_raises_when_final_pass_yields_nothing():
    """If the model emits tool calls even with the tools withheld, there is nothing usable to
    render, so the loop must fail loudly rather than return empty content that would be shown
    as a clean 'no findings' section."""
    clear_tool_cache()

    def post(url, json=None, headers=None, timeout=None, stream=None):
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "c1",
                                "type": "function",
                                "function": {"name": "web_search", "arguments": '{"query":"x"}'},
                            }
                        ],
                    },
                    "finish_reason": "stop",
                }
            ]
        }
        return resp

    with patch("requests.post", side_effect=post):
        with pytest.raises(ModelOutputTruncatedError, match="max_iterations"):
            agentic_openai_query(
                prompt="p",
                system_prompt="s",
                model="qwen",
                openai_url="http://localhost:12345/v1",
                search_func=MagicMock(return_value=["result"]),
                max_iterations=2,
            )


def test_agentic_openai_loop_request_failure_raises():
    """A network error from the OpenAI POST is re-raised as a RuntimeError."""
    clear_tool_cache()
    with patch("requests.post", side_effect=requests.exceptions.ConnectionError("down")):
        with pytest.raises(RuntimeError, match="OpenAI API request failed"):
            agentic_openai_query(
                prompt="p",
                system_prompt="s",
                model="qwen",
                openai_url="http://localhost:12345/v1",
                search_func=MagicMock(),
            )


def test_query_llm_direct_openai():
    """query_llm_direct queries OpenAI successfully."""
    from scanner.util.tool_runner import query_llm_direct

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"choices": [{"message": {"content": "openai reply"}}]}

    with patch("requests.post", return_value=mock_response) as mock_post:
        res = query_llm_direct("user prompt", "sys prompt", "model", "http://openai/v1", format_json=True)
        assert res == "openai reply"
        mock_post.assert_called_once()
        payload = mock_post.call_args[1]["json"]
        assert payload["model"] == "model"
        assert payload["response_format"] == {"type": "json_object"}


def test_openai_headers_omit_authorization_without_api_key():
    set_api_key(None)
    assert "Authorization" not in _openai_headers()


def test_openai_headers_include_bearer_token_when_api_key_set():
    set_api_key("secret-token")
    assert _openai_headers()["Authorization"] == "Bearer secret-token"
    set_api_key(None)


def test_set_request_timeouts():
    import scanner.util.tool_runner as tr

    set_request_timeouts(120, 60)
    assert tr.OPENAI_REQUEST_TIMEOUT == 120
    assert tr.OPENAI_DIRECT_REQUEST_TIMEOUT == 60
    set_request_timeouts(900, 300)


def test_agentic_openai_query_sends_authorization_header():
    set_api_key("secret-token")
    try:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"choices": [{"message": {"content": "done"}}]}

        with patch("scanner.util.tool_runner.requests.post", return_value=mock_resp) as mock_post:
            agentic_openai_query("p", "s", "model", "http://api", MagicMock())

        assert mock_post.call_args[1]["headers"]["Authorization"] == "Bearer secret-token"
    finally:
        set_api_key(None)


def test_direct_openai_query_retries_without_response_format_on_400():
    rejected = MagicMock()
    rejected.status_code = 400
    accepted = MagicMock()
    accepted.status_code = 200
    accepted.json.return_value = {"choices": [{"message": {"content": "plain reply"}}]}

    payload = {"model": "m", "messages": [], "response_format": {"type": "json_object"}}
    with patch("scanner.util.tool_runner.requests.post", side_effect=[rejected, accepted]) as mock_post:
        result = _query_openai_direct("http://api/chat/completions", payload)

    assert result == "plain reply"
    assert mock_post.call_count == 2
    assert "response_format" not in mock_post.call_args_list[1][1]["json"]
    # The caller's payload must not be mutated by the retry path.
    assert "response_format" in payload


def test_direct_openai_query_does_not_retry_400_without_response_format():
    rejected = MagicMock()
    rejected.status_code = 400
    rejected.raise_for_status.side_effect = requests.exceptions.HTTPError("400")

    with patch("scanner.util.tool_runner.requests.post", return_value=rejected) as mock_post:
        with pytest.raises(BackendAPIError):
            _query_openai_direct("http://api/chat/completions", {"model": "m", "messages": []})
    assert mock_post.call_count == 1


def test_agentic_openai_query_raises_backend_api_error_on_network_failure():
    """agentic_openai_query raises BackendAPIError on HTTP or network failure."""
    with patch(
        "scanner.util.tool_runner.requests.post",
        side_effect=requests.exceptions.ConnectionError("Connection refused"),
    ):
        with pytest.raises(BackendAPIError) as exc_info:
            agentic_openai_query("prompt", "sys", "model", "http://api", MagicMock())
    assert "Connection refused" in str(exc_info.value)


def _make_truncated_response(content=None, tool_calls=None, finish_reason="length", completion_tokens=32768):
    """Builds a mock response that reports how the completion ended and what it cost."""
    msg: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls:
        msg["tool_calls"] = tool_calls
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [{"message": msg, "finish_reason": finish_reason}],
        "usage": {"completion_tokens": completion_tokens},
    }
    return mock_resp


def test_agentic_openai_raises_when_budget_exhausted_before_any_output():
    """An empty finish_reason='length' reply must raise, not be treated as 'no findings'."""
    truncated = _make_truncated_response(content=None, finish_reason="length", completion_tokens=32768)
    with patch("scanner.util.tool_runner.requests.post", return_value=truncated):
        with pytest.raises(ModelOutputTruncatedError, match="completion budget"):
            agentic_openai_query("p", "s", "model", "http://api", MagicMock())


def test_agentic_openai_accepts_truncated_reply_that_still_has_content():
    """A length-limited reply that produced text is still usable and must not raise."""
    partial = _make_truncated_response(content="partial answer", finish_reason="length")
    with patch("scanner.util.tool_runner.requests.post", return_value=partial):
        content, _, _ = agentic_openai_query("p", "s", "model", "http://api", MagicMock())
    assert content == "partial answer"


def test_agentic_openai_raises_when_tool_loop_is_exhausted():
    """Hitting the iteration cap mid-tool-call must fail loudly rather than return ''."""
    pending = _make_truncated_response(
        content=None,
        tool_calls=[{"id": "1", "function": {"name": "web_search", "arguments": '{"query": "x"}'}}],
        finish_reason="tool_calls",
    )
    search = MagicMock(return_value=["snippet"])
    with patch("scanner.util.tool_runner.requests.post", return_value=pending):
        with pytest.raises(ModelOutputTruncatedError, match="max_iterations"):
            agentic_openai_query("p", "s", "model", "http://api", search, max_iterations=2)


def test_direct_openai_query_raises_on_empty_truncated_reply():
    """The non-agentic path must also refuse an empty budget-exhausted response."""
    truncated = _make_truncated_response(content="", finish_reason="length", completion_tokens=8192)
    with patch("scanner.util.tool_runner.requests.post", return_value=truncated):
        with pytest.raises(ModelOutputTruncatedError):
            _query_openai_direct("http://api/chat/completions", {"model": "m", "messages": []})


def test_openai_payload_carries_the_raised_token_ceiling():
    """The completion budget is always sent, and capped so a truncation fails cheaply."""
    assert OPENAI_MAX_TOKENS == 16384
    resp = _make_truncated_response(content="done", finish_reason="stop")
    with patch("scanner.util.tool_runner.requests.post", return_value=resp) as mock_post:
        agentic_openai_query("p", "s", "model", "http://api", MagicMock())
    assert mock_post.call_args[1]["json"]["max_tokens"] == OPENAI_MAX_TOKENS


def test_thinking_is_enabled_by_default():
    """Reasoning stays on unless a deployment explicitly turns it off."""
    set_thinking_enabled(True)
    resp = _make_truncated_response(content="done", finish_reason="stop")
    with patch("scanner.util.tool_runner.requests.post", return_value=resp) as mock_post:
        agentic_openai_query("p", "s", "model", "http://api", MagicMock())
    assert "chat_template_kwargs" not in mock_post.call_args[1]["json"]


def test_disabling_thinking_sets_the_chat_template_flag():
    """The flag the server actually honours is chat_template_kwargs.enable_thinking."""
    set_thinking_enabled(False)
    try:
        resp = _make_truncated_response(content="done", finish_reason="stop")
        with patch("scanner.util.tool_runner.requests.post", return_value=resp) as mock_post:
            agentic_openai_query("p", "s", "model", "http://api", MagicMock())
        assert mock_post.call_args[1]["json"]["chat_template_kwargs"] == {"enable_thinking": False}
    finally:
        set_thinking_enabled(True)


def test_web_search_tool_requests_only_the_top_results():
    """Each extra snippet costs input tokens and deliberation time on a reasoning model."""
    assert SEARCH_RESULT_LIMIT == 3
    clear_tool_cache()
    fake_search = MagicMock(return_value=["a", "b", "c"])
    execute_tool_call("web_search", {"query": "x"}, fake_search)
    assert fake_search.call_args[1]["max_results"] == SEARCH_RESULT_LIMIT


def test_openai_loop_executes_multiple_tool_calls_in_one_round():
    """Several tool calls returned together are all executed and all fed back."""
    clear_tool_cache()
    round1 = _make_truncated_response(
        content=None,
        finish_reason="tool_calls",
        tool_calls=[
            {"id": "a", "function": {"name": "web_search", "arguments": '{"query": "one"}'}},
            {"id": "b", "function": {"name": "lookup_nvd_cve", "arguments": '{"cve_id": "CVE-2024-1"}'}},
        ],
    )
    round2 = _make_truncated_response(content='{"no_findings": true}', finish_reason="stop")
    search = MagicMock(return_value=["snippet"])

    with (
        patch("scanner.util.tool_runner.requests.post", side_effect=[round1, round2]) as mock_post,
        patch("scanner.util.tool_runner.lookup_nvd_cve", return_value="CVSS 9.8"),
    ):
        _content, _thinking, log = agentic_openai_query("p", "s", "model", "http://api", search)

    assert [entry["tool_name"] for entry in log] == ["web_search", "lookup_nvd_cve"]
    # Both results must reach the model as separate role=tool messages keyed by call id.
    sent = mock_post.call_args_list[1][1]["json"]["messages"]
    tool_msgs = [m for m in sent if m.get("role") == "tool"]
    assert {m["tool_call_id"] for m in tool_msgs} == {"a", "b"}


def test_openai_stream_labels_only_genuine_cache_hits():
    """The '(cached)' stream label appears on a repeat call, never on the first one."""
    clear_tool_cache()
    received: list[str] = []
    call = {"index": 0, "id": "a", "function": {"name": "web_search", "arguments": '{"query": "okhttp"}'}}

    def _sse(chunks):
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        resp.iter_lines.return_value = [f"data: {json.dumps(c)}".encode() for c in chunks] + [b"data: [DONE]"]
        return resp

    # The same call is issued twice across two rounds: first a genuine miss, then a cache hit.
    responses = [
        _sse([{"choices": [{"delta": {"tool_calls": [call]}}]}]),
        _sse([{"choices": [{"delta": {"tool_calls": [call]}}]}]),
        _sse([{"choices": [{"delta": {"content": "done"}}]}]),
    ]
    with patch("scanner.util.tool_runner.requests.post", side_effect=responses):
        agentic_openai_query(
            "p", "s", "model", "http://api", MagicMock(return_value=["snippet"]), stream_callback=received.append
        )

    tool_lines = [c for c in received if c.startswith("\n[tool]")]
    assert len(tool_lines) == 2
    assert "(cached)" not in tool_lines[0]
    assert "(cached)" in tool_lines[1]
