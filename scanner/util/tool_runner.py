"""Agentic tool-calling engine for the AI security report generator.

Implements the OpenAI-compatible ReAct loop: the model calls tools on demand, results
are fed back as ``role=tool`` messages, and the cycle repeats until the model
produces its final JSON response or the iteration cap is reached.

Provides five tools to the model, all implemented in :mod:`scanner.web`:
- ``web_search`` — DuckDuckGo search through the Playwright scraper container.
- ``lookup_maven_version`` — latest version from Google Maven / Maven Central.
- ``lookup_osv_vulnerabilities`` — CVE list from OSV.dev for a specific package version.
- ``lookup_nvd_cve`` — full CVSS v3 score, vector, and CWE from NVD/NIST for a CVE ID.
- ``lookup_play_store`` — app metadata scraped directly from the Google Play Store.

Identical tool calls are deduplicated for the lifetime of a single
``generate_ai_report()`` run and retried with exponential backoff on transient
network failures.
"""

import json
import time
from collections.abc import Callable
from typing import Any

import instructor
import requests
from loguru import logger
from openai import OpenAI

from scanner.web.lookups import lookup_maven_version, lookup_nvd_cve, lookup_osv_vulnerabilities
from scanner.web.playstore import lookup_play_store
from scanner.web.search import SearchBlockedError, search_ddg

# Hosted OpenAI-compatible endpoints require bearer authentication.
# Configured explicitly via CLI arguments through set_api_key().
_AI_API_KEY: str | None = None

# Snippets handed to the model per search. Each one costs input tokens and, on a reasoning
# model, deliberation time, so the count is kept to the few most relevant results.
SEARCH_RESULT_LIMIT = 3

# Completion budget for OpenAI-compatible requests. Reasoning models can spend the whole
# budget on internal reasoning before emitting a single visible token, so a ceiling that
# merely fits the answer is not enough: at 16384 a vulnerabilities section came back
# completely empty with finish_reason='length'. The field is always sent, because an
# endpoint that receives no max_tokens substitutes a preset of its own that may exceed
# the model's context window and reject the request outright.
OPENAI_MAX_TOKENS = 16384
OPENAI_DIRECT_MAX_TOKENS = 8192

# Timeout in seconds for individual OpenAI-compatible HTTP requests.
# Configurable via CLI arguments through set_request_timeouts().
OPENAI_REQUEST_TIMEOUT = 900
OPENAI_DIRECT_REQUEST_TIMEOUT = 300


def set_api_key(api_key: str | None) -> None:
    """Sets the API key used for OpenAI-compatible endpoint authentication.

    Args:
        api_key (str | None): Bearer token or None if unauthenticated.
    """
    global _AI_API_KEY
    _AI_API_KEY = api_key.strip() if api_key else None


def set_request_timeouts(request_timeout: int = 900, direct_request_timeout: int = 300) -> None:
    """Sets the request timeouts in seconds for OpenAI-compatible requests.

    Args:
        request_timeout (int): Timeout in seconds for agentic loop turns (default 900).
        direct_request_timeout (int): Timeout in seconds for direct queries (default 300).
    """
    global OPENAI_REQUEST_TIMEOUT, OPENAI_DIRECT_REQUEST_TIMEOUT
    OPENAI_REQUEST_TIMEOUT = request_timeout
    OPENAI_DIRECT_REQUEST_TIMEOUT = direct_request_timeout


def get_instructor_client(
    openai_url: str,
    api_key: str | None = None,
    mode: instructor.Mode = instructor.Mode.JSON,
    timeout: float | None = None,
) -> instructor.Instructor:
    """Returns an Instructor-wrapped OpenAI client pointing to the given OpenAI-compatible URL.

    Args:
        openai_url (str): The base URL of the OpenAI-compatible API.
        api_key (str | None): Optional bearer token or API key.
        mode (instructor.Mode): Extraction mode (defaults to Mode.JSON for local model compatibility).
        timeout (float | None): Request timeout in seconds.

    Returns:
        instructor.Instructor: Configured Instructor client.
    """
    key = (api_key or _AI_API_KEY or "sk-optiq-local").strip()
    base_url = openai_url.rstrip("/")
    if not base_url.endswith("/v1"):
        base_url = f"{base_url}/v1"

    client = OpenAI(
        base_url=base_url,
        api_key=key,
        timeout=timeout or OPENAI_DIRECT_REQUEST_TIMEOUT,
    )
    return instructor.from_openai(client, mode=mode)


# Reasoning models decide for themselves how long to deliberate, and a local model that
# reasons without limit can spend an entire budget before writing anything. Thinking stays
# on by default because it is where analysis quality comes from; disabling it is a
# deployment choice for backends where the deliberation cost is not affordable.
_THINKING_ENABLED = True


# Within-run deduplication of identical tool calls: parallel section threads frequently
# request the same lookup, and repeating it would only add latency and block risk. This
# is process-local state with no persistence — nothing survives beyond a single run.
_TOOL_CACHE: dict[tuple, str] = {}


def clear_tool_cache() -> None:
    """Clears the in-run tool result dedup store.

    Must be called once at the start of each ``generate_ai_report()`` invocation
    to prevent stale results from a previous scan leaking into the current one.
    """
    _TOOL_CACHE.clear()
    logger.debug("Tool result cache cleared.")


ALL_TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": (
                "Search the web for current information. Use for domain reputation, "
                "remediation guides, general Android security topics, or anything the "
                "structured tools cannot answer directly."
            ),
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string", "description": "The search query string."}},
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_maven_version",
            "description": (
                "Look up the latest published version of a Maven/Gradle library. "
                "Always use this instead of web_search when you need a library version number."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "group": {
                        "type": "string",
                        "description": "Maven group ID (the reverse-DNS group portion of the coordinate).",
                    },
                    "artifact": {
                        "type": "string",
                        "description": "Maven artifact ID (the artifact portion of the coordinate).",
                    },
                },
                "required": ["group", "artifact"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_osv_vulnerabilities",
            "description": (
                "Look up known CVEs and security vulnerabilities for a specific library version "
                "using the OSV.dev database. Always call this before reporting on any "
                "dependency's security status."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "package": {
                        "type": "string",
                        "description": "Full Maven coordinate in group:artifact form.",
                    },
                    "version": {
                        "type": "string",
                        "description": "The exact version string to check.",
                    },
                },
                "required": ["package", "version"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_nvd_cve",
            "description": (
                "Get the full CVSS v3 base score, severity label, attack vector string, "
                "CWE classification, and publication date for a specific CVE ID from the "
                "NVD/NIST database. Always call this when you have a specific CVE ID to "
                "verify its severity — do not rely on memory."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "The CVE identifier, in the form CVE-YYYY-NNNNN.",
                    }
                },
                "required": ["cve_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_play_store",
            "description": (
                "Fetch current app metadata from the Google Play Store for a given Android "
                "package ID. Use this to find the app name, developer, description, and "
                "active/discontinued status."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "package_id": {
                        "type": "string",
                        "description": "The application's Android package ID.",
                    }
                },
                "required": ["package_id"],
            },
        },
    },
]


def _impl_web_search(query: str, search_func: Callable) -> str:
    """Executes a web search using the provided search function.

    Args:
        query (str): The search query string.
        search_func (Callable): The search function (DuckDuckGo by default).

    Returns:
        str: Formatted snippet results string for the model.
    """
    snippets = search_func(query, max_results=SEARCH_RESULT_LIMIT)
    if not snippets:
        return f"No results found for query: {query}"
    return "\n".join(f"- {s}" for s in snippets)


def resolve_search_func() -> Callable:
    """Resolves the search function used for the ``web_search`` tool.

    DuckDuckGo through the Playwright scraper container is the only backend. If no
    scraper URL is configured the function is still returned; each call then fails
    fast and is reported to the model as an unavailable tool.

    Returns:
        Callable: The DuckDuckGo search function.
    """
    from scanner.web.scraper import SCRAPER_URL

    if SCRAPER_URL:
        logger.info("Web search enabled: DuckDuckGo via scraper container.")
    else:
        logger.info("No scraper URL configured. Web search tool will be unavailable.")
    return search_ddg


_SCRAPER_TOOLS = {"web_search", "lookup_play_store"}
_MAX_RETRIES = 3

# Failures where a retry cannot possibly succeed: a bot-check page will not disappear
# within the backoff window (hammering it makes the block worse), and a missing scraper
# configuration never fixes itself mid-run.
_NON_RETRYABLE_EXCEPTIONS = (SearchBlockedError, ValueError)


def _with_retry(tool_name: str, fn: Callable[[], str]) -> str:
    """Executes a tool implementation function with exponential backoff on failure.

    Args:
        tool_name (str): Name of the tool being called (used for delay tuning).
        fn (Callable[[], str]): Zero-argument callable that performs the tool call.

    Returns:
        str: The result string from the tool on success.

    Raises:
        RuntimeError: If all retry attempts are exhausted or the failure is non-retryable.
    """
    # Scraper-based tools use a longer initial delay to account for Playwright startup
    initial_delay = 2.0 if tool_name in _SCRAPER_TOOLS else 1.0

    last_exc: Exception | None = None
    for attempt in range(_MAX_RETRIES):
        try:
            return fn()
        except _NON_RETRYABLE_EXCEPTIONS as e:
            logger.error(f"Tool '{tool_name}' failed with non-retryable error: {e}")
            raise RuntimeError(f"Tool '{tool_name}' failed: {e}") from e
        except Exception as e:
            last_exc = e
            if attempt < _MAX_RETRIES - 1:
                delay = initial_delay * (2**attempt)
                logger.warning(
                    f"Tool '{tool_name}' attempt {attempt + 1}/{_MAX_RETRIES} failed: {e}. Retrying in {delay:.1f}s..."
                )
                time.sleep(delay)
            else:
                logger.error(f"Tool '{tool_name}' failed after {_MAX_RETRIES} attempts: {e}")

    raise RuntimeError(f"Tool '{tool_name}' exhausted all retries.") from last_exc


def _cache_key(tool_name: str, tool_args: dict) -> tuple:
    """Builds the stable dedup key identifying one tool invocation.

    Args:
        tool_name (str): The name of the tool being called.
        tool_args (dict): Arguments parsed from the model's tool call.

    Returns:
        tuple: A hashable key combining the tool name with its sorted arguments.
    """
    return (tool_name, tuple(sorted(tool_args.items())))


def is_cached_tool_call(tool_name: str, tool_args: dict) -> bool:
    """Whether this exact tool call would be served from the in-run dedup store.

    Must be consulted *before* :func:`execute_tool_call`, which stores every successful
    result and would therefore always report a hit afterwards.

    Args:
        tool_name (str): The name of the tool being called.
        tool_args (dict): Arguments parsed from the model's tool call.

    Returns:
        bool: True if a stored result already exists for this call.
    """
    return _cache_key(tool_name, tool_args) in _TOOL_CACHE


def execute_tool_call(
    tool_name: str,
    tool_args: dict,
    search_func: Callable,
) -> str:
    """Dispatches a single tool call, applying the in-run dedup store and retry logic.

    Checks ``_TOOL_CACHE`` first; on a hit the stored result is returned immediately
    without any network call. On a miss the appropriate implementation is invoked via
    ``_with_retry``. Successful results are stored; failed results are not.

    Args:
        tool_name (str): The name of the tool to execute.
        tool_args (dict): Arguments parsed from the model's tool call.
        search_func (Callable): Search function to use for ``web_search`` calls.

    Returns:
        str: The tool result string to be fed back to the model as a ``role=tool`` message.
    """
    cache_key = _cache_key(tool_name, tool_args)
    if cache_key in _TOOL_CACHE:
        logger.debug(f"[tool cache hit] {tool_name}({tool_args})")
        return _TOOL_CACHE[cache_key]

    logger.info(f"[tool call] {tool_name}({tool_args})")

    try:
        if tool_name == "web_search":
            query = tool_args.get("query", "")
            result = _with_retry(tool_name, lambda: _impl_web_search(query, search_func))

        elif tool_name == "lookup_maven_version":
            group = tool_args.get("group", "")
            artifact = tool_args.get("artifact", "")
            result = _with_retry(tool_name, lambda: lookup_maven_version(group, artifact))

        elif tool_name == "lookup_osv_vulnerabilities":
            package = tool_args.get("package", "")
            version = tool_args.get("version", "")
            result = _with_retry(tool_name, lambda: lookup_osv_vulnerabilities(package, version))

        elif tool_name == "lookup_nvd_cve":
            cve_id = tool_args.get("cve_id", "")
            result = _with_retry(tool_name, lambda: lookup_nvd_cve(cve_id))

        elif tool_name == "lookup_play_store":
            package_id = tool_args.get("package_id", "")
            result = _with_retry(tool_name, lambda: lookup_play_store(package_id))

        else:
            logger.warning(f"Unknown tool requested by model: '{tool_name}'. Returning error.")
            return f"Error: Unknown tool '{tool_name}'. Available tools: web_search, lookup_maven_version, lookup_osv_vulnerabilities, lookup_nvd_cve, lookup_play_store."

    except RuntimeError as e:
        # All retries exhausted (or non-retryable) — return a graceful error string to the model
        error_msg = f"Tool '{tool_name}' failed after all retries: {e}"
        logger.error(error_msg)
        return error_msg

    _TOOL_CACHE[cache_key] = result
    return result


def set_thinking_enabled(enabled: bool) -> None:
    """Sets whether OpenAI-compatible requests ask the model to reason before answering.

    Args:
        enabled (bool): False to send ``chat_template_kwargs.enable_thinking = false``.
    """
    global _THINKING_ENABLED
    _THINKING_ENABLED = enabled
    logger.info(f"Model thinking {'enabled' if enabled else 'disabled'}.")


def _apply_thinking_mode(payload: dict) -> dict:
    """Adds the chat-template flag that turns the model's reasoning phase off.

    Args:
        payload (dict): The request body, mutated in place.

    Returns:
        dict: The same payload, for call-site convenience.
    """
    if not _THINKING_ENABLED:
        payload["chat_template_kwargs"] = {"enable_thinking": False}
    return payload


class ModelOutputTruncatedError(RuntimeError):
    """Raised when the model hit its completion budget before producing any output.

    A reasoning model that exhausts ``max_tokens`` while still reasoning returns an empty
    message with ``finish_reason='length'``. That is indistinguishable from a legitimate
    "nothing to report" answer unless it is raised, and silently treating it as data turns
    a resource limit into a clean bill of health.
    """


class BackendAPIError(RuntimeError):
    """Raised when an OpenAI-compatible API backend request fails.

    Indicates an unrecoverable infrastructure, network, timeout, or authentication failure
    on the LLM endpoint (e.g. 401 Unauthorized, 504 Gateway Timeout, Connection Refused)
    that must fail fast rather than stalling the pipeline across all sections.
    """


def _raise_if_truncated(response: dict, content: str, tool_calls: list) -> None:
    """Rejects a response whose completion budget ran out before any content was produced.

    Args:
        response (dict): The parsed chat completion response.
        content (str): Content extracted from the assistant message.
        tool_calls (list): Tool calls extracted from the assistant message.

    Raises:
        ModelOutputTruncatedError: If the model returned neither content nor tool calls
            because it hit the token ceiling.
    """
    choices = response.get("choices") or []
    finish_reason = choices[0].get("finish_reason") if choices else None
    if finish_reason == "length" and not content.strip() and not tool_calls:
        used = (response.get("usage") or {}).get("completion_tokens")
        raise ModelOutputTruncatedError(
            f"Model produced no output before exhausting its completion budget "
            f"(finish_reason='length', completion_tokens={used})."
        )


def _openai_headers() -> dict[str, str]:
    """Builds request headers for an OpenAI-compatible endpoint.

    Adds a bearer token when an API key has been explicitly configured via :func:`set_api_key`.

    Returns:
        dict[str, str]: Headers for the outgoing request.
    """
    headers = {"Content-Type": "application/json"}
    if _AI_API_KEY:
        headers["Authorization"] = f"Bearer {_AI_API_KEY}"
    return headers


def _accumulate_openai_stream(
    response: requests.Response,
    stream_callback: Callable[[str], None],
) -> tuple[str, str, list[dict]]:
    """Accumulates streamed response chunks from an OpenAI-compatible endpoint.

    Args:
        response (requests.Response): The streaming response.
        stream_callback (Callable[[str], None]): Token streaming callback.

    Returns:
        tuple[str, str, list[dict]]: A tuple of (full_content, thinking_content, tool_calls_list).
    """
    full_content = ""
    thinking_content = ""
    tool_calls_from_stream: list[dict] = []

    for line in response.iter_lines():
        if not line:
            continue
        line_str = line.decode("utf-8").strip()
        if line_str.startswith("data: "):
            data_content = line_str[6:]
            if data_content == "[DONE]":
                break
            try:
                chunk = json.loads(data_content)
                choice = chunk["choices"][0]
                delta = choice.get("delta", {})
            except (json.JSONDecodeError, KeyError, IndexError):
                continue

            # Capture reasoning if model emits reasoning_content, thinking, or reasoning
            reasoning_delta = delta.get("reasoning") or delta.get("reasoning_content") or delta.get("thinking")
            if reasoning_delta:
                thinking_content += reasoning_delta

            delta_content = delta.get("content", "")
            if delta_content:
                full_content += delta_content
                stream_callback(delta_content)

            # Capture tool calls from delta chunks
            if delta.get("tool_calls"):
                for tc_delta in delta["tool_calls"]:
                    idx = tc_delta.get("index", 0)
                    while len(tool_calls_from_stream) <= idx:
                        tool_calls_from_stream.append(
                            {"id": "", "type": "function", "function": {"name": "", "arguments": ""}}
                        )

                    tc_entry = tool_calls_from_stream[idx]
                    if tc_delta.get("id"):
                        tc_entry["id"] += tc_delta["id"]

                    fn_delta = tc_delta.get("function", {})
                    if fn_delta.get("name"):
                        tc_entry["function"]["name"] += fn_delta["name"]
                    if fn_delta.get("arguments"):
                        tc_entry["function"]["arguments"] += fn_delta["arguments"]

    # Filter out empty tool calls
    filtered_tool_calls = [tc for tc in tool_calls_from_stream if tc.get("id") or tc.get("function", {}).get("name")]
    return full_content, thinking_content, filtered_tool_calls


def _execute_openai_tool_calls(
    tool_calls: list[dict],
    messages: list[dict],
    tool_call_log: list[dict],
    search_func: Callable,
    stream_callback: Callable[[str], None] | None = None,
) -> None:
    """Executes tool calls for OpenAI, updates conversation history and log.

    Args:
        tool_calls (list[dict]): Tool calls list to execute.
        messages (list[dict]): Conversation messages history (mutated in-place).
        tool_call_log (list[dict]): Cumulative log of tool calls (mutated in-place).
        search_func (Callable): Search fallback function.
        stream_callback (Callable[[str], None] | None): Optional stream token callback.
    """
    for tc in tool_calls:
        tc_id = tc.get("id")
        fn = tc.get("function", {})
        tool_name = fn.get("name", "")
        raw_args = fn.get("arguments", {})

        if isinstance(raw_args, str):
            try:
                tool_args = json.loads(raw_args)
            except json.JSONDecodeError:
                tool_args = {}
        else:
            tool_args = raw_args

        tool_call_log.append({"tool_name": tool_name, "args": tool_args})

        # Probed before the call: execute_tool_call stores every success, so a check
        # afterwards would report a hit for each first-time call as well.
        cached = is_cached_tool_call(tool_name, tool_args)
        result = execute_tool_call(tool_name, tool_args, search_func)

        if stream_callback:
            cache_label = " (cached)" if cached else ""
            stream_callback(f"\n[tool]{cache_label} {tool_name}({tool_args}) → {result[:80]}...\n")

        messages.append({"role": "tool", "tool_call_id": tc_id, "name": tool_name, "content": result})


def agentic_openai_query(
    prompt: str,
    system_prompt: str,
    model: str,
    openai_url: str,
    search_func: Callable,
    max_iterations: int = 10,
    stream_callback: Callable[[str], None] | None = None,
    format_json: bool = False,
) -> tuple[str, str, list[dict]]:
    """Runs the OpenAI-compatible ReAct (Reasoning + Acting) agentic loop.

    Posts a chat request to an OpenAI-compatible ``/chat/completions`` endpoint with the full
    tool schema. If the model returns tool calls, executes them and feeds results back as
    ``role=tool`` messages keyed by ``tool_call_id``, then re-posts. Repeats until the model
    produces a plain response (no tool calls) or ``max_iterations`` is reached.

    Args:
        prompt (str): The user-turn prompt content.
        system_prompt (str): The system prompt content.
        model (str): Name of the model to use.
        openai_url (str): Base URL of the OpenAI-compatible service; the
            ``/chat/completions`` suffix is appended when absent.
        search_func (Callable): Search function for ``web_search`` tool dispatch.
        max_iterations (int): Maximum number of tool-call rounds before forcing exit.
        stream_callback (Callable[[str], None] | None): Optional callback that receives
            each streamed token chunk for real-time terminal output.
        format_json (bool): If True, requests a JSON object response format.

    Returns:
        tuple[str, str, list[dict]]: A tuple of
            ``(final_content, thinking_content, tool_call_log)`` where
            ``tool_call_log`` is a list of dicts with ``tool_name`` and ``args`` keys.

    Raises:
        RuntimeError: If the HTTP request to the model service fails.
    """
    messages: list[dict] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt},
    ]

    tool_call_log: list[dict] = []
    thinking_content = ""
    api_url = openai_url.rstrip("/")
    if not api_url.endswith("/chat/completions"):
        api_url = f"{api_url}/chat/completions"

    use_stream = stream_callback is not None

    for iteration in range(max_iterations + 1):
        # On the final pass the tools are withheld so the model cannot start another round
        # of research it has no budget left to finish; it must answer from what it already
        # gathered. Weaker models otherwise keep calling tools until the budget runs out and
        # the entire chunk is discarded, which is what drops whole batches of findings.
        final_pass = iteration >= max_iterations
        payload: dict = {
            "model": model,
            "messages": messages,
            "stream": use_stream,
            "temperature": 0.1,
            "max_tokens": OPENAI_MAX_TOKENS,
        }
        if not final_pass:
            payload["tools"] = ALL_TOOLS
        if format_json:
            payload["response_format"] = {"type": "json_object"}
        _apply_thinking_mode(payload)

        try:
            headers = _openai_headers()
            response = requests.post(
                api_url, json=payload, headers=headers, timeout=OPENAI_REQUEST_TIMEOUT, stream=use_stream
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise BackendAPIError(f"OpenAI API request failed: {e}") from e

        # Streaming path
        if use_stream:
            full_content, thinking_delta, tool_calls = _accumulate_openai_stream(response, stream_callback)
            thinking_content += thinking_delta
            message_data: dict[str, Any] = {"role": "assistant", "content": full_content}
            if tool_calls:
                message_data["tool_calls"] = tool_calls

        # Non-streaming path
        else:
            res_data = response.json()
            message_data = res_data["choices"][0]["message"]
            thinking_content = (
                message_data.get("reasoning")
                or message_data.get("reasoning_content")
                or message_data.get("thinking")
                or ""
            ).strip()
            tool_calls = message_data.get("tool_calls") or []
            _raise_if_truncated(res_data, message_data.get("content") or "", tool_calls)

        # Check for tool calls
        if not tool_calls:
            # Model produced its final answer
            final_content = message_data.get("content", "").strip()
            if use_stream and stream_callback:
                stream_callback("\n")
            return final_content, thinking_content, tool_call_log

        if final_pass:
            # Tools were withheld above, so a model still emitting tool calls has produced
            # nothing usable. Returning empty content here would be rendered as "no
            # findings", so an exhausted loop has to fail loudly instead.
            raise ModelOutputTruncatedError(
                f"Agentic loop hit max_iterations={max_iterations} with tool calls still pending."
            )

        # Append assistant message (with tool_calls)
        messages.append(message_data)

        if iteration == max_iterations - 1:
            # One round left: tell the model plainly, so it stops researching and spends the
            # final turn writing the answer instead of being cut off mid-investigation.
            # Must use role 'user' as servers reject mid-conversation 'system' messages.
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "You have no tool calls left. Answer now with the final JSON object, "
                        "using only the information you have already gathered. For anything you "
                        "could not verify, say so plainly instead of omitting the entry."
                    ),
                }
            )

        # Execute tool calls and append results matching tool_call_id
        _execute_openai_tool_calls(tool_calls, messages, tool_call_log, search_func, stream_callback)

    return "", thinking_content, tool_call_log


def _query_openai_direct(api_url: str, payload: dict) -> str:
    """Sends direct OpenAI API request.

    Args:
        api_url (str): Target HTTP url.
        payload (dict): JSON body payload.

    Returns:
        str: Response message content.
    """
    headers = _openai_headers()
    try:
        res = requests.post(api_url, json=payload, headers=headers, timeout=OPENAI_DIRECT_REQUEST_TIMEOUT)

        # Not every backend implements the same JSON mode: some accept only
        # response_format=json_schema and reject json_object outright. The schema is already
        # spelled out in the prompt, so dropping the constraint costs nothing but a retry.
        if res.status_code == 400 and "response_format" in payload:
            logger.warning("Endpoint rejected response_format; retrying without constrained JSON mode.")
            retry_payload = {k: v for k, v in payload.items() if k != "response_format"}
            res = requests.post(api_url, json=retry_payload, headers=headers, timeout=OPENAI_DIRECT_REQUEST_TIMEOUT)

        res.raise_for_status()
        data = res.json()
        content = (data["choices"][0]["message"].get("content") or "").strip()
        _raise_if_truncated(data, content, [])
        return content
    except ModelOutputTruncatedError:
        raise
    except requests.exceptions.RequestException as e:
        raise BackendAPIError(f"Direct OpenAI query failed: {e}") from e
    except Exception as e:
        raise RuntimeError(f"Direct OpenAI query failed: {e}") from e


def query_llm_direct(
    prompt: str,
    system_prompt: str,
    model: str,
    openai_url: str,
    format_json: bool = False,
) -> str:
    """Sends a single-turn chat completion request without tools.

    Used for non-agentic structural tasks (like JSON parsing or formatting) where
    the model needs to focus 100% of its capacity on constraints.

    Args:
        prompt (str): The user query prompt.
        system_prompt (str): The system prompt.
        model (str): Name of the model to query.
        openai_url (str): Base URL of the OpenAI-compatible service.
        format_json (bool): If True, forces the response to be in valid JSON.

    Returns:
        str: The raw text response content from the model.

    Raises:
        RuntimeError: If the HTTP request to the model service fails.
    """
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt},
    ]

    api_url = openai_url.rstrip("/")
    if not api_url.endswith("/chat/completions"):
        api_url = f"{api_url}/chat/completions"
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": OPENAI_DIRECT_MAX_TOKENS,
    }
    if format_json:
        payload["response_format"] = {"type": "json_object"}
    _apply_thinking_mode(payload)
    return _query_openai_direct(api_url, payload)
