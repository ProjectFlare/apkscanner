"""Unit tests for the main entrypoint and CLI interface of the APK Scanner."""

import sys
import unittest.mock as mock_lib
from unittest.mock import MagicMock

import pytest

from main import (
    InterceptHandler,
    _configure_logging,
    _load_apk,
    _load_dex_files,
    _resolve_scraper_url,
    _save_report,
    _validate_args,
)


def test_log_filter_suppresses_androguard_below_error():
    """Verifies that Androguard records below ERROR are suppressed when not verbose."""
    from main import InterceptHandler, _log_filter

    InterceptHandler.verbose = False

    record = {"name": "androguard.something", "level": MagicMock(no=20)}  # INFO = 20
    assert _log_filter(record) is False


def test_log_filter_passes_androguard_error():
    """Verifies that Androguard ERROR records are not suppressed."""
    from main import InterceptHandler, _log_filter

    InterceptHandler.verbose = False

    record = {"name": "androguard.something", "level": MagicMock(no=40)}  # ERROR = 40
    assert _log_filter(record) is True


def test_log_filter_suppresses_requests_below_warning():
    """Verifies that requests/urllib3 records below WARNING are suppressed."""
    from main import InterceptHandler, _log_filter

    InterceptHandler.verbose = False

    for lib in ("requests", "urllib3"):
        record = {"name": lib, "level": MagicMock(no=20)}  # INFO = 20
        assert _log_filter(record) is False


def test_log_filter_passes_all_when_verbose():
    """Verifies that all records pass through when verbose mode is active."""
    from main import InterceptHandler, _log_filter

    InterceptHandler.verbose = True

    try:
        for name in ("androguard.foo", "requests", "urllib3", "myapp"):
            record = {"name": name, "level": MagicMock(no=10)}
            assert _log_filter(record) is True
    finally:
        InterceptHandler.verbose = False


def test_intercept_handler_suppresses_androguard_below_error():
    """Verifies that InterceptHandler silently drops Androguard records below ERROR."""
    import logging as stdlib_logging

    InterceptHandler.verbose = False
    handler = InterceptHandler()

    record = stdlib_logging.LogRecord("androguard.x", stdlib_logging.INFO, "", 0, "msg", (), None)
    handler.emit(record)


def test_intercept_handler_passes_error_level(monkeypatch):
    """Verifies that ERROR-level Androguard records are forwarded through the handler."""
    import logging as stdlib_logging

    InterceptHandler.verbose = False
    handler = InterceptHandler()

    emitted = []
    import loguru

    monkeypatch.setattr(
        loguru.logger,
        "opt",
        lambda **kw: MagicMock(log=lambda lvl, msg: emitted.append((lvl, msg))),
    )

    record = stdlib_logging.LogRecord("androguard.x", stdlib_logging.ERROR, "", 0, "err msg", (), None)
    handler.emit(record)


def test_load_apk_standard(tmp_path, monkeypatch):
    """Verifies _load_apk returns correct tuple for a standard .apk file."""
    mock_apk = MagicMock()
    monkeypatch.setattr("main.APK", lambda path: mock_apk)

    apk, dex_files, split_meta, apk_objects, temp_dir = _load_apk(str(tmp_path / "app.apk"))

    assert apk is mock_apk
    assert dex_files == []
    assert split_meta is None
    assert apk_objects == [mock_apk]
    assert temp_dir is None


def test_load_apk_split_zip(tmp_path, monkeypatch):
    """Verifies _load_apk delegates to parse_split_apks for .zip files."""
    mock_apk = MagicMock()
    mock_dex = [MagicMock()]
    mock_meta = {"splits": []}
    mock_objects = [mock_apk]
    mock_temp = "/tmp/split_dir"

    monkeypatch.setattr(
        "main.parse_split_apks", lambda path: (mock_apk, None, mock_dex, mock_meta, mock_objects, mock_temp)
    )

    apk, dex_files, split_meta, _apk_objects, temp_dir = _load_apk(str(tmp_path / "bundle.zip"))

    assert apk is mock_apk
    assert dex_files is mock_dex
    assert split_meta is mock_meta
    assert temp_dir == mock_temp


def test_load_dex_files_success(monkeypatch):
    """Verifies _load_dex_files correctly parses all .dex entries in an APK."""
    mock_dex_obj = MagicMock()
    mock_apk = MagicMock()
    mock_apk.get_files.return_value = ["classes.dex", "classes2.dex", "res/layout/main.xml"]
    mock_apk.get_file.return_value = b"\x64\x65\x78\x0a"

    monkeypatch.setattr("main.DEX", lambda data: mock_dex_obj)
    monkeypatch.setattr("main.tqdm", lambda iterable, **kw: iterable)

    result = _load_dex_files(mock_apk)
    assert len(result) == 2
    assert result[0] is mock_dex_obj


def test_load_dex_files_parse_error(monkeypatch):
    """Verifies _load_dex_files skips corrupt DEX files and logs a warning."""
    mock_apk = MagicMock()
    mock_apk.get_files.return_value = ["bad.dex"]
    mock_apk.get_file.return_value = b"garbage"

    monkeypatch.setattr("main.DEX", MagicMock(side_effect=Exception("parse error")))
    monkeypatch.setattr("main.tqdm", lambda iterable, **kw: iterable)

    result = _load_dex_files(mock_apk)
    assert result == []


def test_build_analysis(monkeypatch):
    """Verifies _build_analysis constructs Analysis, adds DEX files, and calls create_xref."""
    from main import _build_analysis

    mock_dx = MagicMock()
    monkeypatch.setattr("main.Analysis", lambda: mock_dx)
    monkeypatch.setattr("main.tqdm", lambda iterable, **kw: iterable)

    mock_dex1 = MagicMock()
    mock_dex2 = MagicMock()
    result = _build_analysis([mock_dex1, mock_dex2])

    assert result is mock_dx
    assert mock_dx.add.call_count == 2
    mock_dx.create_xref.assert_called_once()


def test_build_analysis_empty(monkeypatch):
    """Verifies _build_analysis works correctly with no DEX files."""
    from main import _build_analysis

    mock_dx = MagicMock()
    monkeypatch.setattr("main.Analysis", lambda: mock_dx)
    monkeypatch.setattr("main.tqdm", lambda iterable, **kw: iterable)

    result = _build_analysis([])
    assert result is mock_dx
    mock_dx.add.assert_not_called()
    mock_dx.create_xref.assert_called_once()


def test_scan_apk_returns_report_on_success(monkeypatch, tmp_path):
    """Verifies scan_apk assembles and returns a complete report dict."""
    from main import scan_apk

    apk_file = tmp_path / "app.apk"
    apk_file.write_bytes(b"dummy")

    mock_apk = MagicMock()
    mock_apk.get_package.return_value = "com.test"
    mock_dx = MagicMock()
    stub_report = {"apk_metadata": {"package": "com.test"}, "scan_metadata": {}, "network": {}}

    monkeypatch.setattr("main._load_apk", lambda path: (mock_apk, [], None, [mock_apk], None))
    monkeypatch.setattr("main._load_dex_files", lambda apk: [])
    monkeypatch.setattr("main._build_analysis", lambda dex: mock_dx)
    monkeypatch.setattr("main.build_scan_report", lambda *a, **kw: dict(stub_report))
    monkeypatch.setattr("main.apply_deobfuscation", lambda r, dx, pkg: None)
    monkeypatch.setattr("main.analyze_vulnerabilities", lambda apk_objects, r: [])
    monkeypatch.setattr(
        "main.tqdm", MagicMock(return_value=MagicMock(__enter__=lambda s: s, __exit__=MagicMock(return_value=False)))
    )

    result = scan_apk(str(apk_file))
    assert result is not None
    assert result["apk_metadata"]["package"] == "com.test"


def test_scan_apk_returns_none_on_exception(monkeypatch, tmp_path):
    """Verifies scan_apk returns None and does not raise when an inner step fails."""
    from main import scan_apk

    apk_file = tmp_path / "app.apk"
    apk_file.write_bytes(b"dummy")

    monkeypatch.setattr("main._load_apk", MagicMock(side_effect=RuntimeError("parse boom")))
    monkeypatch.setattr(
        "main.tqdm", MagicMock(return_value=MagicMock(__enter__=lambda s: s, __exit__=MagicMock(return_value=False)))
    )

    result = scan_apk(str(apk_file))
    assert result is None


def test_scan_apk_cleans_temp_dir_on_failure(monkeypatch, tmp_path):
    """Verifies scan_apk removes the temp directory even when an exception occurs."""
    from main import scan_apk

    temp_dir = tmp_path / "split_tmp"
    temp_dir.mkdir()
    apk_file = tmp_path / "bundle.zip"
    apk_file.write_bytes(b"dummy")

    mock_apk = MagicMock()
    mock_apk.get_package.return_value = "com.test"

    monkeypatch.setattr("main._load_apk", lambda path: (mock_apk, [], {}, [mock_apk], str(temp_dir)))
    monkeypatch.setattr("main._build_analysis", MagicMock(side_effect=RuntimeError("analysis crash")))
    monkeypatch.setattr(
        "main.tqdm", MagicMock(return_value=MagicMock(__enter__=lambda s: s, __exit__=MagicMock(return_value=False)))
    )

    result = scan_apk(str(apk_file))
    assert result is None
    assert not temp_dir.exists()


def test_scan_apk_attaches_split_metadata(monkeypatch, tmp_path):
    """Verifies scan_apk attaches split_apks metadata when present."""
    from main import scan_apk

    apk_file = tmp_path / "bundle.zip"
    apk_file.write_bytes(b"dummy")

    mock_apk = MagicMock()
    mock_apk.get_package.return_value = "com.split"
    split_meta = [{"name": "config.arm64"}]
    stub_report = {"apk_metadata": {}, "scan_metadata": {}, "network": {}}

    monkeypatch.setattr("main._load_apk", lambda path: (mock_apk, [], split_meta, [mock_apk], None))
    monkeypatch.setattr("main._load_dex_files", lambda apk: [])
    monkeypatch.setattr("main._build_analysis", lambda dex: MagicMock())
    monkeypatch.setattr("main.build_scan_report", lambda *a, **kw: dict(stub_report))
    monkeypatch.setattr("main.apply_deobfuscation", lambda r, dx, pkg: None)
    monkeypatch.setattr("main.analyze_vulnerabilities", lambda apk_objects, r: [])
    monkeypatch.setattr(
        "main.tqdm", MagicMock(return_value=MagicMock(__enter__=lambda s: s, __exit__=MagicMock(return_value=False)))
    )

    result = scan_apk(str(apk_file))
    assert result is not None
    assert result["apk_metadata"]["split_apks"] == split_meta


def test_configure_logging_verbose(monkeypatch):
    """Verifies _configure_logging raises log levels when verbose is set."""
    import logging as stdlib_logging

    args = MagicMock()
    args.verbose = True
    InterceptHandler.verbose = False

    _configure_logging(args)

    assert InterceptHandler.verbose is True
    assert stdlib_logging.getLogger("androguard").level == stdlib_logging.INFO

    # Reset
    InterceptHandler.verbose = False


def test_configure_logging_not_verbose():
    """Verifies _configure_logging leaves verbose flag unchanged when not requested."""
    InterceptHandler.verbose = False
    args = MagicMock()
    args.verbose = False

    _configure_logging(args)

    assert InterceptHandler.verbose is False


def test_resolve_scraper_url_from_args():
    """Verifies _resolve_scraper_url returns the explicitly provided URL immediately."""
    args = MagicMock()
    args.scraper_url = "http://my-scraper.local"
    assert _resolve_scraper_url(args) == "http://my-scraper.local"


def test_resolve_scraper_url_auto_detect(monkeypatch):
    """Verifies _resolve_scraper_url probes localhost:8000 when no URL is given."""
    args = MagicMock()
    args.scraper_url = None

    mock_response = MagicMock()
    mock_response.status_code = 200

    fake_requests = MagicMock()
    fake_requests.get.return_value = mock_response

    with mock_lib.patch.dict(sys.modules, {"requests": fake_requests}):
        url = _resolve_scraper_url(args)
        assert url == "http://localhost:8000"


def test_resolve_scraper_url_auto_detect_failure(monkeypatch):
    """Verifies _resolve_scraper_url returns None when the probe fails."""
    args = MagicMock()
    args.scraper_url = None

    fake_requests = MagicMock()
    fake_requests.get.side_effect = Exception("connection refused")

    with mock_lib.patch.dict(sys.modules, {"requests": fake_requests}):
        url = _resolve_scraper_url(args)
        assert url is None


def test_validate_args_ai_only_missing_ai_report():
    """Verifies _validate_args calls parser.error when --ai-only is missing --ai-report."""
    parser = MagicMock()
    parser.error.side_effect = SystemExit(2)
    args = MagicMock()
    args.ai_only = True
    args.apk_path = "/some/file.json"
    args.ai_report = None

    with pytest.raises(SystemExit):
        _validate_args(parser, args)
    parser.error.assert_called_once()


def test_validate_args_ai_only_file_not_found(tmp_path):
    """Verifies _validate_args exits 1 when the JSON report path does not exist."""
    parser = MagicMock()
    args = MagicMock()
    args.ai_only = True
    args.apk_path = str(tmp_path / "nonexistent.json")
    args.ai_report = "/out/report.md"

    with pytest.raises(SystemExit) as exc_info:
        _validate_args(parser, args)
    assert exc_info.value.code == 1


def test_validate_args_normal_missing_output():
    """Verifies _validate_args calls parser.error when output_file is absent."""
    parser = MagicMock()
    parser.error.side_effect = SystemExit(2)
    args = MagicMock()
    args.ai_only = False
    args.apk_path = "/some/app.apk"
    args.output_file = None

    with pytest.raises(SystemExit):
        _validate_args(parser, args)
    parser.error.assert_called_once()


def test_validate_args_normal_bad_extension(tmp_path):
    """Verifies _validate_args exits 1 when the file has an invalid extension."""
    bad_file = tmp_path / "app.exe"
    bad_file.write_bytes(b"dummy")

    parser = MagicMock()
    args = MagicMock()
    args.ai_only = False
    args.apk_path = str(bad_file)
    args.output_file = "/out/report.json"

    with pytest.raises(SystemExit) as exc_info:
        _validate_args(parser, args)
    assert exc_info.value.code == 1


def test_handle_update_rules_success(monkeypatch):
    """Verifies _handle_update_rules exits 0 when update succeeds."""
    monkeypatch.setattr("main.update_rules_db", lambda path: True)

    args = MagicMock()
    with pytest.raises(SystemExit) as exc_info:
        from main import _handle_update_rules

        _handle_update_rules(args)
    assert exc_info.value.code == 0


def test_handle_update_rules_failure(monkeypatch):
    """Verifies _handle_update_rules exits 1 when update fails."""
    monkeypatch.setattr("main.update_rules_db", lambda path: False)

    args = MagicMock()
    with pytest.raises(SystemExit) as exc_info:
        from main import _handle_update_rules

        _handle_update_rules(args)
    assert exc_info.value.code == 1


def test_handle_ai_only_success(monkeypatch, tmp_path):
    """Verifies _handle_ai_only loads JSON, generates AI report, writes it, and exits 0."""
    import json

    from main import _handle_ai_only

    report_data = {"scan_metadata": {}, "apk_metadata": {"package": "com.test"}}
    json_file = tmp_path / "report.json"
    json_file.write_text(json.dumps(report_data))

    ai_out = tmp_path / "report.md"
    monkeypatch.setattr("main.generate_ai_report", lambda **kw: "# AI Report")

    args = MagicMock()
    args.apk_path = str(json_file)
    args.ai_report = str(ai_out)
    args.ai_model = "deepseek-r1:14b"
    args.ollama_url = "http://127.0.0.1:11434"

    with pytest.raises(SystemExit) as exc_info:
        _handle_ai_only(args, scraper_url=None)

    assert exc_info.value.code == 0
    assert ai_out.read_text() == "# AI Report"


def test_handle_ai_only_bad_json(tmp_path):
    """Verifies _handle_ai_only exits 1 when the JSON file is invalid."""
    from main import _handle_ai_only

    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not valid json}")

    args = MagicMock()
    args.apk_path = str(bad_json)
    args.ai_report = str(tmp_path / "out.md")

    with pytest.raises(SystemExit) as exc_info:
        _handle_ai_only(args, scraper_url=None)
    assert exc_info.value.code == 1


def test_save_report(tmp_path):
    """Verifies _save_report writes valid JSON to the specified path."""
    import json

    report = {"key": "value", "nested": {"a": 1}}
    out_file = tmp_path / "report.json"

    _save_report(report, str(out_file))

    assert out_file.exists()
    loaded = json.loads(out_file.read_text())
    assert loaded == report


def test_write_ai_report(monkeypatch, tmp_path):
    """Verifies _write_ai_report generates and writes the AI report content."""
    from main import _write_ai_report

    monkeypatch.setattr("main.generate_ai_report", lambda **kw: "# Generated Report")

    out_file = tmp_path / "ai_report.md"
    args = MagicMock()
    args.ai_report = str(out_file)
    args.ai_model = "deepseek-r1:14b"
    args.ollama_url = "http://127.0.0.1:11434"

    _write_ai_report({}, args, scraper_url=None)

    assert out_file.read_text() == "# Generated Report"


def test_main_update_rules_flag(monkeypatch):
    """Verifies that --update-rules triggers _handle_update_rules and exits."""

    monkeypatch.setattr(sys, "argv", ["main.py", "--update-rules"])

    with mock_lib.patch("main._handle_update_rules", side_effect=SystemExit(0)) as mock_handler:
        with pytest.raises(SystemExit) as exc_info:
            import main as main_mod

            main_mod.main()

        mock_handler.assert_called_once()
    assert exc_info.value.code == 0


def test_main_missing_args_exits(monkeypatch):
    """Verifies main exits when required positional arguments are missing."""

    monkeypatch.setattr(sys, "argv", ["main.py"])

    with mock_lib.patch("main._validate_args", side_effect=SystemExit(2)):
        with pytest.raises(SystemExit):
            import main as main_mod

            main_mod.main()


def test_main_scan_and_save(monkeypatch, tmp_path):
    """Verifies main runs the full scan and saves the JSON report on success."""

    apk_file = tmp_path / "app.apk"
    apk_file.write_bytes(b"dummy")
    out_file = tmp_path / "report.json"

    monkeypatch.setattr(sys, "argv", ["main.py", str(apk_file), str(out_file)])

    stub_report = {"apk_metadata": {"package": "com.main_test"}, "scan_metadata": {}, "network": {}}

    with mock_lib.patch("main._configure_logging"):
        with mock_lib.patch("main._resolve_scraper_url", return_value=None):
            with mock_lib.patch("main._validate_args"):
                with mock_lib.patch("main.scan_apk", return_value=stub_report):
                    with mock_lib.patch("main._save_report") as mock_save:
                        import main as main_mod

                        main_mod.main()
                        mock_save.assert_called_once_with(stub_report, str(out_file))


def test_main_scan_failure_exits_1(monkeypatch, tmp_path):
    """Verifies main exits with code 1 when scan_apk returns None."""

    apk_file = tmp_path / "app.apk"
    apk_file.write_bytes(b"dummy")
    out_file = tmp_path / "report.json"

    monkeypatch.setattr(sys, "argv", ["main.py", str(apk_file), str(out_file)])

    with mock_lib.patch("main._configure_logging"):
        with mock_lib.patch("main._resolve_scraper_url", return_value=None):
            with mock_lib.patch("main._validate_args"):
                with mock_lib.patch("main.scan_apk", return_value=None):
                    with pytest.raises(SystemExit) as exc_info:
                        import main as main_mod

                        main_mod.main()
                    assert exc_info.value.code == 1


def test_main_with_ai_report(monkeypatch, tmp_path):
    """Verifies main calls _write_ai_report when --ai-report flag is supplied."""

    apk_file = tmp_path / "app.apk"
    apk_file.write_bytes(b"dummy")
    out_file = tmp_path / "report.json"
    ai_file = tmp_path / "ai.md"

    monkeypatch.setattr(sys, "argv", ["main.py", str(apk_file), str(out_file), "--ai-report", str(ai_file)])

    stub_report = {"apk_metadata": {}, "scan_metadata": {}, "network": {}}

    with mock_lib.patch("main._configure_logging"):
        with mock_lib.patch("main._resolve_scraper_url", return_value=None):
            with mock_lib.patch("main._validate_args"):
                with mock_lib.patch("main.scan_apk", return_value=stub_report):
                    with mock_lib.patch("main._save_report"):
                        with mock_lib.patch("main._write_ai_report") as mock_ai:
                            import main as main_mod

                            main_mod.main()
                            mock_ai.assert_called_once()
