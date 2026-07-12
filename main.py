"""Entry point for the APK Scanner.

Initiates the analysis workflow, aggregates reports, and outputs JSON.
"""

import argparse
import json
import logging
import os
import shutil
import sys
from datetime import UTC, datetime

from androguard.core.analysis.analysis import Analysis
from androguard.core.apk import APK
from androguard.core.dex import DEX
from loguru import logger
from tqdm import tqdm

from scanner import analyze_vulnerabilities, generate_ai_report, parse_split_apks, update_rules_db
from scanner.util.json_report import apply_deobfuscation, build_scan_report


def _log_filter(record):
    """Suppresses noisy third-party log records unless verbose mode is active.

    Args:
        record (dict): A Loguru log record dictionary.

    Returns:
        bool: True if the record should be emitted, False to suppress it.
    """
    if not InterceptHandler.verbose:
        if record["name"].startswith("androguard") and record["level"].no < 40:  # ERROR
            return False
        if record["name"].startswith(("requests", "urllib3")) and record["level"].no < 30:  # WARNING
            return False
    return True


# Set up Loguru as the single unified logger, flushing output immediately.
logger.remove()
logger.add(
    sys.stderr,
    level="INFO",
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
    filter=_log_filter,
    enqueue=False,
)


class InterceptHandler(logging.Handler):
    """Routes stdlib ``logging`` calls through Loguru with optional verbose control.

    Attributes:
        verbose (bool): Class-level flag; when False, Androguard records below
            ERROR and requests/urllib3 records below WARNING are silently dropped.
    """

    verbose = False

    def emit(self, record):
        """Translate a stdlib ``LogRecord`` and re-emit it via Loguru.

        Args:
            record (logging.LogRecord): The stdlib log record to forward.
        """
        if not self.verbose:
            if record.name.startswith("androguard") and record.levelno < logging.ERROR:
                return
            if record.name.startswith(("requests", "urllib3")) and record.levelno < logging.WARNING:
                return

        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        frame, depth = sys._getframe(6), 6
        while frame and frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())


# Route all standard logging calls (requests, third-party libraries, Androguard) through Loguru.
logging.basicConfig(handlers=[InterceptHandler()], level=logging.INFO, force=True)

# Silence noisy third-party loggers by default.
logging.getLogger("androguard").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


def _load_apk(target_path):
    """Parses a standard APK or a split-APK ZIP archive.

    Args:
        target_path (str): Path to a ``.apk`` or ``.zip`` file.

    Returns:
        tuple: ``(apk, dex_files, split_apks_metadata, apk_objects, temp_dir)``
            where *dex_files* is pre-populated for split APKs and empty for
            standard APKs, and *temp_dir* is the extraction directory that must
            be cleaned up after use (or ``None`` for standard APKs).
    """
    if target_path.endswith(".zip"):
        apk, _, dex_files, split_apks_metadata, apk_objects, temp_dir = parse_split_apks(target_path)
        return apk, dex_files, split_apks_metadata, apk_objects, temp_dir

    apk = APK(target_path)
    return apk, [], None, [apk], None


def _load_dex_files(apk):
    """Reads and parses all ``.dex`` entries embedded in a standard APK.

    Args:
        apk (androguard.core.apk.APK): The parsed APK object.

    Returns:
        list[androguard.core.dex.DEX]: Successfully parsed DEX file objects.
    """
    dex_filenames = [f for f in apk.get_files() if f.endswith(".dex")]
    dex_files = []

    for f in tqdm(dex_filenames, desc="Reading bytecode", leave=False, unit="file", position=1):
        try:
            dex_data = apk.get_file(f)
            if dex_data:
                dex_files.append(DEX(dex_data))
        except Exception as de:
            logging.warning(f"Failed to parse DEX file {f}: {de!s}")

    return dex_files


def _build_analysis(dex_files):
    """Constructs an Androguard ``Analysis`` object and resolves all cross-references.

    Args:
        dex_files (list[androguard.core.dex.DEX]): DEX objects to include.

    Returns:
        androguard.core.analysis.analysis.Analysis: A fully linked analysis context
            with class, method, field, and string XREFs resolved.
    """
    dx = Analysis()
    for d in tqdm(dex_files, desc="Parsing classes", leave=False, unit="dex", position=1):
        dx.add(d)
    dx.create_xref()
    return dx


def scan_apk(target_path):
    """Parses and scans a single Android APK file or a split APK zip archive.

    Executes static analyses including bytecode cross-referencing, metadata extraction,
    dependency detection, secret sniffing, domain grouping, permission classification,
    AndroidManifest security auditing, and security capability checks.

    Args:
        target_path (str): File system path to the target APK or split APK ZIP.

    Returns:
        dict | None: The final assembled report dictionary, or ``None`` if the scan fails.
    """
    TOTAL_STEPS = 5
    scan_start = datetime.now(UTC)
    temp_dir = None

    with tqdm(total=TOTAL_STEPS, desc="Step 1/5: Parsing APK structure", position=0) as step_pbar:
        try:
            step_pbar.set_description("Step 1/5: Parsing APK structure")
            apk, dex_files, split_apks_metadata, apk_objects, temp_dir = _load_apk(target_path)
            step_pbar.update(1)

            step_pbar.set_description("Step 2/5: Loading DEX files")
            if not target_path.endswith(".zip"):
                dex_files = _load_dex_files(apk)
            step_pbar.update(1)

            step_pbar.set_description("Step 3/5: Initializing analysis matrix")
            dx = _build_analysis(dex_files)
            step_pbar.update(1)

            # XREFs are resolved inside _build_analysis; step 4 label is kept for
            # user-facing progress consistency with the original five-step display.
            step_pbar.set_description("Step 4/5: Building Cross-References (XREFs)")
            step_pbar.update(1)

            step_pbar.set_description("Step 5/5: Running feature extraction modules")
            report = build_scan_report(apk, apk_objects, dx, target_path, scan_start)

            if split_apks_metadata:
                report["apk_metadata"]["split_apks"] = split_apks_metadata

            apply_deobfuscation(report, dx, apk.get_package())

            report["vulnerabilities"] = analyze_vulnerabilities(apk_objects, report)

            step_pbar.update(1)
            step_pbar.set_description("Scan complete")
            return report

        except Exception as e:
            print("", file=sys.stderr)
            logging.error(f"Execution stopped. Analysis failed for {target_path}: {e!s}")
            return None
        finally:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)


def _configure_logging(args):
    """Applies verbose log-level settings when ``--verbose`` is requested.

    Args:
        args (argparse.Namespace): Parsed CLI arguments.
    """
    if args.verbose:
        InterceptHandler.verbose = True
        logging.getLogger("androguard").setLevel(logging.INFO)
        logging.getLogger("requests").setLevel(logging.INFO)
        logging.getLogger("urllib3").setLevel(logging.INFO)


def _resolve_scraper_url(args):
    """Determines the scraper API base URL, falling back to auto-detection.

    If ``--scraper-url`` is not supplied, attempts a fast probe of
    ``http://localhost:8000/`` to detect a locally running scraper instance.

    Args:
        args (argparse.Namespace): Parsed CLI arguments.

    Returns:
        str | None: The resolved scraper base URL, or ``None`` if unavailable.
    """
    if args.scraper_url:
        return args.scraper_url

    try:
        import requests

        r = requests.get("http://localhost:8000/", timeout=0.5)
        if r.status_code in [200, 404]:
            return "http://localhost:8000"
    except Exception:
        pass

    return None


def _validate_args(parser, args):
    """Validates positional arguments for scan and ai-only modes, exiting on error.

    Args:
        parser (argparse.ArgumentParser): The parser used for structured error reporting.
        args (argparse.Namespace): Parsed CLI arguments.
    """
    if args.ai_only:
        if not args.apk_path or not args.ai_report:
            parser.error("when running with --ai-only, the JSON input path (apk_path) and --ai-report are required.")
        if not os.path.isfile(args.apk_path):
            logging.error(f"Target JSON report file not found: {args.apk_path}")
            sys.exit(1)
    else:
        if not args.apk_path or not args.output_file:
            parser.error("the following arguments are required: apk_path, output_file")
        if not os.path.isfile(args.apk_path):
            logging.error(f"Target file not found: {args.apk_path}")
            sys.exit(1)
        if not args.apk_path.endswith((".apk", ".zip")):
            logging.error("Target file must have a .apk or .zip extension.")
            sys.exit(1)


def _handle_update_rules(args):
    """Runs the rules-database update and exits with an appropriate status code.

    Args:
        args (argparse.Namespace): Parsed CLI arguments.
    """
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner", "rules.db")
    logging.info("Updating vulnerability rules database...")
    if update_rules_db(db_path):
        logging.info("Vulnerability rules database successfully updated.")
        sys.exit(0)
    else:
        logging.error("Failed to update vulnerability rules database.")
        sys.exit(1)


def _handle_ai_only(args, scraper_url):
    """Loads an existing JSON report, generates the AI report, and exits.

    Args:
        args (argparse.Namespace): Parsed CLI arguments.
        scraper_url (str | None): Resolved scraper base URL (may be ``None``).
    """
    logging.info(f"Loading existing report: {args.apk_path}")
    try:
        with open(args.apk_path, encoding="utf-8") as f:
            report = json.load(f)
    except Exception:
        logging.exception("Failed to read or parse JSON report.")
        sys.exit(1)

    logging.info(f"Generating AI report utilizing '{args.ai_model}' from existing JSON...")
    ai_report_content = generate_ai_report(
        scan_report=report, model=args.ai_model, ollama_url=args.ollama_url, use_websearch=bool(scraper_url)
    )
    with open(args.ai_report, "w", encoding="utf-8") as f:
        f.write(ai_report_content)
    logging.info(f"AI report successfully exported to {args.ai_report}")
    sys.exit(0)


def _save_report(report, output_file):
    """Serialises the scan report to a JSON file on disk.

    Args:
        report (dict): The assembled scan report.
        output_file (str): Destination file path for the JSON report.
    """
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)
    logging.info(f"Report successfully exported to {output_file}")


def _write_ai_report(report, args, scraper_url):
    """Generates and writes an AI security report to disk.

    Args:
        report (dict): The assembled scan report to analyse.
        args (argparse.Namespace): Parsed CLI arguments supplying model and output path.
        scraper_url (str | None): Resolved scraper base URL (may be ``None``).
    """
    logging.info(f"Generating AI report utilizing '{args.ai_model}'...")
    ai_report_content = generate_ai_report(
        scan_report=report, model=args.ai_model, ollama_url=args.ollama_url, use_websearch=bool(scraper_url)
    )
    with open(args.ai_report, "w", encoding="utf-8") as f:
        f.write(ai_report_content)
    logging.info(f"AI report successfully exported to {args.ai_report}")


def main():
    """Main CLI entry point. Parses command-line arguments and orchestrates the scan."""
    parser = argparse.ArgumentParser(description="APK Scanner")
    parser.add_argument(
        "--update-rules", action="store_true", help="Update rules database from remote sources and exit"
    )
    parser.add_argument(
        "apk_path", nargs="?", help="Path to target .apk or .zip, or existing JSON report (if --ai-only)"
    )
    parser.add_argument("output_file", nargs="?", help="Path to save JSON report (ignored if --ai-only)")
    parser.add_argument("--ai-report", help="Path to save the Markdown AI security report")
    parser.add_argument("--ai-model", default="deepseek-r1:14b", help="Ollama model to use for the AI report")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434", help="Ollama API URL")
    parser.add_argument(
        "--scraper-url",
        help="Playwright scraper API URL (e.g. http://localhost:8000). Required for web searches; if omitted, web search is disabled.",
    )
    parser.add_argument(
        "--ai-only", action="store_true", help="Only generate the AI report using an existing JSON scan report"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Show verbose output including third-party library logging"
    )

    args = parser.parse_args()

    _configure_logging(args)

    scraper_url = _resolve_scraper_url(args)
    if scraper_url:
        from scanner.util.scraper import set_scraper_url

        set_scraper_url(scraper_url)

    if args.update_rules:
        _handle_update_rules(args)

    _validate_args(parser, args)

    if args.ai_only:
        _handle_ai_only(args, scraper_url)

    logging.info(f"Target initialized: {os.path.basename(args.apk_path)}")

    report = scan_apk(args.apk_path)

    if report:
        _save_report(report, args.output_file)
        if args.ai_report:
            _write_ai_report(report, args, scraper_url)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
