# APK Scanner

APK Scanner is a professional static analysis tool designed for parsing, auditing, and evaluating the security configurations of Android applications, with native support for both standard standalone APKs and split APK bundles (.zip).

## Core Capabilities

- **Decompilation & Bytecode Analysis**: Deconstructs DEX bytecode files utilizing [Androguard](https://github.com/androguard/androguard) to audit code patterns, detect common security vulnerabilities and trace execution paths.
- **Manifest Audit & Security Flags**: Scans Android configuration manifests to flag unsafe parameters, such as debug mode enabled, insecure data backup configurations and cleartext traffic allowances.
- **Dependency Vulnerability Scans**: Extracts third-party library dependencies from the application and queries the [OSV database](https://osv.dev/list) for known public security issues.
- **Cryptographic & Secret Auditing**: Analyzes application string data and resource tables to identify accidentally exposed secrets.
- **Network & Domain Categorization**: Queries [URLHouse database](https://urlhaus.abuse.ch/browse/) to flag known malicious websites.
- **Security Rating & OWASP Correlation**: Calculates an recommendation based on findings and mapping identified risks directly to [OWASP MASVS](https://masvs.owasp.org).

---

## AI-Powered Security Reports

In addition to JSON reporting, the scanner supports generating an automated **AI Security Assessment Report** in Markdown format. This works with any OpenAI-compatible API server, local or hosted (e.g., Ollama, Llama.cpp, MLX/OptiQ, LM Studio, or vLLM) and integrates dynamic online threat intelligence lookup.

> [!IMPORTANT]
> The Scraper API is recommended to achieve the best results for the AI report. Without it, the generated report will lack Play Store descriptions, developer context, and live threat intelligence web search, falling back to basic offline-only summaries.

### AI Capabilities

- **Play Store Metadata Probing**: Automatically queries Google Play details using a [Playwright](https://playwright.dev)-rendered scraper to obtain application context (description, developer details, downloads) for a more accurate threat model.
- **LLM Summarization**: Sumerizes findings of the static analysis JSON report, explaining false positives.
- **Recommendations**: Suggests actionable mitigation instructions.

### Scraper API Specification

Because running a heavy Playwright/Chromium scraper in Docker is not always preferred in corporate or restricted environments, the scanner decouples the web-scraping logic. If you want to build or integrate your own scraper microservice (to bypass bot protection on Google Play or search engines), it must implement the API contract detailed below.

This custom scraper endpoint is invoked when running an AI-assisted scan (as shown in [Start a Static Analysis Scan with AI Security Report](#start-a-static-analysis-scan-with-ai-security-report)) or as an optional fallback when performing rules database updates, and is configured via the [`--scraper-url`](#arguments) argument (see [Arguments](#arguments)).

- **Protocol**: HTTP/HTTPS
- **Method**: `GET`
- **Endpoint**: `/scrape`
- **Query Parameters**:
  - `url` _(string, required)_: The fully qualified URL of the target page to fetch.

#### Expected JSON Responses

**Success Response (HTTP 200)**:

```json
{
  "html": "<html>...</html>"
}
```

**Failure Response**:

```json
{
  "error": "Error description details"
}
```

---

## Running the Scanner

Follow these step-by-step instructions to set up the environment and execute a scan:

### Step 1: Install Prerequisites

Make sure you have installed:

- **uv Version**: 0.11.26 (or newer compatible versions). Refer to the [official uv installation guide](https://docs.astral.sh/uv/getting-started/installation/) to install `uv` on your system.
- **Python Version**: 3.12.13 (automatically managed and isolated by `uv`).

### Step 2: Install Local Environment Dependencies

Initialize the workspace virtual environment and install project library dependencies by running the following command in the **project root directory**:

```bash
uv sync
```

This single command will automatically download Python 3.12.13 (if not available), create a `.venv/` virtual environment, and install all required libraries.

### Step 3: Start the Scraper API & LLM Server (Ollama or OptiQ/MLX) (Optional)

If you plan to use **AI report generation** or **update the rules database** from remote sources, make sure your external microservices and local model servers are active:

1. **Start the Scraper API**: Run your [Playwright](https://playwright.dev) Scraper API microservice (see [Scraper API Specification](#scraper-api-specification) for the API details). The Scraper API is highly recommended to achieve the best results for the AI report as it feeds Google Play metadata and live search results into the assessment logic. Without it, online lookups are disabled.
2. **Start the LLM Server**: Choose one of the following options:

#### Option A: Local Ollama instance (OpenAI-compatible endpoint at `/v1`)

Make sure [Ollama](https://ollama.com) is installed and running on your host machine. Its OpenAI-compatible endpoint is `http://localhost:11434/v1`.

Pull and run the Ollama model:

```bash
ollama pull qwen3.6:35b

ollama run qwen3.6:35b
```

#### Option B: Local OpenAI-compatible OptiQ/MLX server (Optimized for Apple Silicon)

Launch the OptiQ/MLX model server:

```bash
optiq serve --model mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit --mtp --port 12345
```

When running the scanner with this option, pass `--openai-url http://localhost:12345/v1` and `--ai-model mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit`.

### Step 4: Update the Rules Database

Update the local SQLite database with fresh definitions from live upstream feeds. For more information, see [Rules Database Updates](#rules-database-updates).

### Step 5: Run the Scan Command

#### Start a Static Analysis Scan without AI Security Report

To perform a standard static analysis scan on an APK or split APK ZIP bundle and save the structured JSON report:

```bash
uv run python main.py ./apks/de.vispiron.carsync.fahrtenbuch_3.6.20_apk.zip ./reports/de.vispiron.carsync.fahrtenbuch_3.6.20_apk_report.json
```

#### Start a Static Analysis Scan with AI Security Report

To perform the static scan, generate a JSON report, and compile an AI report using any OpenAI-compatible model server and the scraper URL:

```bash
uv run python main.py ./apks/de.vispiron.carsync.fahrtenbuch_3.6.20_apk.zip ./reports/de.vispiron.carsync.fahrtenbuch_3.6.20_apk_report.json --ai-model mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit --openai-url http://localhost:12345/v1 --scraper-url http://localhost:8000
```

### Arguments

The main entry point supports the following CLI arguments:

- `apk_path` _(Positional)_: Path to the target `.apk` or `.zip` file, or an existing JSON scan report when running with `--ai-only`.
- `output_file` _(Positional)_: Path to save the structured JSON report.
- `--update-rules`: Rebuilds and updates the local SQLite rules database from remote upstream sources, then exits.
- `--ai-report [path]`: Destination path to save the Markdown AI security assessment report. By default saved to `{output_file_base}_ai.md`.
- `--ai-model <model>`: The LLM model identifier to request from the API server (default: `qwen3.6:35b`).
- `--openai-url <url>`: Base URL of an OpenAI-compatible API server. Required when `--ai-report` is used. Works with any server speaking that protocol, local or hosted: Ollama (`http://localhost:11434/v1`), MLX/OptiQ (`http://localhost:12345/v1`), LM Studio, vLLM, or a remote gateway.
- `--ai-api-key <key>`: Bearer authentication token sent in the Authorization header to OpenAI-compatible endpoints.
- `--ai-request-timeout <seconds>`: Timeout in seconds for agentic loop turns (default: `900`).
- `--ai-direct-request-timeout <seconds>`: Timeout in seconds for direct LLM queries (default: `300`).
- `--ai-concurrency <number>`: Number of concurrent worker threads to execute AI section evaluations in parallel (default: `1`).
- `--max-tool-iterations <number>`: Maximum number of tool-call rounds the model may perform per report section (default: `7`).
- `--scraper-url <url>`: The scraper API URL used for threat intelligence web searches. If omitted, the scanner dynamically probes for a running scraper at `http://localhost:8000`. If unavailable, live web search is disabled. See [Scraper API Specification](#scraper-api-specification) for details.
- `--ai-only`: Skips static analysis scanning and compiles only the AI Markdown report using an existing JSON scan report passed as `apk_path`.
- `--disable-thinking`: Asks the model to skip its reasoning phase. Useful on local reasoning models to accelerate report generation.
- `--pdf`: Generates a companion PDF version of the AI security report (`{report_name}_ai.pdf`). If supplied with an existing `.md` Markdown report file as `apk_path`, converts it directly into a PDF report.
- `--verbose`: Enables verbose logging output, showing raw messages from third-party libraries like Androguard and urllib3.

---

## Rules Database Updates

The scanner relies on a local compiled SQLite database (`scanner/rules.db`) to store OWASP MASVS rule definitions, classify domains, identify ad-trackers, resolve Maven libraries, detect vulnerable code signatures, and categorize permissions. This database is managed using the **SQLModel ORM** (mapping declarative Python models directly to SQLite tables).

To update the rules database with fresh definitions from live upstream feeds, execute:

```bash
uv run python main.py --update-rules
```

### Upstream Sources of Information (Fetched Online)

When `--update-rules` is run, the database fetches the latest records directly over HTTPS from the following official repositories:

- **Dangerous & Install Permissions**: Fetched dynamically from the official [Android Open Source Project (AOSP)](https://source.android.com) manifest repository to map runtime permission criteria.
- **Ad Trackers & Analytics signatures**: Fetched dynamically from the [Exodus Privacy](https://exodus-privacy.eu.org) trackers database API to map signature tokens.
- **Malware & Threat Intelligence Domains**: Fetched dynamically from the [URLhaus](https://urlhaus.abuse.ch) host blocklist to retrieve active malicious domains.

### Offline Fallback Definitions (Loaded from `rules.py`)

If no online update has been performed, or if the update fails, the database initialization falls back to hardcoded definitions defined in `scanner/util/rules.py`:

- **OWASP MASVS & Mobile Top 10 Rules**: Pre-configured definitions mapping findings to MASVS IDs, MASTG tests, category titles, descriptions, and remediations.
- **Cloud Keywords**: Hostname patterns mapping cloud providers (AWS, Azure, Firebase).
- **XML Schema Exclusions**: Common namespaces (w3.org, android namespace) to reduce URL false positives.
- **Secrets Regex Patterns**: Regular expression signatures for API Keys, AWS secrets, Slack tokens, etc.
- **Trusted Package Prefixes**: Core library namespaces (AndroidX, Google GMS/Firebase) to filter out of security audits.
- **Maven Coordinates Mappings**: Package string conversions to official Maven dependencies.

---

## Development & Testing

`Makefile` is used to manage development workflows, quality checks, and documentation. To run formatting, linting, type checking, dead-code analysis, pytest suite, and documentation build:

```bash
make verify
```

The output index file for docs will be compiled at `docs/build/html/index.html`.

### Dependency Management

#### Adding a Package

To add a new library package to the project, add it to the `dependencies` list in `pyproject.toml`, then run:

```bash
uv sync
```

#### Upgrading All Packages

To upgrade libraries to their latest compatible versions within bounds:

```bash
uv lock --upgrade
uv sync
```
