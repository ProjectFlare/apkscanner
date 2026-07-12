# APK Scanner

APK Scanner is a professional static analysis tool designed for parsing, auditing, and evaluating the security configurations of Android applications, with native support for both standard standalone APKs and split APK bundles (.zip).

## Core Capabilities

- **Decompilation & Bytecode Analysis**: Deconstructs DEX bytecode files utilizing [Androguard](https://github.com/androguard/androguard) to audit code patterns, detect common security vulnerabilities (such as weak encryption, disabled SSL connection checks, insecure web configurations, and dynamic loading of untrusted code), and trace execution paths.
- **Manifest Audit & Security Flags**: Scans Android configuration manifests to flag unsafe parameters, such as debug mode enabled, insecure data backup configurations, and cleartext traffic allowances.
- **Dependency Vulnerability Scans**: Extracts third-party library dependencies from the application, maps them to standard software coordinates, and queries the **OSV (Open Source Vulnerability) database** for known public security issues.
- **Cryptographic & Secret Auditing**: Analyzes application string data and resource tables to identify accidentally exposed secrets, such as API keys, private access tokens, passwords, and custom URL schemas.
- **Network & Domain Categorization**: Normalizes extracted web links and hostnames, cross-referencing them with threat databases and ad-tracker records to flag analytics trackers, advertising networks, and known malicious websites.
- **Security Rating & OWASP Correlation**: Calculates an overall security score and grade based on the number and severity of findings, mapping identified risks directly to the [OWASP MASVS (Mobile Application Security Verification Standard)](https://masvs.owasp.org) categories.

---

## AI-Powered Security Reports

In addition to JSON reporting, the scanner supports generating an automated **AI Security Assessment Report** in Markdown format. This leverages a local [Ollama](https://ollama.com) model and integrates dynamic online threat intelligence lookup.

> [!IMPORTANT]
> The Scraper API is required to achieve the best results for the AI report. Without it, the generated report will lack Play Store descriptions, developer context, and live threat intelligence web search, falling back to basic offline-only summaries.

### AI Capabilities

- **Play Store Metadata Probing**: Automatically queries Google Play details using a [Playwright](https://playwright.dev)-rendered scraper to obtain application context (description, developer details, downloads) for a more accurate threat model.
- **LLM Findings Summarization**: Translates raw static analysis JSON dumps into readable threat assessment text, filtering out boilerplate library noise and duplicate reports.
- **Remediation Recommendations**: Suggests actionable mitigation instructions tailored specifically to the Android platform for each flagged vulnerability.

### Scraper API Specification

Because running a heavy Playwright/Chromium scraper in Docker is not always preferred in corporate or restricted environments, the scanner decouples the web-scraping logic. If you want to build or integrate your own scraper microservice (to bypass bot protection on Google Play or search engines), it must implement the API contract detailed below.

This custom scraper endpoint is invoked when running an AI-assisted scan (as shown in [Start a Static Scan with AI Security Report](#start-a-static-analysis-scan-with-ai-security-report)) or when performing rules database updates, and is configured via the [`--scraper-url`](#optional-arguments) argument (see [Optional Arguments](#optional-arguments)).

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

### Step 3: Start the Scraper API & Ollama (Optional)

If you plan to use **AI report generation** or **update the rules database** from remote sources, make sure your external microservices are active:

1. **Start the Scraper API**: Run your [Playwright](https://playwright.dev) Scraper API microservice (see [Scraper API Specification](#scraper-api-specification) for the API details). The Scraper API is highly recommended to achieve the best results for the AI report as it feeds Google Play metadata and live search results into the assessment logic. Without it, online lookups are disabled.
2. **Start a local Ollama instance**: Make sure [Ollama](https://ollama.com) is installed and running on your host machine (default endpoint: `http://127.0.0.1:11434`).
3. **Pull the AI Model**: Download the default LLM model (`deepseek-r1:14b`) or your chosen model:

```bash
 ollama pull deepseek-r1:14b
```

### Step 4: Update the Rules Database (Optional)

To update the local SQLite database with fresh definitions from live upstream feeds (requires the Scraper API to be active):

```bash
uv run python main.py --update-rules
```

For more information, see [Rules Database Updates](#rules-database-updates).

### Step 5: Run the Scan Command

Execute the scanner using one of the examples below:

#### Start a Static Analysis Scan without AI Security Report

To perform a standard static analysis scan on an APK or split APK ZIP bundle and save the structured JSON report:

```bash
uv run python main.py ./apks/de.vispiron.carsync.fahrtenbuch_3.6.20_apk.zip ./reports/de.vispiron.carsync.fahrtenbuch_3.6.20_apk_report.json
```

#### Start a Static Analysis Scan with AI Security Report

To perform the static scan, generate a JSON report, and compile an AI report utilizing a custom Ollama model and Playwright scraper URL:

```bash
uv run python main.py ./apks/de.vispiron.carsync.fahrtenbuch_3.6.20_apk.zip ./reports/de.vispiron.carsync.fahrtenbuch_3.6.20_apk_report.json --ai-report ./reports/de.vispiron.carsync.fahrtenbuch_3.6.20_ai.md --ai-model deepseek-r1:14b --scraper-url http://localhost:8000
```

### Optional Arguments

The main entry point supports the following CLI flags:

- `apk_path` _(Positional)_: Path to the target `.apk` or `.zip` file. (Accepts an existing JSON scan report if using `--ai-only`).
- `output_file` _(Positional)_: Path to save the structured JSON report. (Ignored if running in `--ai-only` mode).
- `--update-rules`: Rebuilds and updates the local SQLite rules database from remote upstream sources, then exits. Requires the Scraper API.
- `--ai-report <path>`: Enables AI report compilation and defines the path to save the generated Markdown report.
- `--ai-model <model>`: The local Ollama model to invoke (default: `deepseek-r1:14b`).
- `--ollama-url <url>`: The local Ollama API service endpoint (default: `http://127.0.0.1:11434`).
- `--scraper-url <url>`: The Playwright scraper API URL (e.g. `http://localhost:8000`) used for Play Store and threat intelligence web searches. If omitted, the scanner attempts to auto-detect a running scraper at `localhost:8000`. Web search is disabled if no scraper is active. See [Scraper API Specification](#scraper-api-specification) for implementation details.
- `--ai-only`: Skips static analysis scanning and compiles only the AI Markdown report using an existing JSON report passed as the first positional argument.
- `--verbose`: Enables verbose logging output, showing raw messages from third-party libraries like Androguard and urllib3.

---

## Rules Database Updates

The scanner relies on a local compiled SQLite database (`scanner/rules.db`) to classify domains, identify ad-trackers, resolve Maven libraries, detect vulnerable code signatures, and categorize permissions. This database is managed using the **SQLModel ORM** (mapping models directly to SQLite schemas).

> [!IMPORTANT]
> The Scraper API is required to successfully update the rules database from remote upstream sources. Without an active scraper API (configured via `--scraper-url`), the database update command will fail or skip network resources, falling back to local configurations.

To update the rules database with fresh definitions from live upstream feeds, execute:

```bash
uv run python main.py --update-rules
```

### Upstream Sources of Information (Fetched Online)

When `--update-rules` is run, the database fetches the latest records from the following official repositories:

- **Dangerous & Install Permissions**: Fetched dynamically from the official [Android Open Source Project (AOSP)](https://source.android.com) manifest repository to map runtime permission criteria.
- **Ad Trackers & Analytics signatures**: Fetched dynamically from the [Exodus Privacy](https://exodus-privacy.eu.org) trackers database API to map signature tokens.
- **Malware & Threat Intelligence Domains**: Fetched dynamically from the [URLhaus](https://urlhaus.abuse.ch) host blocklist to retrieve active malicious domains.

### Offline Fallback Definitions (Loaded from `rules.py`)

If no online update has been performed, or if the update fails, the database initialization falls back to hardcoded python lists defined in `scanner/util/rules.py` to seed the database tables:

- **Cloud Keywords**: Hostname patterns mapping cloud providers (AWS, Azure, Firebase).
- **XML Schema Exclusions**: Common namespaces (w3.org, android namespace) to reduce URL false positives.
- **Secrets Regex Patterns**: Regular expression signatures for API Keys, AWS secrets, Slack tokens, etc.
- **Trusted Package Prefixes**: Core library namespaces (AndroidX, Google GMS/Firebase) to filter out of security audits.
- **Maven Coordinates Mappings**: Package string conversions to official Maven dependencies.

---

## Development & Testing

### Running the Test Suite

To run the automated pytest suite (108 unit and integration tests):

```bash
uv run pytest
```

### Generating Code Coverage Reports

To run tests and output a line-by-line coverage report:

```bash
uv run pytest --cov=scanner --cov-report=term-missing
```

### Rebuilding the Sphinx Documentation

To re-compile the Sphinx HTML documentation (incorporating Napier Google-style docstring parsing):

```bash
uv run sphinx-build -b html docs/source docs/build/html
```

The output index file will be compiled at `docs/build/html/index.html`.

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
