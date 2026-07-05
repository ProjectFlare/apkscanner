# APK Scanner

APK Scanner is a static analysis tool designed for parsing, auditing, and evaluating security configurations of Android applications, including support for split APK bundles. It extracts application permissions, third-party library dependencies, API secrets, and embedded URLs, and groups external domains into clear categories.

## Technical Blueprint for Reproduction

### Prerequisites

- **uv Version:** 0.11.26
- **Python Version:** 3.12.13 (should be automatically managed by uv)

Refer to the [official uv installation guide](https://docs.astral.sh/uv/getting-started/installation/) to install `uv` on your system.

### Environment Setup

uv manages the Python version and virtual environment automatically based on `.python-version` and `pyproject.toml`. To install all dependencies, run the following command in the **project root directory**:

```bash
uv sync
```

This single command will:

1. Download Python 3.12.13 if not already available.
2. Create a `.venv/` virtual environment.
3. Install all locked dependencies from `uv.lock`.

### Dependency Management

#### Adding a package

Add the package to the `dependencies` list in `pyproject.toml`, then run:

```bash
uv sync
```

#### Upgrading all packages to latest compatible versions

```bash
uv lock --upgrade
uv sync
```

### Execution Contract

To run the scanner on a target package (an APK or a split APK ZIP bundle):

```bash
uv run python main.py ./apks/<filename>.zip ./reports/<report_name>.json
```

Example:

```bash
uv run python main.py ./apks/de.vispiron.carsync.fahrtenbuch_3.6.20_apk.zip ./reports/de.vispiron.carsync.fahrtenbuch_3.6.20_apk_report.json
```

### Rules Database Updates

The scanner uses a compiled SQLite rules database (`scanner/rules.db`) for permissions categorization, domain classification, trusted library exclusions, and Maven Central mappings. To dynamically update the rules database from official upstream sources, run:

```bash
uv run python main.py --update-rules
```

#### Upstream Sources of Information

- **Dangerous Permissions**: Fetched dynamically from the official **AOSP (Android Open Source Project) Manifest source repository** to categorize runtime permissions.
- **Ad Trackers & Analytics**: Fetched dynamically from the **Exodus Privacy Trackers Database API** to obtain signature and token keywords for trackers classification.
- **Threat Intelligence Domains**: Fetched dynamically from the **URLHaus Threat Blocklist** to identify active malware and phishing domain indicators.
- **Trusted Library Prefixes**: Configured using standard JDK, Android Jetpack, Google GMS/Firebase, BouncyCastle, and Google Tink package namespaces to suppress boilerplate library noise in bytecode audits.
- **Maven Mappings**: Maps loose dependency names to standard Maven coordinates to query the **OSV (Open Source Vulnerability) database** for public CVE vulnerability records.

### Documentation & Testing

#### Running the Test Suite

```bash
uv run pytest
```

#### Rebuilding the Sphinx Documentation

```bash
uv run sphinx-build -b html docs/source docs/build/html
```

The compiled HTML output will be located in [docs/build/html/index.html](docs/build/html/index.html).
