# APK Scanner

APK Scanner is a static analysis tool designed for parsing, auditing, and evaluating security configurations of Android applications, including support for split APK bundles. It extracts application permissions, third-party library dependencies, API secrets, and embedded URLs, and groups external domains into clear categories.

## Technical Blueprint for Reproduction

### Prerequisites
* **Conda Version:** 25.5.1
* **Python Version:** 3.12.13

### Environment Setup
To initialize and synchronize the environment:

1. Create the Conda environment with the required Python version:
   ```bash
   conda create -n apk_scanner python=3.12.13 -y
   ```
2. Activate the designated Conda environment:
   ```bash
   conda activate apk_scanner
   ```
3. Install `pip-tools` to enable dependency compilation and synchronization:
   ```bash
   pip install pip-tools
   ```
4. Synchronize the local environment packages using `pip-sync` (which locks dependencies to `requirements.txt`):
   ```bash
   pip-sync
   ```

*(Note: If you need to add packages, add them to `requirements.in` first, run `pip-compile requirements.in` to regenerate `requirements.txt`, and then run `pip-sync`.)*

### Execution Contract
To run the scanner on a target package (an APK or a split APK ZIP bundle), use the following positional argument pattern:

```bash
python main.py ./apks/<filename>.zip ./reports/<report_name>.json
```

Example:
```bash
python main.py ./apks/de.vispiron.carsync.fahrtenbuch_3.6.20_apk.zip ./reports/de.vispiron.carsync.fahrtenbuch_3.6.20_apk_report.json
```

### Documentation & Testing

#### Running the Test Suite
Trigger the test suite using `pytest` to execute all unit and integration tests:
```bash
pytest
```

#### Rebuilding the Sphinx Documentation
Compile the automated Google-style and Sphinx-style docstring documentation into local HTML pages:
```bash
sphinx-build -b html docs/source docs/build/html
```
The compiled HTML output will be located in [docs/build/html/index.html](docs/build/html/index.html).
