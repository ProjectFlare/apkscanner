# Agent Instructions

Guidance for AI coding agents working in this repository.

## Environment and Dependency Management

You must operate strictly within the uv-managed virtual environment.

- **Environment Activation:** The project uses uv to manage Python and dependencies. Always prefix commands with `uv run` or activate the environment with `source .venv/bin/activate`.
  Example: `uv run pytest` (Running Python 3.12.13 via uv 0.11.26)
- **Dependency Modification:** Do not use raw `pip install` commands to add packages.
- **Dependency Workflow:**
  1. Add the package name to the `dependencies` list in `pyproject.toml`.
  2. Run `uv sync` to resolve, lock, and install the updated dependency tree.

## Execution and Directory Structure

The scanner operates on specific inputs and outputs. Do not alter this execution contract.

- **Input Location:** Split APK zip files are stored in the `./apks/` directory.
- **Execution Command:** Run the scanner using the exact positional argument pattern:
  `uv run python main.py ./apks/<filename>.zip ./reports/<report_name>.json`
- **Output Target:** Ensure reports are properly formatted as JSON and written to the specified path within `./reports/`.

## Core Logic and Static Analysis

- **Framework Utilization:** This scanner must make full, idiomatic use of the `androguard` library for parsing, decompiling, and extracting structural components of the APKs.
- **Quality and Standards:** Implement robust exception handling around `androguard` calls to gracefully handle corrupted or highly obfuscated split APKs. Avoid superficial regex matching where semantic analysis using `androguard` AST or structural APIs is possible.

## Code Style, Architecture, and Documentation

- **Modularization:** Break down functionalities (e.g., APK parsing, signature verification, pattern matching, report generation) into distinct Python modules following clean architecture principles. Avoid monolithic structures.
- **File Headers:** Every single Python file/module must start with a short, descriptive comment in English explaining the purpose and scope of that file.
- **Code Comments:** Default to writing clean, self-documenting code. Do not add redundant inline comments. However, you must place an English comment directly above complex, non-obvious, or unordinary logic blocks to explain what is happening.
- **Automated Documentation:** Code must remain fully compatible with Sphinx. Write strict Google-style or Sphinx-style docstrings for all public classes, methods, and functions so that the documentation build tool can automatically parse them.

## Testing and Verification

- **Framework:** The project uses `pytest` for all unit and integration testing.
- **Strict Verification Workflow:** 1. Write corresponding tests inside the `tests/` directory immediately after adding or modifying any module. 2. Run the test suite using `uv run pytest` to verify the module works exactly as intended before declaring a task complete. 3. Do not break, weaken, or skip existing tests without human intervention.
