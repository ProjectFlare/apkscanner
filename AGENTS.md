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
- **Best Practices & State-of-the-Art:** Always prefer industry best practices, clean design patterns, and state-of-the-art solutions. Avoid outdated, deprecated, or suboptimal coding approaches.

## Code Style, Architecture, and Documentation

- **Modularization:** Break down functionalities (e.g., APK parsing, signature verification, pattern matching, report generation) into distinct Python modules following clean architecture principles. Avoid monolithic structures.
- **File Headers:** Every single Python file/module must start with a short, descriptive PEP 257 compliant module docstring (`"""..."""`) explaining the purpose and scope of that file. Do not use hash (`#`) comments as module-level header comments.
- **Code Comments:** Default to writing clean, self-documenting code. Do not add redundant inline comments. However, you must place an English comment directly above complex, non-obvious, or unordinary logic blocks to explain what is happening.
- **Automated Documentation:** Code must remain fully compatible with Sphinx. All docstrings (including module headers and function/class docstrings) must follow official PEP 257 conventions. Write strict Google-style docstrings for all public classes, methods, and functions so that they remain highly human-readable in the code while allowing Sphinx to parse them automatically via its napoleon extension.

## Testing and Verification

- **Framework:** The project uses `pytest` for all unit and integration testing.
- **Strict Verification Workflow:**
  1. Run the Ruff formatter and linter check using `uv run ruff format` and `uv run ruff check --fix` to ensure full style and lint compliance. (Avoid running `uv run ruff check` without `--fix` to preserve token usage on fixable items).
  2. Write corresponding tests inside the `tests/` directory immediately after adding or modifying any module.
  3. Run the test suite using `uv run pytest --cov=scanner` to check test coverage. Ensure that new/modified functions have thorough test coverage and do not decrease the project's overall coverage.
  4. Do not break, weaken, or skip existing tests without human intervention.
  5. Regenerate the Sphinx documentation using the command: `uv run sphinx-build -b html docs/source docs/build/html` to ensure the build succeeds without warnings or errors.

## Token Efficiency and Resource Management

You must operate and interact with tools in a token-efficient manner to preserve context window limits:
- **Targeted Reading:** Avoid reading entire large source files if only specific sections or lines are needed. Always specify line range parameters when using reading/viewing tools.
- **Incremental Edits:** Perform targeted code replacements using exact replacements instead of rewriting large sections of files.
- **Command Output Optimization:** Keep command outputs concise (e.g. limit log lists or search outputs) to prevent flooding the context window.
- **Verification Timing:** Do not execute the Strict Verification Workflow (formatting, linting, tests, documentation builds) at the start or during early stages of task execution. Only execute it at the end once the code logic is fully implemented.
- **Command Completion:** Do not set timers or cron jobs to check when background commands finish. The system will automatically wake you up and send a notification when the command concludes. Simply stop calling tools to pause execution and wait.
