"""Module identifying UI frameworks and target CPU architectures (ABIs).

Inspects native shared libraries (.so) and class namespace structures to determine the build environment.
"""

from typing import Any

from scanner.util.rules import (
    REACT_NATIVE_BUNDLE_MARKERS,
    REACT_NATIVE_CLASS_MARKERS,
    REACT_NATIVE_SO_MARKERS,
)


def analyze_ui_framework(apks: Any, dx: Any) -> str:
    """Identifies the UI framework used to compile the application.

    Inspects included native shared libraries (.so), bundle assets across all APKs,
    and class package namespaces. Cross-platform frameworks (Flutter, React Native/Expo)
    take precedence over native UI components (such as Jetpack Compose) that may be pulled
    in transitively by native plugins or wrappers.

    Args:
        apks (APK or list): A single parsed APK object or list of split APK objects.
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.

    Returns:
        str: Detected UI framework name ("Flutter", "React Native", "Native (Jetpack Compose)",
            or "Native (Standard Views)").
    """
    if not isinstance(apks, list):
        apks = [apks]

    all_files: set[str] = set()
    for apk in apks:
        try:
            all_files.update(apk.get_files())
        except Exception:
            continue

    # 1. Flutter detection
    # Flutter applications bundle libflutter.so engine or flutter assets
    if any("libflutter.so" in f for f in all_files) or any(f.startswith("assets/flutter_assets") for f in all_files):
        return "Flutter"

    # 2. React Native / Expo detection
    # React Native bundles native libraries (modern libreactnative.so, legacy libreactnativejni.so,
    # Hermes engine libhermes.so, or Expo core libexpo-modules-core.so) or the JavaScript asset bundle.
    if any(any(lib in f for lib in REACT_NATIVE_SO_MARKERS) for f in all_files):
        return "React Native"

    if any(any(f.endswith(marker) for marker in REACT_NATIVE_BUNDLE_MARKERS) for f in all_files):
        return "React Native"

    # Also check DEX bytecode for React Native framework classes
    if dx is not None:
        try:
            for cls in dx.get_classes():
                cls_name = getattr(cls, "name", "")
                if any(marker in cls_name for marker in REACT_NATIVE_CLASS_MARKERS):
                    return "React Native"
        except Exception:
            pass

    # 3. Jetpack Compose detection (only for pure native apps, not cross-platform hosts)
    if dx is not None:
        try:
            for cls in dx.get_classes():
                cls_name = getattr(cls, "name", "")
                if "Landroidx/compose/" in cls_name:
                    return "Native (Jetpack Compose)"
        except Exception:
            pass

    # 4. Default fallback to classic XML Android views
    return "Native (Standard Views)"


def analyze_cpu_architecture(apks: Any) -> list[str]:
    """Extracts targeted hardware platforms / ABIs by scanning binary folders.

    Args:
        apks (APK or list): A single parsed APK object or list of split APK objects.

    Returns:
        list[str]: Sorted list of supported ABI architecture names (e.g. ["arm64-v8a", "armeabi-v7a"]).
            Returns ["None (No native libraries)"] if no native libraries are found.
    """
    if not isinstance(apks, list):
        apks = [apks]

    abis = set()
    for apk in apks:
        for f in apk.get_files():
            # Native libraries are housed inside the lib/ directory grouped by target ABI
            if f.startswith("lib/"):
                parts = f.split("/")
                if len(parts) > 1:
                    abis.add(parts[1])

    return sorted(abis) if abis else ["None (No native libraries)"]
