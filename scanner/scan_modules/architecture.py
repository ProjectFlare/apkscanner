"""Module identifying UI frameworks and target CPU architectures (ABIs).

Inspects native shared libraries (.so) and class namespace structures to determine the build environment.
"""


def analyze_ui_framework(apks, dx):
    """Identifies the UI framework used to compile the application.

    Inspects included native shared libraries (.so) across all APKs and class
    package namespaces.

    Args:
        apks (APK or list): A single parsed APK object or list of split APK objects.
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.

    Returns:
        str: Detected UI framework name ("Flutter", "React Native", "Native (Jetpack Compose)",
            or "Native (Standard Views)").
    """
    if not isinstance(apks, list):
        apks = [apks]

    for apk in apks:
        files = apk.get_files()
        # Flutter applications bundle the libflutter engine library
        if any("libflutter.so" in f for f in files):
            return "Flutter"

        # React Native applications bundle the libreactnativejni connector library
        if any("libreactnativejni.so" in f for f in files):
            return "React Native"

    # Standard modern native applications using Jetpack Compose contain the compose UI components
    for cls in dx.get_classes():
        if "Landroidx/compose/" in cls.name:
            return "Native (Jetpack Compose)"

    # Default fallback to classic XML Android views
    return "Native (Standard Views)"


def analyze_cpu_architecture(apks):
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
