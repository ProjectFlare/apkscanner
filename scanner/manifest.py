# This module parses AndroidManifest.xml and evaluates security-critical configuration flags.

def analyze_manifest_security(apk):
    """Parses AndroidManifest.xml and evaluates security configurations.

    Checks the application manifest for critical security flags such as allowBackup,
    debuggable, usesCleartextTraffic, and requestLegacyExternalStorage.

    Args:
        apk (androguard.core.apk.APK): The parsed APK object from Androguard.

    Returns:
        dict: A structured report containing:
            - security_flags (dict): Dictionary of evaluated Boolean security-critical attributes.
            - error (str, optional): Parsing error message if retrieval fails.
    """
    manifest_report: dict = {
        "security_flags": {
            "allowBackup": False,
            "debuggable": False,
            "usesCleartextTraffic": False,
            "networkSecurityConfigPresent": False,
            "requestLegacyExternalStorage": False
        }
    }
    
    try:
        xml_root = apk.get_android_manifest_xml()
    except Exception as e:
        manifest_report["error"] = f"Failed to retrieve AndroidManifest XML: {str(e)}"
        return manifest_report

    android_ns = "{http://schemas.android.com/apk/res/android}"
    
    app_elem = xml_root.find("application")
    if app_elem is not None:
        attribs = app_elem.attrib
        
        # Determine default value of usesCleartextTraffic based on targetSdkVersion
        target_sdk = apk.get_target_sdk_version()
        default_cleartext = True
        if target_sdk:
            try:
                if int(target_sdk) >= 28:
                    default_cleartext = False
            except ValueError:
                pass
        default_cleartext_str = "true" if default_cleartext else "false"

        manifest_report["security_flags"]["allowBackup"] = attribs.get(f"{android_ns}allowBackup", "true").lower() == "true"
        manifest_report["security_flags"]["debuggable"] = attribs.get(f"{android_ns}debuggable", "false").lower() == "true"
        manifest_report["security_flags"]["usesCleartextTraffic"] = attribs.get(f"{android_ns}usesCleartextTraffic", default_cleartext_str).lower() == "true"
        
        net_config = attribs.get(f"{android_ns}networkSecurityConfig")
        manifest_report["security_flags"]["networkSecurityConfigPresent"] = net_config is not None
            
        manifest_report["security_flags"]["requestLegacyExternalStorage"] = attribs.get(f"{android_ns}requestLegacyExternalStorage", "false").lower() == "true"

    return manifest_report
