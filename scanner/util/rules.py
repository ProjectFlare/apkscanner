"""Rules configuration for the static APK scanner.

Holds permission categories, domain classification keywords, and filter lists used across
multiple scanner modules, loading dynamically from rules.db if available. All constants
defined here serve as offline fallback defaults that the SQLite loader at the bottom of
this file may override at import time.
"""

import os
import re

from loguru import logger

# Dangerous-level Android permissions that require an explicit runtime grant from the user.
# Used in scanner/permissions.py to flag declared permissions that need user consent.
# rules.db is populated from the live AOSP manifest on internet access; this set is the
# offline fallback for when no network update has been run yet.
RUNTIME_PERMISSIONS = {
    "android.permission.ACCEPT_HANDOVER",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BODY_SENSORS",
    "android.permission.BODY_SENSORS_BACKGROUND",
    "android.permission.CALL_PHONE",
    "android.permission.CAMERA",
    "android.permission.GET_ACCOUNTS",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_CALENDAR",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECORD_AUDIO",
    "android.permission.SEND_SMS",
    "android.permission.USE_SIP",
    "android.permission.UWB_RANGING",
    "android.permission.WRITE_CALENDAR",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.WRITE_CONTACTS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
}

# Hostname substrings that identify a domain as a cloud-hosting or backend-API provider.
# Used in scanner/domains.py -> extract_domains() to group matching domains into the
# "cloud_services" report bucket. rules.db contains only this hardcoded list; no external
# source fills it during a network update.
CLOUD_KEYWORDS = ["firebase", "googleapis", "azurewebsites", "cloudfunctions", "microsoft", "aws", "amazonws"]

# Fallback keywords for identifying tracker and ad-network domains when no Exodus Privacy
# regex signature matches. Used in scanner/domains.py -> is_tracker_domain(), where each
# keyword is tested against individual hostname segments to avoid false positives.
# rules.db is populated from the Exodus Privacy API on internet access; this list is the
# offline fallback and is merged with any fetched keywords when the DB is loaded.
TRACKER_KEYWORDS = [
    "mixpanel",
    "analytics",
    "app-measurement",
    "googleadservices",
    "googletagmanager",
    "doubleclick",
    "adjust",
    "appsflyer",
    "facebook.com/tr",
    "crashlytics",
]

# Substrings that identify a URL or hostname as a well-known XML namespace, W3C schema,
# or developer documentation stub rather than a real network endpoint. Used in
# scanner/domains.py -> extract_domains() and scanner/urls.py -> is_schema_url() to
# silently exclude these from reports. rules.db contains only this hardcoded list; no
# external source fills it during a network update.
SCHEMA_KEYWORDS = [
    "schemas.android.com",
    "w3.org",
    "ns.adobe.com",
    "dummy.example",
    "example.com",
    "github.com/google/gson",
    "Troubleshooting.md",
    "google.github.io",
]

# Stop-word set used only during rules-database update runs in scanner/update_rules.py
# -> fetch_exodus_trackers(). When tokenising Exodus code and network signatures, tokens
# found in this set are discarded so that only meaningful library names reach the
# tracker_keywords table. Without this filter, words like "com", "android", or "google"
# would be stored and cause false-positive domain classifications at scan time.
IGNORED_TOKENS = {
    "com",
    "org",
    "net",
    "api",
    "sdk",
    "www",
    "http",
    "https",
    "track",
    "analytics",
    "android",
    "google",
    "internal",
    "service",
    "github",
    "githubusercontent",
    "gitlab",
    "bitbucket",
    "square",
    "squareup",
    "maven",
    "jitpack",
    "kotlin",
    "kotlinx",
    "apache",
    "eclipse",
    "jetbrains",
    "facebook",
    "twitter",
    "microsoft",
    "amazon",
}

# Internal-format Dalvik class prefixes (e.g. "Landroid/") for well-known platform and
# third-party library namespaces. Used in scanner/bytecode_audit.py as IGNORE_PREFIXES
# to skip instructions whose owning class starts with one of these, preventing false
# positives on benign framework calls (e.g. flagging java.util.Base64 as suspicious).
# rules.db contains only this hardcoded list; no external source fills it during a
# network update.
TRUSTED_PACKAGE_PREFIXES = {
    "Landroid/",
    "Landroidx/",
    "Lcom/google/android/",
    "Lcom/google/firebase/",
    "Lkotlin/",
    "Lkotlinx/",
    "Ljava/",
    "Ljavax/",
    "Lorg/intellij/",
    "Lorg/jetbrains/",
    "Lorg/apache/",
    "Lorg/xml/",
    "Lorg/w3c/",
    "Lorg/json/",
    "Lorg/bouncycastle/",
    "Lcom/google/crypto/tink/",
}

# Maps short library identifiers found in AAR/JAR manifests to their canonical Maven
# Group:Artifact coordinates. Used in scanner/vulnerabilities.py ->
# resolve_maven_coordinate() so OSV.dev CVE queries use a precise artifact name rather
# than a heuristic guess. rules.db contains only this hardcoded list; no external source
# fills it during a network update.
MAVEN_MAPPING = {
    "okhttp3": "com.squareup.okhttp3:okhttp",
    "okhttp": "com.squareup.okhttp3:okhttp",
    "retrofit2": "com.squareup.retrofit2:retrofit",
    "retrofit": "com.squareup.retrofit2:retrofit",
    "ktor-client": "io.ktor:ktor-client-core",
    "ktor": "io.ktor:ktor-client-core",
    "google-datatransport": "com.google.android.datatransport:transport-api",
    "datatransport": "com.google.android.datatransport:transport-api",
    "transport-api": "com.google.android.datatransport:transport-api",
    "google-gson": "com.google.code.gson:gson",
    "gson": "com.google.code.gson:gson",
    "firebase-crashlytics-sdk": "com.google.firebase:firebase-crashlytics",
    "crashlytics android sdk": "com.google.firebase:firebase-crashlytics",
    "mixpanel-android": "com.mixpanel.android:mixpanel-android",
    "mixpanel": "com.mixpanel.android:mixpanel-android",
    "yubikit": "com.yubico.device:yubikit",
    "billing": "com.android.billingclient:billing",
    "billing-ktx": "com.android.billingclient:billing-ktx",
    "review": "com.google.android.play:review",
    "review-ktx": "com.google.android.play:review-ktx",
    "app-update": "com.google.android.play:app-update",
    "app-update-ktx": "com.google.android.play:app-update-ktx",
    "integrity": "com.google.android.play:integrity",
    "feature-delivery": "com.google.android.play:feature-delivery",
    "feature-delivery-ktx": "com.google.android.play:feature-delivery-ktx",
    "googleid": "com.google.android.libraries.identity.googleid:googleid",
}

# Prefix-based heuristics used to dynamically map Google, Firebase, and Datatransport
# libraries directly to their standard Maven groupIds.
# Used in scanner/scan_modules/vulnerabilities.py -> resolve_maven_coordinate() to map library
# names to standardized coordinates without needing to exhaustively hardcode every individual
# artifact in MAVEN_MAPPING. rules.db contains only this hardcoded prefix list; no external
# source fills it during a network update.
MAVEN_PREFIXES = {
    "play-services-": "com.google.android.gms",
    "firebase-": "com.google.firebase",
    "transport-": "com.google.android.datatransport",
}


# Known-malicious hostnames checked against every domain found in the APK in
# scanner/vulnerabilities.py -> check_malicious_domains(). Matches are surfaced as
# high-severity findings. The default is intentionally empty; this set is populated
# entirely from the URLHaus blocklist on internet access and has no hardcoded entries.
DANGEROUS_DOMAINS = set()

# Compiled regex patterns for detecting hardcoded credentials and sensitive tokens.
# Used in scanner/secrets.py -> scan_strings(), scan_dex_classes(), and
# scan_resources(), where all three scan paths iterate over this dict to apply every
# pattern in one pass. rules.db contains only this hardcoded list; no external source
# fills it during a network update.
SECRETS_PATTERNS = {
    "google_api": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "google_oauth": re.compile(r"\b\d+-\w{32}\.apps\.googleusercontent\.com\b"),
    "firebase_app_id": re.compile(r"\b1:\d+:\w+:[a-f0-9]{24,32}\b"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
    "stripe_standard": re.compile(r"sk_live_[0-9a-zA-Z]{24}"),
    "rsa_private_key": re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
    "generic_api_key": re.compile(
        r"(?i)(?:api[-_]?key|secret[-_]?key|access[-_]?token)[=:]\s*[\"']?([a-z0-9\-_]{16,64})[\"']?"
    ),
    "jwt_token": re.compile(r"ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "mapbox_token": re.compile(r"\bpk\.ey[a-zA-Z0-9._-]{50,}\b"),
    "github_token": re.compile(r"\bgh[opr]_[a-zA-Z0-9]{36,255}\b"),
    "sendgrid_key": re.compile(r"\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b"),
    "facebook_access_token": re.compile(r"\b\d{15,16}\|[a-zA-Z0-9_-]{27,32}\b"),
}

# Regex that identifies an obfuscated DEX submodule name: either a single letter or a
# letter immediately followed by digits (e.g. "a", "b3", "x12"). Used in
# scanner/dependencies.py -> _group_packages() to replace such tokens with the generic
# "core" label so obfuscation noise does not create spurious sub-module entries.
OBFUSCATED_SUBMODULE = re.compile(r"^[a-zA-Z]\d+$|^[a-zA-Z]$")

# Pre-compiled regex patterns that match embedded version strings for well-known libraries
# inside the DEX string pool. Used in scanner/dependencies.py ->
# _extract_versions_from_strings() to recover exact version numbers when property files
# are absent or incomplete. Each pattern captures (library_name, version).
VERSION_PATTERNS = [
    # name/version (e.g. okhttp/4.12.0 or datatransport/3.3.0)
    re.compile(r"\b(okhttp|retrofit|ktor|datatransport|jackson|gson)/(\d+\.\d+\.\d+[-a-z\d\.]*)", re.IGNORECASE),
    # name:version (e.g. firebase-sessions:1.1.0)
    re.compile(r"\b(firebase-[a-z\d_\-\.]+):(\d+\.\d+\.\d+)", re.IGNORECASE),
    # Name (version) (e.g. Mixpanel (8.0.2) or GSON (2.11.0))
    re.compile(r"\b(mixpanel|gson)\s*\(?(\d+\.\d+\.\d+)\)?", re.IGNORECASE),
    # SDK/version (e.g. Crashlytics Android SDK/19.4.1)
    re.compile(r"\b(Crashlytics Android SDK)/(\d+\.\d+\.\d+)", re.IGNORECASE),
    # Maven coordinate @@ version
    re.compile(r"\b([a-zA-Z0-9_\-\.]+:[a-zA-Z0-9_\-\.]+)@@(\d+\.\d+\.\d+)"),
]

# Java/Kotlin/Android package prefixes that carry no diagnostic value for deobfuscation.
# Used in scanner/deobfuscator.py -> StringClassifier._extract_java_pkg_contexts() to
# discard package path matches whose first two dot-separated segments appear in this set,
# preventing generic platform namespaces (e.g. "java.util", "android.view") from
# polluting the context labels attached to obfuscated classes.
DEOBFUSCATOR_IGNORED_PKG_PREFIXES = {
    "java.lang",
    "java.util",
    "java.io",
    "android.os",
    "android.view",
    "android.content",
    "android.widget",
    "android.app",
    "android.graphics",
    "kotlin.jvm",
    "kotlin.coroutines",
    "android.net",
    "java.net",
    "java.security",
    "javax.net",
    "kotlin.collections",
}

# Pre-compiled packer signatures to optimize detection loops.
# Maps packer/protector names to their signatures: native library filename patterns (libs)
# and class package name sub-strings (classes). Used in scanner/security_checks.py ->
# _detect_packer_via_libs() and _detect_packer_via_classes() to check if the APK is
# packed or protected. rules.db does not contain these signatures; this is the static
# source for packer detection.
PACKER_SIGNATURES = {
    "Qihoo 360 / Jiagu": {
        "libs": [
            re.compile(r"libjiagu\.so", re.IGNORECASE),
            re.compile(r"libjiagu_a64\.so", re.IGNORECASE),
            re.compile(r"libjiagu_x86\.so", re.IGNORECASE),
        ],
        "classes": ["com/qihoo", "com/qihoo360"],
    },
    "Tencent Legu / Shell": {
        "libs": [
            re.compile(r"libtxlog\.so", re.IGNORECASE),
            re.compile(r"libshell\.so", re.IGNORECASE),
            re.compile(r"libtup\.so", re.IGNORECASE),
        ],
        "classes": ["com/tencent/StubShell"],
    },
    "Bangcle / SecApk": {
        "libs": [re.compile(r"libsecapk\.so", re.IGNORECASE), re.compile(r"libsecexe\.so", re.IGNORECASE)],
        "classes": ["com/secapk", "com/bangcle"],
    },
    "SecShell": {"libs": [re.compile(r"libsecshell\.so", re.IGNORECASE)], "classes": ["com/secshell"]},
    "Ali Shield": {
        "libs": [re.compile(r"libmobisecy\.so", re.IGNORECASE), re.compile(r"libfakejni\.so", re.IGNORECASE)],
        "classes": ["com/ali/mobisecy"],
    },
    "Baidu Protect": {"libs": [re.compile(r"libbaiduprotect\.so", re.IGNORECASE)], "classes": ["com/baidu/protect"]},
    "IJiami": {
        "libs": [re.compile(r"libegis\.so", re.IGNORECASE), re.compile(r"libegisboot\.so", re.IGNORECASE)],
        "classes": [],
    },
}

# String pool indicators suggesting potential root detection mechanisms.
# Set of common root-related binaries, packages, and zip files. Used in
# scanner/security_checks.py -> _scan_string_pool_for_root() to audit whether the APK
# implements checks for rooted devices. rules.db does not contain these indicators;
# this is the static source for root detection strings.
ROOT_STRINGS = {
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/system/su",
    "/system/bin/.ext",
    "/system/usr/we-need-root/su-backup",
    "/system/app/Superuser.apk",
    "supersu",
    "KingoUser.apk",
    "SuperSU-v2.82.zip",
    "magisk",
    "test-keys",
    "/system/xbin/daemonsu",
}


# Load dynamic rules from the compiled SQLite database if present on disk
db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules.db")
if os.path.exists(db_path):
    try:
        from sqlalchemy import inspect
        from sqlmodel import Session, create_engine, select

        from scanner.models import (
            CloudKeyword,
            DangerousDomain,
            MavenMapping,
            RuntimePermission,
            SchemaKeyword,
            SecretsPattern,
            TrackerKeyword,
            TrustedPackagePrefix,
        )

        engine = create_engine(f"sqlite:///{db_path}")
        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()

        with Session(engine) as session:
            # Load runtime permissions
            if "runtime_permissions" in existing_tables:
                perms = session.exec(select(RuntimePermission)).all()
                if perms:
                    RUNTIME_PERMISSIONS = {p.name for p in perms}

            # Load cloud keywords
            if "cloud_keywords" in existing_tables:
                keywords = session.exec(select(CloudKeyword)).all()
                if keywords:
                    CLOUD_KEYWORDS = list(set(CLOUD_KEYWORDS).union([k.keyword for k in keywords]))

            # Load tracker keywords
            if "tracker_keywords" in existing_tables:
                keywords = session.exec(select(TrackerKeyword)).all()
                if keywords:
                    TRACKER_KEYWORDS = list(set(TRACKER_KEYWORDS).union([k.keyword for k in keywords]))

            # Load schema keywords
            if "schema_keywords" in existing_tables:
                keywords = session.exec(select(SchemaKeyword)).all()
                if keywords:
                    SCHEMA_KEYWORDS = [k.keyword for k in keywords]

            # Load dangerous domains
            if "dangerous_domains" in existing_tables:
                domains = session.exec(select(DangerousDomain)).all()
                if domains:
                    DANGEROUS_DOMAINS = {d.domain for d in domains}

            # Load trusted package prefixes
            if "trusted_package_prefixes" in existing_tables:
                prefixes = session.exec(select(TrustedPackagePrefix)).all()
                if prefixes:
                    TRUSTED_PACKAGE_PREFIXES = {p.prefix for p in prefixes}

            # Load maven mappings
            if "maven_mappings" in existing_tables:
                mappings = session.exec(select(MavenMapping)).all()
                if mappings:
                    MAVEN_MAPPING = {m.lib_name: m.coordinate for m in mappings}

            # Load secrets patterns
            if "secrets_patterns" in existing_tables:
                patterns = session.exec(select(SecretsPattern)).all()
                if patterns:
                    SECRETS_PATTERNS = {p.key: re.compile(p.pattern) for p in patterns}
    except Exception as e:
        logger.warning(f"Failed to load dynamic rules from SQLite database. Using defaults. Error: {e}")
