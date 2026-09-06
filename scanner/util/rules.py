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

# System and framework-level permissions enforced purely at the Android OS process or
# manifest level without requiring in-code runtime string queries or framework API calls.
# Used in scanner/scan_modules/permissions.py to filter out false positives when detecting
# declared-but-unused (over-privileged) permissions.
OS_LEVEL_PERMISSIONS = {
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.EXPAND_STATUS_BAR",
    "android.permission.FLASHLIGHT",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.FOREGROUND_SERVICE_CAMERA",
    "android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE",
    "android.permission.FOREGROUND_SERVICE_DATA_SYNC",
    "android.permission.FOREGROUND_SERVICE_HEALTH",
    "android.permission.FOREGROUND_SERVICE_LOCATION",
    "android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK",
    "android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION",
    "android.permission.FOREGROUND_SERVICE_MICROPHONE",
    "android.permission.FOREGROUND_SERVICE_PHONE_CALL",
    "android.permission.FOREGROUND_SERVICE_REMOTE_MESSAGING",
    "android.permission.FOREGROUND_SERVICE_SHORT_SERVICE",
    "android.permission.FOREGROUND_SERVICE_SPECIAL_USE",
    "android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED",
    "android.permission.INTERNET",
    "android.permission.KILL_BACKGROUND_PROCESSES",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.REORDER_TASKS",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
    "com.google.android.c2dm.permission.RECEIVE",
    "com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE",
    "com.google.android.gms.permission.AD_ID",
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

# Compiled Exodus Privacy network signature regexes, the high-precision first pass of
# scanner/scan_modules/domains.py -> is_tracker_domain() before it falls back to
# TRACKER_KEYWORDS. Populated exclusively from rules.db; there is no offline fallback,
# because the signatures are only meaningful as the verbatim Exodus dataset. An empty
# list therefore means "no database", not "no trackers".
TRACKER_SIGNATURE_PATTERNS: list[re.Pattern] = []

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

# Domains ignored specifically in the AI report generation to reduce token bloat.
# These represent common libraries or metadata package namespaces that are safe
# to filter from the network domain tables to prevent distracting the AI model,
# while the vulnerability module continues auditing them for security findings.
IGNORED_AI_DOMAINS = {
    "w3.org",
    "xml.org",
    "xmlpull.org",
    "xmlsoap.org",
    "schemas.xmlsoap.org",
    "schemas.microsoft.com",
    "kotlinlang.org",
    "jetbrains.com",
    "slf4j.org",
    "bouncycastle.org",
    "jsoup.org",
}


# Trusted journalism and security-news domains used to constrain the "Security Incidents &
# Publicity" research in the AI report. An incident is only reported if it is covered by one
# of these outlets, dated within the last two years, tied to the app / its backend / directly
# connected infrastructure, and material to an adoption-risk decision. Used in
# scanner/web/search.py (web-search result filtering) and referenced by the app-context
# prompt in scanner/util/ai_prompt_templates.py. Curated static list — no external feed
# populates it (mirrors PACKER_SIGNATURES / ROOT_STRINGS).
NEWS_SOURCE_DOMAINS = {
    "reuters.com",
    "apnews.com",
    "bbc.com",
    "bbc.co.uk",
    "theguardian.com",
    "heise.de",
    "golem.de",
    "spiegel.de",
    "zeit.de",
    "bleepingcomputer.com",
    "krebsonsecurity.com",
    "thehackernews.com",
    "therecord.media",
    "arstechnica.com",
    "wired.com",
    "securityweek.com",
    "darkreading.com",
    "techcrunch.com",
    "cisa.gov",
    "bsi.bund.de",
    "enisa.europa.eu",
    "ncsc.gov.uk",
    "cert.europa.eu",
}

# Authoritative security and developer-reference domains for remediation ("how to fix") and
# dependency/vulnerability research. Combined with NEWS_SOURCE_DOMAINS to form SEARCH_ALLOWLIST,
# the strict allowlist every web_search result is filtered against in
# scanner/web/search.py. Domains handled by the dedicated structured tools (Play Store,
# OSV.dev, NVD, Maven) are intentionally omitted so the model uses those tools instead of noisy
# search snippets. Curated static list — no external feed populates it.
SECURITY_REFERENCE_DOMAINS = {
    "owasp.org",
    "mas.owasp.org",
    "cheatsheetseries.owasp.org",
    "developer.android.com",
    "android-developers.googleblog.com",
    "source.android.com",
    "support.google.com",
    "security.googleblog.com",
    "cloud.google.com",
    "firebase.google.com",
    "cwe.mitre.org",
    "capec.mitre.org",
    "first.org",
    "portswigger.net",
    "github.com",
    "github.blog",
    "developer.mozilla.org",
    "snyk.io",
    "sans.org",
    "docs.gradle.org",
    "gradle.org",
    "kotlinlang.org",
    "access.redhat.com",
    "ubuntu.com",
    "stackoverflow.com",
}

# Master allowlist of registrable domains whose results survive web_search filtering. Any hit
# whose host is not this set (or a subdomain of it) is dropped before reaching the model,
# raising the signal quality of every section. Used in scanner/web/search.py.
SEARCH_ALLOWLIST = NEWS_SOURCE_DOMAINS | SECURITY_REFERENCE_DOMAINS

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
    "asset-delivery": "com.google.android.play:asset-delivery",
    "asset-delivery-ktx": "com.google.android.play:asset-delivery-ktx",
    "barcode-scanning": "com.google.mlkit:barcode-scanning",
    "barcode-scanning-common": "com.google.mlkit:barcode-scanning-common",
    "vision-common": "com.google.mlkit:vision-common",
    "vision-interfaces": "com.google.mlkit:vision-interfaces",
    "user-messaging-platform": "com.google.android.ump:user-messaging-platform",
    "text-recognition": "com.google.mlkit:text-recognition",
    "text-recognition-bundled-common": "com.google.mlkit:text-recognition-bundled-common",
    "text-recognition-chinese": "com.google.mlkit:text-recognition-chinese",
    "text-recognition-devanagari": "com.google.mlkit:text-recognition-devanagari",
    "text-recognition-japanese": "com.google.mlkit:text-recognition-japanese",
    "text-recognition-korean": "com.google.mlkit:text-recognition-korean",
    "kotlinx_coroutines_android": "org.jetbrains.kotlinx:kotlinx-coroutines-android",
    "kotlinx_coroutines_core": "org.jetbrains.kotlinx:kotlinx-coroutines-core",
    "kotlinx_coroutines_slf4j": "org.jetbrains.kotlinx:kotlinx-coroutines-slf4j",
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
    "aes_hex_key": re.compile(r"\b(?!(?:00+|ff+|FF+)\b)[0-9a-fA-F]{32}\b|\b(?!(?:00+|ff+|FF+)\b)[0-9a-fA-F]{64}\b"),
}

# Regex that identifies an obfuscated DEX submodule name: either a single letter or a
# letter immediately followed by digits (e.g. "a", "b3", "x12"). Used in
# scanner/dependencies.py -> _group_packages() to replace such tokens with the generic
# "core" label so obfuscation noise does not create spurious sub-module entries.
OBFUSCATED_SUBMODULE = re.compile(r"^[a-zA-Z]\d*$")

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
}

# Token types in SECRETS_PATTERNS that represent public client identifiers rather than
# confidential backend secrets (e.g. OAuth 2.0 native client IDs and Firebase App IDs).
PUBLIC_CLIENT_TOKEN_TYPES = {"google_oauth", "firebase_app_id"}

# Package/namespace identifiers of trusted cryptography libraries where low-level block
# cipher modes (like AES/ECB) are used safely as internal primitives to construct secure algorithms.
TRUSTED_CRYPTO_LIBRARIES = (
    "com.google.crypto.tink",
    "org.bouncycastle",
    "org.conscrypt",
    "org.spongycastle",
    "com.yubico",
    "com.pslocks.sdk",
    "pslocks",
)

# Common package substrings indicating security or cryptography utility libraries
CRYPTO_PACKAGE_PATTERNS = (".cryptography.", ".crypto.", ".security.")

# The minimum Android API level where Janus vulnerability (CVE-2017-13156) is fixed.
# Apps with minSdkVersion >= JANUS_MIN_SECURE_SDK cannot be installed on Janus-vulnerable Android devices.
JANUS_MIN_SECURE_SDK = 28


# Static definitions mapping vulnerability findings to OWASP MASVS v2.0 and Mobile Top 10.
MASVS_RULES: dict[str, dict] = {
    "hardcoded_secrets": {
        "rule_id": "hardcoded_secrets",
        "masvs_id": "MASVS-STORAGE-1",
        "masvs_category": "MASVS-STORAGE",
        "mastg_id": "MASTG-STORAGE-1",
        "owasp_mobile_id": "M1",
        "category_name": "Improper Credential Usage",
        "title": "Hardcoded Secrets and API Keys",
        "description": "Hardcoded secrets and API keys detected in DEX string pool or raw resource/assets.",
        "remediation": "Move sensitive credentials out of compiled code to a secure backend or use keystore systems.",
        "default_severity": "INFORMATIONAL",
    },
    "hardcoded_crypto_keys": {
        "rule_id": "hardcoded_crypto_keys",
        "masvs_id": "MASVS-CRYPTO-1",
        "masvs_category": "MASVS-CRYPTO",
        "mastg_id": "MASTG-CRYPTO-1",
        "owasp_mobile_id": "M1",
        "category_name": "Improper Credential Usage",
        "title": "Hardcoded Symmetric Encryption Keys",
        "description": "Potential hardcoded symmetric encryption keys initialized with SecretKeySpec found in Dalvik bytecode.",
        "remediation": "Never store cryptographic keys in bytecode or resource strings. Use Android Keystore System or retrieve keys dynamically from a secure API endpoint.",
        "default_severity": "INFORMATIONAL",
    },
    "vulnerable_dependencies": {
        "rule_id": "vulnerable_dependencies",
        "masvs_id": "MASVS-CODE-4",
        "masvs_category": "MASVS-CODE",
        "mastg_id": "MASTG-CODE-4",
        "owasp_mobile_id": "M2",
        "category_name": "Inadequate Supply Chain Security",
        "title": "Vulnerable Third-Party Dependencies",
        "description": "Third-party libraries with known vulnerabilities (CVEs) detected.",
        "remediation": "Upgrade vulnerable packages to versions where the listed CVEs are resolved.",
        "default_severity": "HIGH",
    },
    "allow_backup": {
        "rule_id": "allow_backup",
        "masvs_id": "MASVS-STORAGE-2",
        "masvs_category": "MASVS-STORAGE",
        "mastg_id": "MASTG-STORAGE-2",
        "owasp_mobile_id": "M3",
        "category_name": "Insecure Data Storage",
        "title": "Application Data Backup Enabled",
        "description": "Application data backup is enabled ('allowBackup=true').",
        "remediation": 'Set android:allowBackup="false" in AndroidManifest.xml to prevent copying app private data.',
        "default_severity": "MEDIUM",
    },
    "zip_slip": {
        "rule_id": "zip_slip",
        "masvs_id": "MASVS-STORAGE-1",
        "masvs_category": "MASVS-STORAGE",
        "mastg_id": "MASTG-STORAGE-1",
        "owasp_mobile_id": "M3",
        "category_name": "Insecure Data Storage",
        "title": "Zip Slip Path Traversal",
        "description": "Zip Slip path traversal vulnerability (extracting files from ZipEntry without validating path limits) detected in bytecode.",
        "remediation": "Always validate the destination path when extracting archives. Ensure that the canonical path of the output file starts with the target directory prefix.",
        "default_severity": "INFORMATIONAL",
    },
    "cleartext_traffic": {
        "rule_id": "cleartext_traffic",
        "masvs_id": "MASVS-NETWORK-1",
        "masvs_category": "MASVS-NETWORK",
        "mastg_id": "MASTG-NETWORK-1",
        "owasp_mobile_id": "M4",
        "category_name": "Insecure Communication",
        "title": "Cleartext Traffic Allowed or Insecure Hosts",
        "description": "Cleartext traffic configuration, plain HTTP URLs, or malicious domain references identified.",
        "remediation": 'Enforce HTTPS connection rules, set android:usesCleartextTraffic="false", and avoid insecure hosts.',
        "default_severity": "HIGH",
    },
    "net_global_cleartext": {
        "rule_id": "net_global_cleartext",
        "masvs_id": "MASVS-NETWORK-1",
        "masvs_category": "MASVS-NETWORK",
        "mastg_id": "MASTG-NETWORK-1",
        "owasp_mobile_id": "M4",
        "category_name": "Insecure Communication",
        "title": "Global Cleartext Permitted in Network Config",
        "description": "Network Security Configuration permits cleartext traffic globally.",
        "remediation": 'Set cleartextTrafficPermitted="false" globally in base-config and restrict cleartext to specific domains if absolutely necessary.',
        "default_severity": "HIGH",
    },
    "net_domain_cleartext": {
        "rule_id": "net_domain_cleartext",
        "masvs_id": "MASVS-NETWORK-1",
        "masvs_category": "MASVS-NETWORK",
        "mastg_id": "MASTG-NETWORK-1",
        "owasp_mobile_id": "M4",
        "category_name": "Insecure Communication",
        "title": "Domain-Specific Cleartext Traffic Permitted",
        "description": "Network Security Configuration permits cleartext traffic for specific domains.",
        "remediation": "Enforce HTTPS/TLS for all domain communications and avoid cleartext exceptions.",
        "default_severity": "MEDIUM",
    },
    "net_user_certs": {
        "rule_id": "net_user_certs",
        "masvs_id": "MASVS-NETWORK-2",
        "masvs_category": "MASVS-NETWORK",
        "mastg_id": "MASTG-NETWORK-2",
        "owasp_mobile_id": "M4",
        "category_name": "Insecure Communication",
        "title": "Trusts User Certificates in Production",
        "description": "Network Security Configuration trusts user-installed certificates in production.",
        "remediation": "Remove user-installed CA certificates from the production trust anchors. Only trust system/CA certificates.",
        "default_severity": "HIGH",
    },
    "ssl_bypass": {
        "rule_id": "ssl_bypass",
        "masvs_id": "MASVS-NETWORK-2",
        "masvs_category": "MASVS-NETWORK",
        "mastg_id": "MASTG-NETWORK-2",
        "owasp_mobile_id": "M4",
        "category_name": "Insecure Communication",
        "title": "SSL/TLS Trust Validation Bypass",
        "description": "Insecure custom SSL/TLS trust validation bypass found in Dalvik bytecode.",
        "remediation": "Do not bypass certificate/hostname checks. Avoid empty TrustManager implementations and use default system trust verification or standard certificate pinning configurations.",
        "default_severity": "HIGH",
    },
    "unsafe_webview": {
        "rule_id": "unsafe_webview",
        "masvs_id": "MASVS-PLATFORM-2",
        "masvs_category": "MASVS-PLATFORM",
        "mastg_id": "MASTG-PLATFORM-2",
        "owasp_mobile_id": "M5",
        "category_name": "Inadequate Platform Interaction",
        "title": "Unsafe WebView Configuration (Universal File Access)",
        "description": "Unsafe WebView settings allowing cross-origin file URL access with JavaScript enabled detected in bytecode.",
        "remediation": "Ensure WebView configuration restricts file access: setAllowFileAccess(false), setAllowFileAccessFromFileURLs(false), and setAllowUniversalAccessFromFileURLs(false).",
        "default_severity": "HIGH",
    },
    "permissive_webview_file_access": {
        "rule_id": "permissive_webview_file_access",
        "masvs_id": "MASVS-PLATFORM-2",
        "masvs_category": "MASVS-PLATFORM",
        "mastg_id": "MASTG-PLATFORM-2",
        "owasp_mobile_id": "M5",
        "category_name": "Inadequate Platform Interaction",
        "title": "Permissive WebView Local File Access",
        "description": "WebView enables local file access ('setAllowFileAccess(true)') with JavaScript enabled, without universal cross-origin access.",
        "remediation": "Unless explicitly needed for local asset loading, disable file access with setAllowFileAccess(false) or migrate to androidx.webkit.WebViewAssetLoader.",
        "default_severity": "MEDIUM",
    },
    "debuggable": {
        "rule_id": "debuggable",
        "masvs_id": "MASVS-CODE-2",
        "masvs_category": "MASVS-CODE",
        "mastg_id": "MASTG-CODE-2",
        "owasp_mobile_id": "M6",
        "category_name": "Inadequate Security Controls",
        "title": "Application Is Debuggable",
        "description": "Application marked as debuggable ('debuggable=true') in manifest.",
        "remediation": 'Set android:debuggable="false" in production release builds to prevent debugging/memory inspection.',
        "default_severity": "CRITICAL",
    },
    "debug_signed": {
        "rule_id": "debug_signed",
        "masvs_id": "MASVS-CODE-1",
        "masvs_category": "MASVS-CODE",
        "mastg_id": "MASTG-CODE-1",
        "owasp_mobile_id": "M6",
        "category_name": "Inadequate Security Controls",
        "title": "Signed with Debug Certificate",
        "description": "Application is signed with a debug certificate or known debug keystore.",
        "remediation": "Sign the release build with a securely stored private production release key.",
        "default_severity": "HIGH",
    },
    "weak_hash": {
        "rule_id": "weak_hash",
        "masvs_id": "MASVS-CODE-1",
        "masvs_category": "MASVS-CODE",
        "mastg_id": "MASTG-CODE-1",
        "owasp_mobile_id": "M7",
        "category_name": "Insufficient Binary Protection",
        "title": "Weak Signature Hash Algorithm",
        "description": "Application signature certificate uses a cryptographically weak hashing algorithm (MD5/SHA-1).",
        "remediation": "Re-sign the application using SHA-256 or stronger signature digest algorithms.",
        "default_severity": "HIGH",
    },
    "v1_only_signature": {
        "rule_id": "v1_only_signature",
        "masvs_id": "MASVS-CODE-1",
        "masvs_category": "MASVS-CODE",
        "mastg_id": "MASTG-CODE-1",
        "owasp_mobile_id": "M7",
        "category_name": "Insufficient Binary Protection",
        "title": "Legacy v1-Only Signature Scheme (Janus Vulnerable)",
        "description": "Application uses only legacy JAR (v1) signing with minSdkVersion < 28, exposing it to the Janus vulnerability (CVE-2017-13156).",
        "remediation": "Enable APK Signature Scheme v2/v3 in the build configuration or increase minSdkVersion to 28+.",
        "default_severity": "HIGH",
    },
    "insecure_crypto_mode": {
        "rule_id": "insecure_crypto_mode",
        "masvs_id": "MASVS-CRYPTO-1",
        "masvs_category": "MASVS-CRYPTO",
        "mastg_id": "MASTG-CRYPTO-1",
        "owasp_mobile_id": "M10",
        "category_name": "Insufficient Cryptography",
        "title": "Insecure Cryptographic Encryption Mode (ECB)",
        "description": "Insecure symmetric cipher mode (AES/ECB) initialized in bytecode.",
        "remediation": "Use authenticated encryption modes such as AES-GCM (256-bit) or CBC mode with random IVs and HMAC authentication.",
        "default_severity": "HIGH",
    },
    "deprecated_cipher_algorithm": {
        "rule_id": "deprecated_cipher_algorithm",
        "masvs_id": "MASVS-CRYPTO-1",
        "masvs_category": "MASVS-CRYPTO",
        "mastg_id": "MASTG-CRYPTO-1",
        "owasp_mobile_id": "M10",
        "category_name": "Insufficient Cryptography",
        "title": "Deprecated / Weak Cryptographic Algorithm (DES/3DES)",
        "description": "Application utilizes deprecated or cryptographically broken legacy ciphers (DES with 56-bit key or DESede).",
        "remediation": "Migrate to modern standardized ciphers such as AES-256 (GCM mode). If retained for legacy protocol compatibility (e.g. NTLM authentication), ensure communication is strictly encapsulated within TLS.",
        "default_severity": "MEDIUM",
    },
    "unpadded_ecb_primitive": {
        "rule_id": "unpadded_ecb_primitive",
        "masvs_id": "MASVS-CRYPTO-1",
        "masvs_category": "MASVS-CRYPTO",
        "mastg_id": "MASTG-CRYPTO-1",
        "owasp_mobile_id": "M10",
        "category_name": "Insufficient Cryptography",
        "title": "Low-Level Unpadded Block Cipher Primitive (AES/ECB/NoPadding)",
        "description": "Application references unpadded single-block cipher mode (AES/ECB/NoPadding), typically used for low-level cryptographic primitives (e.g. CMAC or custom block modes) or hardware challenges rather than bulk data encryption.",
        "remediation": "Prefer high-level authenticated cryptographic schemes (such as AES-GCM or Tink AEAD primitives). If implementing MAC or key derivation, ensure usage complies with standardized specifications (RFC 4493 / NIST SP 800-38B).",
        "default_severity": "MEDIUM",
    },
    "exported_components": {
        "rule_id": "exported_components",
        "masvs_id": "MASVS-PLATFORM-1",
        "masvs_category": "MASVS-PLATFORM",
        "mastg_id": "MASTG-PLATFORM-1",
        "owasp_mobile_id": "M5",
        "category_name": "Inadequate Platform Interaction",
        "title": "Exported Components Without Permission",
        "description": "Android components exported without guarding permissions.",
        "remediation": "Ensure exported components require signature-level or custom permissions.",
        "default_severity": "INFORMATIONAL",
    },
    "custom_scheme_intents": {
        "rule_id": "custom_scheme_intents",
        "masvs_id": "MASVS-PLATFORM-1",
        "masvs_category": "MASVS-PLATFORM",
        "mastg_id": "MASTG-PLATFORM-1",
        "owasp_mobile_id": "M5",
        "category_name": "Inadequate Platform Interaction",
        "title": "Custom Scheme Deep Links",
        "description": "Custom URL schemes exposed in activity intent filters.",
        "remediation": "Validate input data from custom scheme intents and use Android App Links (HTTPS) where possible.",
        "default_severity": "INFORMATIONAL",
    },
    "root_detection": {
        "rule_id": "root_detection",
        "masvs_id": "MASVS-RESILIENCE-1",
        "masvs_category": "MASVS-RESILIENCE",
        "mastg_id": "MASTG-RESILIENCE-1",
        "owasp_mobile_id": "M7",
        "category_name": "Insufficient Binary Protection",
        "title": "Rooted-Device Detection",
        "description": "Root detection mechanisms identified in application bytecode.",
        "remediation": "Implement layered root/tamper detection to protect sensitive operations on compromised devices.",
        "default_severity": "INFORMATIONAL",
    },
    "packer": {
        "rule_id": "packer",
        "masvs_id": "MASVS-RESILIENCE-2",
        "masvs_category": "MASVS-RESILIENCE",
        "mastg_id": "MASTG-RESILIENCE-2",
        "owasp_mobile_id": "M7",
        "category_name": "Insufficient Binary Protection",
        "title": "Packer / Binary Protection",
        "description": "Third-party APK packer or binary protector detected.",
        "remediation": "Ensure packer and code obfuscation tools are properly integrated to protect proprietary intellectual property.",
        "default_severity": "INFORMATIONAL",
    },
    "dynamic_code_loading": {
        "rule_id": "dynamic_code_loading",
        "masvs_id": "MASVS-CODE-3",
        "masvs_category": "MASVS-CODE",
        "mastg_id": "MASTG-CODE-3",
        "owasp_mobile_id": "M6",
        "category_name": "Inadequate Security Controls",
        "title": "Dynamic Code Loading",
        "description": "Dynamic Dalvik bytecode loading APIs detected in application code.",
        "remediation": "Avoid loading DEX or APK code dynamically from writable storage locations.",
        "default_severity": "INFORMATIONAL",
    },
    "v1_only_signature_hardened": {
        "rule_id": "v1_only_signature_hardened",
        "masvs_id": "MASVS-CODE-1",
        "masvs_category": "MASVS-CODE",
        "mastg_id": "MASTG-CODE-1",
        "owasp_mobile_id": "M7",
        "category_name": "Insufficient Binary Protection",
        "title": "Legacy v1 Signature Scheme (Hardened by MinSDK)",
        "description": "Signed with legacy v1 scheme only, but minSdkVersion >= 28 prevents installation on Janus-vulnerable devices (API <= 27).",
        "remediation": "Re-sign the application with APK Signature Scheme v2 or v3 for whole-file integrity.",
        "default_severity": "INFORMATIONAL",
    },
    "public_client_identifiers": {
        "rule_id": "public_client_identifiers",
        "masvs_id": "MASVS-STORAGE-1",
        "masvs_category": "MASVS-STORAGE",
        "mastg_id": "MASTG-STORAGE-1",
        "owasp_mobile_id": "M1",
        "category_name": "Improper Credential Usage",
        "title": "Public Client Identifiers in Code",
        "description": "Public client tokens (OAuth client IDs, Firebase App IDs) discovered in compiled code.",
        "remediation": "Ensure Google Cloud / OAuth client IDs are restricted to the application package name and SHA-256 signing fingerprint.",
        "default_severity": "INFORMATIONAL",
    },
}


def load_dynamic_rules(db_path: str) -> None:
    """Overlays the static threat intelligence defaults with the compiled SQLite rules database.

    Dynamic threat feed tables (runtime_permissions, tracker_keywords, tracker_signatures,
    dangerous_domains) replace or extend their offline defaults when rules.db is present.

    Args:
        db_path (str): File system path of the compiled ``rules.db``.
    """
    global RUNTIME_PERMISSIONS, TRACKER_KEYWORDS, TRACKER_SIGNATURE_PATTERNS, DANGEROUS_DOMAINS

    if not os.path.exists(db_path):
        return
    try:
        from sqlalchemy import inspect
        from sqlmodel import Session, create_engine, select

        from scanner.models import (
            DangerousDomain,
            RuntimePermission,
            TrackerKeyword,
            TrackerSignature,
        )

        engine = create_engine(f"sqlite:///{db_path}")
        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()

        with Session(engine) as session:
            # Load runtime permissions from AOSP feed
            if "runtime_permissions" in existing_tables:
                perms = session.exec(select(RuntimePermission)).all()
                if perms:
                    RUNTIME_PERMISSIONS = {p.name for p in perms}

            # Load tracker keywords from Exodus Privacy feed
            if "tracker_keywords" in existing_tables:
                keywords = session.exec(select(TrackerKeyword)).all()
                if keywords:
                    TRACKER_KEYWORDS = list(set(TRACKER_KEYWORDS).union([k.keyword for k in keywords]))

            # Load and compile Exodus network signatures
            if "tracker_signatures" in existing_tables:
                signatures = session.exec(select(TrackerSignature)).all()
                for sig in signatures:
                    if not sig.network_signature:
                        continue
                    try:
                        TRACKER_SIGNATURE_PATTERNS.append(re.compile(f"(?:{sig.network_signature})", re.IGNORECASE))
                    except re.error as sig_err:
                        logger.warning(f"Skipping malformed Exodus network signature for '{sig.id}': {sig_err}")

            # Load dangerous domains from URLhaus threat feed
            if "dangerous_domains" in existing_tables:
                domains = session.exec(select(DangerousDomain)).all()
                if domains:
                    DANGEROUS_DOMAINS = {d.domain for d in domains}

    except Exception as e:
        logger.warning(f"Failed to load dynamic rules from SQLite database. Using defaults. Error: {e}")


# Overlay the static defaults with the compiled database when one is present on disk.
load_dynamic_rules(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules.db"))
