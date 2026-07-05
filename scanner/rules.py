# Rules configuration for the static APK scanner.
# Holds permission categories, domain classification keywords, and filter lists.
# Dynamically loads updated lists from rules_db.json if available.

import os
import re
import json
from loguru import logger

# Hardcoded default values for robust offline fallback execution
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
    "android.permission.WRITE_EXTERNAL_STORAGE"
}

CLOUD_KEYWORDS = [
    "firebase",
    "googleapis",
    "azurewebsites",
    "cloudfunctions",
    "microsoft",
    "aws",
    "amazonws"
]

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
    "crashlytics"
]

SCHEMA_KEYWORDS = [
    "schemas.android.com",
    "w3.org",
    "ns.adobe.com",
    "dummy.example",
    "example.com",
    "github.com/google/gson",
    "Troubleshooting.md",
    "google.github.io"
]

IGNORED_TOKENS = {
    "com", "org", "net", "api", "sdk", "www", "http", "https", 
    "track", "analytics", "android", "google", "internal", "service",
    "github", "githubusercontent", "gitlab", "bitbucket", "square", "squareup", 
    "maven", "jitpack", "kotlin", "kotlinx", "apache", "eclipse", "jetbrains", 
    "facebook", "twitter", "microsoft", "amazon"
}

TRUSTED_PACKAGE_PREFIXES = {
    "Landroid/", "Landroidx/", "Lcom/google/android/", 
    "Lcom/google/firebase/", "Lkotlin/", "Lkotlinx/", 
    "Ljava/", "Ljavax/", "Lorg/intellij/", "Lorg/jetbrains/",
    "Lorg/apache/", "Lorg/xml/", "Lorg/w3c/", "Lorg/json/",
    "Lorg/bouncycastle/", "Lcom/google/crypto/tink/"
}

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
    "googleid": "com.google.android.libraries.identity.googleid:googleid"
}

DANGEROUS_DOMAINS = set()

# Regular expressions for detecting secrets, keys, and tokens
SECRETS_PATTERNS = {
    "google_api": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "google_oauth": re.compile(r"\b\d+-\w{32}\.apps\.googleusercontent\.com\b"),
    "firebase_app_id": re.compile(r"\b1:\d+:\w+:[a-f0-9]{24,32}\b"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
    "stripe_standard": re.compile(r"sk_live_[0-9a-zA-Z]{24}"),
    "rsa_private_key": re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
    "generic_api_key": re.compile(r"(?i)(?:api[-_]?key|secret[-_]?key|access[-_]?token)[=:]\s*[\"']?([a-z0-9\-_]{16,64})[\"']?"),
    "jwt_token": re.compile(r"ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "mapbox_token": re.compile(r"\bpk\.ey[a-zA-Z0-9._-]{50,}\b"),
    "github_token": re.compile(r"\bgh[opr]_[a-zA-Z0-9]{36,255}\b"),
    "sendgrid_key": re.compile(r"\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b"),
    "facebook_access_token": re.compile(r"\b\d{15,16}\|[a-zA-Z0-9_-]{27,32}\b")
}

# Load dynamic rules from the compiled SQLite database if present on disk
db_path = os.path.join(os.path.dirname(__file__), "rules.db")
if os.path.exists(db_path):
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Helper to check if a table exists
        def table_exists(table_name):
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
            return cursor.fetchone() is not None

        # Load runtime permissions
        if table_exists("runtime_permissions"):
            cursor.execute("SELECT name FROM runtime_permissions")
            rows = cursor.fetchall()
            if rows:
                RUNTIME_PERMISSIONS = {row[0] for row in rows}

        # Load cloud keywords
        if table_exists("cloud_keywords"):
            cursor.execute("SELECT keyword FROM cloud_keywords")
            rows = cursor.fetchall()
            if rows:
                CLOUD_KEYWORDS = list(set(CLOUD_KEYWORDS).union([row[0] for row in rows]))

        # Load tracker keywords
        if table_exists("tracker_keywords"):
            cursor.execute("SELECT keyword FROM tracker_keywords")
            rows = cursor.fetchall()
            if rows:
                TRACKER_KEYWORDS = list(set(TRACKER_KEYWORDS).union([row[0] for row in rows]))

        # Load schema keywords
        if table_exists("schema_keywords"):
            cursor.execute("SELECT keyword FROM schema_keywords")
            rows = cursor.fetchall()
            if rows:
                SCHEMA_KEYWORDS = [row[0] for row in rows]

        # Load dangerous domains
        if table_exists("dangerous_domains"):
            cursor.execute("SELECT domain FROM dangerous_domains")
            rows = cursor.fetchall()
            if rows:
                DANGEROUS_DOMAINS = {row[0] for row in rows}

        # Load trusted package prefixes
        if table_exists("trusted_package_prefixes"):
            cursor.execute("SELECT prefix FROM trusted_package_prefixes")
            rows = cursor.fetchall()
            if rows:
                TRUSTED_PACKAGE_PREFIXES = {row[0] for row in rows}

        # Load maven mappings
        if table_exists("maven_mappings"):
            cursor.execute("SELECT lib_name, coordinate FROM maven_mappings")
            rows = cursor.fetchall()
            if rows:
                MAVEN_MAPPING = {row[0]: row[1] for row in rows}

        # Load secrets patterns
        if table_exists("secrets_patterns"):
            cursor.execute("SELECT key, pattern FROM secrets_patterns")
            rows = cursor.fetchall()
            if rows:
                SECRETS_PATTERNS = {row[0]: re.compile(row[1]) for row in rows}

        conn.close()
    except Exception as e:
        logger.warning(f"Failed to load dynamic rules from SQLite database. Using defaults. Error: {e}")
