"""Prompt templates for mobile application security report generation.

Used by the AI static analysis scanner modules to query local LLMs via the
agentic tool-calling loop in ``tool_runner``.

The templates deliberately avoid em/en dashes and rare jargon: local models mirror
the vocabulary and punctuation of their prompts, so the style rules enforced on the
report output are also followed in the prompt text itself.
"""

SYSTEM_PROMPT_TEMPLATE = (
    "You are an expert mobile application security analyst. "
    "Today's date is __CURRENT_DATE__. Your own training data is older than that, so treat any "
    "date, version number, or 'latest release' you remember as outdated until a tool result confirms it.\n\n"
    "Critical Rules:\n"
    "1. TOOL VERIFICATION: Never rely on memory for version numbers, CVE severities, or CVSS scores. "
    "Verify them using lookup_maven_version, lookup_osv_vulnerabilities, or lookup_nvd_cve. "
    "Use web_search selectively for domain reputation or remediation guidance, within a budget of at most "
    "10 queries. Results come from a curated allowlist of trusted sites. Prefer the MOST RECENT results. "
    "NEVER add a year or date to a web_search query; search the bare topic. "
    "A source URL is ONLY valid if returned verbatim inside a tool result; never invent or guess URLs.\n"
    "2. EVIDENCE GROUNDING: Every factual claim about exposed data or behaviour MUST be strictly supported "
    "by the concrete evidence in the findings. A detected flag (for example allowBackup, usesCleartextTraffic, "
    "debuggable) proves only that the flag is set, never which specific data is affected. If impact depends "
    "on unverified data, state it conditionally.\n"
    "3. ACTION-FIRST WRITING: State the bottom-line verdict or primary action first, followed by a concise "
    "1-2 sentence technical explanation. Let sentences flow naturally, and do not use em or en dashes.\n"
    "4. TOOL CALLING: During tool-calling turns output ONLY the tool call, with no conversational text.\n"
    "5. STRICT JSON OUTPUT: Your final response must be a single valid JSON object matching the requested "
    "schema. Do not wrap in markdown fences or output text outside the JSON object."
)

# JSON output schema reference strings (embedded in section prompts)
FINDINGS_SCHEMA = (
    "Output a single JSON object matching this exact schema:\n"
    "{\n"
    '  "no_findings": false,\n'
    '  "findings": [\n'
    "    {\n"
    '      "title": "<Descriptive finding name referencing the concrete artifact named in the findings>",\n'
    '      "risk": "<Action-First verdict and severity impact first, followed by a concise 1-2 sentence technical risk grounded strictly in the evidence; describe any unverified impact conditionally>",\n'
    '      "attack_vector": "<Direct threat model and preconditions first, followed by concise steps an attacker would take, consistent with the evidence>",\n'
    '      "developer_intent": "<The logical engineering reason this ended up in the app, reasoned from the APP developer\'s perspective. If in a third-party dependency, explain why the app developer included that library>",\n'
    '      "remediation": "<Actionable, step-by-step developer remediation instructions>",\n'
    '      "code_snippet": "<Targeted code-level fix (XML config or Kotlin/Java, under ~20 lines; raw code only, do not wrap in markdown code fences or backticks). If no direct code fix is applicable (such as when issue is inside a third-party dependency, requires library updates, or is an architectural recommendation), set to null>",\n'
    '      "code_language": "<lowercase language identifier for syntax highlighting, such as kotlin, java, xml, or empty string if code_snippet is null>",\n'
    '      "sources": [{"url": "<official documentation or CVE advisory URL from tool results>", "description": "<A few words describing what this page shows>"}]\n'
    "    }\n"
    "  ]\n"
    "}\n"
    'If there are no security risks, output: {"no_findings": true, "findings": []}'
)

SECRETS_SCHEMA = (
    "Output a single JSON object matching this exact schema:\n"
    "{\n"
    '  "no_findings": false,\n'
    '  "findings": [\n'
    "    {\n"
    '      "title": "<Secret type and identifier from findings>",\n'
    '      "risk": "<Action-First severity verdict first, followed by 1-2 sentences stating the EXACT unmasked secret value and potential exposure risk>",\n'
    '      "attack_vector": "<How an attacker extracts and abuses this credential from the decompiled APK>",\n'
    '      "developer_intent": "<Why this key was embedded in client code, noting if it is a public identifier or backend secret>",\n'
    '      "remediation": "<Key rotation, server-side migration, and scoping steps>",\n'
    '      "sources": [{"url": "<official API security documentation URL>", "description": "<Source description>"}]\n'
    "    }\n"
    "  ]\n"
    "}\n"
    'If there are no secrets (or all candidates are public constants / false positives), output: {"no_findings": true, "findings": []}'
)

SIGNATURES_SCHEMA = (
    "Output a single JSON object matching this exact schema:\n"
    "{\n"
    '  "no_findings": false,\n'
    '  "findings": [\n'
    "    {\n"
    '      "title": "<Weak Signature Algorithm | Debug Certificate>",\n'
    '      "risk": "<Action-First verdict first, followed by 1-2 sentences on APK signature verification and collision risks>",\n'
    '      "attack_vector": "<How an attacker could exploit weak hashes or debug signing>",\n'
    '      "developer_intent": "<Why this signing configuration was used, such as legacy build scripts or debug builds>",\n'
    '      "remediation": "<Concrete steps to re-sign using APK Signature Scheme v2/v3 and SHA-256>",\n'
    '      "code_snippet": "<Targeted build configuration fix (such as Gradle signingConfigs, under ~20 lines; raw code only, do not wrap in markdown code fences or backticks). If no direct code fix is applicable, set to null>",\n'
    '      "code_language": "<lowercase language identifier for syntax highlighting, such as groovy, kotlin, or empty string if code_snippet is null>",\n'
    '      "sources": [{"url": "https://source.android.com/docs/security/features/apksigning", "description": "Android APK Signature Scheme documentation"}]\n'
    "    }\n"
    "  ]\n"
    "}\n"
    'If there are no signature risks, output: {"no_findings": true, "findings": []}'
)

INFORMATIONAL_SCHEMA = (
    "Output a single JSON object matching this exact schema:\n"
    "{\n"
    '  "no_findings": false,\n'
    '  "items": [\n'
    "    {\n"
    '      "finding": "<The observation\'s title from the findings>",\n'
    '      "evidence": ["<All exact artifacts from this item\'s evidence: class names, deep-link schemes, root indicators, or components>"],\n'
    '      "detail": "<Action-First posture verdict first, followed by 1-2 sentences explaining what this construct is and its role in this app, assessing all evidence items>",\n'
    '      "recommendation": "<Core action first, followed by what to verify, or state plainly if expected>",\n'
    '      "sources": [{"url": "<official Android developer doc URL from tool results or standard reference>", "description": "<Source description>"}]\n'
    "    }\n"
    "  ]\n"
    "}\n"
    'If there are no items found, output: {"no_findings": true, "items": []}'
)

PERMISSIONS_SCHEMA = (
    "Output a single JSON object matching this exact schema:\n"
    "{\n"
    '  "no_findings": false,\n'
    '  "items": [\n'
    "    {\n"
    '      "name": "<exact permission string from findings>",\n'
    '      "group": "<runtime_requested | install_time_or_system | custom_or_third_party>",\n'
    '      "description": "<1-2 sentences: what the permission allows and specific class/methods where called>",\n'
    '      "verdict": "Safe (Expected)",\n'
    '      "rationale": "<1-sentence technical explanation tied to the app\'s verified purpose>",\n'
    '      "sources": [{"url": "<https://developer.android.com/reference/android/Manifest.permission#...>", "description": "Android Manifest.permission reference"}]\n'
    "    }\n"
    "  ]\n"
    "}\n"
    'If there are no permissions, output: {"no_findings": true, "items": []}'
)

DEPS_SCHEMA = (
    "Output a single JSON object matching this exact schema:\n"
    "{\n"
    '  "no_findings": false,\n'
    '  "items": [\n'
    "    {\n"
    '      "source_name": "<the EXACT dependency key from the findings, echoed verbatim>",\n'
    '      "name": "<full Maven coordinate in group:artifact form or root library name>",\n'
    '      "version_used": "<exact version from findings, or \'unknown\'>",\n'
    '      "latest_version": "<the known_facts latest_version, else lookup tool result, or \'unknown\'>",\n'
    '      "latest_version_url": "<the known_facts latest_version_url, else URL from lookup tool, or empty string>",\n'
    '      "purpose": "<The library\'s functionality and role in this application>",\n'
    "      \"vulnerabilities\": \"<If version_used is known: specific CVEs from known_facts or tool lookup, or 'No known vulnerabilities found'. If version_used is 'unknown': exactly the text 'Version unknown - not assessed'. NEVER state a CVE ID that did not come from known_facts or a tool result>\"\n"
    "    }\n"
    "  ]\n"
    "}\n"
    'If there are no dependencies, output: {"no_findings": true, "items": []}'
)

NETWORK_SCHEMA = (
    "Output a single JSON object matching this exact schema:\n"
    "{\n"
    '  "no_findings": false,\n'
    '  "cloud_services": [\n'
    '    {"domain": "<domain from findings>", "assessment": "<Threat analysis and reputation check>", "is_developer_code": true, "sources": [{"url": "<url>", "description": "<Source description>"}]}\n'
    "  ],\n"
    '  "trackers_and_ads": [\n'
    '    {"domain": "<domain from findings>", "assessment": "<Threat assessment, tracking capabilities, and privacy impact>", "is_developer_code": false, "sources": [{"url": "<url>", "description": "<Source description>"}]}\n'
    "  ],\n"
    '  "other": [\n'
    '    {"domain": "<domain from findings>", "assessment": "<Domain reputation and connection justification>", "is_developer_code": false, "sources": [{"url": "<url>", "description": "<Source description>"}]}\n'
    "  ]\n"
    "}\n"
    'If there are no network findings, output: {"no_findings": true, "cloud_services": [], "trackers_and_ads": [], "other": []}'
)

VULNS_SCHEMA = (
    "Output a single JSON object matching this exact schema:\n"
    "{\n"
    '  "no_findings": false,\n'
    '  "summary": "<2-3 sentence overall security posture summary of the application>",\n'
    '  "findings": [\n'
    "    {\n"
    '      "owasp_id": "<OWASP category ID from findings>",\n'
    '      "owasp_category": "<OWASP Mobile Top 10 category name from findings>",\n'
    '      "vulnerability": "<Concise, descriptive security vulnerability name>",\n'
    '      "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",\n'
    '      "cvss_score": "<CVSS v3 base score or null>",\n'
    '      "cwe": "<CWE identifier and name matching the weakness>",\n'
    '      "sources": [{"url": "<source URL from tool results>", "description": "<Source description>"}]\n'
    "    }\n"
    "  ]\n"
    "}\n"
    'If there are no vulnerabilities, output: {"no_findings": true, "summary": "", "findings": []}'
)

APP_CONTEXT_SCHEMA = (
    "Output a single JSON object matching this exact schema:\n"
    "{\n"
    '  "app_name": "<name>",\n'
    '  "developer": "<developer or company name>",\n'
    '  "primary_purpose": "<Concise 1-sentence summary of the core function and category of the app>",\n'
    '  "play_store_url": "https://play.google.com/store/apps/details?id=<package>",\n'
    '  "official_website": "<URL or null>",\n'
    '  "status": "<Active | Discontinued | Unknown>",\n'
    '  "description": "<2-3 sentence paragraph describing user workflows, supported features, and cloud integrations in neutral, third-person prose. Never copy marketing wording or rhetorical questions>",\n'
    '  "security_incidents": [\n'
    "    {\n"
    '      "summary": "<What happened, in 1-2 factual sentences>",\n'
    '      "date": "<YYYY-MM or YYYY-MM-DD>",\n'
    '      "relation": "<mobile_app | backend | connected_infrastructure>",\n'
    '      "impact": "<Affected users and adoption decision impact>",\n'
    '      "source_url": "<trusted news source URL returned verbatim by a tool>"\n'
    "    }\n"
    "  ],\n"
    '  "sources": [{"url": "<real source URL from tool result or official listing>", "description": "<Source description>"}]\n'
    "}\n"
    'If no information is found, output: {"app_name": null, "developer": null, "primary_purpose": "No information found.", '
    '"play_store_url": null, "official_website": null, "status": "Unknown", "description": "No information about this application could be found online.", "security_incidents": [], "sources": []}'
)

PERMISSIONS_PROMPT_TEMPLATE = (
    "Audit the following Android permissions for the application using the following data:\n\n"
    "Application Context:\n__APP_CONTEXT__\n\n"
    "Permissions to Audit:\n__DATA_JSON__\n\n"
    "Instructions:\n"
    "- Set each item's 'group' to runtime_requested, install_time_or_system, or custom_or_third_party.\n"
    "- For each permission, explain what it allows on Android and where it is used, naming the provided call sites/classes.\n"
    "- If a permission has no call sites listed, note that it is a manifest-level declaration.\n"
    "- Set 'verdict' to 'Safe (Expected)', 'Potentially Risky', or 'Unnecessary/Legacy', and provide a 1-sentence technical rationale.\n"
    "- Set 'sources' to the official Android Manifest.permission reference URL.\n\n" + PERMISSIONS_SCHEMA
)

DEPENDENCIES_PROMPT_TEMPLATE = (
    "Audit the 'Dependencies' for the application using the following data:\n\n"
    "Application Context:\n__APP_CONTEXT__\n\n"
    "Dependency Group Context: __DEP_GROUP_LABEL__\n\n"
    "Static Analysis Findings:\n__DATA_JSON__\n\n"
    "Instructions:\n"
    "- The findings map third-party dependency names to their version details (version_used, latest_version, latest_version_url, osv_findings).\n"
    "- Output exactly one item for EVERY entry in the provided mapping. Never skip or drop an entry.\n"
    "- Set every item's 'source_name' to the exact findings key it corresponds to, echoed verbatim.\n"
    "- Copy the provided version_used, latest_version, and latest_version_url straight into the output; do NOT call lookup_maven_version or lookup_osv_vulnerabilities for entries that already contain these values.\n"
    "- If osv_findings are listed, summarize each CVE. If osv_findings is empty and version_used is known, state 'No known vulnerabilities found for this version by the OSV.dev batch check'.\n"
    "- For unversioned libraries (version_used is null or 'unknown'), set version_used and latest_version to 'unknown' and vulnerabilities to 'Version unknown - not assessed': a CVE cannot be attributed without a version, and recalling one from memory produces errors.\n\n"
    + DEPS_SCHEMA
)

SECRETS_PROMPT_TEMPLATE = (
    "Audit the 'Secrets' found in the application using the following data:\n\n"
    "Application Context:\n__APP_CONTEXT__\n\n"
    "Static Analysis Findings:\n__DATA_JSON__\n\n"
    "Instructions:\n"
    "- Each item in the findings represents a detected secret or a consolidated group of keys sharing the same origin or variable name.\n"
    "- Evaluate each item as a single consolidated assessment covering all associated values and locations.\n"
    "- In the 'risk' field, state the Action-First severity verdict and print all exact unmasked values.\n"
    "- Detail the attack vector, developer intent, and server-side remediation steps.\n"
    '- If a finding candidate is determined to be a public constant, standard cryptographic domain parameter (such as elliptic curve coordinates, generator points, S-boxes, or DRBG test vectors), or false positive rather than an actionable secret, omit it from \'findings\'. If all candidate items are false positives or public constants, output: {"no_findings": true, "findings": []}.\n\n'
    + SECRETS_SCHEMA
)

NETWORK_PROMPT_TEMPLATE = (
    "Audit the 'Network' findings for the application using the following data:\n\n"
    "Application Context:\n__APP_CONTEXT__\n\n"
    "Static Analysis Findings:\n__DATA_JSON__\n\n"
    "Instructions:\n"
    "- Provide an assessment for every single domain present in the findings; never drop or omit any domain.\n"
    "- Only report domains present in findings.\n"
    "- Attribute each domain to developer or third-party code based on referencing packages.\n"
    "- Assess reputation and group into cloud_services, trackers_and_ads, and other.\n\n" + NETWORK_SCHEMA
)

VULNERABILITIES_PROMPT_TEMPLATE = (
    "Audit the 'Vulnerabilities' for the application using the following data:\n\n"
    "Application Context:\n__APP_CONTEXT__\n\n"
    "Static Analysis Findings:\n__DATA_JSON__\n\n"
    "Instructions:\n"
    "- Report every finding in the data; never drop one.\n"
    "- Echo the OWASP Mobile Top 10 category and MASVS identifiers provided in the findings.\n"
    "- Provide the standard CWE identifier and weakness name matching the evidence.\n"
    "- When evidence points strictly to third-party library internals, lower severity to LOW and explain from the evidence rather than from any assumption.\n\n"
    + VULNS_SCHEMA
)

STANDARD_SECTION_PROMPT_TEMPLATE = (
    "Audit the '__SECTION_NAME__' findings for the application using the following data:\n\n"
    "Application Context:\n__APP_CONTEXT__\n\n"
    "Static Analysis Findings:\n__DATA_JSON__\n\n"
    "Specific Section Guidelines:\n__GUIDELINES__\n\n"
    "Instructions:\n"
    "- Every finding MUST correspond to a specific issue in the provided findings.\n"
    "- For any CVE: call lookup_nvd_cve(cve_id) to get the CVSS v3 score.\n"
    "- Provide actionable remediation. Provide targeted code snippets where application code can be modified, or set code_snippet to null if the issue is in a third-party dependency with no direct code fix (do not generate comment-only placeholder snippets).\n"
    "- Place all code fixes in 'code_snippet' with 'code_language'. Do not paste raw unfenced code blocks into 'remediation'.\n\n"
    + FINDINGS_SCHEMA
)

APP_CONTEXT_PROMPT_TEMPLATE = (
    "Gather metadata for the Android app named '__KNOWN_APP_NAME__' (package ID: __PACKAGE__).\n\n"
    "Build environment detected by static analysis: __UI_FRAMEWORK__.\n\n"
    "Verified Play Store metadata:\n__PLAYSTORE_METADATA__\n\n"
    "Instructions:\n"
    "1. Use the verified Play Store metadata above. If empty, call lookup_play_store('__PACKAGE__').\n"
    "2. If needed, call web_search to discover the official website or verify active status.\n"
    "3. Write primary_purpose as a concise 1-sentence summary, and description as a 2-3 sentence paragraph in neutral prose.\n"
    "4. Assess security incidents strictly as an ADOPTION-RISK question. Search trusted news for material security incidents "
    "reported by a trusted source on or after __INCIDENT_CUTOFF_DATE__. If none, output an empty security_incidents array.\n"
    "5. Populate the 'sources' array with all retrieved URLs.\n\n" + APP_CONTEXT_SCHEMA
)

MANIFEST_AUDIT_GUIDELINES = (
    "- Audits security configurations inside AndroidManifest.xml.\n"
    "- For findings requiring manifest changes, provide a targeted, valid XML remediation snippet ready to insert into AndroidManifest.xml (or set code_snippet to null if not applicable).\n"
    "- For allowBackup: state exposure conditionally unless private storage data findings exist. "
    "It does not expose Keystore keys or biometric data, which are system-managed. "
    "Note android:fullBackupContent or android:dataExtractionRules scoping.\n"
    "- Consider target_sdk_version and uses_cleartext_traffic: on API 28+ (Android 9+), cleartext HTTP traffic is disabled by default.\n"
    "- Do not invent generic findings or report positive security flags as issues."
)

SIGNATURES_GUIDELINES = (
    "- Audits developer certificates and APK signature schemes (v1, v2, v3).\n"
    "- Do not report self-signed certificates as a risk; they are standard on Android.\n"
    "- Only report a risk if is_debug_signed is True or has_weak_hash is True.\n"
    "- Provide targeted build configuration code snippets (such as Gradle signingConfigs, <20 lines; raw code without markdown backticks) under 'code_snippet', and keep 'remediation' as descriptive steps.\n"
    '- If no signature risks exist, output {"no_findings": true, "findings": []}.'
)

BYTECODE_AUDIT_GUIDELINES = (
    "- Audits Dalvik bytecode for insecure operations detected in the findings.\n"
    "- Name the exact classes and methods where issues were detected.\n"
    "- Consolidate identical vulnerability types: when multiple classes or methods exhibit the same weakness, combine them into a single consolidated finding that references all affected classes and methods, rather than creating separate duplicate findings.\n"
    "- Report every detection in the data; never drop one. When findings point strictly to third-party library internals, "
    "rate severity as LOW and explain from the evidence rather than from any assumption about libraries.\n"
    "- Provide minimal, copy-pasteable Java/Kotlin replacement snippets (<20 lines; raw code without markdown backticks). "
    "If an issue is entirely inside a third-party library or cannot be fixed by modifying application code, set code_snippet to null instead of generating placeholder comments."
)

INFORMATIONAL_GUIDELINES = (
    "- Audits informational security-posture observations (exported components, custom deep links, root detection, dynamic code loading, legacy signature hardening).\n"
    "- Output exactly one item for EVERY observation present in the findings; never skip or drop any observation. These do not affect the security score.\n"
    "- In the 'evidence' list for each item, include all exact artifacts present in the findings for that observation; never truncate to only the top-most item.\n"
    "- In 'detail', evaluate the entire set of evidence artifacts collectively to assess the overall security posture.\n"
    "- State Action-First posture verdict in detail based on evidence, followed by concise technical context.\n"
    "- Distinguish standard development tooling artifacts from actionable attack surface and state expected posture plainly."
)

INFORMATIONAL_PROMPT_TEMPLATE = (
    "Audit the 'Informational' observations for the application using the following data:\n\n"
    "Application Context:\n__APP_CONTEXT__\n\n"
    "Static Analysis Findings:\n__DATA_JSON__\n\n"
    "Instructions:\n" + INFORMATIONAL_GUIDELINES + "\n\n" + INFORMATIONAL_SCHEMA
)
