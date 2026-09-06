"""Module implementing a dynamic, heuristic-based deobfuscator for static APK analysis reports.

Resolves obfuscated class and package names to their original library or application modules using string constants, Java package signatures, and Android component naming patterns.
"""

import re
from collections.abc import Iterable
from typing import Any

from loguru import logger

from scanner.util.rules import DEOBFUSCATOR_IGNORED_PKG_PREFIXES

# Precompiled regex patterns for dynamic string classification
_JAVA_PKG_RE = re.compile(r"\b[a-z0-9]{2,8}\.[a-z0-9_]+(?:\.[a-z0-9_]+)+\b")
_COMPONENT_RE = re.compile(r"([a-zA-Z]\w*?(?:Fragment|Activity|ViewModel|Service|Receiver|Provider|Repository|Args))")
_KOTLIN_DATA_CLASS_RE = re.compile(r"\b([A-Z]\w+)\([a-zA-Z_]\w*=")
_EVIDENCE_RE = re.compile(r"\b([Cc]lass\s+)'([\w.$]+)'(\s+method\s+)'([\w<>]+)'")

# Semantic signature keywords and their associated library packages
_SEMANTIC_SIGNATURES: dict[str, str] = {
    "fips-mode": "com.google.crypto.tink",
    "fips mode": "com.google.crypto.tink",
    "decryptionerror": "com.google.crypto.tink",
    "resourcescompat": "androidx.core",
    "dynamic_receiver_not_exported": "androidx.core",
}

# Verbs to skip when converting camelCase component identifiers
_IGNORED_VERBS: tuple[str, ...] = (
    "get",
    "set",
    "is",
    "has",
    "start",
    "stop",
    "bind",
    "unbind",
    "register",
    "unregister",
    "resolve",
    "make",
    "create",
    "remove",
    "add",
    "check",
    "find",
    "init",
    "on",
    "to",
)

# Common generic Android component base names to skip
_GENERIC_COMPONENTS: frozenset[str] = frozenset(
    {
        "Fragment",
        "Activity",
        "ViewModel",
        "Service",
        "Receiver",
        "Provider",
        "Repository",
    }
)

# System standard library class names to ignore in API call extraction
_IGNORED_SYSTEM_CLASSES: frozenset[str] = frozenset(
    {
        "Object",
        "String",
        "StringBuilder",
        "Integer",
        "Boolean",
        "Class",
        "Math",
        "ArrayList",
        "HashMap",
        "List",
        "Map",
        "System",
        "Arrays",
    }
)


class StringClassifier:
    """Classifies obfuscated classes based on string constants referenced inside them."""

    def __init__(self, dx: Any, package_name: str) -> None:
        """Initializes the classifier with the Dex analysis context and main app package name.

        Args:
            dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
            package_name (str): The main app package name (e.g. 'de.muenchen.appcenter.helpme').
        """
        self.dx = dx
        self.package_name = package_name
        self.cache: dict[str, str] = {}

        # Regex references for backward compatibility and performance
        self.java_pkg_regex = _JAVA_PKG_RE
        self.component_regex = _COMPONENT_RE
        self.kotlin_data_class_regex = _KOTLIN_DATA_CLASS_RE

        # Common boilerplate package prefixes that don't add diagnostic value;
        # defined centrally in rules.py as DEOBFUSCATOR_IGNORED_PKG_PREFIXES.
        self.ignored_prefixes = DEOBFUSCATOR_IGNORED_PKG_PREFIXES

    def _get_class_strings(self, internal_class_name: str) -> set[str]:
        """Collects all string constants referenced by a class and its nested/inner classes.

        Args:
            internal_class_name (str): Class signature in internal format (e.g. 'LB8/h;').

        Returns:
            set[str]: Set of referenced string constants.
        """
        strings = set()
        nested_prefix = internal_class_name[:-1] + "$"
        for s in self.dx.get_strings():
            for xref_class, _ in s.get_xref_from():
                if xref_class.name == internal_class_name or xref_class.name.startswith(nested_prefix):
                    strings.add(s.get_value())
        return strings

    def _get_package_strings(self, internal_class_name: str) -> set[str]:
        """Collects all string constants referenced by all classes in the same package.

        Args:
            internal_class_name (str): Class signature in internal format (e.g. 'LB8/h;').

        Returns:
            set[str]: Set of package-level string constants.
        """
        strings = set()
        last_slash = internal_class_name.rfind("/")
        if last_slash <= 1:
            return strings
        pkg_prefix = internal_class_name[: last_slash + 1]
        for s in self.dx.get_strings():
            for xref_class, _ in s.get_xref_from():
                if xref_class.name.startswith(pkg_prefix):
                    strings.add(s.get_value())
        return strings

    def _extract_semantic_and_marker_contexts(self, s: str, contexts: set[str]) -> None:
        """Extracts contexts from semantic signatures and specific marker strings.

        Args:
            s (str): The string constant to analyze.
            contexts (set[str]): The set of contexts to append resolved names to.
        """
        for kw, pkg in _SEMANTIC_SIGNATURES.items():
            if kw in s.lower():
                contexts.add(pkg)

        if "pslocks" in s.lower():
            contexts.add("com.pslocks.sdk")

    def _extract_kotlin_contexts(self, s: str, contexts: set[str]) -> None:
        """Extracts contexts from Kotlin data class string representations.

        Args:
            s (str): The string constant to analyze.
            contexts (set[str]): The set of contexts to append resolved names to.
        """
        k_matches = self.kotlin_data_class_regex.findall(s)
        for km in k_matches:
            contexts.add(km)

    def _extract_component_contexts(self, s: str, contexts: set[str]) -> None:
        """Extracts contexts based on Android component class naming patterns.

        Args:
            s (str): The string constant to analyze.
            contexts (set[str]): The set of contexts to append resolved names to.
        """
        comp_matches = self.component_regex.findall(s)
        for cm in comp_matches:
            clean_comp = cm
            if clean_comp.startswith("Action") and len(clean_comp) > 6 and clean_comp[6].isupper():
                clean_comp = clean_comp[6:]
            if clean_comp.startswith("To") and len(clean_comp) > 2 and clean_comp[2].isupper():
                clean_comp = clean_comp[2:]
            if clean_comp.endswith("Args"):
                clean_comp = clean_comp[:-4]
            if clean_comp.endswith("Directions"):
                clean_comp = clean_comp[:-10]

            # Normalize camelCase property / variable identifiers to PascalCase class names
            if clean_comp and clean_comp[0].islower():
                if any(clean_comp.startswith(v) for v in _IGNORED_VERBS):
                    continue
                # Handle leading acronyms lowercased by Kotlin / JavaBean conventions (e.g. ibS14... -> IBS14...)
                if (
                    clean_comp.startswith("ib")
                    and len(clean_comp) > 2
                    and (clean_comp[2].isupper() or clean_comp[2].isdigit())
                ):
                    clean_comp = "IB" + clean_comp[2:]
                else:
                    clean_comp = clean_comp[0].upper() + clean_comp[1:]

            if len(clean_comp) > 6 and clean_comp not in _GENERIC_COMPONENTS:
                contexts.add(clean_comp)

    def _extract_java_pkg_contexts(self, s: str, contexts: set[str]) -> None:
        """Extracts contexts based on standard Java package naming patterns.

        Args:
            s (str): The string constant to analyze.
            contexts (set[str]): The set of contexts to append resolved names to.
        """
        pkg_matches = self.java_pkg_regex.findall(s)
        for pm in pkg_matches:
            parts = pm.split(".")
            prefix = ".".join(parts[:2])
            if prefix not in self.ignored_prefixes and pm not in self.ignored_prefixes:
                # Simplify to up to 3 segments for readability
                if len(parts) >= 3:
                    contexts.add(".".join(parts[:3]))
                else:
                    contexts.add(pm)

    def _filter_contexts(self, contexts: set[str]) -> set[str]:
        """Filters out generic contexts if application/library-specific ones are present.

        Args:
            contexts (set[str]): The set of extracted contexts.

        Returns:
            set[str]: The filtered set of contexts.
        """
        if not contexts:
            return contexts
        has_app_or_lib = any(
            "com.pslocks" in c or "Fragment" in c or "Activity" in c or self.package_name in c for c in contexts
        )
        if has_app_or_lib:
            return {c for c in contexts if not c.startswith(("com.google.android", "androidx."))}
        return contexts

    def _extract_contexts(self, strings: Iterable[str]) -> set[str]:
        """Analyzes a set of strings and extracts potential class or package contexts.

        Args:
            strings (Iterable[str]): Iterable of string constants.

        Returns:
            set[str]: Set of resolved module or library contexts.
        """
        contexts: set[str] = set()
        for s in strings:
            self._extract_semantic_and_marker_contexts(s, contexts)
            self._extract_kotlin_contexts(s, contexts)
            self._extract_component_contexts(s, contexts)
            self._extract_java_pkg_contexts(s, contexts)

        return self._filter_contexts(contexts)

    def classify(self, class_name: str) -> str:
        """Resolves an obfuscated class name to its original library/module name.

        Args:
            class_name (str): Obfuscated class name (e.g. 'B8.h' or 'LV4/d;').

        Returns:
            str: Resolved context formatting (e.g. 'B8.h [com.pslocks.sdk]').
        """
        if class_name in self.cache:
            return self.cache[class_name]

        # Convert dotted format to internal signature if needed
        if not class_name.startswith("L"):
            internal_name = "L" + class_name.replace(".", "/") + ";"
        else:
            internal_name = class_name

        cls_ana = self.dx.classes.get(internal_name)
        if not cls_ana:
            return class_name

        # Try class-level extraction, then fall back to package-level extraction
        for fetcher in (self._get_class_strings, self._get_package_strings):
            strings = fetcher(internal_name)
            contexts = self._extract_contexts(strings)
            if contexts:
                sorted_ctx = sorted(contexts)
                formatted = f"{class_name} [{' | '.join(sorted_ctx[:2])}]"
                self.cache[class_name] = formatted
                return formatted

        self.cache[class_name] = class_name
        return class_name


class Deobfuscator:
    """Aggregates string classification heuristics to translate APK reports."""

    def __init__(self, dx: Any, package_name: str) -> None:
        """Initializes the deobfuscator.

        Args:
            dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
            package_name (str): The main app package name.
        """
        self.classifier = StringClassifier(dx, package_name)

    def deobfuscate_class(self, class_name: str) -> str:
        """Translates a class name using string heuristics.

        Args:
            class_name (str): Obfuscated class name.

        Returns:
            str: Deobfuscated class representation.
        """
        return self.classifier.classify(class_name)

    def _is_ignored_system_class(self, short_class: str) -> bool:
        """Checks if a short class name should be ignored in API call extraction.

        Args:
            short_class (str): Short class name (e.g. 'String').

        Returns:
            bool: True if the class is in the ignore list, False otherwise.
        """
        return short_class in _IGNORED_SYSTEM_CLASSES

    def _extract_method_calls(self, m_ana: Any) -> list[str]:
        """Extracts external API call signatures invoked within a method analysis.

        Args:
            m_ana (androguard.core.analysis.analysis.MethodAnalysis): Method analysis object.

        Returns:
            list[str]: List of resolved external API call strings.
        """
        called = []
        for target_class, target_method, _ in m_ana.get_xref_to():
            t_name = target_class.name
            if t_name.startswith("L") and t_name.endswith(";"):
                t_name = t_name[1:-1].replace("/", ".")
            if t_name.startswith(("android.", "java.", "javax.", "androidx.")):
                short_class = t_name.split(".")[-1]
                if not self._is_ignored_system_class(short_class):
                    called.append(f"{short_class}.{target_method.name}")
        return called

    def _get_method_api_calls(self, class_name: str, method_name: str) -> str:
        """Extracts key system API calls invoked by a given method.

        Args:
            class_name (str): Obfuscated class name.
            method_name (str): Obfuscated method name.

        Returns:
            str: Resolved API call formatting context (e.g. ' (calls Cipher.doFinal)').
        """
        # Convert dotted class name to signature format
        if not class_name.startswith("L"):
            internal_class = "L" + class_name.replace(".", "/") + ";"
        else:
            internal_class = class_name

        cls_ana = self.classifier.dx.classes.get(internal_class)
        if not cls_ana:
            return ""

        for m_ana in cls_ana.get_methods():
            if m_ana.name == method_name:
                called = self._extract_method_calls(m_ana)
                if called:
                    unique_calls = sorted(set(called))
                    return " (calls " + " | ".join(unique_calls[:3]) + ")"
        return ""

    def _deobfuscate_call_site(self, ref: str) -> str:
        """Deobfuscates a single call-site string.

        Args:
            ref (str): Raw call-site string.

        Returns:
            str: Deobfuscated call-site string with annotated API calls.
        """
        if "->" in ref:
            parts = ref.split("->")
            cls_part, method_part = parts[0], parts[1]
            deobf_cls = self.deobfuscate_class(cls_part)
            api_calls = self._get_method_api_calls(cls_part, method_part)
            return f"{deobf_cls}->{method_part}{api_calls}"
        return ref

    def _deobfuscate_permission_references(self, report: dict[str, Any]) -> None:
        """Deobfuscates permission references in the scan report.

        Args:
            report (dict[str, Any]): Target scan report dictionary.
        """
        if "permissions" not in report or "references" not in report["permissions"]:
            return

        new_refs: dict[str, Any] = {}
        for perm, refs in report["permissions"]["references"].items():
            if isinstance(refs, dict):
                new_refs[perm] = {
                    "app_internal": sorted(self._deobfuscate_call_site(r) for r in refs.get("app_internal", [])),
                    "third_party": sorted(self._deobfuscate_call_site(r) for r in refs.get("third_party", [])),
                }
            elif isinstance(refs, list):
                new_refs[perm] = sorted(self._deobfuscate_call_site(r) for r in refs)
            else:
                new_refs[perm] = refs
        report["permissions"]["references"] = new_refs

    def _deobfuscate_text(self, text: str) -> str:
        """Replaces obfuscated class and method names in evidence text blocks.

        Args:
            text (str): Raw evidence string.

        Returns:
            str: Deobfuscated evidence string.
        """

        def repl(match: re.Match) -> str:
            prefix = match.group(1)
            cls_name = match.group(2)
            method_suffix = match.group(3)
            method_name = match.group(4)

            deobf_cls = self.deobfuscate_class(cls_name)
            api_calls = self._get_method_api_calls(cls_name, method_name)
            return f"{prefix}'{deobf_cls}'{method_suffix}'{method_name}{api_calls}'"

        return _EVIDENCE_RE.sub(repl, text)

    def _deobfuscate_bytecode_audit_evidence(self, report: dict[str, Any]) -> None:
        """Deobfuscates bytecode audit evidence strings in the scan report.

        Args:
            report (dict[str, Any]): Target scan report dictionary.
        """
        if "bytecode_audit" not in report:
            return

        audit = report["bytecode_audit"]
        for key, val in audit.items():
            if isinstance(val, list):
                audit[key] = sorted(self._deobfuscate_text(ev) for ev in val)

    def deobfuscate_report(self, report: dict[str, Any]) -> None:
        """Deobfuscates package, class, and method references in-place inside the report dict.

        Args:
            report (dict[str, Any]): Target scan report dictionary.
        """
        logger.info("Running dynamic deobfuscation heuristic on scan results...")
        self._deobfuscate_permission_references(report)
        self._deobfuscate_bytecode_audit_evidence(report)
