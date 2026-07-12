"""Module implementing a dynamic, heuristic-based deobfuscator for static APK analysis reports.

Resolves obfuscated class and package names to their original library or application modules using string constants, Java package signatures, and Android component naming patterns.
"""

import re

from loguru import logger

from scanner.util.rules import DEOBFUSCATOR_IGNORED_PKG_PREFIXES


class StringClassifier:
    """Classifies obfuscated classes based on string constants referenced inside them."""

    def __init__(self, dx, package_name):
        """Initializes the classifier with the Dex analysis context and main app package name.

        Args:
            dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
            package_name (str): The main app package name (e.g. 'de.muenchen.appcenter.helpme').
        """
        self.dx = dx
        self.package_name = package_name
        self.cache = {}

        # Regexes for dynamic extraction
        # JAVA_PKG_REGEX: strictly lowercase Java package paths to avoid matching uppercase constants/actions
        self.java_pkg_regex = re.compile(r"\b[a-z0-9]{2,8}\.[a-z0-9_]+(?:\.[a-z0-9_]+)+\b")
        # COMPONENT_REGEX: extracts standard Android class naming patterns (e.g. Fragment, Activity)
        self.component_regex = re.compile(
            r"([A-Z]\w*?(?:Fragment|Activity|ViewModel|Service|Receiver|Provider|Repository|Args))"
        )
        # kotlin_data_class_regex: matches Kotlin data class strings with a title property
        self.kotlin_data_class_regex = re.compile(r"\b([A-Z]\w+)\(title=")

        # Common boilerplate package prefixes that don't add diagnostic value;
        # defined centrally in rules.py as DEOBFUSCATOR_IGNORED_PKG_PREFIXES.
        self.ignored_prefixes = DEOBFUSCATOR_IGNORED_PKG_PREFIXES

    def _get_class_strings(self, internal_class_name):
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

    def _get_package_strings(self, internal_class_name):
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

    def _extract_semantic_and_marker_contexts(self, s, contexts):
        """Extracts contexts from semantic signatures and specific marker strings.

        Args:
            s (str): The string constant to analyze.
            contexts (set[str]): The set of contexts to append resolved names to.
        """
        semantic_signatures = {
            "fips-mode": "com.google.crypto.tink",
            "fips mode": "com.google.crypto.tink",
            "decryptionerror": "com.google.crypto.tink",
            "resourcescompat": "androidx.core",
            "dynamic_receiver_not_exported": "androidx.core",
        }
        for kw, pkg in semantic_signatures.items():
            if kw in s.lower():
                contexts.add(pkg)

        if "pslocks" in s.lower():
            contexts.add("com.pslocks.sdk")

    def _extract_kotlin_contexts(self, s, contexts):
        """Extracts contexts from Kotlin data class string representations.

        Args:
            s (str): The string constant to analyze.
            contexts (set[str]): The set of contexts to append resolved names to.
        """
        k_matches = self.kotlin_data_class_regex.findall(s)
        for km in k_matches:
            contexts.add(km)

    def _extract_component_contexts(self, s, contexts):
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
            if len(clean_comp) > 6 and clean_comp not in ("Fragment", "Activity", "ViewModel", "Service"):
                contexts.add(clean_comp)

    def _extract_java_pkg_contexts(self, s, contexts):
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

    def _filter_contexts(self, contexts):
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

    def _extract_contexts(self, strings):
        """Analyzes a set of strings and extracts potential class or package contexts.

        Args:
            strings (iterable[str]): Iterable of string constants.

        Returns:
            set[str]: Set of resolved module or library contexts.
        """
        contexts = set()
        for s in strings:
            self._extract_semantic_and_marker_contexts(s, contexts)
            self._extract_kotlin_contexts(s, contexts)
            self._extract_component_contexts(s, contexts)
            self._extract_java_pkg_contexts(s, contexts)

        return self._filter_contexts(contexts)

    def classify(self, class_name):
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
        for fetcher, _ in [(self._get_class_strings, "class"), (self._get_package_strings, "package")]:
            strings = fetcher(internal_name)
            contexts = self._extract_contexts(strings)
            if contexts:
                sorted_ctx = sorted(contexts)
                formatted = f"{class_name} [{' | '.join(sorted_ctx)}]"
                self.cache[class_name] = formatted
                return formatted

        self.cache[class_name] = class_name
        return class_name


class Deobfuscator:
    """Aggregates string classification heuristics to translate APK reports."""

    def __init__(self, dx, package_name):
        """Initializes the deobfuscator.

        Args:
            dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
            package_name (str): The main app package name.
        """
        self.classifier = StringClassifier(dx, package_name)

    def deobfuscate_class(self, class_name):
        """Translates a class name using string heuristics.

        Args:
            class_name (str): Obfuscated class name.

        Returns:
            str: Deobfuscated class representation.
        """
        return self.classifier.classify(class_name)

    def _is_ignored_system_class(self, short_class):
        """Checks if a short class name should be ignored in API call extraction.

        Args:
            short_class (str): Short class name (e.g. 'String').

        Returns:
            bool: True if the class is in the ignore list, False otherwise.
        """
        return short_class in {
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

    def _extract_method_calls(self, m_ana):
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

    def _get_method_api_calls(self, class_name, method_name):
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

    def _deobfuscate_permission_references(self, report):
        """Deobfuscates permission references in the scan report.

        Args:
            report (dict): Target scan report dictionary.
        """
        if "permissions" not in report or "references" not in report["permissions"]:
            return

        new_refs = {}
        for perm, refs in report["permissions"]["references"].items():
            new_perm_refs = []
            for ref in refs:
                if "->" in ref:
                    parts = ref.split("->")
                    cls_part, method_part = parts[0], parts[1]
                    deobf_cls = self.deobfuscate_class(cls_part)
                    api_calls = self._get_method_api_calls(cls_part, method_part)
                    new_perm_refs.append(f"{deobf_cls}->{method_part}{api_calls}")
                else:
                    new_perm_refs.append(ref)
            new_refs[perm] = sorted(new_perm_refs)
        report["permissions"]["references"] = new_refs

    def _deobfuscate_text(self, text):
        """Replaces obfuscated class and method names in evidence text blocks.

        Args:
            text (str): Raw evidence string.

        Returns:
            str: Deobfuscated evidence string.
        """

        def repl(match):
            prefix = match.group(1)
            cls_name = match.group(2)
            method_suffix = match.group(3)
            method_name = match.group(4)

            deobf_cls = self.deobfuscate_class(cls_name)
            api_calls = self._get_method_api_calls(cls_name, method_name)
            return f"{prefix}'{deobf_cls}'{method_suffix}'{method_name}{api_calls}'"

        return re.sub(
            r"\b([Cc]lass\s+)\'([\w\.\$]+)\'(\s+method\s+)\'([\w<>]+)\'",
            repl,
            text,
        )

    def _deobfuscate_bytecode_audit_evidence(self, report):
        """Deobfuscates bytecode audit evidence strings in the scan report.

        Args:
            report (dict): Target scan report dictionary.
        """
        if "bytecode_audit" not in report:
            return

        audit = report["bytecode_audit"]
        for key in audit:
            if key.endswith("_evidence") and isinstance(audit[key], list):
                deobf_ev = []
                for ev in audit[key]:
                    deobf_ev.append(self._deobfuscate_text(ev))
                audit[key] = sorted(deobf_ev)

    def deobfuscate_report(self, report):
        """Deobfuscates package, class, and method references in-place inside the report dict.

        Args:
            report (dict): Target scan report dictionary.
        """
        logger.info("Running dynamic deobfuscation heuristic on scan results...")
        self._deobfuscate_permission_references(report)
        self._deobfuscate_bytecode_audit_evidence(report)
