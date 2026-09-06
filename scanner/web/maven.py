"""Maven repository version lookups for Google Maven and Maven Central.

Queries Google's Android Maven repository and Maven Central (authoritative XML metadata)
to resolve the latest stable release versions of Java and Android libraries.
"""

import re
import xml.etree.ElementTree as ET

import requests

# Version qualifiers that mark a prerelease build. Reporting one of these as "latest" would
# make the AI report flag apps on the current stable release as outdated.
_PRERELEASE_PATTERN = re.compile(r"(?i)(alpha|beta|rc|snapshot|dev|eap|preview|-m\d+)")


def _latest_stable(versions: list[str]) -> str | None:
    """Picks the last stable entry from an ascending version list.

    Args:
        versions (list[str]): Version strings in the repository's ascending order.

    Returns:
        str | None: The last entry without a prerelease qualifier, the last entry overall
            when only prereleases exist, or None for an empty list.
    """
    cleaned = [v.strip() for v in versions if v.strip()]
    if not cleaned:
        return None
    stable = [v for v in cleaned if not _PRERELEASE_PATTERN.search(v)]
    return stable[-1] if stable else cleaned[-1]


def _format_version(version: str, source: str) -> str:
    """Renders a resolved version and its source page as the model-facing tool result."""
    return f"Latest version: {version} (Source: {source})"


def _query_google_maven(group: str, artifact: str) -> tuple[str, str] | None:
    """Queries Google Maven repository for the latest version.

    Args:
        group (str): Maven group ID.
        artifact (str): Maven artifact ID.

    Returns:
        tuple[str, str] | None: The (version, source URL) pair, or None if not found/failed.
    """
    if any(group.startswith(p) for p in ["androidx", "com.google.", "com.android"]):
        group_path = group.replace(".", "/")
        url = f"https://dl.google.com/dl/android/maven2/{group_path}/group-index.xml"
        try:
            res = requests.get(url, timeout=5.0)
            if res.status_code == 200:
                root = ET.fromstring(res.text)
                elem = root.find(artifact)
                if elem is not None:
                    versions_str = elem.attrib.get("versions", "")
                    # The index is ascending and often ends with alpha/beta/rc builds of the
                    # next release, so the last STABLE entry is the honest "latest".
                    latest = _latest_stable(versions_str.split(","))
                    if latest:
                        # Artifact-specific page in Google's official Maven repository browser.
                        return latest, f"https://maven.google.com/web/index.html#{group}:{artifact}"
        except Exception:
            pass
    return None


def _query_maven_metadata(group: str, artifact: str) -> tuple[str, str] | None:
    """Reads the authoritative ``maven-metadata.xml`` for an artifact on Maven Central.

    The ``<release>``/``<latest>`` elements of ``repo1.maven.org`` are the repository's
    own version bookkeeping and stay current, unlike the ``latestVersion`` field of the
    search.maven.org Solr index, which is known to lag by years (e.g. it reported
    okhttp 5.0.0-alpha.16 while the real release was 5.4.0).

    Args:
        group (str): Maven group ID.
        artifact (str): Maven artifact ID.

    Returns:
        tuple[str, str] | None: The (version, source URL) pair, or None if not found/failed.
    """
    group_path = group.replace(".", "/")
    url = f"https://repo1.maven.org/maven2/{group_path}/{artifact}/maven-metadata.xml"
    try:
        res = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=5.0)
        if res.status_code == 200:
            root = ET.fromstring(res.text)
            latest = root.findtext("versioning/release") or root.findtext("versioning/latest")
            # <release> is merely the newest non-SNAPSHOT and can be an alpha/RC (okhttp
            # famously reported 5.0.0-alpha.x for years); prefer the newest stable from the
            # full version list when the bookkeeping value is a prerelease.
            if latest and _PRERELEASE_PATTERN.search(latest):
                all_versions = [v.text or "" for v in root.findall("versioning/versions/version")]
                latest = _latest_stable(all_versions) or latest
            if latest:
                return latest, f"https://mvnrepository.com/artifact/{group}/{artifact}"
    except Exception:
        pass
    return None


def _query_maven_central(group: str, artifact: str) -> str | None:
    """Queries Maven Central for the latest version.

    Tries the authoritative per-artifact ``maven-metadata.xml`` first. The
    search.maven.org Solr index is only used as a last resort to discover an artifact
    published under a different group ID; because that match is not verified to be the
    same library, the result explicitly says so instead of silently returning it.

    Args:
        group (str): Maven group ID.
        artifact (str): Maven artifact ID.

    Returns:
        str | None: Formatted version string or None if not found/failed.
    """
    if metadata_res := _query_maven_metadata(group, artifact):
        return _format_version(*metadata_res)

    # Last resort: discover the artifact under a different group via the search index,
    # then resolve the version from that group's authoritative metadata.
    url = f"https://search.maven.org/solrsearch/select?q=a:{artifact}&rows=1&wt=json"
    try:
        res = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=5.0)
        if res.status_code == 200:
            docs = res.json().get("response", {}).get("docs", [])
            if docs:
                found_g = docs[0].get("g")
                if found_g and found_g != group:
                    if other_group := _query_maven_metadata(found_g, artifact):
                        return (
                            f"No artifact '{artifact}' under group '{group}'. A same-named artifact exists "
                            f"under the DIFFERENT group '{found_g}' - verify it is the same library before "
                            f"using this: {_format_version(*other_group)}"
                        )
    except Exception:
        pass
    return None


def resolve_latest_version(group: str, artifact: str) -> tuple[str, str] | None:
    """Resolves the latest stable version of an artifact from its authoritative repository.

    This is the structured entry point used to prefetch versions in bulk before the report
    runs. It deliberately covers only the unambiguous sources: an artifact found solely
    under a different group ID needs the human-readable warning that
    :func:`lookup_maven_version` produces, so it is left for the model's own lookup.

    Args:
        group (str): Maven group ID.
        artifact (str): Maven artifact ID.

    Returns:
        tuple[str, str] | None: The (version, source URL) pair, or None if unresolved.
    """
    return _query_google_maven(group, artifact) or _query_maven_metadata(group, artifact)


def lookup_maven_version(group: str, artifact: str) -> str:
    """Queries Google Maven then Maven Central for the latest version of a library.

    Args:
        group (str): Maven group ID.
        artifact (str): Maven artifact ID.

    Returns:
        str: Formatted result string for the model.
    """
    if google_res := _query_google_maven(group, artifact):
        return _format_version(*google_res)

    if maven_central_res := _query_maven_central(group, artifact):
        return maven_central_res

    return "Not found in Google Maven or Maven Central."
