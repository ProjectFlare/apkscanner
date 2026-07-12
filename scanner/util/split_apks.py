"""Module for extracting and parsing split APK ZIP files.

Identifies the base APK and extracts all DEX bytecode files from the split bundle.
"""

import hashlib
import os
import shutil
import tempfile
import zipfile

from androguard.core.apk import APK
from androguard.core.dex import DEX
from loguru import logger


def _extract_and_find_apks(zip_path, temp_dir):
    """Unzips the archive to a temp directory and returns paths of all .apk files.

    Args:
        zip_path (str): Path to the split APK ZIP file.
        temp_dir (str): Path to the temporary directory.

    Returns:
        list[str]: Paths to the extracted APK files.
    """
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(temp_dir)

    apk_files = []
    for root_dir, _, files in os.walk(temp_dir):
        for file in files:
            if file.endswith(".apk"):
                apk_files.append(os.path.join(root_dir, file))
    return apk_files


def _calculate_metadata_and_load(apk_files):
    """Loads APKs and computes their sizes and SHA256 hashes.

    Args:
        apk_files (list[str]): Paths to APK files.

    Returns:
        tuple[list[tuple[str, APK]], list[dict]]: A tuple of loaded APK pairs and split metadata.
    """
    all_apks = []
    split_apks_metadata = []
    for path in apk_files:
        apk_obj = APK(path)
        all_apks.append((path, apk_obj))

        size = os.path.getsize(path)
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)

        split_apks_metadata.append({"name": os.path.basename(path), "size_bytes": size, "sha256": sha256.hexdigest()})
    return all_apks, split_apks_metadata


def _find_base_apk(all_apks):
    """Identifies the base APK from a list of loaded APKs.

    Args:
        all_apks (list[tuple[str, APK]]): Loaded APK objects.

    Returns:
        tuple[APK, str]: The base APK and its filesystem path.
    """
    # 1. Look for split attribute missing in AndroidManifest.xml
    for path, apk_obj in all_apks:
        manifest_xml = apk_obj.get_android_manifest_xml()
        if manifest_xml is not None and "split" not in manifest_xml.attrib:
            return apk_obj, path

    # 2. Fallback to filenames containing 'base.apk'
    for path, apk_obj in all_apks:
        if "base.apk" in os.path.basename(path).lower():
            return apk_obj, path

    # 3. Fallback to first APK in the list
    return all_apks[0][1], all_apks[0][0]


def _extract_dex_files(all_apks):
    """Extracts all DEX files from a list of loaded APKs.

    Args:
        all_apks (list[tuple[str, APK]]): Loaded APK objects.

    Returns:
        list[DEX]: Extracted DEX files.
    """
    dex_files = []
    for path, apk_obj in all_apks:
        dex_filenames = [f for f in apk_obj.get_files() if f.endswith(".dex")]
        for f in dex_filenames:
            try:
                dex_data = apk_obj.get_file(f)
                if dex_data:
                    dex_files.append(DEX(dex_data))
            except Exception as de:
                logger.warning(f"Failed to parse DEX file {f} in {os.path.basename(path)}: {de!s}")
    return dex_files


def parse_split_apks(zip_path):
    """Unzips a split APK ZIP file, identifies base APK, and retrieves DEX files.

    Args:
        zip_path (str): Path to the split APK ZIP file.

    Returns:
        tuple: A tuple containing:
            - base_apk (androguard.core.apk.APK): The parsed base APK object.
            - base_apk_path (str): File system path to the extracted base APK.
            - dex_files (list[androguard.core.dex.DEX]): List of DEX objects from all split APKs.
            - split_apks_metadata (list[dict]): List of metadata dictionaries for each split APK.
            - apk_objects (list[androguard.core.apk.APK]): List of all APK objects in the split ZIP.
            - temp_dir (str): Path to the temporary directory containing extracted APKs.

    Raises:
        ValueError: If no .apk files are found in the zip archive.
    """
    temp_dir = tempfile.mkdtemp(prefix="split_apk_")

    try:
        apk_files = _extract_and_find_apks(zip_path, temp_dir)
        if not apk_files:
            raise ValueError("No .apk files found in the zip archive.")

        all_apks, split_apks_metadata = _calculate_metadata_and_load(apk_files)
        base_apk, base_apk_path = _find_base_apk(all_apks)
        dex_files = _extract_dex_files(all_apks)
        apk_objects = [apk_obj for _, apk_obj in all_apks]

        return base_apk, base_apk_path, dex_files, split_apks_metadata, apk_objects, temp_dir

    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise e
