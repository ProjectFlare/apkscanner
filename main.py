# Entry point for the APK Scanner.
# Initiates the analysis workflow, aggregates reports, and outputs JSON.

import os
import sys
import json
import argparse
import logging
import hashlib
import shutil
from datetime import datetime, timezone

from loguru import logger
# Disable default loguru logging configuration to prevent stdout cluttering
logger.remove()

from tqdm import tqdm
from androguard.core.apk import APK
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import Analysis

from scanner import (
    extract_dependencies,
    extract_permissions,
    extract_secrets,
    extract_urls,
    extract_domains,
    analyze_ui_framework,
    analyze_cpu_architecture,
    analyze_manifest_security,
    analyze_security_checks,
    parse_split_apks,
    analyze_vulnerabilities,
    update_rules_db,
    audit_signatures,
    analyze_bytecode
)

# Standard logging configuration for command-line feedback
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def calculate_hashes(filepath):
    """Computes cryptographic hashes (SHA256, SHA1, MD5) for a given file.

    Args:
        filepath (str): Path to the target binary file.

    Returns:
        dict: A dictionary mapping hash names ("sha256", "sha1", "md5") to their hex digests.
    """
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
            
    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest()
    }


def scan_apk(target_path):
    """Parses and scans a single Android APK file or a split APK zip archive.

    Executes static analyses including bytecode cross-referencing, metadata extraction,
    dependency detection, secret sniffing, domain grouping, permission classification,
    AndroidManifest security auditing, and security capability checks.

    Args:
        target_path (str): File system path to the target APK or split APK ZIP.

    Returns:
        dict: The final assembled report dictionary, or None if the scan fails.
    """
    TOTAL_STEPS = 5
    scan_start = datetime.now(timezone.utc)
    
    temp_dir = None
    split_apks_metadata = None
    dex_files = []
    
    with tqdm(total=TOTAL_STEPS, desc="Step 1/5: Parsing APK structure", position=0) as step_pbar:
        try:
            # Step 1: Parse the file structure and AndroidManifest.xml
            if target_path.endswith('.zip'):
                step_pbar.set_description("Step 1/5: Extracting and parsing split APKs")
                apk, _, dex_files, split_apks_metadata, apk_objects, temp_dir = parse_split_apks(target_path)
            else:
                apk = APK(target_path)
                apk_objects = [apk]
                
            step_pbar.update(1)
            step_pbar.set_description("Step 2/5: Loading DEX files")
            
            # Step 2: Retrieve all Dalvik Executable (DEX) bytecode files
            if not target_path.endswith('.zip'):
                dex_filenames = [f for f in apk.get_files() if f.endswith('.dex')]
                dex_files = []
                
                if dex_filenames:
                    for f in tqdm(dex_filenames, desc="Reading bytecode", leave=False, unit="file", position=1):
                        try:
                            dex_data = apk.get_file(f)
                            if dex_data:
                                dex_files.append(DEX(dex_data))
                        except Exception as de:
                            logging.warning(f"Failed to parse DEX file {f}: {str(de)}")
            
            step_pbar.update(1)
            step_pbar.set_description("Step 3/5: Initializing analysis matrix")
            
            # Step 3: Parse and link internal structures into the multidex analysis framework
            dx = Analysis()
            if dex_files:
                for d in tqdm(dex_files, desc="Parsing classes", leave=False, unit="dex", position=1):
                    dx.add(d)
            
            step_pbar.update(1)
            step_pbar.set_description("Step 4/5: Building Cross-References (XREFs)")
            
            # Step 4: Resolve class, method, field and string relationships (XREFs)
            dx.create_xref()
            
            step_pbar.update(1)
            step_pbar.set_description("Step 5/5: Running feature extraction modules")
            
            # Step 5: Execute security scanners and metadata analyzers
            scan_end = datetime.now(timezone.utc)
            found_urls = extract_urls(dx)
            package_name = apk.get_package()
            
            # Audit AndroidManifest configuration flags and entrypoints across all split APK objects
            manifest_security = analyze_manifest_security(apk_objects)
            
            # Run security capabilities checks (root detection and allows static analysis)
            security_checks = analyze_security_checks(apk_objects, dx)
            
            # Audit developer certificates and signature schemes
            signatures = audit_signatures(apk_objects)
            
            # Execute Dalvik bytecode analysis
            bytecode_audit = analyze_bytecode(dx)
            
            # Assemble the structured report JSON
            report = {
                "scan_metadata": {
                    "scan_started": scan_start.isoformat(),
                    "scan_completed": scan_end.isoformat(),
                    "duration_seconds": (scan_end - scan_start).total_seconds()
                },
                "apk_metadata": {
                    "apk_name": os.path.basename(target_path),
                    "package": package_name,
                    "app_version_name": apk.get_androidversion_name(),
                    "app_version_code": apk.get_androidversion_code(),
                    "min_sdk_version": apk.get_min_sdk_version(),
                    "target_sdk_version": apk.get_target_sdk_version(),
                    "hashes": calculate_hashes(target_path)
                },
                "environment_details": {
                    "ui_framework": analyze_ui_framework(apk_objects, dx),
                    "cpu_architecture": analyze_cpu_architecture(apk_objects)
                },
                "manifest_audit": manifest_security,
                "security_checks": security_checks,
                "signatures": signatures,
                "permissions": extract_permissions(apk_objects),
                "dependencies": extract_dependencies(apk_objects, dx),
                "secrets": extract_secrets(dx, apk_objects),
                "bytecode_audit": bytecode_audit,
                "network": {
                    "attributed_urls": found_urls,
                    "categorized_domains": extract_domains(found_urls)
                }
            }
            
            if split_apks_metadata:
                report["apk_metadata"]["split_apks"] = split_apks_metadata
                
            # Perform OWASP Mobile Top 10 vulnerabilities mapping (including OSV.dev dependency lookup)
            report["vulnerabilities"] = analyze_vulnerabilities(apk_objects, report)
            
            step_pbar.update(1)
            step_pbar.set_description("Scan complete")
            return report

        except Exception as e:
            print("", file=sys.stderr)
            logging.error(f"Execution stopped. Analysis failed for {target_path}: {str(e)}")
            return None
        finally:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

def main():
    """Main CLI entrypoint. Parses command line arguments and runs the scan."""
    parser = argparse.ArgumentParser(description="APK Scanner")
    parser.add_argument("--update-rules", action="store_true", help="Update rules database from remote sources and exit")
    parser.add_argument("apk_path", nargs="?", help="Path to the target .apk or .zip file")
    parser.add_argument("output_file", nargs="?", help="Path to save the JSON output report")
    args = parser.parse_args()

    # Handle update-rules command option
    if args.update_rules:
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner", "rules.db")
        logging.info("Updating vulnerability rules database...")
        success = update_rules_db(db_path)
        if success:
            logging.info("Vulnerability rules database successfully updated.")
            sys.exit(0)
        else:
            logging.error("Failed to update vulnerability rules database.")
            sys.exit(1)

    # Validate positional arguments if not running rules updater
    if not args.apk_path or not args.output_file:
        parser.error("the following arguments are required: apk_path, output_file")
        sys.exit(1)

    # Validate target file exists on disk
    if not os.path.isfile(args.apk_path):
        logging.error(f"Target file not found: {args.apk_path}")
        sys.exit(1)

    # Validate file extension
    if not args.apk_path.endswith((".apk", ".zip")):
        logging.error("Target file must have a .apk or .zip extension.")
        sys.exit(1)

    logging.info(f"Target initialized: {os.path.basename(args.apk_path)}")
    
    report = scan_apk(args.apk_path)
    
    if report:
        with open(args.output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)
        logging.info(f"Report successfully exported to {args.output_file}")
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()