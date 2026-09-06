"""Vulture dead-code detection whitelist for dynamic Pydantic models.

Suppresses false-positive dead-code warnings for Pydantic report attributes,
validators, and serializers that are dynamically accessed by Instructor.
"""

from typing import Any

# Global stub object for Vulture member whitelisting
_ = Any

model_config  # unused variable (scanner/models/ai_report.py)
_.sanitize_url  # unused method (scanner/models/ai_report.py)
attack_vector  # unused variable (scanner/models/ai_report.py)
developer_intent  # unused variable (scanner/models/ai_report.py)
remediation  # unused variable (scanner/models/ai_report.py)
_.normalize_sources  # unused method (scanner/models/ai_report.py)
_.sanitize_code_snippet  # unused method (scanner/models/ai_report.py)
_.pre_validate_finding  # unused method (scanner/models/ai_report.py)
_.normalize_evidence  # unused method (scanner/models/ai_report.py)
_.pre_validate_items  # unused method (scanner/models/ai_report.py)
no_findings  # unused variable (scanner/models/ai_report.py)
source_name  # unused variable (scanner/models/ai_report.py)
latest_version_url  # unused variable (scanner/models/ai_report.py)
purpose  # unused variable (scanner/models/ai_report.py)
is_developer_code  # unused variable (scanner/models/ai_report.py)
cloud_services  # unused variable (scanner/models/ai_report.py)
trackers_and_ads  # unused variable (scanner/models/ai_report.py)
owasp_id  # unused variable (scanner/models/ai_report.py)
owasp_category  # unused variable (scanner/models/ai_report.py)
vulnerability  # unused variable (scanner/models/ai_report.py)
cvss_score  # unused variable (scanner/models/ai_report.py)
primary_purpose  # unused variable (scanner/models/ai_report.py)
play_store_url  # unused variable (scanner/models/ai_report.py)
official_website  # unused variable (scanner/models/ai_report.py)
status  # unused variable (scanner/models/ai_report.py)
security_incidents  # unused variable (scanner/models/ai_report.py)
