"""
OmniBioAI audit.events.

Purpose:
    Defines the AuditEvents class for audit.events.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

class AuditEvents:
    AUTH_LOGIN = "auth_login"
    AUTH_FAILED = "auth_failed"

    IAM_CACHE_HIT = "iam_cache_hit"
    IAM_CACHE_MISS = "iam_cache_miss"

    POLICY_DECISION = "policy_decision"

    TES_SUBMIT = "tes_submit"
    TES_COMPLETE = "tes_complete"