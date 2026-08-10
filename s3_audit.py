#!/usr/bin/env python3
"""Audit an S3 bucket configuration for public exposure.

Analyzes a bucket policy, ACL grants, and the Public Access Block settings for
world-readable/writable exposure, unconditioned public principals, and missing
TLS-only enforcement. Standard library only. Input is JSON you export (e.g. from
the AWS CLI); this tool makes no network calls.
"""
import argparse
import json
import sys

ALLUSERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTHUSERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
CONDITION_KEYS_THAT_RESTRICT = (
    "aws:sourceip", "aws:sourcevpc", "aws:sourcevpce", "s3:x-amz-server-side-encryption",
    "aws:referer", "aws:principalorgid", "aws:userid", "aws:sourcearn",
)
PAB_SETTINGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def is_public_principal(principal):
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return "*" in as_list(principal.get("AWS"))
    return False


def condition_restricts(stmt):
    condition = stmt.get("Condition") or {}
    keys = []
    for operator_block in condition.values():
        if isinstance(operator_block, dict):
            keys.extend(k.lower() for k in operator_block)
    return any(k in CONDITION_KEYS_THAT_RESTRICT for k in keys)


def _finding(severity, message, detail=""):
    return {"severity": severity, "message": message, "detail": detail}


def analyze_policy(policy):
    findings = []
    has_tls_deny = False
    for stmt in as_list(policy.get("Statement")):
        actions = [a.lower() for a in as_list(stmt.get("Action")) if isinstance(a, str)]

        # TLS-only enforcement detection
        if stmt.get("Effect") == "Deny":
            cond = stmt.get("Condition") or {}
            bool_block = cond.get("Bool") or {}
            if str(bool_block.get("aws:SecureTransport", "")).lower() == "false":
                has_tls_deny = True

        if stmt.get("Effect") != "Allow" or not is_public_principal(stmt.get("Principal")):
            continue

        restricted = condition_restricts(stmt)
        writes = any(a.startswith("s3:put") or a.startswith("s3:delete") or a == "s3:*" or a == "*"
                     for a in actions)
        reads = any(a.startswith("s3:get") or a.startswith("s3:list") or a == "s3:*" or a == "*"
                    for a in actions)

        if writes and not restricted:
            findings.append(_finding("critical", "Public write access to bucket",
                                     "Principal:* allowed %s with no restricting Condition" % ",".join(actions)))
        elif reads and not restricted:
            findings.append(_finding("high", "Public read access to bucket",
                                     "Principal:* allowed %s with no restricting Condition" % ",".join(actions)))
        elif restricted:
            findings.append(_finding("medium", "Public principal, but constrained by Condition",
                                     ",".join(actions)))

    if not has_tls_deny:
        findings.append(_finding("medium", "No TLS-only enforcement",
                                 "add a Deny on aws:SecureTransport=false"))
    return findings


def analyze_acl(acl):
    findings = []
    for grant in as_list((acl or {}).get("grants") or (acl or {}).get("Grants")):
        grantee = grant.get("grantee") or grant.get("Grantee") or {}
        uri = grantee.get("uri") or grantee.get("URI")
        perm = grant.get("permission") or grant.get("Permission") or ""
        if uri == ALLUSERS:
            findings.append(_finding("high", "ACL grants access to AllUsers (public)", perm))
        elif uri == AUTHUSERS:
            findings.append(_finding("high", "ACL grants access to AuthenticatedUsers (any AWS account)", perm))
    return findings


def analyze_pab(pab):
    findings = []
    if pab is None:
        findings.append(_finding("medium", "No Public Access Block configuration provided"))
        return findings
    off = [s for s in PAB_SETTINGS if not pab.get(s, False)]
    if off:
        findings.append(_finding("medium", "Public Access Block not fully enabled",
                                 "disabled/missing: %s" % ", ".join(off)))
    return findings


def audit(doc):
    policy = doc.get("policy") if "policy" in doc else (doc if "Statement" in doc else {})
    findings = []
    findings.extend(analyze_policy(policy or {}))
    findings.extend(analyze_acl(doc.get("acl")))
    if "policy" in doc or "acl" in doc or "public_access_block" in doc:
        findings.extend(analyze_pab(doc.get("public_access_block")))
    findings.sort(key=lambda f: SEVERITY_RANK[f["severity"]], reverse=True)
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description="Audit an S3 bucket config for public exposure.")
    parser.add_argument("config", help="bucket config JSON (policy/acl/public_access_block or a bare policy)")
    parser.add_argument("--json", dest="json_out", help="write findings to this JSON file")
    parser.add_argument("--fail-on", choices=list(SEVERITY_RANK), default="high")
    args = parser.parse_args(argv)

    with open(args.config, encoding="utf-8") as fh:
        doc = json.load(fh)
    findings = audit(doc)

    if not findings:
        sys.stdout.write("%s: OK - no public-exposure findings\n" % args.config)
    for f in findings:
        sys.stdout.write("[%-8s] %s%s\n" % (f["severity"].upper(), f["message"],
                                            " - " + f["detail"] if f["detail"] else ""))

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as out:
            json.dump(findings, out, indent=2)

    worst = max((SEVERITY_RANK[f["severity"]] for f in findings), default=-1)
    return 1 if worst >= SEVERITY_RANK[args.fail_on] else 0


if __name__ == "__main__":
    raise SystemExit(main())
