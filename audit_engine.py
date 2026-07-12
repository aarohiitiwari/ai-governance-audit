"""
AI Governance Audit Engine
Automated compliance auditing for AI-generated outputs
in regulated enterprise environments.
"""

import json
import re
import hashlib
from datetime import datetime
from collections import defaultdict


def load_config(filepath="audit_config.json"):
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def load_outputs(filepath="sample_outputs.json"):
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def generate_audit_id(output_id, timestamp):
    """Generates unique tamper-evident audit trail ID."""
    raw = f"{output_id}-{timestamp}"
    return "AUD-" + hashlib.md5(raw.encode()).hexdigest()[:10].upper()


def check_content_safety(response, config):
    """
    Scans AI output for prohibited content patterns
    defined in governance policy.
    """
    prohibited = config["compliance_checks"]["content_safety"]["prohibited_patterns"]
    response_lower = response.lower()

    violations = [
        pattern for pattern in prohibited
        if pattern.lower() in response_lower
    ]

    score = max(0, 100 - (len(violations) * 25))
    return {
        "score": score,
        "violations": violations,
        "status": "PASS" if not violations else "FAIL",
        "detail": (
            f"Found {len(violations)} prohibited pattern(s): "
            f"{', '.join(violations)}" if violations
            else "No prohibited content detected."
        )
    }


def check_data_privacy(response, config):
    """
    Detects PII exposure in AI outputs using
    regex patterns for common Indian PII formats.
    """
    patterns = config["compliance_checks"]["data_privacy"]["pii_patterns"]
    pii_found = []

    for pattern in patterns:
        matches = re.findall(pattern, response)
        if matches:
            pii_found.extend(matches)

    score = 0 if pii_found else 100
    return {
        "score": score,
        "pii_detected": pii_found,
        "pii_count": len(pii_found),
        "status": "FAIL" if pii_found else "PASS",
        "detail": (
            f"PII EXPOSURE DETECTED: {len(pii_found)} instance(s) found. "
            f"Immediate remediation required." if pii_found
            else "No PII detected in output."
        )
    }


def check_factual_grounding(response, config):
    """
    Identifies hallucination risk markers and
    unsubstantiated absolute claims in AI outputs.
    """
    markers = config["compliance_checks"]["factual_grounding"]["hallucination_markers"]
    response_lower = response.lower()

    triggered = [
        marker for marker in markers
        if marker.lower() in response_lower
    ]

    score = max(0, 100 - (len(triggered) * 20))
    return {
        "score": score,
        "markers_triggered": triggered,
        "status": "PASS" if score >= 75 else "FAIL",
        "detail": (
            f"Hallucination risk markers detected: "
            f"{', '.join(triggered)}" if triggered
            else "Response appears factually grounded."
        )
    }


def check_transparency(response, config):
    """
    Verifies presence of required AI disclosure
    statements per regulatory transparency obligations.
    """
    disclosures = config["compliance_checks"]["transparency"]["required_disclosures"]
    response_lower = response.lower()

    present = [
        d for d in disclosures
        if d.lower() in response_lower
    ]

    score = 100 if present else 30
    return {
        "score": score,
        "disclosures_found": present,
        "status": "PASS" if present else "REVIEW",
        "detail": (
            f"Transparency disclosure present: {present[0]}"
            if present
            else "No AI disclosure statement found. "
                 "Consider adding transparency notice."
        )
    }


def check_bias_indicators(response, config):
    """
    Scans for demographic bias patterns that could
    create regulatory or reputational exposure.
    """
    patterns = config["compliance_checks"]["bias_indicators"]["bias_patterns"]
    response_lower = response.lower()

    detected = [
        p for p in patterns
        if p.lower() in response_lower
    ]

    score = max(0, 100 - (len(detected) * 35))
    return {
        "score": score,
        "bias_patterns_detected": detected,
        "status": "FAIL" if detected else "PASS",
        "detail": (
            f"Potential bias detected: {', '.join(detected)}"
            if detected
            else "No demographic bias indicators detected."
        )
    }


def compute_weighted_score(check_results, config):
    """
    Computes compliance-weighted overall score
    using weights defined in governance config.
    """
    checks = config["compliance_checks"]
    total = 0.0

    weight_map = {
        "content_safety": checks["content_safety"]["weight"],
        "data_privacy": checks["data_privacy"]["weight"],
        "factual_grounding": checks["factual_grounding"]["weight"],
        "transparency": checks["transparency"]["weight"],
        "bias_indicators": checks["bias_indicators"]["weight"]
    }

    for check_name, weight in weight_map.items():
        total += check_results[check_name]["score"] * weight

    return round(total, 2)


def classify_severity(score, config):
    thresholds = config["severity_thresholds"]
    if score < thresholds["critical"]:
        return "CRITICAL"
    elif score < thresholds["high"]:
        return "HIGH"
    elif score < thresholds["medium"]:
        return "MEDIUM"
    elif score < thresholds["low"]:
        return "LOW"
    else:
        return "COMPLIANT"


def determine_action(severity, risk_tier):
    actions = {
        "CRITICAL": "BLOCK — Do not publish. Immediate human review required. Escalate to AI Governance team.",
        "HIGH": "HOLD — Pending senior reviewer approval before publication.",
        "MEDIUM": "REVIEW — Flag for human review within 24 hours.",
        "LOW": "MONITOR — Log and monitor. No immediate action required.",
        "COMPLIANT": "APPROVE — Output meets compliance standards. Cleared for publication."
    }

    if risk_tier == "L3" and severity in ["MEDIUM", "LOW"]:
        return "REVIEW — L3 risk tier requires mandatory human review regardless of score."

    return actions.get(severity, "REVIEW — Manual assessment required.")


def audit_single_output(output, config, risk_tier):
    """
    Runs full compliance audit on a single AI output
    and generates structured audit record.
    """
    response = output["ai_response"]
    audit_id = generate_audit_id(output["output_id"], output["timestamp"])

    check_results = {
        "content_safety": check_content_safety(response, config),
        "data_privacy": check_data_privacy(response, config),
        "factual_grounding": check_factual_grounding(response, config),
        "transparency": check_transparency(response, config),
        "bias_indicators": check_bias_indicators(response, config)
    }

    overall_score = compute_weighted_score(check_results, config)
    severity = classify_severity(overall_score, config)
    action = determine_action(severity, risk_tier)

    failed_checks = [
        k for k, v in check_results.items()
        if v["status"] == "FAIL"
    ]

    return {
        "audit_id": audit_id,
        "output_id": output["output_id"],
        "timestamp": output["timestamp"],
        "audited_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "model": output.get("model", "unknown"),
        "risk_tier": risk_tier,
        "overall_score": overall_score,
        "severity": severity,
        "recommended_action": action,
        "failed_checks": failed_checks,
        "check_results": check_results,
        "audit_complete": True
    }


def generate_batch_report(batch_data, audit_results, config):
    """
    Aggregates individual audit records into
    batch-level compliance report.
    """
    scores = [r["overall_score"] for r in audit_results]
    avg_score = round(sum(scores) / len(scores), 2)

    severity_counts = defaultdict(int)
    for r in audit_results:
        severity_counts[r["severity"]] += 1

    check_failure_counts = defaultdict(int)
    for r in audit_results:
        for check in r["failed_checks"]:
            check_failure_counts[check] += 1

    most_failed = (
        max(check_failure_counts, key=check_failure_counts.get)
        if check_failure_counts else "none"
    )

    compliant_count = severity_counts.get("COMPLIANT", 0)
    compliance_rate = round(compliant_count / len(audit_results) * 100, 1)

    return {
        "report_metadata": {
            "batch_id": batch_data["batch_id"],
            "source_system": batch_data["source_system"],
            "use_case": batch_data["use_case"],
            "risk_tier": batch_data["risk_tier"],
            "regulatory_framework": config["regulatory_framework"],
            "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total_outputs_audited": len(audit_results),
            "retention_policy_days": config["retention_policy_days"]
        },
        "batch_summary": {
            "average_compliance_score": avg_score,
            "compliance_rate_percent": compliance_rate,
            "severity_distribution": dict(severity_counts),
            "most_frequently_failed_check": most_failed,
            "outputs_requiring_action": len([
                r for r in audit_results
                if r["severity"] in ["CRITICAL", "HIGH"]
            ])
        },
        "regulatory_posture": (
            "COMPLIANT" if avg_score >= 75
            else "AT RISK" if avg_score >= 55
            else "NON-COMPLIANT"
        ),
        "check_failure_summary": dict(check_failure_counts),
        "audit_records": audit_results
    }


def print_report(report):
    print("\n" + "=" * 65)
    print("AI GOVERNANCE AUDIT REPORT")
    print("=" * 65)
    meta = report["report_metadata"]
    print(f"Batch ID:    {meta['batch_id']}")
    print(f"System:      {meta['source_system']}")
    print(f"Use Case:    {meta['use_case']}")
    print(f"Risk Tier:   {meta['risk_tier']}")
    print(f"Framework:   {meta['regulatory_framework']}")
    print(f"Generated:   {meta['generated_at']}")
    print(f"Outputs:     {meta['total_outputs_audited']}")
    print("-" * 65)
    print("BATCH SUMMARY")
    print("-" * 65)
    bs = report["batch_summary"]
    print(f"Average Compliance Score:   {bs['average_compliance_score']}%")
    print(f"Compliance Rate:            {bs['compliance_rate_percent']}%")
    print(f"Regulatory Posture:         {report['regulatory_posture']}")
    print(f"Outputs Requiring Action:   {bs['outputs_requiring_action']}")
    print(f"Most Failed Check:          {bs['most_frequently_failed_check'].replace('_', ' ')}")
    print("-" * 65)
    print("SEVERITY DISTRIBUTION")
    print("-" * 65)
    for severity, count in bs["severity_distribution"].items():
        bar = "█" * count
        print(f"{severity:<12} {count}  {bar}")
    print("-" * 65)
    print("INDIVIDUAL AUDIT RECORDS")
    print("-" * 65)
    for record in report["audit_records"]:
        print(f"\n{record['audit_id']}  |  {record['output_id']}")
        print(f"  Score:    {record['overall_score']}%  |  "
              f"Severity: {record['severity']}")
        print(f"  Action:   {record['recommended_action']}")
        if record["failed_checks"]:
            print(f"  Failed:   {', '.join(record['failed_checks'])}")
        for check, result in record["check_results"].items():
            status_symbol = "✓" if result["status"] == "PASS" else "✗"
            print(f"    {status_symbol} {check.replace('_', ' '):<22} "
                  f"Score: {result['score']:<6} "
                  f"{result['detail'][:60]}")
    print("=" * 65)


def save_report(report, filepath="governance_audit_report.json"):
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\nAudit report saved → {filepath}")


if __name__ == "__main__":
    config = load_config()
    batch_data = load_outputs()

    print(f"Batch: {batch_data['batch_id']}")
    print(f"System: {batch_data['source_system']}")
    print(f"Risk Tier: {batch_data['risk_tier']}")
    print(f"Outputs to audit: {len(batch_data['outputs'])}\n")

    audit_results = []
    for output in batch_data["outputs"]:
        result = audit_single_output(
            output, config, batch_data["risk_tier"]
        )
        audit_results.append(result)
        print(f"{result['output_id']} — "
              f"{result['overall_score']}% — "
              f"{result['severity']} — "
              f"{result['recommended_action'][:50]}")

    report = generate_batch_report(batch_data, audit_results, config)
    print_report(report)
    save_report(report)
