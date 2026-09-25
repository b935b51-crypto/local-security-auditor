"""SARIF 2.1.0 results from deterministic findings only."""

from __future__ import annotations

import json
from urllib.parse import quote

from .models import ScanReport
from .serialization import report_view

SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"


def render(report: ScanReport) -> str:
    view = report_view(report)
    rules = {}
    group_by_fingerprint = {member["fingerprint"]: group["id"]
                            for group in view["finding_groups"]
                            for member in group["members"]}
    for rule in view["rules"]:
        rules[rule["id"]] = {"id": rule["id"], "shortDescription": {"text": rule["title"]},
                             "properties": {"tags": ["security"]}}
        if rule["help_uri"]:
            rules[rule["id"]]["helpUri"] = rule["help_uri"]
    results = []
    for finding in view["findings"]:
        rule_id = finding["rule_id"]
        if rule_id not in rules:
            rules[rule_id] = {"id": rule_id, "shortDescription": {"text": finding["title"]},
                              "properties": {"tags": [finding["category"]]}}
        level = ("error" if finding["severity"] in {"CRITICAL", "HIGH"} else
                 "warning" if finding["severity"] == "MEDIUM" else "note")
        item = {"ruleId": rule_id, "level": level, "message": {"text": finding["title"]},
                "partialFingerprints": {"localSecurityAuditor/v1": finding["fingerprint"]},
                "properties": {"severity": finding["severity"], "confidence": finding["confidence"],
                               "category": finding["category"], "role": finding["role"],
                               "riskPriority": finding["risk_priority"],
                               "aiAdvisory": finding["ai_review"]}}
        if group_id := group_by_fingerprint.get(finding["fingerprint"]):
            item["properties"]["findingGroupId"] = group_id
        path = finding["location"]["path"]
        if path and path != "[UNSAFE PATH]":
            physical = {"artifactLocation": {"uri": quote(path, safe="/")}}
            line = finding["location"]["start_line"]
            if type(line) is int and line > 0:
                region = {"startLine": line}
                column = finding["location"]["start_column"]
                if type(column) is int and column > 0:
                    region["startColumn"] = column
                physical["region"] = region
            item["locations"] = [{"physicalLocation": physical}]
        if finding["dependency"]:
            item["properties"]["dependency"] = finding["dependency"]
        if finding["vulnerability"]:
            item["properties"]["vulnerability"] = finding["vulnerability"]
        results.append(item)
    run = {"tool": {"driver": {"name": view["tool"]["name"],
                               "version": view["tool"]["version"],
                               "rules": [rules[key] for key in sorted(rules)]}},
           "results": results,
           "properties": {"scanCoverage": view["coverage"],
                          "scanScope": view["discovery"]["scope"],
                          "reportTruncated": view["report_truncated"],
                          "schemaVersion": view["schema_version"],
                          "externalServices": view["summary"]["external_services"]}}
    return json.dumps({"$schema": SCHEMA, "version": "2.1.0", "runs": [run]},
                      ensure_ascii=False, sort_keys=True, allow_nan=False,
                      separators=(",", ":")) + "\n"
