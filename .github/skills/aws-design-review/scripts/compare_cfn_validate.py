"""Compare VPC/Subnet design checks with AWS CloudFormation Validate.

This probe emits the CloudFormation template used for comparison. It only
converts selected, unambiguous top-level properties and resolved VpcId refs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from aws_design_sheet.models import Design, ValueState


SUPPORTED_TYPES = {"AWS::EC2::VPC", "AWS::EC2::Subnet"}


def validate_result(design: Design, result: dict) -> None:
    if result.get("status") != "COMPLETE":
        raise ValueError("the design result must have status COMPLETE")
    current = hashlib.sha256(design.model_dump_json(exclude_none=False).encode()).hexdigest()
    if result.get("input_sha256") != current:
        raise ValueError("the design result does not match the design input")


def make_template(design: Design) -> tuple[dict, dict[str, str], list[dict]]:
    resources = {}
    names = {}
    skipped = []
    by_id = {resource.id: resource for resource in design.resources}
    for index, resource in enumerate(design.resources, 1):
        if resource.type not in SUPPORTED_TYPES:
            skipped.append({"resource_id": resource.id, "reason": "unsupported type"})
            continue
        if (resource.scope.environment, resource.scope.account, resource.scope.region) != (
                design.environment, design.account, design.region):
            skipped.append({"resource_id": resource.id, "reason": "different scope"})
            continue
        if any(field.state not in (ValueState.KNOWN, ValueState.MISSING,
                                   ValueState.NOT_APPLICABLE)
               or len(field.path.split("/")) != 3 for field in resource.fields):
            skipped.append({"resource_id": resource.id, "reason": "ambiguous or nested field"})
            continue
        names[resource.id] = f"R{index}"
        properties = {field.path.split("/")[2].replace("~1", "/").replace("~0", "~"):
                      field.selected().value for field in resource.fields
                      if field.state == ValueState.KNOWN}
        resources[resource.id] = {"Type": resource.type, "Properties": properties}

    for resource_id in list(resources):
        resource = by_id[resource_id]
        related = [relation for relation in design.relations
                   if relation.source_resource_id == resource_id]
        if any(relation.source_path != "/properties/VpcId" or
               relation.target_resource_id not in resources or
               by_id[relation.target_resource_id].type != "AWS::EC2::VPC"
               for relation in related):
            skipped.append({"resource_id": resource_id, "reason": "unconverted relation"})
            del resources[resource_id]
            del names[resource_id]
            continue
        if len(related) > 1:
            skipped.append({"resource_id": resource_id, "reason": "multiple VpcId relations"})
            del resources[resource_id]
            del names[resource_id]
            continue
        if related:
            resources[resource_id]["Properties"]["VpcId"] = {
                "Ref": names[related[0].target_resource_id]}

    template = {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {
        names[resource_id]: body for resource_id, body in resources.items()}}
    return template, names, skipped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("design", type=Path)
    parser.add_argument("result", type=Path)
    parser.add_argument("--template", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    try:
        from cloudformation_validate import CompositeEngine
    except ImportError as exc:
        parser.error("install the optional dependency: pip install -e .[validation]")
        raise AssertionError from exc

    design = Design.model_validate_json(args.design.read_text(encoding="utf-8"))
    result = json.loads(args.result.read_text(encoding="utf-8"))
    try:
        validate_result(design, result)
    except ValueError as exc:
        parser.error(str(exc))
    template, names, skipped = make_template(design)
    if not template["Resources"]:
        parser.error("no supported resources can be converted")
    args.template.parent.mkdir(parents=True, exist_ok=True)
    args.template.write_text(json.dumps(template, ensure_ascii=False, indent=2) + "\n",
                             encoding="utf-8")
    report = CompositeEngine().validate_template(str(args.template))
    comparison = {
        "validator_version": str(report.version),
        "logical_ids": names,
        "skipped": skipped,
        "cloudformation_diagnostics": [
            {"rule_id": d.rule_id, "severity": d.severity.name,
             "logical_id": d.entity.logical_id if d.entity else None,
             "property_path": d.property_path, "message": d.message}
            for d in report.diagnostics if d.severity.name in ("FATAL", "ERROR", "WARNING")],
        "design_results": [
            {"rule_id": item["rule_id"], "resource_id": item["resource_id"],
             "path": item.get("path"), "verdict": item["verdict"],
             "reason": item.get("reason")}
            for item in result["results"] if item["resource_id"] in names and
            item["verdict"] in ("FAIL", "NEEDS_REVIEW", "ERROR")],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(comparison, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
