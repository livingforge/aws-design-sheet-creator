"""Schema and cross-resource checks for saved design JSON."""
from __future__ import annotations

import hashlib
import heapq
import ipaddress
import json
import re
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any
from uuid import uuid4

from .models import Design, FieldValue, Resource, ValueState
from .ledger import validate_ledger
from .template_dependencies import evaluate_template_dependencies, SOURCES as TEMPLATE_SOURCES
from .checks.registry import rule_sources, run_resource_checks
from .network_modes import subnet_ipv6_checks, vpc_ipv4_source
from .checks.aiops.investigation_group_uniqueness import evaluate_aiops_investigation_group_uniqueness
from .network_ipv4 import SOURCE as VPC_CIDR_SOURCE, vpc_ipv4_addresses
from .rule_engine import evaluate_rule_all, load_ruleset, reference_view
from .checks.batch.platform_guard import guard_batch_findings
from .rule_review import load_reference_catalog


RULE_VERSION = "1.0"


@lru_cache(maxsize=4)
def _parsed_ruleset(raw: bytes):
    data = json.loads(raw)
    return data["ruleset_version"], load_ruleset(data)


@lru_cache(maxsize=4)
def _validated_ledger(ledger_path: Path, schema_dir: Path, ruleset_path: Path | None,
                      ledger_hash: str, ruleset_hash: str | None,
                      manifest_hash: str, archive_hash: str):
    # Content hashes keep edits to files at the same path from reusing an old validation.
    return validate_ledger(ledger_path, schema_dir, ruleset_path)


def _has_nested_state(value) -> bool:
    """True when a value holds a {"$state": ...} marker for an unresolved part."""
    if isinstance(value, dict):
        return set(value) == {"$state"} or any(_has_nested_state(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_nested_state(item) for item in value)
    return False


RULE_SOURCES = {
    "RDS_EVENT_SUBSCRIPTION_SNS_STANDARD": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-eventsubscription.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sns-topic.html"],
    "S3_ACCESS_GRANTS_INSTANCE_REGION_UNIQUE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-s3-accessgrantsinstance.html"],
    "VPC_IPV4_SOURCE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpc.html"],
    "IPV6_CIDR_FORMAT": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-subnet.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpccidrblock.html"],
    "IPV6_CIDR_CONTAINMENT": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-subnet.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpccidrblock.html"],
    "IPV6_CIDR_OVERLAP": [
        "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html"],
    "SUBNET_IPV6_ASSIGNMENT": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-subnet.html"],
}
RULE_SOURCES.update(rule_sources())
RULE_SOURCES.update(TEMPLATE_SOURCES)
RULE_SOURCES.update({rule: [VPC_CIDR_SOURCE] for rule in (
    "VPC_IPV4_CIDR_SIZE", "VPC_IPV4_CIDR_RESERVED", "VPC_SECONDARY_CIDR_OVERLAP",
    "VPC_SECONDARY_CIDR_RANGE")})
REFERENCE_TYPES = {
    ("AWS::EC2::VPCCidrBlock", "/properties/VpcId"): "AWS::EC2::VPC",
    ("AWS::AmazonMQ::ConfigurationAssociation", "/properties/Broker"): "AWS::AmazonMQ::Broker",
    ("AWS::AccountAccess::Entitlement", "/properties/ApplicationArn"): "AWS::AccountAccess::Application",
    ("AWS::APS::AnomalyDetector", "/properties/Workspace"): "AWS::APS::Workspace",
    ("AWS::APS::ResourcePolicy", "/properties/WorkspaceArn"): "AWS::APS::Workspace",
    ("AWS::APS::RuleGroupsNamespace", "/properties/Workspace"): "AWS::APS::Workspace",
    ("AWS::IAM::AccessKey", "/properties/UserName"): "AWS::IAM::User",
    ("AWS::EC2::Route", "/properties/RouteTableId"): "AWS::EC2::RouteTable",
    ("AWS::EC2::Route", "/properties/NatGatewayId"): "AWS::EC2::NatGateway",
    ("AWS::EC2::Route", "/properties/TransitGatewayId"): "AWS::EC2::TransitGateway",
    ("AWS::EC2::Subnet", "/properties/VpcId"): "AWS::EC2::VPC",
    ("AWS::EC2::SecurityGroup", "/properties/VpcId"): "AWS::EC2::VPC",
    ("AWS::RDS::DBSubnetGroup", "/properties/SubnetIds/*"): "AWS::EC2::Subnet",
    ("AWS::RDS::DBInstance", "/properties/DBSubnetGroupName"): "AWS::RDS::DBSubnetGroup",
    ("AWS::RDS::DBInstance", "/properties/VPCSecurityGroups/*"): "AWS::EC2::SecurityGroup",
}
S3_REPLICATION_DESTINATION = re.compile(
    r"^/properties/ReplicationConfiguration/Rules/\d+/Destination/Bucket$"
)


def reference_type(type_name: str, path: str,
                   catalog: dict[tuple[str, str], str] | None = None) -> str | None:
    for (source_type, pattern), target_type in (REFERENCE_TYPES if catalog is None else catalog).items():
        if source_type == type_name and _pointer_matches(pattern, path):
            return target_type
    return None


def _pointer_matches(pattern: str, path: str) -> bool:
    """Match a pointer where each '*' token stands for one array index."""
    if "*" not in pattern:
        return path == pattern
    wanted, actual = pattern.split("/"), path.split("/")
    return len(wanted) == len(actual) and all(
        w == a or (w == "*" and a.isdigit()) for w, a in zip(wanted, actual))


def pointer(parts: list[Any]) -> str:
    return "/properties" + "".join("/" + str(x).replace("~", "~0").replace("/", "~1") for x in parts)


def field_evidence(field: FieldValue | None) -> list[str]:
    if not field:
        return []
    return list(dict.fromkeys([*field.intent_evidence_ids,
                               *(e for c in field.candidates for e in c.evidence_ids)]))


def value(resource: Resource, path: str) -> Any | None:
    field = resource.field(path)
    return field.selected().value if field and field.state == ValueState.KNOWN else None


def nested_property_schema(root: dict, path: str) -> dict | None:
    """Find a directly described nested property without guessing across unions."""
    tokens = path.split("/")[2:]
    node = root
    for token in tokens:
        for _ in range(20):
            ref = node.get("$ref")
            if not ref:
                break
            if not ref.startswith("#/definitions/"):
                return None
            name = ref[len("#/definitions/"):].replace("~1", "/").replace("~0", "~")
            node = root.get("definitions", {}).get(name)
            if not isinstance(node, dict):
                return None
        else:
            return None
        if any(key in node for key in ("allOf", "anyOf", "oneOf", "if", "then", "else")):
            return None
        if node.get("type") == "array":
            if not token.isdigit() or not isinstance(node.get("items"), dict):
                return None
            node = node["items"]
        elif node.get("type") == "object" or "properties" in node:
            name = token.replace("~1", "/").replace("~0", "~")
            node = node.get("properties", {}).get(name)
            if not isinstance(node, dict):
                return None
        else:
            return None
    return node


class Checker:
    def __init__(self, schema_dir: Path, profile_path: Path,
                 ledger_path: Path | None = None,
                 ruleset_path: Path | None = None,
                 references_path: Path | None = None, *, cfn_lint: bool = False):
        self.cfn_lint = cfn_lint
        raw_manifest = (schema_dir / "manifest.json").read_bytes()
        self.manifest = json.loads(raw_manifest)
        self.schemas = {}
        self.schema_dir = schema_dir
        if archive := self.manifest.get("archive"):
            raw = (schema_dir / archive).read_bytes()
            archive_hash = hashlib.sha256(raw).hexdigest()
            if archive_hash != self.manifest["zip_sha256"]:
                raise ValueError("schema archive hash mismatch")
            self.archive = zipfile.ZipFile(schema_dir / archive)
        else:
            archive_hash = ""
            self.archive = None
        raw_profile = profile_path.read_bytes()
        self.profile_hash = hashlib.sha256(raw_profile).hexdigest()
        self.profile = json.loads(raw_profile)
        explicit_ledger = ledger_path is not None
        explicit_ruleset = ruleset_path is not None
        ledger_path = ledger_path or schema_dir.parent / "rules/ledger.json"
        ruleset_path = ruleset_path or schema_dir.parent / "rules/ruleset.json"
        if explicit_ledger and not ledger_path.exists():
            raise ValueError(f"review ledger not found: {ledger_path}")
        if explicit_ruleset and not ruleset_path.exists():
            raise ValueError(f"ruleset not found: {ruleset_path}")
        if ruleset_path.exists():
            raw_ruleset = ruleset_path.read_bytes()
            self.ruleset_version, self.rules = _parsed_ruleset(raw_ruleset)
            self.ruleset_hash = hashlib.sha256(raw_ruleset).hexdigest()
        else:
            self.rules = ()
            self.ruleset_version = None
            self.ruleset_hash = None
        raw_ledger = ledger_path.read_bytes() if ledger_path.exists() else None
        self.ledger_hash = hashlib.sha256(raw_ledger).hexdigest() if raw_ledger is not None else None
        self.ledger = (_validated_ledger(ledger_path, schema_dir,
                                         ruleset_path if ruleset_path.exists() else None,
                                         self.ledger_hash, self.ruleset_hash,
                                         hashlib.sha256(raw_manifest).hexdigest(), archive_hash)
                       if raw_ledger is not None else None)
        if self.rules and not self.ledger:
            raise ValueError("ruleset requires a review ledger")
        self.rules_by_type = defaultdict(list)
        claimed = {rule_id for entry in self.ledger["types"].values()
                   for rule_id in entry["rule_ids"]} if self.ledger else set()
        for rule in self.rules:
            if rule.source_type not in self.manifest["types"]:
                raise ValueError(f"rule source type absent from schema manifest: {rule.source_type}")
            if rule.id not in claimed:
                raise ValueError(f"rule absent from review ledger: {rule.id}")
            self.rules_by_type[rule.source_type].append(rule)
        explicit_references = references_path is not None
        references_path = references_path or schema_dir.parent / "rules/references.json"
        if explicit_references and not references_path.exists():
            raise ValueError(f"reference catalog not found: {references_path}")
        self.reference_types = dict(REFERENCE_TYPES)
        self.references_version = self.references_hash = None
        if references_path.exists():
            raw_references = references_path.read_bytes()
            catalog = load_reference_catalog(json.loads(raw_references), self.manifest["types"])
            for key, target in catalog.items():
                if self.reference_types.get(key, target) != target:
                    raise ValueError(f"reference catalog conflicts with built-in rule: {key}")
                self.reference_types[key] = target
            self.references_version = json.loads(raw_references)["catalog_version"]
            self.references_hash = hashlib.sha256(raw_references).hexdigest()
        self.results: list[dict] = []
        self.coverage: list[dict] = []
        self.relations_by_source: dict[str, list] = {}

    def add(self, rule: str, resource: Resource | None, path: str | None, verdict: str,
            reason: str, *, severity: str = "ERROR", expected: Any = None,
            actual: Any = None, evidence: list[str] | None = None,
            dependencies: list[str] | None = None):
        self.results.append({"rule_id": rule, "rule_version": RULE_VERSION,
                             "resource_id": resource.id if resource else None, "path": path,
                             "verdict": verdict, "severity": severity, "expected": expected,
                             "actual": actual, "reason": reason, "evidence_ids": evidence or [],
                             "dependencies": dependencies or []})

    def uncovered(self, kind: str, resource: Resource | None, path: str | None, reason: str):
        self.coverage.append({"kind": kind, "resource_id": resource.id if resource else None,
                              "path": path, "reason": reason})

    def check(self, design: Design) -> dict:
        if design.region != self.manifest["region"]:
            raise ValueError(f"schema region {self.manifest['region']} does not match design region {design.region}")
        self.results, self.coverage = [], []
        self.relations_by_source = defaultdict(list)
        for relation in design.relations:
            self.relations_by_source[relation.source_resource_id].append(relation)
        resource_types = {resource.id: resource.type for resource in design.resources}
        for resource in design.resources:
            if resource.scope.region != self.manifest["region"]:
                self.uncovered("REGION_SCHEMA", resource, None, "schema not loaded for resource region")
                continue
            if resource.type not in self.manifest["types"]:
                self.uncovered("RESOURCE_TYPE", resource, None, "schema not loaded")
                continue
            self._schema(resource)
            self._profile(resource)
            self._schema_design_rules(resource)
            self._field_conflicts(resource)
            view = reference_view(resource, self.relations_by_source[resource.id], resource_types)
            for rule in self.rules_by_type[resource.type]:
                self.results.extend(guard_batch_findings(rule, design, resource, evaluate_rule_all(rule, view)))
            if self.ledger:
                entry = self.ledger["types"][resource.type]
                state = entry["state"]
                if state == "UNRESEARCHED":
                    self.uncovered("RULE_UNRESEARCHED", resource, None,
                                   "service-specific design rules have not been reviewed")
                elif state == "REVIEW_REQUIRED":
                    for question in entry["open_questions"]:
                        self.uncovered("RULE_REVIEW_REQUIRED", resource, None, question)
            for finding in run_resource_checks(design, resource):
                self._add_check_finding(finding)
            if resource.type == "AWS::EC2::VPC":
                self._add_check_finding(vpc_ipv4_source(resource))
            for finding in evaluate_template_dependencies(design, resource):
                self._add_check_finding(finding)
            for field in resource.fields:
                if field.path in ("/properties/Ipv6CidrBlocks", "/properties/CidrBlockAssociations"):
                    self.uncovered("NETWORK_MODE", resource, field.path,
                                   "network consistency rule for this address mode is not implemented")
        for finding in subnet_ipv6_checks(design):
            self._add_check_finding(finding)
        for finding in evaluate_aiops_investigation_group_uniqueness(design):
            self._add_check_finding(finding)
        self._identity(design)
        self._relations(design)
        self._networks(design)
        self._rds(design)
        self._s3_access_grants(design)
        cfn_lint_version = None
        if self.cfn_lint:
            from .cfn_lint_check import CFN_LINT_VERSION, lint_design
            lint_results, lint_coverage = lint_design(design)
            self.results += lint_results
            self.coverage += lint_coverage
            cfn_lint_version = CFN_LINT_VERSION
        for req in design.requirements:
            if not req.rule_id or not any(r["rule_id"] == req.rule_id and
                    (req.target_resource_id is None or r["resource_id"] == req.target_resource_id)
                    for r in self.results):
                self.uncovered("REQUIREMENT", None, None,
                               f"requirement {req.id} has no evaluated rule")
        for document in design.documents:
            covered = set()
            for start, end in document.extracted_ranges:
                covered.update(range(start, end + 1))
            for line_number, line in enumerate(document.text.splitlines(), 1):
                if line.strip() and line_number not in covered:
                    self.uncovered("UNPROCESSED_TEXT", None, None,
                                   f"{document.id}: line {line_number} not extracted")
        return {"run_id": str(uuid4()), "status": "COMPLETE",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "input_sha256": hashlib.sha256(design.model_dump_json(exclude_none=False).encode()).hexdigest(),
                "summary": dict(Counter(r["verdict"] for r in self.results)),
                "results": self.results, "coverage": self.coverage,
                "versions": {"model": design.model_version, "rules": RULE_VERSION,
                             "extractor": design.extractor_version,
                             "profile": self.profile.get("version"), "profile_sha256": self.profile_hash,
                             "schema_manifest": self.manifest,
                             "ledger": self.ledger["ledger_version"] if self.ledger else None,
                             "ledger_sha256": self.ledger_hash,
                             "ruleset": self.ruleset_version,
                             "ruleset_sha256": self.ruleset_hash,
                             "references": self.references_version,
                             "references_sha256": self.references_hash,
                             "cfn_lint": cfn_lint_version}}

    def _add_check_finding(self, finding: dict):
        self.results.append({"rule_version": "1.0", "severity": "ERROR",
                             "expected": None, "actual": None,
                             "authority": "AWS_SPEC",
                             "source_checked_at": "2026-09-29",
                             "source_urls": RULE_SOURCES[finding["rule_id"]],
                             **finding})

    def _schema(self, resource: Resource):
        """Schema facts the CloudFormation export cannot hand to cfn-lint.

        cfn-lint validates property values, required properties and unknown
        properties of the exported template. This keeps read-only properties,
        the shape and count of logical references, and values the design leaves
        undetermined, which the export turns into opaque parameters.
        """
        original = self._load_schema(resource.type)
        read_only = set(original.get("readOnlyProperties", []))
        known = {}
        for field in resource.fields:
            if field.path in read_only or any(field.path.startswith(p + "/") for p in read_only):
                if field.state == ValueState.KNOWN:
                    self.add("SCHEMA_READ_ONLY", resource, field.path, "FAIL", "read-only property supplied",
                             evidence=field_evidence(field))
                elif field.state not in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
                    self.add("SCHEMA_READ_ONLY", resource, field.path, "NEEDS_REVIEW",
                             "read-only property has an unresolved value",
                             evidence=field_evidence(field), dependencies=[field.path])
                continue
            if field.state == ValueState.KNOWN and _has_nested_state(field.selected().value):
                self.add("SCHEMA_UNCERTAIN", resource, field.path, "NEEDS_REVIEW",
                         "value contains unresolved nested parts", evidence=field_evidence(field),
                         dependencies=[field.path])
            elif field.state == ValueState.KNOWN:
                if field.path.count("/") == 2:
                    known[field.path.split("/")[2].replace("~1", "/").replace("~0", "~")] = field.selected().value
            elif field.state != ValueState.NOT_APPLICABLE:
                self.add("SCHEMA_UNCERTAIN", resource, field.path, "NEEDS_REVIEW",
                         f"value state is {field.state}", evidence=field_evidence(field),
                         dependencies=[field.path])
        for relation in self.relations_by_source[resource.id]:
            if relation.source_path in read_only or any(
                relation.source_path.startswith(path + "/") for path in read_only
            ):
                self.add("SCHEMA_READ_ONLY", resource, relation.source_path, "FAIL",
                         "read-only property supplied", evidence=relation.evidence_ids)
                continue
            parts = relation.source_path.split("/")[2:]
            if not parts or parts[0] not in original["properties"]:
                self.uncovered("UNKNOWN_PROPERTY", resource, relation.source_path,
                               "reference property absent from fixed schema")
                continue
            specification = original["properties"][parts[0]]
            if len(parts) > 2 or (len(parts) == 2 and not parts[1].isdigit()):
                self.uncovered("NESTED_REFERENCE", resource, relation.source_path,
                               "nested reference path is not supported")
                continue
            if len(parts) == 2 and specification.get("type") not in (None, "array"):
                self.add("SCHEMA_REFERENCE_TYPE", resource, relation.source_path, "FAIL",
                         "indexed reference is not an array property", evidence=relation.evidence_ids)
            elif len(parts) == 1 and specification.get("type") not in (None, "string"):
                self.add("SCHEMA_REFERENCE_TYPE", resource, relation.source_path, "FAIL",
                         "scalar reference is not a string property", evidence=relation.evidence_ids)
            if relation.expected_target_type:
                self.uncovered("REFERENCE_VALUE", resource, relation.source_path,
                               "physical reference value cannot be checked against property constraints")
        for path in original.get("readOnlyProperties", []):
            if path.count("/") > 2 and path.startswith("/properties/"):  # top level handled above
                parts = path.split("/")[2:]
                container = known.get(parts[0])
                for part in parts[1:]:
                    container = container.get(part) if isinstance(container, dict) else None
                if container is not None:
                    self.add("SCHEMA_READ_ONLY", resource, path, "FAIL", "read-only property supplied",
                             evidence=field_evidence(resource.field(pointer([parts[0]]))))
        for name, specification in original["properties"].items():
            if specification.get("type") != "array":
                continue
            # Only references that are the array items count; nested ones belong to an item.
            refs = [r for r in self.relations_by_source[resource.id]
                    if r.source_path.startswith(pointer([name]) + "/")
                    and r.source_path[len(pointer([name])) + 1:].isdigit()]
            if not refs:
                continue
            identifiers = [r.target_resource_id or r.unresolved_name for r in refs]
            if specification.get("uniqueItems") and len(identifiers) != len(set(identifiers)):
                self.add("SCHEMA_REFERENCE_UNIQUE", resource, pointer([name]), "FAIL",
                         "duplicate logical references in unique array", actual=identifiers,
                         evidence=list(dict.fromkeys(e for r in refs for e in r.evidence_ids)))
            if "minItems" in specification and len(refs) < specification["minItems"]:
                self.add("SCHEMA_REFERENCE_SIZE", resource, pointer([name]), "FAIL",
                         "too few logical references", expected=specification["minItems"], actual=len(refs))
            if "maxItems" in specification and len(refs) > specification["maxItems"]:
                self.add("SCHEMA_REFERENCE_SIZE", resource, pointer([name]), "FAIL",
                         "too many logical references", expected=specification["maxItems"], actual=len(refs))

    def _load_schema(self, type_name: str) -> dict:
        if type_name not in self.schemas:
            entry = self.manifest["types"][type_name]
            raw = (self.archive.read(entry) if self.archive else
                   (self.schema_dir / entry["file"]).read_bytes())
            if not self.archive and hashlib.sha256(raw).hexdigest() != entry["sha256"]:
                raise ValueError(f"schema hash mismatch: {type_name}")
            schema = json.loads(raw)
            if schema.get("typeName") != type_name:
                raise ValueError(f"schema type mismatch: {type_name}")
            self.schemas[type_name] = schema
        return self.schemas[type_name]

    def _profile(self, resource: Resource):
        for rule in self.profile["types"].get(resource.type, []):
            path = rule["path"]
            condition = rule.get("when", {})
            if condition.get("environment") and condition["environment"] != resource.scope.environment:
                self.add("PROFILE_REQUIRED", resource, path, "NOT_APPLICABLE", "environment does not match")
                continue
            if condition.get("field"):
                conditional = resource.field(condition["field"])
                if not conditional or conditional.state != ValueState.KNOWN:
                    self.add("PROFILE_REQUIRED", resource, path, "NEEDS_REVIEW", "condition unresolved",
                             dependencies=[condition["field"]])
                    continue
                if conditional.selected().value != condition["equals"]:
                    continue
            field = resource.field(path)
            if any(reference_type(resource.type, path if not p.endswith("/*") else p[:-1] + "0",
                                  self.reference_types)
                   for (t, p) in self.reference_types if t == resource.type and
                   (path == p or path == p[:-2])):
                references = [r for r in self.relations_by_source[resource.id]
                              if r.source_path == path or r.source_path.startswith(path + "/")]
                if references:
                    single = path not in ("/properties/SubnetIds", "/properties/VPCSecurityGroups")
                    self.add("PROFILE_REQUIRED", resource, path,
                             "PASS" if not single or len(references) == 1 else "NEEDS_REVIEW",
                             "logical reference is present" if not single or len(references) == 1 else "reference conflicts",
                             dependencies=[path] if single and len(references) > 1 else [])
                    continue
            if any(resource.field(p) and resource.field(p).state == ValueState.KNOWN
                   for p in rule.get("alternatives", [])):
                self.add("PROFILE_REQUIRED", resource, path, "PASS", "alternative design item is present")
                continue
            if field and field.state == ValueState.KNOWN:
                self.add("PROFILE_REQUIRED", resource, path, "PASS", "design item is present",
                         evidence=field_evidence(field))
            elif field and field.state == ValueState.NOT_APPLICABLE:
                self.add("PROFILE_REQUIRED", resource, path, "NOT_APPLICABLE", "marked non-applicable")
            else:
                self.add("PROFILE_REQUIRED", resource, path, "NEEDS_REVIEW", "design item needs a value",
                         dependencies=[path], evidence=field_evidence(field))

    def _schema_design_rules(self, resource: Resource):
        schema = self._load_schema(resource.type)
        tagging = schema.get("tagging") or {}
        tag_path = tagging.get("tagProperty") if tagging.get("taggable") else None
        field = resource.field(tag_path) if tag_path else None
        if field and field.state == ValueState.KNOWN:
            tags = field.selected().value
            if isinstance(tags, list) and all(isinstance(tag, dict) for tag in tags):
                keys = [tag.get("Key") for tag in tags if isinstance(tag.get("Key"), str)]
                if len(keys) != len(set(keys)):
                    self.add("TAG_KEY_UNIQUE", resource, tag_path, "FAIL",
                             "duplicate tag keys", actual=keys, evidence=field_evidence(field))
        for path in schema.get("deprecatedProperties", []):
            if path.count("/") > 2 or not path.startswith("/properties/"):
                parts = path.split("/")
                top = "/properties/" + parts[2] if len(parts) > 2 and parts[1] == "properties" else None
                if top and resource.field(top):
                    self.uncovered("DEPRECATED_NESTED", resource, path,
                                   "nested deprecated property needs manual review")
                continue
            field = resource.field(path)
            if field and field.state == ValueState.KNOWN:
                self.add("DEPRECATED_PROPERTY", resource, path, "NEEDS_REVIEW",
                         "property is deprecated in the pinned resource schema",
                         evidence=field_evidence(field))

    def _field_conflicts(self, resource: Resource):
        for field in resource.fields:
            if field.state == ValueState.CONFLICT:
                self.add("VALUE_CONFLICT", resource, field.path, "NEEDS_REVIEW",
                         "conflicting candidates", actual=[c.value for c in field.candidates],
                         evidence=field_evidence(field), dependencies=[field.path])

    def _identity(self, design: Design):
        names = defaultdict(list)
        for r in design.resources:
            names[(r.scope.environment, r.scope.account, r.scope.region, r.type, r.name)].append(r)
        for group in names.values():
            if len(group) > 1:
                for r in group:
                    self.add("IDENTITY_NAME", r, None, "NEEDS_REVIEW", "same-name resources in scope",
                             actual=[x.id for x in group])

    def _relations(self, design: Design):
        by_id = {r.id: r for r in design.resources}
        by_name = defaultdict(list)
        for resource in design.resources:
            by_name[(resource.type, resource.name, resource.scope.environment,
                     resource.scope.account, resource.scope.region)].append(resource)
        relations = defaultdict(list)
        by_source = defaultdict(list)
        for rel in design.relations:
            relations[(rel.source_resource_id, rel.source_path)].append(rel)
            by_source[rel.source_resource_id].append(rel)
        for rel in design.relations:
            source = by_id.get(rel.source_resource_id)
            if not source:
                self.uncovered("ORPHAN_RELATION", None, rel.source_path, f"source {rel.source_resource_id} missing")
                continue
            configured_type = reference_type(source.type, rel.source_path, self.reference_types)
            expected_type = configured_type or rel.expected_target_type
            if not expected_type:
                self.uncovered("RELATION_TYPE", source, rel.source_path, "reference rule not implemented")
                continue
            if configured_type and rel.expected_target_type and configured_type != rel.expected_target_type:
                self.add("REFERENCE", source, rel.source_path, "FAIL",
                         "declared reference type conflicts with resource rule",
                         expected=configured_type, actual=rel.expected_target_type,
                         evidence=rel.evidence_ids)
                continue
            if len(relations[(source.id, rel.source_path)]) > 1:
                continue
            target = by_id.get(rel.target_resource_id) if rel.target_resource_id else None
            if not target and rel.unresolved_name:
                if source.type == "AWS::IAM::AccessKey" and rel.source_path == "/properties/UserName":
                    matches = [item for item in design.resources if item.type == expected_type
                               and item.name == rel.unresolved_name
                               and item.scope.environment == source.scope.environment
                               and item.scope.account == source.scope.account]
                else:
                    matches = by_name[(expected_type, rel.unresolved_name, source.scope.environment,
                                       source.scope.account, source.scope.region)]
                if len(matches) == 1:
                    target = matches[0]
                elif len(matches) > 1:
                    self.add("REFERENCE", source, rel.source_path, "NEEDS_REVIEW", "ambiguous target name",
                             actual=[r.id for r in matches], evidence=rel.evidence_ids,
                             dependencies=[rel.source_path])
                    continue
            if not target:
                self.add("REFERENCE", source, rel.source_path, "NEEDS_REVIEW", "target not found",
                         actual=rel.target_resource_id or rel.unresolved_name,
                         evidence=rel.evidence_ids, dependencies=[rel.source_path])
            elif target.type != expected_type or (target.scope != source.scope and not (
                    source.type == "AWS::S3::Bucket" and target.type == "AWS::S3::Bucket" and
                    S3_REPLICATION_DESTINATION.fullmatch(rel.source_path)) and not (
                    source.type == "AWS::IAM::AccessKey" and rel.source_path == "/properties/UserName" and
                    target.scope.account == source.scope.account and
                    target.scope.environment == source.scope.environment)):
                self.add("REFERENCE", source, rel.source_path, "FAIL", "target type or scope differs",
                         actual=target.id, evidence=rel.evidence_ids)
            else:
                self.add("REFERENCE", source, rel.source_path, "PASS", "resource reference resolved",
                         actual=target.id, evidence=rel.evidence_ids)
        for r in design.resources:
            for (source_type, pattern), _ in self.reference_types.items():
                if r.type != source_type:
                    continue
                path = pattern[:-2] if pattern.endswith("/*") else pattern
                matching = [rel for rel in by_source[r.id]
                            if rel.source_path == path or rel.source_path.startswith(path + "/")]
                if not matching:
                    field = r.field(path)
                    if field and field.state == ValueState.KNOWN:
                        self.uncovered("EXTERNAL_REFERENCE", r, path,
                                       "physical or external identifier cannot be resolved from internal resources")
                        self.add("REFERENCE", r, path, "NEEDS_REVIEW",
                                 "external identifier cannot be resolved to a design resource",
                                 actual=field.selected().value, evidence=field_evidence(field),
                                 dependencies=[path])
                    elif (r.type in ("AWS::EC2::Subnet", "AWS::EC2::SecurityGroup", "AWS::RDS::DBSubnetGroup")
                          and (source_type, pattern) in REFERENCE_TYPES and "*" not in path):
                        # Only the built-in top-level reference slots expect a relation;
                        # optional nested slots from the catalog are simply unused.
                        self.add("REFERENCE", r, path, "NEEDS_REVIEW", "relation missing",
                                 dependencies=[path])
        for (resource_id, path), group in relations.items():
            if len(group) > 1 and resource_id in by_id:
                self.add("REFERENCE", by_id[resource_id], path, "NEEDS_REVIEW",
                         "conflicting references", actual=[x.target_resource_id or x.unresolved_name for x in group],
                         evidence=list(dict.fromkeys(e for x in group for e in x.evidence_ids)),
                         dependencies=[path])

    def _networks(self, design: Design):
        by_id = {r.id: r for r in design.resources}
        vpc_addresses, findings = vpc_ipv4_addresses(design)
        for finding in findings:
            self._add_check_finding(finding)
        subnet_groups = defaultdict(list)
        reference_counts = Counter(r.source_resource_id for r in design.relations
                                   if r.source_path == "/properties/VpcId")
        reported_conflicts = set()
        for resource in design.resources:
            if resource.type == "AWS::EC2::Subnet" and reference_counts[resource.id] == 0:
                self.add("CIDR_CONTAINMENT", resource, "/properties/CidrBlock", "NEEDS_REVIEW",
                         "VPC reference unavailable", dependencies=["/properties/VpcId"])
        for relation in design.relations:
            if relation.source_path != "/properties/VpcId":
                continue
            subnet = by_id.get(relation.source_resource_id)
            if reference_counts[relation.source_resource_id] > 1:
                if subnet and subnet.type == "AWS::EC2::Subnet" and subnet.id not in reported_conflicts:
                    self.add("CIDR_CONTAINMENT", subnet, "/properties/CidrBlock", "NEEDS_REVIEW",
                             "VPC reference conflicts", dependencies=["/properties/VpcId"])
                    reported_conflicts.add(subnet.id)
                continue
            vpc = by_id.get(relation.target_resource_id)
            if not vpc and relation.unresolved_name and subnet:
                matches = [r for r in design.resources if r.name == relation.unresolved_name
                           and r.scope == subnet.scope and r.type == "AWS::EC2::VPC"]
                vpc = matches[0] if len(matches) == 1 else None
            if not subnet or subnet.type != "AWS::EC2::Subnet" or not vpc or vpc.type != "AWS::EC2::VPC" or subnet.scope != vpc.scope:
                if subnet and subnet.type == "AWS::EC2::Subnet":
                    self.add("CIDR_CONTAINMENT", subnet, "/properties/CidrBlock", "NEEDS_REVIEW",
                             "VPC reference unavailable", dependencies=["/properties/VpcId"])
                continue
            subnet_field = subnet.field("/properties/CidrBlock")
            subnet_cidr = self._ipv4(subnet, subnet_field)
            known = vpc_addresses[vpc.id]
            blocks = [block.network for block in known.blocks]
            block_fields = [block.field for block in known.blocks]
            if subnet_cidr:
                subnet_groups[vpc.id].append((subnet_cidr, subnet, subnet_field))
            evidence = field_evidence(subnet_field) + [e for f in block_fields for e in field_evidence(f)]
            contained = bool(subnet_cidr) and any(subnet_cidr.subnet_of(block) for block in blocks)
            if subnet_cidr and (contained or (blocks and not known.incomplete)):
                self.add("CIDR_CONTAINMENT", subnet, "/properties/CidrBlock",
                         "PASS" if contained else "FAIL",
                         "subnet CIDR lies within VPC" if contained else "subnet CIDR outside VPC",
                         actual=str(subnet_cidr),
                         expected=str(blocks[0]) if len(blocks) == 1 else [str(b) for b in blocks],
                         evidence=list(dict.fromkeys(evidence)))
            elif subnet_cidr and blocks:
                self.add("CIDR_CONTAINMENT", subnet, "/properties/CidrBlock", "NEEDS_REVIEW",
                         "another VPC IPv4 block is unresolved", actual=str(subnet_cidr),
                         expected=[str(b) for b in blocks], dependencies=["/properties/VpcId"],
                         evidence=list(dict.fromkeys(evidence)))
            else:
                self.add("CIDR_CONTAINMENT", subnet, "/properties/CidrBlock", "NEEDS_REVIEW",
                         "IPv4 CIDR unavailable", dependencies=["/properties/CidrBlock"],
                         evidence=list(dict.fromkeys(evidence)))
        for entries in subnet_groups.values():
            entries.sort(key=lambda x: (int(x[0].network_address), int(x[0].broadcast_address)))
            active = {}
            ending = []
            for i, (network, subnet, field) in enumerate(entries):
                start = int(network.network_address)
                while ending and ending[0][0] < start:
                    _, expired = heapq.heappop(ending)
                    active.pop(expired, None)
                for other, other_subnet, other_field in active.values():
                    self.add("CIDR_OVERLAP", subnet, "/properties/CidrBlock", "FAIL",
                             "subnet CIDRs overlap", actual=[subnet.id, other_subnet.id],
                             evidence=field_evidence(field) + field_evidence(other_field))
                active[i] = (network, subnet, field)
                heapq.heappush(ending, (int(network.broadcast_address), i))

    def _rds(self, design: Design):
        by_id = {r.id: r for r in design.resources}
        by_name = defaultdict(list)
        for r in design.resources:
            by_name[(r.type, r.name, r.scope.environment, r.scope.account, r.scope.region)].append(r)
        by_source = defaultdict(list)
        for relation in design.relations:
            by_source[relation.source_resource_id].append(relation)

        def target(source: Resource, relation, expected_type: str):
            found = by_id.get(relation.target_resource_id)
            if not found and relation.unresolved_name:
                matches = by_name[(expected_type, relation.unresolved_name, source.scope.environment,
                                   source.scope.account, source.scope.region)]
                found = matches[0] if len(matches) == 1 else None
            return found if found and found.type == expected_type and found.scope == source.scope else None

        def vpc_for(resource: Resource):
            refs = [rel for rel in by_source[resource.id] if rel.source_path == "/properties/VpcId"]
            return target(resource, refs[0], "AWS::EC2::VPC") if len(refs) == 1 else None

        group_vpcs = {}
        for group in (r for r in design.resources if r.type == "AWS::RDS::DBSubnetGroup"):
            refs = [rel for rel in by_source[group.id] if rel.source_path.startswith("/properties/SubnetIds/")]
            if len({rel.source_path for rel in refs}) != len(refs):
                self.add("RDS_SUBNET_AZ", group, "/properties/SubnetIds", "NEEDS_REVIEW",
                         "subnet references conflict", dependencies=["/properties/SubnetIds"])
                self.add("RDS_SUBNET_VPC", group, "/properties/SubnetIds", "NEEDS_REVIEW",
                         "subnet references conflict", dependencies=["/properties/SubnetIds"])
                continue
            subnets = [target(group, rel, "AWS::EC2::Subnet") for rel in refs]
            if len(refs) < 2 or any(s is None for s in subnets):
                self.add("RDS_SUBNET_AZ", group, "/properties/SubnetIds", "NEEDS_REVIEW",
                         "at least two resolved subnets in different AZs are needed",
                         dependencies=["/properties/SubnetIds"])
            else:
                zones = [value(subnet, "/properties/AvailabilityZone") for subnet in subnets]
                if any(not isinstance(zone, str) or not zone for zone in zones):
                    self.add("RDS_SUBNET_AZ", group, "/properties/SubnetIds", "NEEDS_REVIEW",
                             "subnet AvailabilityZone is unresolved",
                             dependencies=["/properties/AvailabilityZone"])
                else:
                    self.add("RDS_SUBNET_AZ", group, "/properties/SubnetIds",
                             "PASS" if len(set(zones)) >= 2 else "FAIL",
                             "subnets cover at least two AZs" if len(set(zones)) >= 2 else "subnets share one AZ",
                             actual=zones)
            vpcs = [vpc_for(subnet) for subnet in subnets if subnet]
            if len(vpcs) != len(subnets) or not vpcs or any(vpc is None for vpc in vpcs):
                self.add("RDS_SUBNET_VPC", group, "/properties/SubnetIds", "NEEDS_REVIEW",
                         "subnet VPC is unresolved", dependencies=["/properties/VpcId"])
            elif len({vpc.id for vpc in vpcs}) > 1:
                self.add("RDS_SUBNET_VPC", group, "/properties/SubnetIds", "FAIL",
                         "subnets belong to different VPCs", actual=[vpc.id for vpc in vpcs])
            else:
                group_vpcs[group.id] = vpcs[0]
                self.add("RDS_SUBNET_VPC", group, "/properties/SubnetIds", "PASS",
                         "subnets share a VPC", actual=vpcs[0].id)

        for instance in (r for r in design.resources if r.type == "AWS::RDS::DBInstance"):
            group_refs = [rel for rel in by_source[instance.id]
                          if rel.source_path == "/properties/DBSubnetGroupName"]
            sg_refs = [rel for rel in by_source[instance.id]
                       if rel.source_path.startswith("/properties/VPCSecurityGroups/")]
            if not sg_refs:
                continue
            if len({rel.source_path for rel in sg_refs}) != len(sg_refs):
                self.add("RDS_SECURITY_GROUP_VPC", instance, "/properties/VPCSecurityGroups", "NEEDS_REVIEW",
                         "security group references conflict", dependencies=["/properties/VPCSecurityGroups"])
                continue
            group = target(instance, group_refs[0], "AWS::RDS::DBSubnetGroup") if len(group_refs) == 1 else None
            group_vpc = group_vpcs.get(group.id) if group else None
            security_groups = [target(instance, rel, "AWS::EC2::SecurityGroup") for rel in sg_refs]
            security_vpcs = [vpc_for(sg) for sg in security_groups if sg]
            if not group_vpc or len(security_vpcs) != len(sg_refs) or any(vpc is None for vpc in security_vpcs):
                self.add("RDS_SECURITY_GROUP_VPC", instance, "/properties/VPCSecurityGroups", "NEEDS_REVIEW",
                         "DB subnet group or security group VPC unresolved",
                         dependencies=["/properties/DBSubnetGroupName", "/properties/VPCSecurityGroups"])
            else:
                valid = all(vpc.id == group_vpc.id for vpc in security_vpcs)
                self.add("RDS_SECURITY_GROUP_VPC", instance, "/properties/VPCSecurityGroups",
                         "PASS" if valid else "FAIL",
                         "security groups share DB VPC" if valid else "security group belongs to another VPC",
                         actual=[vpc.id for vpc in security_vpcs], expected=group_vpc.id)

        for subscription in (r for r in design.resources if r.type == "AWS::RDS::EventSubscription"):
            path = "/properties/SnsTopicArn"
            refs = [rel for rel in by_source[subscription.id] if rel.source_path == path]
            topic = target(subscription, refs[0], "AWS::SNS::Topic") if len(refs) == 1 else None
            if topic is None:
                self.add("RDS_EVENT_SUBSCRIPTION_SNS_STANDARD", subscription, path, "NEEDS_REVIEW",
                         "SNS topic must be resolved to verify that it is a standard topic",
                         dependencies=[path])
                continue
            fifo = topic.field("/properties/FifoTopic")
            if fifo is None or fifo.state == ValueState.MISSING:
                self.add("RDS_EVENT_SUBSCRIPTION_SNS_STANDARD", subscription, path, "PASS",
                         "SNS topic defaults to standard when FifoTopic is omitted", actual=topic.id)
            elif fifo.state != ValueState.KNOWN:
                self.add("RDS_EVENT_SUBSCRIPTION_SNS_STANDARD", subscription, path, "NEEDS_REVIEW",
                         "SNS topic FIFO setting is unresolved", actual=topic.id,
                         dependencies=["/properties/FifoTopic"])
            else:
                is_fifo = fifo.selected().value
                if not isinstance(is_fifo, bool):
                    self.add("RDS_EVENT_SUBSCRIPTION_SNS_STANDARD", subscription, path,
                             "NEEDS_REVIEW", "SNS topic FIFO setting is not a resolved boolean",
                             actual=is_fifo, evidence=field_evidence(fifo),
                             dependencies=["/properties/FifoTopic"])
                else:
                    self.add("RDS_EVENT_SUBSCRIPTION_SNS_STANDARD", subscription, path,
                             "FAIL" if is_fifo else "PASS",
                             "RDS does not support FIFO SNS topics" if is_fifo else
                             "SNS topic is standard", actual=topic.id,
                             evidence=field_evidence(fifo))

    def _s3_access_grants(self, design: Design):
        by_scope = defaultdict(list)
        for resource in design.resources:
            if resource.type == "AWS::S3::AccessGrantsInstance":
                by_scope[(resource.scope.account, resource.scope.region)].append(resource)
        for instances in by_scope.values():
            duplicate = len(instances) > 1
            for instance in instances:
                self.add("S3_ACCESS_GRANTS_INSTANCE_REGION_UNIQUE", instance, None,
                         "FAIL" if duplicate else "NEEDS_REVIEW",
                         "multiple Access Grants instances in one account and Region" if duplicate else
                         "other instances in the account and Region cannot be ruled out from the design",
                         actual=[item.id for item in instances])

    def _ipv4(self, resource: Resource, field: FieldValue | None):
        if not field or field.state != ValueState.KNOWN:
            return None
        raw = field.selected().value
        if not isinstance(raw, str):
            return None
        try:
            cidr = ipaddress.ip_network(raw, strict=True)
        except ValueError:
            self.add("CIDR_FORMAT", resource, field.path, "FAIL", "invalid CIDR", actual=raw,
                     evidence=field_evidence(field))
            return None
        if cidr.version != 4:
            self.uncovered("IPV6", resource, field.path, "initial CIDR rules support IPv4 only")
            return None
        return cidr
