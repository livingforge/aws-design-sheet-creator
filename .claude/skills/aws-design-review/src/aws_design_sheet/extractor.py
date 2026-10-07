"""Replaceable, deterministic extractor for line-oriented UTF-8 design notes.

Grammar (one resource per line):
    VPC <name>: <Property>=<value>; ...
    Subnet <name>: Vpc=<VPC name>; <Property>=<value>; ...
Values are JSON scalars/arrays/objects or unquoted strings. A bare `default`
records default intent without inventing a value. Unrecognized lines stay
outside extracted_ranges and appear in the checker's coverage output.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Protocol

from .models import Design, TemplateContext


LINE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*::[A-Za-z][A-Za-z0-9]*::[A-Za-z][A-Za-z0-9]*|VPC|Subnet|SecurityGroup|DBSubnetGroup|DBInstance)\s+([^:\uFF1A\s]+)\s*[:\uFF1A]\s*(.*?)\s*$", re.IGNORECASE)
REQUIREMENT_LINE = re.compile(r"^\s*Requirement\s+([^:\uFF1A\s]+)\s*[:\uFF1A]\s*(.+?)\s*$", re.IGNORECASE)
ALIASES = {
    "CIDR": "CidrBlock",
    "DNS\u30b5\u30dd\u30fc\u30c8": "EnableDnsSupport",
    "\u30d1\u30d6\u30ea\u30c3\u30afIP\u81ea\u52d5\u5272\u5f53": "MapPublicIpOnLaunch",
    "VPC": "Vpc",
}
TYPES = {"vpc": "AWS::EC2::VPC", "subnet": "AWS::EC2::Subnet",
         "securitygroup": "AWS::EC2::SecurityGroup",
         "dbsubnetgroup": "AWS::RDS::DBSubnetGroup",
         "dbinstance": "AWS::RDS::DBInstance"}
REFERENCE_FIELDS = {
    ("AWS::EC2::Subnet", "Vpc"): ("VpcId", "AWS::EC2::VPC", False),
    ("AWS::EC2::SecurityGroup", "Vpc"): ("VpcId", "AWS::EC2::VPC", False),
    ("AWS::RDS::DBSubnetGroup", "Subnets"): ("SubnetIds", "AWS::EC2::Subnet", True),
    ("AWS::RDS::DBInstance", "DBSubnetGroup"): ("DBSubnetGroupName", "AWS::RDS::DBSubnetGroup", False),
    ("AWS::RDS::DBInstance", "SecurityGroups"): ("VPCSecurityGroups", "AWS::EC2::SecurityGroup", True),
}
TYPED_REFERENCE = re.compile(
    r"^@([A-Za-z][A-Za-z0-9]*::[A-Za-z][A-Za-z0-9]*::[A-Za-z][A-Za-z0-9]*)/([^/\s]+)$"
)


@dataclass(frozen=True)
class TextSource:
    id: str
    name: str
    version: str
    text: str


class TextExtractor(Protocol):
    def extract(self, sources: list[TextSource], *, project: str, environment: str,
                account: str, region: str) -> Design: ...


def parse_value(raw: str):
    raw = raw.strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def merge_template(resource: dict, value, evidence_id: str):
    if not isinstance(value, dict):
        raise ValueError("@Template must be a JSON object")
    declaration = TemplateContext.model_validate({**value, 'evidence_ids': [evidence_id]}).model_dump(mode='json')
    previous = resource.get('template')
    if previous:
        keys = ('id', 'depends_on', 'state')
        if any(previous.get(k) != declaration.get(k) for k in keys):
            declaration = TemplateContext(state='CONFLICT').model_dump(mode='json')
        declaration['evidence_ids'] = previous['evidence_ids'] + [evidence_id]
    resource['template'] = declaration


def typed_references(value, path: str):
    if isinstance(value, str):
        match = TYPED_REFERENCE.fullmatch(value)
        if match:
            yield path, *match.groups()
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from typed_references(item, f"{path}/{index}")
    elif isinstance(value, dict):
        for key, item in value.items():
            escaped = str(key).replace("~", "~0").replace("/", "~1")
            yield from typed_references(item, f"{path}/{escaped}")


def _segments(body: str) -> list[tuple[str, str]] | None:
    """Split semicolons outside JSON strings, arrays and objects."""
    segments, start, depth, quoted, escaped = [], 0, 0, False, False
    for i, char in enumerate(body):
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif not quoted and char in "[{":
            depth += 1
        elif not quoted and char in "]}":
            depth -= 1
            if depth < 0:
                return None
        elif not quoted and depth == 0 and char == ";":
            segments.append(body[start:i].strip())
            start = i + 1
    if quoted or depth != 0:
        return None
    segments.append(body[start:].strip())
    if not segments or any("=" not in segment for segment in segments):
        return None
    pairs = [tuple(part.strip() for part in segment.split("=", 1)) for segment in segments]
    if any(not key for key, _ in pairs):
        return None
    return pairs


class LineExtractor:
    """Line extractor. With a reference catalog it also links bare names (line-v4).

    A catalog maps (resource type, property pointer) to the referenced type; array
    items use a trailing ``/*``. A top-level value, or every item of a top-level
    array, that exactly names a resource of that type in the same input becomes a
    relation instead of a literal. Anything else stays a literal value.
    """

    def __init__(self, reference_catalog: dict[tuple[str, str], str] | None = None):
        self.reference_catalog = dict(reference_catalog or {})

    @property
    def version(self) -> str:
        return "line-v4" if self.reference_catalog else "line-v3"

    def _link_names(self, data: dict, resources: dict[tuple[str, str], dict]):
        for resource in data["resources"]:
            kept = []
            for field in resource["fields"]:
                path = field["path"]
                single = self.reference_catalog.get((resource["type"], path))
                many = self.reference_catalog.get((resource["type"], path + "/*"))
                selected = next((c for c in field["candidates"]
                                 if c["id"] == field.get("selected_candidate_id")), None)
                value = selected["value"] if field["state"] == "KNOWN" and selected else None
                names = ([value] if single and isinstance(value, str) else
                         value if many and isinstance(value, list) and value and
                         all(isinstance(item, str) for item in value) else None)
                target_type = single or many
                targets = [resources.get((target_type, name)) for name in names or []]
                if not names or not all(targets):
                    kept.append(field)
                    continue
                for index, (name, target) in enumerate(zip(names, targets)):
                    data["relations"].append({
                        "id": f"rel-{len(data['relations']) + 1}", "source_resource_id": resource["id"],
                        "source_path": path if single else f"{path}/{index}",
                        "target_resource_id": target["id"], "unresolved_name": name,
                        "expected_target_type": target_type,
                        "evidence_ids": list(selected["evidence_ids"])})
            resource["fields"] = kept

    def extract(self, sources: list[TextSource], *, project: str, environment: str,
                account: str, region: str = "ap-northeast-1") -> Design:
        if len({s.id for s in sources}) != len(sources):
            raise ValueError("duplicate source ID")
        scope = {"environment": environment, "account": account, "region": region}
        data = {"model_version": "1.0", "extractor_version": self.version,
                "project": project, "environment": environment,
                "account": account, "region": region, "documents": [], "evidence": [],
                "resources": [], "relations": [], "requirements": []}
        resources: dict[tuple[str, str], dict] = {}
        pending_refs: list[tuple[dict, str, str]] = []
        relation_index: dict[tuple[str, str, str, str], dict] = {}
        evidence_no = 0
        candidate_no = 0
        relation_no = 0

        for source in sources:
            document = {"id": source.id, "name": source.name, "version": source.version,
                        "sha256": hashlib.sha256(source.text.encode("utf-8")).hexdigest(),
                        "text": source.text, "extracted_ranges": []}
            data["documents"].append(document)
            for line_no, line in enumerate(source.text.splitlines(), 1):
                requirement = REQUIREMENT_LINE.match(line)
                if requirement:
                    evidence_no += 1
                    evidence_id = f"ev-{evidence_no}"
                    data["evidence"].append({"id": evidence_id, "document_id": source.id,
                                             "start_line": line_no, "end_line": line_no, "excerpt": line})
                    data["requirements"].append({"id": requirement.group(1),
                                                  "description": requirement.group(2),
                                                  "evidence_ids": [evidence_id]})
                    document["extracted_ranges"].append([line_no, line_no])
                    continue
                match = LINE.match(line)
                if not match:
                    continue
                raw_type = match.group(1)
                type_name = raw_type if "::" in raw_type else TYPES[raw_type.lower()]
                name = match.group(2)
                pairs = _segments(match.group(3))
                if pairs is None:
                    continue
                key = (type_name, name)
                if key not in resources:
                    resource = {"id": f"res-{len(resources) + 1}", "type": type_name,
                                "name": name, "scope": scope.copy(), "fields": []}
                    resources[key] = resource
                    data["resources"].append(resource)
                resource = resources[key]
                document["extracted_ranges"].append([line_no, line_no])
                for property_name, raw in pairs:
                    property_name = ALIASES.get(property_name, property_name)
                    evidence_no += 1
                    evidence_id = f"ev-{evidence_no}"
                    data["evidence"].append({"id": evidence_id, "document_id": source.id,
                                             "start_line": line_no, "end_line": line_no, "excerpt": line})
                    reference = REFERENCE_FIELDS.get((type_name, property_name))
                    parsed = parse_value(raw)
                    if property_name == "@Template":
                        merge_template(resource, parsed, evidence_id)
                        continue
                    typed = ([TYPED_REFERENCE.fullmatch(item) for item in parsed]
                             if isinstance(parsed, list) and all(isinstance(item, str) for item in parsed) else
                             [TYPED_REFERENCE.fullmatch(parsed)] if isinstance(parsed, str) else [])
                    if typed and all(typed):
                        canonical = reference[0] if reference else property_name
                        for index, match_ref in enumerate(typed):
                            source_path = "/properties/" + canonical + (f"/{index}" if isinstance(parsed, list) else "")
                            target_type, target_name = match_ref.groups()
                            reference_key = (resource["id"], source_path, target_name, target_type)
                            existing_relation = relation_index.get(reference_key)
                            if existing_relation:
                                existing_relation["evidence_ids"].append(evidence_id)
                                continue
                            relation_no += 1
                            relation = {"id": f"rel-{relation_no}",
                                        "source_resource_id": resource["id"],
                                        "source_path": source_path,
                                        "unresolved_name": target_name,
                                        "expected_target_type": target_type,
                                        "evidence_ids": [evidence_id]}
                            data["relations"].append(relation)
                            relation_index[reference_key] = relation
                            pending_refs.append((relation, target_name, target_type))
                        continue
                    nested_references = list(typed_references(
                        parsed, "/properties/" + property_name.replace("~", "~0").replace("/", "~1")
                    ))
                    for source_path, target_type, target_name in nested_references:
                        reference_key = (resource["id"], source_path, target_name, target_type)
                        existing_relation = relation_index.get(reference_key)
                        if existing_relation:
                            existing_relation["evidence_ids"].append(evidence_id)
                            continue
                        relation_no += 1
                        relation = {"id": f"rel-{relation_no}",
                                    "source_resource_id": resource["id"],
                                    "source_path": source_path,
                                    "unresolved_name": target_name,
                                    "expected_target_type": target_type,
                                    "evidence_ids": [evidence_id]}
                        data["relations"].append(relation)
                        relation_index[reference_key] = relation
                        pending_refs.append((relation, target_name, target_type))
                    if reference and not nested_references and raw.lower() != "default":
                        canonical, target_type, many = reference
                        names = parsed if many else [parsed]
                        if isinstance(names, list) and all(isinstance(item, str) for item in names):
                            for index, target_name in enumerate(names):
                                source_path = "/properties/" + canonical + (f"/{index}" if many else "")
                                reference_key = (resource["id"], source_path, target_name, target_type)
                                existing_relation = relation_index.get(reference_key)
                                if existing_relation:
                                    existing_relation["evidence_ids"].append(evidence_id)
                                    continue
                                relation_no += 1
                                relation = {"id": f"rel-{relation_no}",
                                            "source_resource_id": resource["id"],
                                            "source_path": source_path,
                                            "unresolved_name": target_name,
                                            "evidence_ids": [evidence_id]}
                                data["relations"].append(relation)
                                relation_index[reference_key] = relation
                                pending_refs.append((relation, target_name, target_type))
                            continue
                        property_name = canonical
                    elif reference:
                        property_name = reference[0]
                    path = "/properties/" + property_name.replace("~", "~0").replace("/", "~1")
                    fields = resource["fields"]
                    field = next((f for f in fields if f["path"] == path), None)
                    if field is None:
                        field = {"path": path, "state": "MISSING", "candidates": []}
                        fields.append(field)
                    if raw.lower() == "default":
                        field["default_intent"] = True
                        field.setdefault("intent_evidence_ids", []).append(evidence_id)
                        field["state"] = "UNRESOLVED"
                        field.pop("selected_candidate_id", None)
                        continue
                    candidate_no += 1
                    candidate = {"id": f"cand-{candidate_no}", "raw": raw,
                                 "value": parse_value(raw), "evidence_ids": [evidence_id]}
                    field["candidates"].append(candidate)
                    distinct = {json.dumps(c["value"], ensure_ascii=False, sort_keys=True)
                                for c in field["candidates"]}
                    if len(distinct) > 1 or field.get("default_intent"):
                        field["state"] = "CONFLICT" if len(field["candidates"]) > 1 else "UNRESOLVED"
                        field.pop("selected_candidate_id", None)
                    else:
                        field["state"] = "KNOWN"
                        field["selected_candidate_id"] = field["candidates"][0]["id"]
        for relation, name, target_type in pending_refs:
            target = resources.get((target_type, name))
            if target:
                relation["target_resource_id"] = target["id"]
        if self.reference_catalog:
            self._link_names(data, resources)
        if any(r.get('template') for r in data['resources']):
            data['extractor_version'] = 'line-v5'
        return Design.model_validate(data)
