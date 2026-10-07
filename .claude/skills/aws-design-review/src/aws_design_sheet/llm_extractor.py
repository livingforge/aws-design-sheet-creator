"""Free-text extractor backed by Claude, with every item checked against the source.

The model returns resources, property values and requirements, each with a line
number and a verbatim excerpt. An item is kept only if its excerpt appears on
the cited line of the cited document and its value parses as JSON; everything
else is reported as rejected. Lines without a kept item stay outside
``extracted_ranges`` and surface as UNPROCESSED_TEXT in the checker's coverage.
The model's reading of the text is not trusted beyond this: evaluate extraction
with ``aws-design-evaluate`` against gold data before relying on it.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .extractor import LineExtractor, TextSource, TYPED_REFERENCE, typed_references, merge_template
from .models import Design


MODEL = "claude-opus-5"
TYPE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9]*::[A-Za-z][A-Za-z0-9]*::[A-Za-z][A-Za-z0-9]*$")
LOCATED = {"document_id": {"type": "string"}, "line": {"type": "integer"},
           "excerpt": {"type": "string"}}
SCHEMA = {
    "type": "object",
    "properties": {
        "resources": {"type": "array", "items": {
            "type": "object",
            "properties": {
                "type": {"type": "string"}, "name": {"type": "string"}, **LOCATED,
                "properties": {"type": "array", "items": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}, "value_json": {"type": "string"},
                                   **LOCATED},
                    "required": ["name", "value_json", *LOCATED], "additionalProperties": False}}},
            "required": ["type", "name", *LOCATED, "properties"], "additionalProperties": False}},
        "requirements": {"type": "array", "items": {
            "type": "object",
            "properties": {"id": {"type": "string"}, "description": {"type": "string"}, **LOCATED},
            "required": ["id", "description", *LOCATED], "additionalProperties": False}},
    },
    "required": ["resources", "requirements"],
    "additionalProperties": False,
}
SYSTEM = """You extract AWS design information from design documents into CloudFormation terms.
Extract only what the text states. Do not infer values, defaults or resources that are not written.
- type: the CloudFormation resource type name, e.g. AWS::EC2::VPC. name: the logical name used in the text.
- properties: CloudFormation property names of that type. value_json: the value as JSON text
  (strings quoted, numbers, true/false, arrays, objects). When a value names another resource
  described in the documents, write "@<Type>/<name>" as the JSON string, e.g. "@AWS::EC2::VPC/main".
- requirements: design requirements or policies stated in the text, with a short stable id.
- Explicit template membership may be recorded as a special property named @Template,
  with value_json {"id":"template name","depends_on":["logical resource names"]}.
  Include depends_on only when its complete list is stated; [] means explicitly none.
  Do not infer template membership from sharing a document or an account.
- For every item give document_id, the 1-based line number, and excerpt: a verbatim substring of
  that line that shows the item. Items whose excerpt is not on that line are discarded."""


def _numbered(sources: list[TextSource]) -> str:
    parts = []
    for source in sources:
        lines = source.text.splitlines()
        parts.append(f'<document id="{source.id}" name="{source.name}">\n' +
                     "\n".join(f"{number}: {line}" for number, line in enumerate(lines, 1)) +
                     "\n</document>")
    return "\n\n".join(parts)


class LlmExtractor:
    """TextExtractor that asks Claude for structured JSON and verifies it line by line."""

    version = "llm-v1"

    def __init__(self, client: Any = None, *, model: str = MODEL,
                 reference_catalog: dict[tuple[str, str], str] | None = None,
                 max_tokens: int = 64000):
        self.client = client
        self.model = model
        self.max_tokens = max_tokens
        self.reference_catalog = dict(reference_catalog or {})
        self.rejected: list[dict] = []

    def _client(self):
        if self.client is None:
            try:
                import anthropic
            except ImportError as exc:  # optional dependency
                raise RuntimeError("install the 'llm' extra: pip install -e .[llm]") from exc
            self.client = anthropic.Anthropic()
        return self.client

    def _request(self, sources: list[TextSource]) -> dict:
        client = self._client()
        with client.beta.messages.stream(
            model=self.model,
            max_tokens=self.max_tokens,
            system=SYSTEM,
            thinking={"type": "adaptive"},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            output_config={"format": {"type": "json_schema", "schema": SCHEMA}},
            messages=[{"role": "user", "content": _numbered(sources)}],
        ) as stream:
            response = stream.get_final_message()
        if response.stop_reason == "refusal":
            raise RuntimeError("extraction request was refused")
        if response.stop_reason == "max_tokens":
            raise RuntimeError("extraction output was truncated at max_tokens")
        text = next(block.text for block in response.content if block.type == "text")
        return json.loads(text)

    def extract(self, sources: list[TextSource], *, project: str, environment: str,
                account: str, region: str = "ap-northeast-1") -> Design:
        if len({s.id for s in sources}) != len(sources):
            raise ValueError("duplicate source ID")
        return self.build(self._request(sources), sources, project=project,
                          environment=environment, account=account, region=region)

    def build(self, output: dict, sources: list[TextSource], *, project: str, environment: str,
              account: str, region: str) -> Design:
        """Turn model output into a Design, keeping only items that match the source."""
        self.rejected = []
        lines = {source.id: source.text.splitlines() for source in sources}
        scope = {"environment": environment, "account": account, "region": region}
        data = {"model_version": "1.0", "extractor_version": self.version, "project": project,
                "environment": environment, "account": account, "region": region,
                "documents": [{"id": s.id, "name": s.name, "version": s.version,
                               "sha256": hashlib.sha256(s.text.encode("utf-8")).hexdigest(),
                               "text": s.text, "extracted_ranges": []} for s in sources],
                "evidence": [], "resources": [], "relations": [], "requirements": []}
        documents = {document["id"]: document for document in data["documents"]}
        resources: dict[tuple[str, str], dict] = {}
        counters = {"evidence": 0, "candidate": 0}

        def evidence(item: dict, kind: str) -> str | None:
            document, line, excerpt = item.get("document_id"), item.get("line"), item.get("excerpt")
            source_lines = lines.get(document)
            if (source_lines is None or not isinstance(line, int) or not 1 <= line <= len(source_lines)
                    or not isinstance(excerpt, str) or not excerpt.strip()
                    or excerpt not in source_lines[line - 1]):
                self.rejected.append({"kind": kind, "item": item, "reason": "excerpt not on cited line"})
                return None
            counters["evidence"] += 1
            evidence_id = f"ev-{counters['evidence']}"
            data["evidence"].append({"id": evidence_id, "document_id": document, "start_line": line,
                                     "end_line": line, "excerpt": excerpt})
            documents[document]["extracted_ranges"].append([line, line])
            return evidence_id

        for item in output.get("resources", []):
            if not isinstance(item.get("type"), str) or not TYPE_NAME.fullmatch(item["type"]) or \
                    not isinstance(item.get("name"), str) or not item["name"].strip():
                self.rejected.append({"kind": "resource", "item": item, "reason": "invalid type or name"})
                continue
            if evidence(item, "resource") is None:
                continue
            key = (item["type"], item["name"])
            resource = resources.get(key)
            if resource is None:
                resource = {"id": f"res-{len(resources) + 1}", "type": item["type"], "name": item["name"],
                            "scope": scope.copy(), "fields": []}
                resources[key] = resource
                data["resources"].append(resource)
            for prop in item.get("properties", []):
                name = prop.get("name")
                if not isinstance(name, str) or (name != '@Template' and not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", name)):
                    self.rejected.append({"kind": "property", "item": prop, "reason": "invalid property name"})
                    continue
                try:
                    value = json.loads(prop.get("value_json", ""))
                except (TypeError, ValueError):
                    self.rejected.append({"kind": "property", "item": prop, "reason": "value is not JSON"})
                    continue
                evidence_id = evidence(prop, "property")
                if evidence_id is None:
                    continue
                if name == '@Template':
                    try:
                        merge_template(resource, value, evidence_id)
                    except ValueError:
                        self.rejected.append({'kind': 'property', 'item': prop, 'reason': 'invalid template context'})
                    continue
                path = "/properties/" + name
                references = list(typed_references(value, path))
                if references:
                    for source_path, target_type, target_name in references:
                        data["relations"].append({
                            "id": f"rel-{len(data['relations']) + 1}",
                            "source_resource_id": resource["id"], "source_path": source_path,
                            "unresolved_name": target_name, "expected_target_type": target_type,
                            "evidence_ids": [evidence_id]})
                    if isinstance(value, str) or (isinstance(value, list) and all(
                            isinstance(v, str) and TYPED_REFERENCE.fullmatch(v) for v in value)):
                        continue
                field = next((f for f in resource["fields"] if f["path"] == path), None)
                if field is None:
                    field = {"path": path, "state": "MISSING", "candidates": []}
                    resource["fields"].append(field)
                counters["candidate"] += 1
                field["candidates"].append({"id": f"cand-{counters['candidate']}",
                                            "raw": prop["value_json"], "value": value,
                                            "evidence_ids": [evidence_id]})
                distinct = {json.dumps(c["value"], sort_keys=True) for c in field["candidates"]}
                if len(distinct) > 1:
                    field["state"] = "CONFLICT"
                    field.pop("selected_candidate_id", None)
                else:
                    field["state"] = "KNOWN"
                    field["selected_candidate_id"] = field["candidates"][0]["id"]
        for relation in data["relations"]:
            target = resources.get((relation["expected_target_type"], relation["unresolved_name"]))
            if target:
                relation["target_resource_id"] = target["id"]
        ids = set()
        for item in output.get("requirements", []):
            identifier, description = item.get("id"), item.get("description")
            if not isinstance(identifier, str) or not identifier.strip() or identifier in ids or \
                    not isinstance(description, str) or not description.strip():
                self.rejected.append({"kind": "requirement", "item": item, "reason": "invalid or duplicate id"})
                continue
            evidence_id = evidence(item, "requirement")
            if evidence_id is None:
                continue
            ids.add(identifier)
            data["requirements"].append({"id": identifier, "description": description,
                                         "evidence_ids": [evidence_id]})
        for document in data["documents"]:
            document["extracted_ranges"] = [list(pair) for pair in
                                            sorted({tuple(pair) for pair in document["extracted_ranges"]})]
        if self.reference_catalog:
            LineExtractor(self.reference_catalog)._link_names(data, resources)
        if any(r.get('template') for r in data['resources']):
            data['extractor_version'] = 'llm-v2'
        return Design.model_validate(data)
