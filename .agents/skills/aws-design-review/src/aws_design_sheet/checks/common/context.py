"""Base check context: field values, dependencies, evidence and finding records."""
from __future__ import annotations

from ...models import ValueState


def _evidence(field: FieldValue | None) -> list[str]:
    if field is None:
        return []
    return [*field.intent_evidence_ids,
            *(item for candidate in field.candidates for item in candidate.evidence_ids)]


class Context:
    def __init__(self, design: Design, resource: Resource):
        self.design = design
        self.resource = resource
        self.by_id = {item.id: item for item in design.resources}
        self.evidence: list[str] = []
        self.dependencies: list[str] = []

    def value(self, resource: Resource, path: str) -> Any:
        field = resource.field(path)
        self.evidence.extend(_evidence(field))
        if field is None or field.state != ValueState.KNOWN:
            self.dependencies.append(f"{resource.id}{path}")
            return None
        return field.selected().value

    def target(self, source: Resource, path: str, expected_type: str) -> Resource | None:
        field = source.field(path)
        self.evidence.extend(_evidence(field))
        if field is not None and field.state not in (ValueState.KNOWN, ValueState.MISSING):
            self.dependencies.append(f"{source.id}{path}")
            return None
        refs = [ref for ref in self.design.relations
                if ref.source_resource_id == source.id and ref.source_path == path]
        self.evidence.extend(item for ref in refs for item in ref.evidence_ids)
        if len(refs) != 1:
            self.dependencies.append(f"{source.id}{path}")
            return None
        target = self.by_id.get(refs[0].target_resource_id)
        if target is None or target.type != expected_type or target.scope != source.scope:
            self.dependencies.append(f"{source.id}{path}")
            return None
        return target

    def finding(self, rule_id: str, path: str, verdict: str, reason: str) -> dict[str, Any]:
        return {"rule_id": rule_id, "resource_id": self.resource.id, "path": path,
                "verdict": verdict, "reason": reason,
                "dependencies": list(dict.fromkeys(self.dependencies)) if verdict == "NEEDS_REVIEW" else [],
                "evidence_ids": list(dict.fromkeys(self.evidence))}
