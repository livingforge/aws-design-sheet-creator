"""Versioned interchange contract. No implicit value coercion is performed."""
from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ValueState(StrEnum):
    KNOWN = "KNOWN"
    MISSING = "MISSING"
    INFERRED = "INFERRED"
    CONFLICT = "CONFLICT"
    UNRESOLVED = "UNRESOLVED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Evidence(StrictModel):
    id: str
    document_id: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    excerpt: str

    @model_validator(mode="after")
    def valid_range(self):
        if self.end_line < self.start_line:
            raise ValueError("end_line precedes start_line")
        return self


class Document(StrictModel):
    id: str
    name: str
    version: str
    sha256: str
    text: str
    extracted_ranges: list[list[int]] = Field(default_factory=list)

    @model_validator(mode="after")
    def valid_source(self):
        if hashlib.sha256(self.text.encode("utf-8")).hexdigest() != self.sha256:
            raise ValueError("document SHA-256 does not match text")
        line_count = len(self.text.splitlines())
        for pair in self.extracted_ranges:
            if len(pair) != 2 or not 1 <= pair[0] <= pair[1] <= line_count:
                raise ValueError("invalid extracted line range")
        return self


class Candidate(StrictModel):
    id: str
    raw: str
    value: Any
    evidence_ids: list[str] = Field(default_factory=list)
    origin: str = "extracted"


class FieldValue(StrictModel):
    path: str
    state: ValueState
    candidates: list[Candidate] = Field(default_factory=list)
    selected_candidate_id: str | None = None
    detail_ids: list[str] = Field(default_factory=list)
    default_intent: bool = False
    intent_evidence_ids: list[str] = Field(default_factory=list)

    @field_validator("state", mode="before")
    @classmethod
    def parse_state(cls, raw):
        return ValueState(raw) if isinstance(raw, str) else raw

    @model_validator(mode="after")
    def valid_state(self):
        if not self.path.startswith("/properties/") or len(self.path.split("/")) < 3:
            raise ValueError("field path must be a /properties JSON Pointer")
        ids = [c.id for c in self.candidates]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate candidate ID")
        if self.state == ValueState.KNOWN:
            if self.selected_candidate_id not in ids:
                raise ValueError("KNOWN requires a selected candidate")
            selected = next(c for c in self.candidates if c.id == self.selected_candidate_id)
            if not selected.evidence_ids:
                raise ValueError("KNOWN requires evidence")
        elif self.selected_candidate_id is not None:
            raise ValueError("only KNOWN can select a candidate")
        if self.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE) and self.candidates:
            raise ValueError("missing/non-applicable field cannot have candidates")
        if self.state in (ValueState.INFERRED, ValueState.CONFLICT) and not self.candidates:
            raise ValueError("inferred/conflicting field requires candidates")
        if self.state == ValueState.CONFLICT and len(self.candidates) < 2:
            raise ValueError("conflict requires at least two candidates")
        if self.default_intent and self.state == ValueState.KNOWN:
            raise ValueError("default intent cannot assert a resolved value")
        if self.default_intent and not self.intent_evidence_ids:
            raise ValueError("default intent requires evidence")
        return self

    def selected(self) -> Candidate | None:
        return next((c for c in self.candidates if c.id == self.selected_candidate_id), None)


class Scope(StrictModel):
    environment: str
    account: str
    region: str


class Resource(StrictModel):
    id: str
    type: str
    name: str
    scope: Scope
    fields: list[FieldValue] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_paths(self):
        paths = [f.path for f in self.fields]
        if len(paths) != len(set(paths)):
            raise ValueError("duplicate field path")
        return self

    def field(self, path: str) -> FieldValue | None:
        return next((f for f in self.fields if f.path == path), None)


class Relation(StrictModel):
    id: str
    source_resource_id: str
    source_path: str
    target_resource_id: str | None = None
    unresolved_name: str | None = None
    expected_target_type: str | None = None
    condition: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)


class Requirement(StrictModel):
    id: str
    description: str
    target_resource_id: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    rule_id: str | None = None


class Correction(StrictModel):
    target: str
    before: Any
    after: Any
    reason: str
    author: str
    source_run_id: str


class Design(StrictModel):
    model_version: str = "1.0"
    extractor_version: str | None = None
    project: str
    environment: str
    account: str
    region: str = "ap-northeast-1"
    documents: list[Document] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    resources: list[Resource] = Field(default_factory=list)
    relations: list[Relation] = Field(default_factory=list)
    requirements: list[Requirement] = Field(default_factory=list)
    corrections: list[Correction] = Field(default_factory=list)

    @field_validator("model_version")
    @classmethod
    def supported_version(cls, raw):
        if raw != "1.0":
            raise ValueError("unsupported model version")
        return raw

    @model_validator(mode="after")
    def valid_ids(self):
        for kind, values in (("document", self.documents), ("evidence", self.evidence),
                             ("resource", self.resources), ("relation", self.relations),
                             ("requirement", self.requirements)):
            ids = [value.id for value in values]
            if len(ids) != len(set(ids)):
                raise ValueError(f"duplicate {kind} ID")
        documents = {d.id for d in self.documents}
        document_lines = {d.id: d.text.splitlines() for d in self.documents}
        evidences = {e.id for e in self.evidence}
        for e in self.evidence:
            if e.document_id not in documents:
                raise ValueError(f"unknown document in evidence {e.id}")
            lines = document_lines[e.document_id]
            if e.end_line > len(lines) or e.excerpt not in "\n".join(lines[e.start_line - 1:e.end_line]):
                raise ValueError(f"evidence excerpt does not match source: {e.id}")
        for r in self.resources:
            for f in r.fields:
                if any(e not in evidences for e in f.intent_evidence_ids):
                    raise ValueError(f"unknown default intent evidence in {f.path}")
                for c in f.candidates:
                    if any(e not in evidences for e in c.evidence_ids):
                        raise ValueError(f"unknown evidence in candidate {c.id}")
        for relation in self.relations:
            if any(e not in evidences for e in relation.evidence_ids):
                raise ValueError(f"unknown evidence in relation {relation.id}")
        for requirement in self.requirements:
            if any(e not in evidences for e in requirement.evidence_ids):
                raise ValueError(f"unknown evidence in requirement {requirement.id}")
        return self
