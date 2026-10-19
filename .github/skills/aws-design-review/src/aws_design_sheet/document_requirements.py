"""Explicit project input requirements; no natural-language policy inference."""
from typing import Literal

from pydantic import Field

from .models import StrictModel


class InputRequirement(StrictModel):
    id: str = Field(pattern=r'^[a-z][a-z0-9_-]{0,63}$')
    requirement_id: str = Field(min_length=1)
    resource_id: str
    path: str = Field(pattern=r'^/properties/[^/]+(?:/[^/]+)*$')
    # JSON Schema predicate on this resource's effective properties. Unknown
    # keywords/values are deliberately not interpreted as a true condition.
    when: dict | None = None
    environments: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    confirmation: Literal['CONFIRMED', 'UNCONFIRMED'] = 'UNCONFIRMED'
    rationale: str = ''
    allow_documented_default: bool = False


def validate_requirements(spec):
    """Validate identities and writable paths without judging requirement prose."""
    from .document_catalog import catalog
    cat = catalog()
    resources = {r.id: r for r in spec.resources}
    sources = {s.id for s in spec.sources}
    requirements = {r.id for r in spec.requirements}
    environments = {e.id for e in spec.environments}
    ids = [r.id for r in spec.required_inputs]
    if len(ids) != len(set(ids)):
        raise ValueError('duplicate required-input ID')
    for req in spec.required_inputs:
        if req.resource_id not in resources or req.requirement_id not in requirements:
            raise ValueError('required-input resource or requirement is not declared')
        if set(req.sources) - sources or set(req.environments) - environments:
            raise ValueError('required-input source or environment is not declared')
        parts = [p.replace('~1', '/').replace('~0', '~') for p in req.path.split('/')[2:]]
        parts = [int(p) if p.isdigit() else p for p in parts]
        kind = resources[req.resource_id].type
        catalogs = ([catalog(getattr(resources[req.resource_id], 'region', None) or env.region)
                     for env in spec.environments] if spec.schema_version == '1.1' else [cat])
        if any(c.readonly(kind, parts) or not c.at(kind, parts) for c in catalogs):
            raise ValueError('required-input path is unknown or read-only')
        if req.when is not None:
            from jsonschema import Draft7Validator, SchemaError
            try:
                Draft7Validator.check_schema(req.when)
            except SchemaError as exc:
                raise ValueError('invalid requirement predicate schema') from exc
            # Existing secret detector is applied before any condition is stored
            # in generated artifacts. Predicates must never carry credentials.
            from .document_normalize import secret_literal
            from .document_v11 import sensitive
            def walk(node, path):
                if not isinstance(node, dict):
                    return
                if path and sensitive(kind, path) and any(k in node for k in ('const', 'enum', 'pattern')):
                    raise ValueError('secret predicates cannot contain literal expectations')
                for key, child in node.get('properties', {}).items():
                    walk(child, [*path, key])
                for key in ('allOf', 'anyOf', 'oneOf'):
                    for child in node.get(key, []): walk(child, path)
                for key in ('not', 'if', 'then', 'else'): walk(node.get(key), path)
            if secret_literal(req.when):
                raise ValueError('secret-like condition literal')
            walk(req.when, [])


class Checklist(StrictModel):
    version: str = '1.0'
    status: str = 'NOT_CHECKED'
    summary: dict = Field(default_factory=dict)
    rows: list[dict] = Field(default_factory=list)
    provenance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
