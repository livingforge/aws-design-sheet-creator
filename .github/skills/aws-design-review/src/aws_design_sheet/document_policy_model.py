"""Small, explicitly sourced project policy declarations; never AWS-wide rules."""
import json
import re
from typing import Literal

from pydantic import Field, JsonValue, field_validator, model_validator

from .models import StrictModel


class PolicyConfigurationError(Exception):
    """Only a fixed code is safe to log; never include a declaration's values."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def path_parts(path):
    if (not path.startswith('/properties/') or len(path) > 512 or
            len(path.split('/')) > 18 or re.search(r'~(?![01])', path)):
        raise ValueError('invalid policy pointer')
    parts = [p.replace('~1', '/').replace('~0', '~') for p in path.split('/')[2:]]
    if any(not p or ('*' in p and p != '*') for p in parts):
        raise ValueError('invalid policy selector')
    if any(p.isdigit() and (not re.fullmatch(r'[0-9]+', p) or len(p) > 1 and p.startswith('0')) for p in parts):
        raise ValueError('policy indices require canonical ASCII integers')
    return parts


class PolicyPredicate(StrictModel):
    path: str
    operator: Literal['EQUALS', 'IN'] = 'EQUALS'
    values: list[JsonValue] = Field(min_length=1, max_length=64)

    @field_validator('path')
    @classmethod
    def valid_path(cls, value):
        path_parts(value)
        return value

    @model_validator(mode='after')
    def scalar_expectations(self):
        if self.operator == 'EQUALS' and len(self.values) != 1:
            raise ValueError('EQUALS requires one value')
        if any(isinstance(v, (dict, list)) or isinstance(v, str) and len(v) > 256 for v in self.values):
            raise ValueError('policy expectations must be bounded JSON scalars')
        keys = [json.dumps(v, sort_keys=True) for v in self.values]
        if len(keys) != len(set(keys)):
            raise ValueError('duplicate allowed value')
        return self


class ProjectPolicy(PolicyPredicate):
    id: str = Field(pattern=r'^[a-z][a-z0-9_-]{0,63}$')
    requirement_id: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    environments: list[str] = Field(min_length=1, max_length=64)
    sources: list[str] = Field(min_length=1, max_length=64)
    rationale: str = Field(min_length=1, max_length=2000)
    confirmation: Literal['CONFIRMED', 'UNCONFIRMED'] = 'UNCONFIRMED'
    # All predicates must hold. Selectors containing * mean every array member,
    # with an empty or unresolved selection requiring review, never vacuous PASS.
    when: list[PolicyPredicate] = Field(default_factory=list, max_length=16)

    @field_validator('rationale')
    @classmethod
    def nonblank(cls, value):
        if not value.strip(): raise ValueError('policy rationale is required')
        return value


class PolicyException(StrictModel):
    id: str = Field(pattern=r'^[a-z][a-z0-9_-]{0,63}$')
    policy_id: str
    # Resource/requirement are inherited from exactly this policy. Paths must be
    # concrete members of its selector; no wildcard or all-environments waiver.
    paths: list[str] = Field(min_length=1, max_length=128)
    environments: list[str] = Field(min_length=1, max_length=64)
    sources: list[str] = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=2000)
    confirmation: Literal['CONFIRMED', 'UNCONFIRMED'] = 'UNCONFIRMED'

    @model_validator(mode='after')
    def explicit_scope(self):
        if not self.reason.strip(): raise ValueError('exception reason is required')
        for path in self.paths:
            if '*' in path_parts(path): raise ValueError('exception requires concrete paths')
        return self


def selector_matches(selector, concrete):
    wanted, actual = path_parts(selector), path_parts(concrete)
    return len(wanted) == len(actual) and all(a == b or a == '*' and b.isdigit() for a, b in zip(wanted, actual))


def validate_policies(spec):
    if not spec.project_policies and not spec.policy_exceptions: return
    from .document_catalog import catalog
    from .document_normalize import secret_literal
    from .document_v11 import sensitive
    cat = catalog()
    resources = {r.id: r for r in spec.resources}
    requirements = {r.id for r in spec.requirements}
    sources = {s.id for s in spec.sources}
    environments = {e.id for e in spec.environments}

    def fail(code): raise PolicyConfigurationError(code)
    def unique(values): return len(values) == len(set(values))
    rules = {r.id: r for r in spec.project_policies}
    declarations = [*spec.project_policies, *spec.policy_exceptions]
    existing = {x.id for x in [spec.system, *spec.resources, *spec.requirements, *spec.sources,
                               *spec.environments, *spec.connections, *spec.operations, *spec.issues, *spec.required_inputs]}
    if not unique([r.id for r in declarations]) or existing & {r.id for r in declarations}: fail('DUPLICATE_POLICY_ID')

    def check_path(resource, predicate):
        parts = path_parts(predicate.path)
        typed = [int(p) if p.isdigit() else p for p in parts]
        if cat.readonly(resource.type, typed) or not cat.at(resource.type, typed): fail('UNKNOWN_POLICY_PATH')
        # * is for arrays only; never silently enumerate dynamic object keys.
        for i, part in enumerate(typed):
            if part == '*' and not any('array' in ([b.get('type')] if isinstance(b.get('type'), str) else b.get('type', []))
                                      for node in cat.at(resource.type, typed[:i]) for b in cat.branches(resource.type, node)):
                fail('WILDCARD_REQUIRES_ARRAY')
        if sensitive(resource.type, typed) or secret_literal(predicate.values): fail('SECRET_POLICY_EXPECTATION')

    for rule in spec.project_policies:
        if rule.resource_id not in resources or rule.requirement_id not in requirements: fail('UNKNOWN_POLICY_TARGET')
        if set(rule.environments) - environments or set(rule.sources) - sources: fail('UNKNOWN_POLICY_SCOPE_OR_SOURCE')
        if not unique(rule.environments) or not unique(rule.sources): fail('DUPLICATE_POLICY_SCOPE_OR_SOURCE')
        for predicate in [rule, *rule.when]:
            resource = resources[rule.resource_id]
            check_path(resource, predicate)
            # A string comparison against a declared secret could itself contain
            # a credential. Reject it before normalized input/report serialization.
            if any(isinstance(v, str) for v in predicate.values):
                from .document_policy import Node, decision, select
                for env in spec.environments:
                    if env.id not in rule.environments: continue
                    override = next((o.settings for o in env.overrides if o.resource_id == resource.id), {})
                    values = {k: decision(v, '') for k, v in {**resource.settings, **override}.items()}
                    try: selected = select(Node(values, 'VALUE', '', []), predicate.path)
                    except ValueError: fail('POLICY_SELECTOR_LIMIT')
                    if any(n.state == 'SECRET_REFERENCE' for _, n in selected):
                        fail('SECRET_POLICY_EXPECTATION')
    used = set()
    for exception in spec.policy_exceptions:
        rule = rules.get(exception.policy_id)
        if rule is None: fail('UNKNOWN_EXCEPTION_POLICY')
        if set(exception.sources) - sources or set(exception.environments) - set(rule.environments): fail('INVALID_EXCEPTION_SCOPE_OR_SOURCE')
        if not unique(exception.sources) or not unique(exception.environments) or not unique(exception.paths): fail('DUPLICATE_EXCEPTION_SCOPE')
        for path in exception.paths:
            if not selector_matches(rule.path, path): fail('EXCEPTION_OUTSIDE_POLICY_SELECTOR')
            check_path(resources[rule.resource_id], PolicyPredicate(path=path, values=rule.values, operator=rule.operator))
            for env in exception.environments:
                key = (rule.id, path, env)
                if key in used: fail('OVERLAPPING_POLICY_EXCEPTIONS')
                used.add(key)


class PolicyEvaluation(StrictModel):
    version: str = '1.0'
    status: Literal['NOT_REGISTERED', 'COMPLETE', 'FAILED'] = 'NOT_REGISTERED'
    assessment: Literal['NOT_EVALUATED', 'COMPLIANT_WITHIN_DECLARED_SCOPE', 'NONCOMPLIANT',
                        'REVIEW', 'NO_APPLICABLE_RULES', 'ERROR'] = 'NOT_EVALUATED'
    summary: dict = Field(default_factory=dict)
    rows: list[dict] = Field(default_factory=list)
    requirement_coverage: list[dict] = Field(default_factory=list)
    provenance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
