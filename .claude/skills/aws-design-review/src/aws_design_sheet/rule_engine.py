"""Evaluator for single-resource declarative design rules.

A rule reads design values by JSON Pointer. A pointer resolves to one of three
states: a known value, a definite absence (the field or key is not specified),
or an unknown value (unresolved, conflicting or inferred). Assertions never
turn an unknown value into PASS or FAIL.
"""
from __future__ import annotations

import json
import re
from decimal import Decimal, InvalidOperation
from dataclasses import dataclass, field as dataclass_field
from typing import Any

from .extractor import TYPED_REFERENCE
from .models import Candidate, FieldValue, Resource, ValueState


TYPE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9]*::[A-Za-z][A-Za-z0-9]*::[A-Za-z][A-Za-z0-9]*$")
RULE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*$")
POINTER_TOKEN = re.compile(r"^(?:[^~/]|~[01])+$")
UNKNOWN = object()
ABSENT = object()
VERDICTS = {"PASS", "FAIL", "NEEDS_REVIEW", "NOT_APPLICABLE"}
COMPARISONS = {"lt": lambda a, b: a < b, "le": lambda a, b: a <= b,
               "gt": lambda a, b: a > b, "ge": lambda a, b: a >= b,
               "eq": lambda a, b: a == b, "ne": lambda a, b: a != b}


@dataclass(frozen=True)
class Rule:
    id: str
    version: str
    source_type: str
    when: dict[str, Any]
    assertion: dict[str, Any]
    severity: str = "ERROR"
    authority: str | None = None
    source_urls: tuple[str, ...] = ()
    source_checked_at: str | None = None
    scope: str | None = None
    basis: tuple[dict[str, str], ...] = ()
    examples: tuple[dict[str, Any], ...] = dataclass_field(default=(), compare=False)


def _object(raw: Any, allowed: set[str], required: set[str], label: str) -> dict:
    if not isinstance(raw, dict) or set(raw) - allowed or required - set(raw):
        raise ValueError(f"invalid {label} keys")
    return raw


def _tokens(raw: str) -> list[str]:
    return [token.replace("~1", "/").replace("~0", "~") for token in raw.split("/")[1:]]


def _path(raw: Any, *, relative: bool = False, wildcard: bool = False) -> str:
    """Validate a pointer. In a scoped rule, "$/properties/..." addresses the resource root."""
    if relative and isinstance(raw, str) and raw.startswith("$/"):
        _path(raw[1:])
        return raw
    if not isinstance(raw, str) or not raw.startswith("/"):
        raise ValueError(f"invalid property JSON Pointer: {raw!r}")
    tokens = raw.split("/")[1:] if relative else raw.split("/")[2:]
    if (not relative and not raw.startswith("/properties/")) or not tokens or not all(
            POINTER_TOKEN.fullmatch(token) and (wildcard or token != "*") for token in tokens):
        raise ValueError(f"invalid property JSON Pointer: {raw!r}")
    return raw


def _json_value(raw: Any) -> Any:
    def valid(value: Any) -> bool:
        if value is None or type(value) in (str, bool, int):
            return True
        if type(value) is float:
            try:
                json.dumps(value, allow_nan=False)
                return True
            except ValueError:
                return False
        if type(value) is list:
            return all(valid(item) for item in value)
        if type(value) is dict:
            return all(type(key) is str and valid(item) for key, item in value.items())
        return False

    if not valid(raw):
        raise ValueError("equals must be a JSON value")
    return raw


def _values(raw: Any) -> list:
    if not isinstance(raw, list) or not raw:
        raise ValueError("values must be a nonempty array")
    return [_json_value(item) for item in raw]


def _operand(raw: Any, relative: bool) -> Any:
    if isinstance(raw, dict):
        body = _object(raw, {"path", "value"}, set(), "comparison operand")
        if len(body) != 1:
            raise ValueError("comparison operand needs path or value")
        if "path" in body:
            _path(body["path"], relative=relative)
        elif type(body["value"]) not in (int, float) or type(body["value"]) is bool:
            raise ValueError("comparison value must be a number")
        return body
    raise ValueError("comparison operand must be an object")


def _condition(raw: Any, relative: bool) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("when must be an object")
    op = raw.get("op")
    if op == "always":
        return _object(raw, {"op"}, {"op"}, "when")
    if op == "field_equals":
        result = _object(raw, {"op", "path", "equals"}, {"op", "path", "equals"}, "when")
        _path(result["path"], relative=relative)
        _json_value(result["equals"])
        return result
    if op == "field_in":
        result = _object(raw, {"op", "path", "values"}, {"op", "path", "values"}, "when")
        _path(result["path"], relative=relative)
        _values(result["values"])
        return result
    if op == "field_present":
        result = _object(raw, {"op", "path"}, {"op", "path"}, "when")
        _path(result["path"], relative=relative)
        return result
    if op == "field_contains":
        result = _object(raw, {"op", "path", "value"}, {"op", "path", "value"}, "when")
        _path(result["path"], relative=relative)
        _json_value(result["value"])
        return result
    if op == "field_matches":
        result = _object(raw, {"op", "path", "pattern"}, {"op", "path", "pattern"}, "when")
        _path(result["path"], relative=relative)
        if not isinstance(result["pattern"], str) or not result["pattern"]:
            raise ValueError("pattern must be a nonempty string")
        re.compile(result["pattern"])
        return result
    if op in ("all_of", "any_of"):
        result = _object(raw, {"op", "conditions"}, {"op", "conditions"}, "when")
        if not isinstance(result["conditions"], list) or len(result["conditions"]) < 2:
            raise ValueError(f"{op} needs at least two conditions")
        for item in result["conditions"]:
            if isinstance(item, dict) and item.get("op") == "always":
                raise ValueError("always cannot be combined")
            _condition(item, relative)
        return result
    if op == "not":
        result = _object(raw, {"op", "condition"}, {"op", "condition"}, "when")
        if isinstance(result["condition"], dict) and result["condition"].get("op") == "always":
            raise ValueError("always cannot be negated")
        _condition(result["condition"], relative)
        return result
    raise ValueError(f"unknown when operator: {op!r}")


def _assertion(raw: Any, relative: bool) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("assert must be an object")
    op = raw.get("op")
    if op == "field_equals":
        result = _object(raw, {"op", "path", "equals"}, {"op", "path", "equals"}, "assert")
        _path(result["path"], relative=relative)
        _json_value(result["equals"])
        return result
    if op in ("required", "present", "absent"):
        result = _object(raw, {"op", "path"}, {"op", "path"}, "assert")
        _path(result["path"], relative=relative)
        return result
    if op in ("cardinality", "count_present"):
        target = "path" if op == "cardinality" else "paths"
        result = _object(raw, {"op", target, "min", "max"}, {"op", target}, "assert")
        if op == "cardinality":
            _path(result["path"], relative=relative)
        else:
            paths = result["paths"]
            if not isinstance(paths, list) or len(paths) < 2 or len(set(paths)) != len(paths):
                raise ValueError("count_present needs at least two distinct paths")
            for path in paths:
                _path(path, relative=relative)
        if "min" not in result and "max" not in result:
            raise ValueError(f"{op} needs min or max")
        for key in ("min", "max"):
            if key in result and (type(result[key]) is not int or result[key] < 0):
                raise ValueError(f"{op} {key} must be a nonnegative integer")
        if "min" in result and "max" in result and result["min"] > result["max"]:
            raise ValueError(f"{op} min exceeds max")
        return result
    if op in ("count_items_equal", "count_items_present"):
        allowed = {"op", "path", "item_path", "min", "max"}
        required = {"op", "path", "item_path"}
        if op == "count_items_equal":
            allowed.add("equals")
            required.add("equals")
        result = _object(raw, allowed, required, "assert")
        _path(result["path"], relative=relative)
        _path(result["item_path"], relative=True)
        if op == "count_items_equal":
            _json_value(result["equals"])
        if "min" not in result and "max" not in result:
            raise ValueError(f"{op} needs min or max")
        for key in ("min", "max"):
            if key in result and (type(result[key]) is not int or result[key] < 0):
                raise ValueError(f"{op} {key} must be a nonnegative integer")
        if "min" in result and "max" in result and result["min"] > result["max"]:
            raise ValueError(f"{op} min exceeds max")
        return result
    if op == "items_same":
        result = _object(raw, {"op", "path", "item_path"}, {"op", "path", "item_path"}, "assert")
        _path(result["path"], relative=relative)
        _path(result["item_path"], relative=True)
        return result
    if op in ("value_in", "items_in"):
        result = _object(raw, {"op", "path", "values"}, {"op", "path", "values"}, "assert")
        _path(result["path"], relative=relative)
        _values(result["values"])
        return result
    if op == "unique":
        result = _object(raw, {"op", "path", "key"}, {"op", "path"}, "assert")
        _path(result["path"], relative=relative)
        if "key" in result:
            _path(result["key"], relative=True)
        return result
    if op in ("matches", "items_match", "map_values_match"):
        result = _object(raw, {"op", "path", "pattern"}, {"op", "path", "pattern"}, "assert")
        _path(result["path"], relative=relative)
        if not isinstance(result["pattern"], str) or not result["pattern"]:
            raise ValueError("pattern must be a nonempty string")
        re.compile(result["pattern"])
        return result
    if op == "map_keys_match":
        result = _object(raw, {"op", "path", "pattern"}, {"op", "path", "pattern"}, "assert")
        _path(result["path"], relative=relative)
        if not isinstance(result["pattern"], str) or not result["pattern"]:
            raise ValueError("pattern must be a nonempty string")
        re.compile(result["pattern"])
        return result
    if op == "items_in_map_keys":
        result = _object(raw, {"op", "path", "map_path"}, {"op", "path", "map_path"}, "assert")
        _path(result["path"], relative=relative)
        _path(result["map_path"], relative=relative)
        return result
    if op == "compare":
        result = _object(raw, {"op", "left", "cmp", "right"}, {"op", "left", "cmp", "right"}, "assert")
        left = _operand(result["left"], relative)
        _operand(result["right"], relative)
        if "path" not in left:
            raise ValueError("comparison left operand must be a path")
        if result["cmp"] not in COMPARISONS:
            raise ValueError("invalid comparison operator")
        return result
    if op == "compare_scaled":
        result = _object(raw, {"op", "left", "cmp", "right", "factor"},
                         {"op", "left", "cmp", "right", "factor"}, "assert")
        _path(result["left"], relative=relative)
        _path(result["right"], relative=relative)
        if result["cmp"] not in COMPARISONS:
            raise ValueError("invalid comparison operator")
        factor = result["factor"]
        if type(factor) not in (int, float, str):
            raise ValueError("compare_scaled factor must be a finite nonnegative number")
        try:
            parsed = Decimal(str(factor))
        except InvalidOperation as exc:
            raise ValueError("compare_scaled factor must be a finite nonnegative number") from exc
        if not parsed.is_finite() or parsed < 0:
            raise ValueError("compare_scaled factor must be a finite nonnegative number")
        return result
    if op == "multiple_of":
        result = _object(raw, {"op", "path", "divisor"}, {"op", "path", "divisor"}, "assert")
        _path(result["path"], relative=relative)
        divisor = _decimal_number(result["divisor"])
        if divisor is None or divisor <= 0:
            raise ValueError("multiple_of divisor must be a finite positive number")
        return result
    raise ValueError(f"unknown assert operator: {op!r}")


def _basis(raw: Any) -> tuple[dict[str, str], ...]:
    if not isinstance(raw, list) or not raw:
        raise ValueError("basis must be a nonempty array")
    result = []
    for item in raw:
        body = _object(item, {"pointer", "quote", "url"}, {"quote"}, "basis")
        if not isinstance(body["quote"], str) or not body["quote"].strip():
            raise ValueError("basis quote must be a nonempty string")
        if ("pointer" in body) == ("url" in body):
            raise ValueError("basis needs exactly one of pointer or url")
        location = body.get("pointer", body.get("url"))
        if not isinstance(location, str) or not location:
            raise ValueError("basis location must be a nonempty string")
        if "pointer" in body and not location.startswith("/"):
            raise ValueError("basis pointer must be a schema JSON Pointer")
        result.append(dict(body))
    return tuple(result)


def _examples(raw: Any) -> tuple[dict[str, Any], ...]:
    if not isinstance(raw, list) or not raw:
        raise ValueError("examples must be a nonempty array")
    result = []
    for item in raw:
        body = _object(item, {"fields", "verdict", "note"}, {"fields", "verdict"}, "example")
        if body["verdict"] not in VERDICTS:
            raise ValueError("invalid example verdict")
        if not isinstance(body["fields"], dict):
            raise ValueError("example fields must be an object")
        for path, value in body["fields"].items():
            _path(path)
            if len(path.split("/")) != 3:
                raise ValueError("example fields must be top-level properties")
            if isinstance(value, dict) and "$state" in value:
                _object(value, {"$state"}, {"$state"}, "example state")
                if value["$state"] not in ("MISSING", "UNRESOLVED", "CONFLICT", "INFERRED", "NOT_APPLICABLE"):
                    raise ValueError("invalid example state")
            else:
                _json_value(value)
        result.append(dict(body))
    return tuple(result)


def load_ruleset(raw: Any) -> tuple[Rule, ...]:
    """Validate a JSON-decoded rule set. Unknown keys and operators are errors."""
    body = _object(raw, {"ruleset_version", "rules"}, {"ruleset_version", "rules"}, "ruleset")
    if not isinstance(body["ruleset_version"], str) or not body["ruleset_version"]:
        raise ValueError("ruleset_version must be a nonempty string")
    if not isinstance(body["rules"], list):
        raise ValueError("rules must be an array")
    result: list[Rule] = []
    ids: set[str] = set()
    for item in body["rules"]:
        rule = _object(item, {"id", "version", "source_type", "when", "assert", "severity",
                              "authority", "source_urls", "source_checked_at", "description",
                              "dependencies", "scope", "basis", "examples"},
                       {"id", "version", "source_type", "when", "assert"}, "rule")
        if not isinstance(rule["id"], str) or not RULE_ID.fullmatch(rule["id"]):
            raise ValueError("invalid rule id")
        if rule["id"] in ids:
            raise ValueError(f"duplicate rule id: {rule['id']}")
        ids.add(rule["id"])
        if not isinstance(rule["version"], str) or not rule["version"]:
            raise ValueError("version must be a nonempty string")
        if not isinstance(rule["source_type"], str) or not TYPE_NAME.fullmatch(rule["source_type"]):
            raise ValueError("invalid source_type")
        severity = rule.get("severity", "ERROR")
        if severity not in ("ERROR", "WARNING", "INFO"):
            raise ValueError("invalid severity")
        if "authority" in rule and rule["authority"] not in ("AWS_SPEC", "PROJECT_POLICY"):
            raise ValueError("invalid authority")
        if "source_urls" in rule and (not isinstance(rule["source_urls"], list) or
                any(not isinstance(url, str) or not url for url in rule["source_urls"])):
            raise ValueError("source_urls must be an array of strings")
        for key in ("source_checked_at", "description"):
            if key in rule and (not isinstance(rule[key], str) or not rule[key]):
                raise ValueError(f"{key} must be a nonempty string")
        scope = rule.get("scope")
        if scope is not None:
            _path(scope, wildcard=True)
        relative = scope is not None
        if "dependencies" in rule:
            if not isinstance(rule["dependencies"], list):
                raise ValueError("dependencies must be an array")
            for dependency in rule["dependencies"]:
                _path(dependency)
        result.append(Rule(rule["id"], rule["version"], rule["source_type"],
                           _condition(rule["when"], relative),
                           _assertion(rule["assert"], relative), severity,
                           rule.get("authority"), tuple(rule.get("source_urls", ())),
                           rule.get("source_checked_at"), scope,
                           _basis(rule["basis"]) if "basis" in rule else (),
                           _examples(rule["examples"]) if "examples" in rule else ()))
    return tuple(result)


def _evidence(field: FieldValue | None) -> list[str]:
    if field is None:
        return []
    return list(dict.fromkeys([*field.intent_evidence_ids,
                               *(e for candidate in field.candidates for e in candidate.evidence_ids)]))


def _nested_state(value: Any) -> Any:
    """Interpret reserved state markers in nested example/design values."""
    if isinstance(value, dict) and set(value) == {"$state"}:
        if value["$state"] in ("MISSING", "NOT_APPLICABLE"):
            return ABSENT
        return UNKNOWN
    return value


class _Context:
    """Where relative pointers resolve: the resource, or one known object inside it."""

    def __init__(self, resource: Resource, base: str = "", value: Any = None,
                 field: FieldValue | None = None):
        self.resource = resource
        self.base = base
        self.value = value
        self.field = field

    def absolute(self, path: str) -> str:
        return path[1:] if path.startswith("$/") else self.base + path

    def lookup(self, path: str) -> tuple[Any, FieldValue | None]:
        """Return (value | ABSENT | UNKNOWN, owning field)."""
        if path.startswith("$/"):
            return _Context(self.resource).lookup(path[1:])
        if not self.base:
            field = self.resource.field(path)
            if field is not None:
                return _nested_state(_state(field)), field
            tokens = _tokens(path)[1:]
            field = self.resource.field("/properties/" + tokens[0].replace("~", "~0").replace("/", "~1"))
            value = _state(field)
            tokens = tokens[1:]
        else:
            field, value, tokens = self.field, self.value, _tokens(path)
        for token in tokens:
            value = _nested_state(value)
            if value is UNKNOWN or value is ABSENT:
                return value, field
            if isinstance(value, dict):
                value = value[token] if token in value else ABSENT
            elif isinstance(value, list):
                value = (value[int(token)] if token.isdigit() and int(token) < len(value)
                         else ABSENT)
            elif value is None:
                value = ABSENT
            else:
                return UNKNOWN, field
        return _nested_state(value), field


def _insert_reference(node: Any, tokens: list[str], leaf: Any) -> Any:
    if not tokens:
        return leaf
    if isinstance(node, dict) and set(node) == {"$state"}:
        node = None
    token = tokens[0]
    if token.isdigit():
        items = list(node) if isinstance(node, list) else []
        index = int(token)
        items.extend({"$state": "UNRESOLVED"} for _ in range(index + 1 - len(items)))
        items[index] = _insert_reference(items[index], tokens[1:], leaf)
        return items
    mapping = dict(node) if isinstance(node, dict) else {}
    mapping[token] = _insert_reference(mapping.get(token), tokens[1:], leaf)
    return mapping


def reference_view(resource: Resource, relations: list, types: dict[str, str]) -> Resource:
    """Return the resource with reference-only properties shown as typed references.

    A property given only as ``@Type/name`` is stored as a relation, not as a field.
    Rules must still see it as specified; its physical value stays unknown, so value
    checks on the reference string need review. ``types`` maps resource IDs to types.
    """
    values: dict[str, Any] = {}
    evidence: dict[str, list[str]] = {}
    seen: set[str] = set()
    for relation in relations:
        tokens = _tokens(relation.source_path)
        if len(tokens) < 2 or tokens[0] != "properties":
            continue
        top = "/properties/" + tokens[1].replace("~", "~0").replace("/", "~1")
        field = resource.field(top)
        if field is not None and field.state != ValueState.MISSING:
            continue
        target_type = relation.expected_target_type or types.get(relation.target_resource_id or "")
        name = relation.unresolved_name
        leaf = (f"@{target_type}/{name}" if target_type and name and not relation.condition
                and relation.source_path not in seen else {"$state": "UNRESOLVED"})
        seen.add(relation.source_path)
        values[top] = _insert_reference(values.get(top), tokens[2:], leaf)
        evidence.setdefault(top, []).extend(relation.evidence_ids)
    if not values:
        return resource
    fields = [field for field in resource.fields if field.path not in values]
    for top, value in values.items():
        candidate = Candidate(id="reference-" + top, raw=json.dumps(value, ensure_ascii=False),
                              value=value, evidence_ids=list(dict.fromkeys(evidence[top])) or ["reference"],
                              origin="reference")
        fields.append(FieldValue(path=top, state=ValueState.KNOWN, candidates=[candidate],
                                 selected_candidate_id=candidate.id))
    return resource.model_copy(update={"fields": fields})


def _state(field: FieldValue | None) -> Any:
    if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return ABSENT
    if field.state != ValueState.KNOWN:
        return UNKNOWN
    return field.selected().value


def _scopes(resource: Resource, scope: str) -> tuple[list[_Context], list[str], list[FieldValue]]:
    """Expand a scope pointer; return contexts, unresolved pointers and their fields."""
    tokens = _tokens(scope)[1:]
    top = "/properties/" + tokens[0].replace("~", "~0").replace("/", "~1")
    field = resource.field(top)
    frontier = [(top, _state(field))]
    for token in tokens[1:]:
        following = []
        for base, value in frontier:
            value = _nested_state(value)
            if value is ABSENT or value is None:
                continue
            if value is UNKNOWN:
                following.append((base, UNKNOWN))
            elif token == "*" and isinstance(value, list):
                following.extend((f"{base}/{index}", item) for index, item in enumerate(value))
            elif isinstance(value, dict) and token != "*":
                if token in value:
                    following.append((base + "/" + token.replace("~", "~0").replace("/", "~1"),
                                      value[token]))
            elif isinstance(value, list) and token.isdigit():
                if int(token) < len(value):
                    following.append((f"{base}/{token}", value[int(token)]))
            else:
                following.append((base, UNKNOWN))
        frontier = following
    contexts, unresolved = [], []
    for base, value in frontier:
        value = _nested_state(value)
        if value is UNKNOWN or not isinstance(value, dict):
            if value is not ABSENT and value is not None:
                unresolved.append(base)
        else:
            contexts.append(_Context(resource, base, value, field))
    return contexts, unresolved, [field] if field else []


def _equal(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, list):
        return len(left) == len(right) and all(_equal(a, b) for a, b in zip(left, right))
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_equal(left[key], right[key]) for key in left)
    return left == right


def _test(condition: dict, context: _Context, dependencies: list[str],
          fields: list[FieldValue]) -> bool | None:
    """Three-valued condition: True, False, or None when unresolved."""
    op = condition["op"]
    if op == "always":
        return True
    if op in ("all_of", "any_of"):
        outcomes = [_test(item, context, dependencies, fields) for item in condition["conditions"]]
        decisive = op == "any_of"
        if decisive in outcomes:
            return decisive
        return None if None in outcomes else not decisive
    if op == "not":
        outcome = _test(condition["condition"], context, dependencies, fields)
        return None if outcome is None else not outcome
    value, field = context.lookup(condition["path"])
    if field is not None:
        fields.append(field)
    if (op in ("field_equals", "field_in") and isinstance(value, str)
            and TYPED_REFERENCE.fullmatch(value)):
        value = UNKNOWN
    if value is UNKNOWN or (op == "field_equals" and value is ABSENT):
        dependencies.append(context.absolute(condition["path"]))
        return None
    if op == "field_equals":
        return _equal(value, condition["equals"])
    if op == "field_present":
        return value is not ABSENT
    if op == "field_contains":
        if value is ABSENT:
            return False
        if not isinstance(value, list):
            dependencies.append(context.absolute(condition["path"]))
            return None
        return any(_equal(item, condition["value"]) for item in value)
    if op == "field_matches":
        if value is ABSENT:
            return False
        if not isinstance(value, str) or TYPED_REFERENCE.fullmatch(value):
            dependencies.append(context.absolute(condition["path"]))
            return None
        return re.search(condition["pattern"], value) is not None
    return value is not ABSENT and any(_equal(value, item) for item in condition["values"])


def _number(value: Any) -> float | int | None:
    if type(value) in (int, float):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?\d+(?:\.\d+)?", value.strip()):
        return float(value) if "." in value else int(value)
    return None


def _decimal_number(value: Any) -> Decimal | None:
    if type(value) not in (int, float, str):
        return None
    try:
        result = Decimal(str(value).strip())
    except InvalidOperation:
        return None
    return result if result.is_finite() else None


def _check(assertion: dict, context: _Context) -> tuple[str, str, Any, Any, list[str], list[FieldValue]]:
    """Return verdict, reason, expected, actual, dependencies and fields read."""
    op = assertion["op"]
    fields: list[FieldValue] = []

    def read(path: str) -> Any:
        value, field = context.lookup(path)
        if field is not None:
            fields.append(field)
        return value

    if op == "items_in_map_keys":
        path, map_path = assertion["path"], assertion["map_path"]
        items = read(path)
        expected = read(map_path)
        if items is ABSENT:
            return "NOT_APPLICABLE", "array is not specified", map_path, None, [], fields
        if items is UNKNOWN or expected is UNKNOWN:
            pending = [context.absolute(p) for p, value in ((path, items), (map_path, expected))
                       if value is UNKNOWN]
            return "NEEDS_REVIEW", "array or map is unresolved", map_path, None, pending, fields
        if not isinstance(items, list):
            return "FAIL", "value is not an array", map_path, items, [], fields
        if not items:
            return "PASS", "array is empty", map_path, items, [], fields
        if expected is ABSENT:
            return "FAIL", "required map is not specified", map_path, items, [], fields
        if not isinstance(expected, dict):
            return "FAIL", "value is not a map", map_path, expected, [], fields
        outside = [item for item in items if not isinstance(item, str) or
                   (not TYPED_REFERENCE.fullmatch(item) and item not in expected)]
        if outside:
            return "FAIL", "array item is absent from map keys", map_path, outside, [], fields
        pending = [f"{context.absolute(path)}/{index}" for index, item in enumerate(items)
                   if TYPED_REFERENCE.fullmatch(item)]
        if pending:
            return "NEEDS_REVIEW", "array item is a resource reference", map_path, items, pending, fields
        return "PASS", "array items exist in map keys", map_path, items, [], fields
    if op == "count_present":
        values = {path: read(path) for path in assertion["paths"]}
        present = [path for path, value in values.items() if value not in (ABSENT, UNKNOWN)]
        unknown = [path for path, value in values.items() if value is UNKNOWN]
        expected = {key: assertion[key] for key in ("min", "max") if key in assertion}

        def valid(count: int) -> bool:
            return ("min" not in assertion or count >= assertion["min"]) and (
                "max" not in assertion or count <= assertion["max"])
        low, high = len(present), len(present) + len(unknown)
        actual = [context.absolute(path) for path in present]
        if all(valid(count) for count in range(low, high + 1)):
            return "PASS", "number of specified properties is in range", expected, actual, [], fields
        if not any(valid(count) for count in range(low, high + 1)):
            return "FAIL", "number of specified properties is out of range", expected, actual, [], fields
        return ("NEEDS_REVIEW", "specified properties depend on unresolved values", expected, actual,
                [context.absolute(path) for path in unknown], fields)
    if op in ("count_items_equal", "count_items_present"):
        path = assertion["path"]
        actual = read(path)
        absolute = context.absolute(path)
        expected = {key: assertion[key] for key in ("item_path", "equals", "min", "max")
                    if key in assertion}
        if actual is UNKNOWN:
            return "NEEDS_REVIEW", "array value is unresolved", expected, None, [absolute], fields
        if actual is ABSENT:
            return "NOT_APPLICABLE", "array is not specified", expected, None, [], fields
        if not isinstance(actual, list):
            return "FAIL", "value is not an array", expected, actual, [], fields
        matches = 0
        unknown = []
        for index, item in enumerate(actual):
            item_base = f"{absolute}/{index}"
            value = _Context(context.resource, item_base, item).lookup(assertion["item_path"])[0]
            if value is UNKNOWN or (isinstance(value, dict) and set(value) == {"$state"}):
                unknown.append(item_base + assertion["item_path"])
            elif value is not ABSENT and (op == "count_items_present" or _equal(value, assertion["equals"])):
                matches += 1
        def valid(count: int) -> bool:
            return ("min" not in assertion or count >= assertion["min"]) and (
                "max" not in assertion or count <= assertion["max"])
        verdicts = {valid(count) for count in range(matches, matches + len(unknown) + 1)}
        if verdicts == {True}:
            return "PASS", "matching item count is in range", expected, matches, [], fields
        if verdicts == {False}:
            return "FAIL", "matching item count is out of range", expected, matches, [], fields
        return "NEEDS_REVIEW", "matching item count depends on unresolved values", expected, matches, unknown, fields
    if op == "items_same":
        path = assertion["path"]
        actual = read(path)
        absolute = context.absolute(path)
        item_path = assertion["item_path"]
        if actual is UNKNOWN:
            return "NEEDS_REVIEW", "array value is unresolved", item_path, None, [absolute], fields
        if actual is ABSENT:
            return "NOT_APPLICABLE", "array is not specified", item_path, None, [], fields
        if not isinstance(actual, list):
            return "FAIL", "value is not an array", item_path, actual, [], fields
        known, pending = [], []
        missing = 0
        for index, item in enumerate(actual):
            item_base = f"{absolute}/{index}"
            value = _Context(context.resource, item_base, item).lookup(item_path)[0]
            if value is UNKNOWN or (isinstance(value, dict) and set(value) == {"$state"}):
                pending.append(item_base + item_path)
            elif value is not ABSENT:
                known.append(value)
            else:
                missing += 1
                pending.append(item_base + item_path)
        if not known and not actual:
            return "NOT_APPLICABLE", "array has no items", item_path, [], [], fields
        if missing == len(actual):
            return "NOT_APPLICABLE", "item property is not specified", item_path, None, [], fields
        if known and any(not _equal(value, known[0]) for value in known[1:]):
            return "FAIL", "array items specify different values", item_path, known, [], fields
        if pending:
            return "NEEDS_REVIEW", "some array item values are unresolved or missing", item_path, known, pending, fields
        return "PASS", "array items specify the same value", item_path, known, [], fields
    if op == "multiple_of":
        path = assertion["path"]
        actual = read(path)
        absolute = context.absolute(path)
        expected = {"multiple_of": assertion["divisor"]}
        if actual is ABSENT:
            return "NOT_APPLICABLE", "value is not specified", expected, None, [], fields
        if actual is UNKNOWN:
            return "NEEDS_REVIEW", "value is unresolved", expected, None, [absolute], fields
        number = _decimal_number(actual)
        if number is None:
            return "NEEDS_REVIEW", "value is not a finite number", expected, actual, [absolute], fields
        # Integer ratios avoid floating point tolerance and Decimal context rounding.
        numerator, denominator = number.as_integer_ratio()
        step_numerator, step_denominator = _decimal_number(assertion["divisor"]).as_integer_ratio()
        passed = (numerator * step_denominator) % (denominator * step_numerator) == 0
        return (("PASS", "value is a multiple of the required increment") if passed else
                ("FAIL", "value is not a multiple of the required increment")) + (
                    expected, actual, [], fields)
    if op == "compare":
        left = read(assertion["left"]["path"])
        right = read(assertion["right"]["path"]) if "path" in assertion["right"] else assertion["right"]["value"]
        expected = {"cmp": assertion["cmp"], "right": assertion["right"]}
        pending = [context.absolute(side["path"]) for side, value in
                   ((assertion["left"], left), (assertion["right"], right))
                   if "path" in side and value is UNKNOWN]
        if pending:
            return "NEEDS_REVIEW", "compared value is unresolved", expected, None, pending, fields
        if left is ABSENT or right is ABSENT:
            return "NOT_APPLICABLE", "compared value is not specified", expected, None, [], fields
        numbers = _number(left), _number(right)
        if None in numbers:
            return ("NEEDS_REVIEW", "compared value is not numeric", expected, [left, right],
                    [context.absolute(assertion["left"]["path"])], fields)
        passed = COMPARISONS[assertion["cmp"]](*numbers)
        return (("PASS", "comparison holds") if passed else ("FAIL", "comparison does not hold")) + (
            expected, [left, right], [], fields)
    if op == "compare_scaled":
        left = read(assertion["left"])
        right = read(assertion["right"])
        expected = {"cmp": assertion["cmp"], "right": assertion["right"],
                    "factor": assertion["factor"]}
        pending = [context.absolute(path) for path, value in
                   ((assertion["left"], left), (assertion["right"], right)) if value is UNKNOWN]
        if pending:
            return "NEEDS_REVIEW", "compared value is unresolved", expected, None, pending, fields
        if left is ABSENT or right is ABSENT:
            return "NOT_APPLICABLE", "compared value is not specified", expected, None, [], fields
        numbers = _decimal_number(left), _decimal_number(right)
        if None in numbers:
            dependencies = [context.absolute(path) for path, number in
                            ((assertion["left"], numbers[0]), (assertion["right"], numbers[1]))
                            if number is None]
            return "NEEDS_REVIEW", "compared value is not numeric", expected, [left, right], dependencies, fields
        passed = COMPARISONS[assertion["cmp"]](numbers[0], numbers[1] * Decimal(str(assertion["factor"])))
        return (("PASS", "scaled comparison holds") if passed else
                ("FAIL", "scaled comparison does not hold")) + (expected, [left, right], [], fields)

    path = assertion["path"]
    actual = read(path)
    absolute = context.absolute(path)
    if actual is UNKNOWN:
        return "NEEDS_REVIEW", "design value is unresolved", None, None, [absolute], fields
    if (op not in ("required", "present", "absent") and isinstance(actual, str)
            and TYPED_REFERENCE.fullmatch(actual)):
        # A reference is specified, but the physical value it resolves to is unknown.
        return "NEEDS_REVIEW", "value is a resource reference", None, actual, [absolute], fields
    if op == "required":
        if actual is ABSENT:
            return "NEEDS_REVIEW", "design value is unresolved", "known value", None, [absolute], fields
        return "PASS", "design value is present", "known value", actual, [], fields
    if op == "present":
        if actual is ABSENT:
            return "FAIL", "required value is not specified", "specified", None, [], fields
        return "PASS", "required value is specified", "specified", actual, [], fields
    if op == "absent":
        if actual is ABSENT:
            return "PASS", "value is not specified", "not specified", None, [], fields
        return "FAIL", "value must not be specified", "not specified", actual, [], fields
    if op == "field_equals":
        expected = assertion["equals"]
        if actual is ABSENT:
            return "NEEDS_REVIEW", "design value is unresolved", expected, None, [absolute], fields
        return (("PASS", "value matches") if _equal(actual, expected) else
                ("FAIL", "value differs")) + (expected, actual, [], fields)
    if op == "cardinality":
        expected = {key: assertion[key] for key in ("min", "max") if key in assertion}
        if actual is ABSENT:
            return "NEEDS_REVIEW", "array value is unresolved", expected, None, [absolute], fields
        if not isinstance(actual, list):
            return "FAIL", "value is not an array", expected, actual, [], fields
        count = len(actual)
        valid = ("min" not in assertion or count >= assertion["min"]) and (
            "max" not in assertion or count <= assertion["max"])
        return (("PASS", "array size is in range") if valid else
                ("FAIL", "array size is out of range")) + (expected, count, [], fields)
    if actual is ABSENT:
        return "NOT_APPLICABLE", "value is not specified", None, None, [], fields
    if op == "map_keys_match":
        expected = assertion["pattern"]
        if not isinstance(actual, dict):
            return "FAIL", "value is not a map", expected, actual, [], fields
        outside = [key for key in actual if not isinstance(key, str) or not re.fullmatch(expected, key)]
        return (("FAIL", "map has keys that do not match pattern") if outside else
                ("PASS", "all map keys match pattern")) + (expected, outside or list(actual), [], fields)
    if op == "map_values_match":
        expected = assertion["pattern"]
        if not isinstance(actual, dict):
            return "FAIL", "value is not a map", expected, actual, [], fields
        outside = {key: value for key, value in actual.items()
                   if not isinstance(value, str) or
                   (not TYPED_REFERENCE.fullmatch(value) and not re.fullmatch(expected, value))}
        pending = [absolute + "/" + key.replace("~", "~0").replace("/", "~1")
                   for key, value in actual.items()
                   if isinstance(value, str) and TYPED_REFERENCE.fullmatch(value)]
        if outside:
            return "FAIL", "map has values that do not match pattern", expected, outside, [], fields
        if pending:
            return "NEEDS_REVIEW", "map value is a resource reference", expected, actual, pending, fields
        return "PASS", "all map values match pattern", expected, actual, [], fields
    if op in ("unique", "items_in", "items_match"):
        if not isinstance(actual, list):
            return "FAIL", "value is not an array", None, actual, [], fields
        if op == "items_match":
            pattern = assertion["pattern"]
            outside = [item for item in actual if isinstance(item, str)
                       and not TYPED_REFERENCE.fullmatch(item) and not re.fullmatch(pattern, item)]
            outside.extend(item for item in actual if not isinstance(item, str)
                           and _nested_state(item) is not UNKNOWN)
            pending = [f"{absolute}/{index}" for index, item in enumerate(actual)
                       if _nested_state(item) is UNKNOWN or
                       (isinstance(item, str) and TYPED_REFERENCE.fullmatch(item))]
            if not outside and pending:
                return "NEEDS_REVIEW", "array item is a resource reference", pattern, actual, pending, fields
            return (("FAIL", "array has items that do not match pattern") if outside else
                    ("PASS", "all array items match pattern")) + (pattern, outside or actual, [], fields)
        if op == "items_in":
            expected = assertion["values"]
            outside = [item for item in actual if _nested_state(item) is not UNKNOWN
                       and not any(_equal(item, v) for v in expected)]
            pending = [f"{absolute}/{index}" for index, item in enumerate(actual)
                       if _nested_state(item) is UNKNOWN or
                       (isinstance(item, str) and TYPED_REFERENCE.fullmatch(item))]
            outside = [item for item in outside if not (
                isinstance(item, str) and TYPED_REFERENCE.fullmatch(item))]
            if not outside and pending:
                return "NEEDS_REVIEW", "array items are unresolved", expected, actual, pending, fields
            return (("FAIL", "array has items that are not allowed") if outside else
                    ("PASS", "all array items are allowed")) + (expected, outside or actual, [], fields)
        keys = []
        for item in actual:
            if "key" in assertion:
                value = _Context(context.resource, absolute + "/*", item, None).lookup(assertion["key"])[0]
                if value is ABSENT:
                    continue
                if value is UNKNOWN:
                    return ("NEEDS_REVIEW", "item key is unresolved", None, None, [absolute], fields)
            else:
                value = item
            keys.append(json.dumps(value, sort_keys=True))
        duplicates = sorted({key for key in keys if keys.count(key) > 1})
        return (("FAIL", "array items are not unique") if duplicates else
                ("PASS", "array items are unique")) + ("unique", duplicates or len(keys), [], fields)
    if op == "value_in":
        expected = assertion["values"]
        return (("PASS", "value is allowed") if any(_equal(actual, item) for item in expected) else
                ("FAIL", "value is not allowed")) + (expected, actual, [], fields)
    expected = assertion["pattern"]
    if not isinstance(actual, str):
        return "FAIL", "value is not a string", expected, actual, [], fields
    return (("PASS", "value matches pattern") if re.search(expected, actual) else
            ("FAIL", "value does not match pattern")) + (expected, actual, [], fields)


def _result(rule: Rule, resource: Resource, path: str, verdict: str, reason: str, *,
            expected: Any = None, actual: Any = None, evidence: list[str] | None = None,
            dependencies: list[str] | None = None) -> dict[str, Any]:
    return {"rule_id": rule.id, "rule_version": rule.version,
            "resource_id": resource.id, "path": path, "verdict": verdict,
            "severity": rule.severity, "expected": expected, "actual": actual,
            "reason": reason, "evidence_ids": evidence or [],
            "dependencies": list(dict.fromkeys(dependencies or [])),
            "authority": rule.authority, "source_urls": list(rule.source_urls),
            "source_checked_at": rule.source_checked_at}


def _target_path(assertion: dict) -> str:
    if "path" in assertion:
        return assertion["path"]
    if "paths" in assertion:
        return assertion["paths"][0]
    return assertion["left"]["path"] if isinstance(assertion["left"], dict) else assertion["left"]


def _evaluate(rule: Rule, context: _Context) -> dict[str, Any]:
    dependencies: list[str] = []
    fields: list[FieldValue] = []
    outcome = _test(rule.when, context, dependencies, fields)
    path = context.absolute(_target_path(rule.assertion))
    evidence = list(dict.fromkeys(e for field in fields for e in _evidence(field)))
    if outcome is None:
        return _result(rule, context.resource, path, "NEEDS_REVIEW", "condition value is unresolved",
                       evidence=evidence, dependencies=dependencies)
    if outcome is False:
        return _result(rule, context.resource, path, "NOT_APPLICABLE", "condition does not match")
    verdict, reason, expected, actual, dependencies, read = _check(rule.assertion, context)
    evidence = list(dict.fromkeys(e for field in [*fields, *read] for e in _evidence(field)))
    return _result(rule, context.resource, path, verdict, reason, expected=expected,
                   actual=actual, evidence=evidence, dependencies=dependencies)


def evaluate_rule_all(rule: Rule, resource: Resource) -> list[dict[str, Any]]:
    """Evaluate a rule, once per object matched by its scope when it has one."""
    if resource.type != rule.source_type:
        raise ValueError("resource type does not match rule source_type")
    if rule.scope is None:
        return [_evaluate(rule, _Context(resource))]
    contexts, unresolved, fields = _scopes(resource, rule.scope)
    results = [_evaluate(rule, context) for context in contexts]
    evidence = list(dict.fromkeys(e for field in fields for e in _evidence(field)))
    results.extend(_result(rule, resource, base, "NEEDS_REVIEW", "scope value is unresolved",
                           evidence=evidence, dependencies=[base]) for base in unresolved)
    if not results:
        results.append(_result(rule, resource, rule.scope, "NOT_APPLICABLE",
                               "no object matches the rule scope"))
    return results


def evaluate_rule(rule: Rule, resource: Resource) -> dict[str, Any]:
    """Evaluate one unscoped rule; a condition that cannot be resolved needs review."""
    if rule.scope is not None:
        raise ValueError("scoped rules produce several results; use evaluate_rule_all")
    return evaluate_rule_all(rule, resource)[0]


def example_resource(rule: Rule, example: dict[str, Any], scope: Any = None) -> Resource:
    """Build the resource described by one registered rule example."""
    from .models import Candidate, Scope

    fields = []
    for path, value in example["fields"].items():
        if isinstance(value, dict) and set(value) == {"$state"}:
            state = ValueState(value["$state"])
            candidates = ([Candidate(id=f"c{index}", raw=str(index), value=index, evidence_ids=["ex"])
                           for index in range(2)] if state in (ValueState.CONFLICT, ValueState.INFERRED)
                          else [])
            fields.append(FieldValue(path=path, state=state, candidates=candidates))
        else:
            fields.append(FieldValue(path=path, state=ValueState.KNOWN, selected_candidate_id="c",
                                     candidates=[Candidate(id="c", raw=json.dumps(value), value=value,
                                                           evidence_ids=["ex"])]))
    return Resource(id="example", type=rule.source_type, name="example",
                    scope=scope or Scope(environment="example", account="111111111111",
                                         region="ap-northeast-1"),
                    fields=fields)
