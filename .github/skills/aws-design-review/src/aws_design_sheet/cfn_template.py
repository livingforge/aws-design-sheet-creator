"""Convert a CloudFormation template into line notes for the line extractor.

Values are resolved only when deployment with parameter defaults determines
them: parameter defaults, scope pseudo parameters, conditions, Fn::FindInMap,
Fn::Sub, Fn::Join, Fn::Select, Fn::Split, Fn::Cidr (IPv4) and Fn::Base64.
Ref/Fn::GetAtt to a template resource becomes a typed reference. Any other
intrinsic is replaced by {"$state": "UNRESOLVED"}; no value is invented. A
property that is wholly unknown is stored as UNRESOLVED, and one with unknown
nested parts keeps the marker inside its known value. Resources the
unresolved expression refers to are added to the template dependency list,
because CloudFormation orders them the same way as DependsOn.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import re
from dataclasses import dataclass, field

import yaml

from .extractor import LineExtractor, TextSource
from .models import Design


UNRESOLVED = {"$state": "UNRESOLVED"}
TYPE = re.compile(r"^[A-Za-z][A-Za-z0-9]*::[A-Za-z][A-Za-z0-9]*::[A-Za-z][A-Za-z0-9]*$")
SUB_VARIABLE = re.compile(r"\$\{([^}]*)\}")
NUMBER_PARAMETER = "Number"
LIST_PARAMETERS = ("CommaDelimitedList", "List<")
SHORT_FORMS = ("Ref", "Condition", "Fn::Base64", "Fn::Cidr", "Fn::FindInMap", "Fn::GetAtt",
               "Fn::GetAZs", "Fn::ImportValue", "Fn::Join", "Fn::Select", "Fn::Split",
               "Fn::Sub", "Fn::Transform", "Fn::And", "Fn::Equals", "Fn::If", "Fn::Not",
               "Fn::Or", "Fn::Length", "Fn::ToJsonString")


class _Unresolved(Exception):
    pass


class _TemplateLoader(yaml.SafeLoader):
    """SafeLoader with CloudFormation short forms; timestamps stay strings."""


_TemplateLoader.yaml_implicit_resolvers = {
    key: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:timestamp"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def _short_form(name):
    def construct(loader, node):
        if isinstance(node, yaml.ScalarNode):
            value = loader.construct_scalar(node)
            if name == "Fn::GetAtt":
                value = value.split(".", 1)
        elif isinstance(node, yaml.SequenceNode):
            value = loader.construct_sequence(node, deep=True)
        else:
            value = loader.construct_mapping(node, deep=True)
        return {name: value}
    return construct


for _name in SHORT_FORMS:
    _TemplateLoader.add_constructor("!" + _name.removeprefix("Fn::"), _short_form(_name))


def load_template(text: str) -> dict:
    """Parse JSON or YAML template text, keeping short forms as long-form keys."""
    stripped = text.lstrip("﻿")
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        data = yaml.load(stripped, Loader=_TemplateLoader)
    if not isinstance(data, dict) or not isinstance(data.get("Resources"), dict):
        raise ValueError("not a CloudFormation template: Resources mapping is missing")
    return data


@dataclass
class ConversionReport:
    resources: int = 0
    converted: list[str] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)
    unresolved_properties: dict[str, list[str]] = field(default_factory=dict)
    resolved_properties: int = 0

    def as_dict(self) -> dict:
        return {"resources": self.resources, "converted": len(self.converted),
                "skipped": self.skipped,
                "resolved_properties": self.resolved_properties,
                "unresolved_properties": sum(map(len, self.unresolved_properties.values())),
                "unresolved_by_resource": self.unresolved_properties}


class _Resolver:
    def __init__(self, template: dict, *, account: str, region: str):
        self.template = template
        self.resources = {name: body for name, body in template["Resources"].items()
                          if isinstance(body, dict)}
        self.parameters = template.get("Parameters") or {}
        self.mappings = template.get("Mappings") or {}
        self.conditions = template.get("Conditions") or {}
        self.pseudo = {"AWS::Region": region, "AWS::AccountId": account,
                       "AWS::Partition": "aws", "AWS::URLSuffix": "amazonaws.com"}
        self.dependencies: set[str] = set()
        self._condition_cache: dict[str, bool | None] = {}

    def reference(self, name: str) -> str:
        resource_type = self.resources[name].get("Type", "")
        if not isinstance(resource_type, str) or not TYPE.fullmatch(resource_type):
            self.dependencies.add(name)
            raise _Unresolved
        return f"@{resource_type}/{name}"

    def parameter(self, name: str):
        if name in self.pseudo:
            return self.pseudo[name]
        spec = self.parameters.get(name)
        if not isinstance(spec, dict) or "Default" not in spec:
            raise _Unresolved
        kind, default = str(spec.get("Type", "String")), spec["Default"]
        if kind.startswith("AWS::SSM::Parameter::Value"):
            raise _Unresolved
        if kind == NUMBER_PARAMETER and isinstance(default, str):
            number = float(default)
            return int(number) if number.is_integer() and "." not in default else number
        if kind.startswith(LIST_PARAMETERS):
            if isinstance(default, list):
                return default
            return [] if default == "" else [item.strip() for item in str(default).split(",")]
        return default

    def condition(self, name: str) -> bool:
        if name not in self._condition_cache:
            self._condition_cache[name] = None
            try:
                self._condition_cache[name] = bool(self.evaluate(self.conditions[name]))
            except (_Unresolved, KeyError, TypeError, ValueError):
                pass
        result = self._condition_cache[name]
        if result is None:
            raise _Unresolved
        return result

    def evaluate(self, node):
        if isinstance(node, dict) and len(node) == 1:
            key, value = next(iter(node.items()))
            if key == "Condition":
                return self.condition(value)
            if key == "Fn::Equals":
                left, right = (self.scalar(item) for item in value)
                return _text(left) == _text(right)
            if key == "Fn::And":
                return all(self.evaluate(item) for item in value)
            if key == "Fn::Or":
                return any(self.evaluate(item) for item in value)
            if key == "Fn::Not":
                return not self.evaluate(value[0])
        return self.scalar(node)

    def scalar(self, node):
        value = self.value(node)
        if isinstance(value, (dict, list)) or value is UNRESOLVED:
            raise _Unresolved
        return value

    def strings(self, node) -> list:
        value = self.value(node)
        if not isinstance(value, list) or any(isinstance(item, (dict, list)) for item in value):
            raise _Unresolved
        return value

    def collect_dependencies(self, node):
        """Record template resources an unresolved expression refers to."""
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "Ref" and isinstance(value, str) and value in self.resources:
                    self.dependencies.add(value)
                elif key == "Fn::GetAtt":
                    target = value[0] if isinstance(value, list) and value else None
                    if isinstance(target, str) and target in self.resources:
                        self.dependencies.add(target)
                elif key == "Fn::Sub":
                    text = value[0] if isinstance(value, list) and value else value
                    if isinstance(text, str):
                        for variable in SUB_VARIABLE.findall(text):
                            head = variable.split(".", 1)[0]
                            if not variable.startswith("!") and head in self.resources:
                                self.dependencies.add(head)
                self.collect_dependencies(value)
        elif isinstance(node, list):
            for item in node:
                self.collect_dependencies(item)

    def value(self, node):
        """Return the resolved value, or UNRESOLVED for unknown parts."""
        if isinstance(node, list):
            items = [self.value(item) for item in node]
            return [item for item in items if item is not _NO_VALUE]
        if not isinstance(node, dict):
            return node
        if len(node) == 1:
            key, argument = next(iter(node.items()))
            if key == "Ref" or key.startswith("Fn::"):
                try:
                    return self.intrinsic(key, argument)
                except (_Unresolved, KeyError, IndexError, TypeError, ValueError):
                    self.collect_dependencies(node)
                    return dict(UNRESOLVED)
        resolved = {key: self.value(item) for key, item in node.items()}
        return {key: item for key, item in resolved.items() if item is not _NO_VALUE}

    def intrinsic(self, key: str, argument):
        if key == "Ref":
            if argument == "AWS::NoValue":
                return _NO_VALUE
            if argument in self.resources:
                return self.reference(argument)
            return self.parameter(argument)
        if key == "Fn::GetAtt":
            target = argument[0] if isinstance(argument, list) else str(argument).split(".", 1)[0]
            if target not in self.resources:
                raise _Unresolved
            return self.reference(target)
        if key == "Fn::If":
            name, when_true, when_false = argument
            return self.value(when_true if self.condition(name) else when_false)
        if key == "Fn::Sub":
            text, variables = (argument, {}) if isinstance(argument, str) else argument
            def replace(match):
                name = match.group(1)
                if name.startswith("!"):
                    return "${" + name[1:] + "}"
                if name in variables:
                    resolved = self.scalar(variables[name])
                elif name in self.resources or "." in name:
                    raise _Unresolved
                else:
                    resolved = self.parameter(name)
                if isinstance(resolved, (dict, list)) or (
                        isinstance(resolved, str) and resolved.startswith("@")):
                    raise _Unresolved
                return _text(resolved)
            return SUB_VARIABLE.sub(replace, text)
        if key == "Fn::Join":
            delimiter, items = argument
            parts = self.strings(items)
            if any(isinstance(item, str) and item.startswith("@") for item in parts):
                raise _Unresolved
            return str(delimiter).join(_text(item) for item in parts)
        if key == "Fn::Select":
            index, items = argument
            return self.strings(items)[int(self.scalar(index))]
        if key == "Fn::Split":
            delimiter, text = argument
            text = self.scalar(text)
            if not isinstance(text, str) or text.startswith("@"):
                raise _Unresolved
            return text.split(delimiter)
        if key == "Fn::FindInMap":
            names = [self.scalar(item) for item in argument[:3]]
            return self.value(self.mappings[names[0]][names[1]][names[2]])
        if key == "Fn::Cidr":
            block, count, bits = (self.scalar(item) for item in argument)
            network = ipaddress.ip_network(str(block), strict=True)
            if network.version != 4:
                raise _Unresolved
            subnets = network.subnets(new_prefix=32 - int(bits))
            return [str(next(subnets)) for _ in range(int(count))]
        if key == "Fn::Base64":
            text = self.scalar(argument)
            if not isinstance(text, str) or text.startswith("@"):
                raise _Unresolved
            return base64.b64encode(text.encode("utf-8")).decode("ascii")
        raise _Unresolved


_NO_VALUE = object()


def _text(value) -> str:
    """String form CloudFormation substitutes for a scalar."""
    return json.dumps(value) if isinstance(value, bool) else str(value)


def _contains_unresolved(value) -> bool:
    if isinstance(value, dict):
        return value == UNRESOLVED or any(_contains_unresolved(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_unresolved(item) for item in value)
    return False


def template_to_lines(template: dict, *, template_id: str, account: str,
                      region: str) -> tuple[str, ConversionReport]:
    """Return line-grammar text with one line per converted resource."""
    resolver = _Resolver(template, account=account, region=region)
    report = ConversionReport(resources=len(template["Resources"]))
    lines = []
    for name, body in template["Resources"].items():
        if not isinstance(body, dict):
            report.skipped[name] = "resource body is not a mapping"
            continue
        resource_type = body.get("Type")
        if not isinstance(resource_type, str) or not TYPE.fullmatch(resource_type):
            report.skipped[name] = f"type outside the AWS::Service::Resource form: {resource_type}"
            continue
        condition = body.get("Condition")
        if condition is not None:
            try:
                if not resolver.condition(condition):
                    report.skipped[name] = f"condition {condition} is false with parameter defaults"
                    continue
            except _Unresolved:
                pass
        resolver.dependencies = set()
        properties = body.get("Properties") or {}
        segments, unresolved = [], []
        for key, raw in properties.items():
            value = resolver.value(raw)
            if value is _NO_VALUE:
                continue
            if _contains_unresolved(value):
                unresolved.append(key)
            else:
                report.resolved_properties += 1
            segments.append(f"{key}={json.dumps(value, ensure_ascii=False)}")
        depends_on = body.get("DependsOn", [])
        depends_on = [depends_on] if isinstance(depends_on, str) else list(depends_on)
        depends_on += sorted(resolver.dependencies - set(depends_on) - {name})
        meta = {"id": template_id, "depends_on": depends_on}
        segments.insert(0, f"@Template={json.dumps(meta, ensure_ascii=False)}")
        lines.append(f"{resource_type} {name}: " + "; ".join(segments))
        report.converted.append(name)
        if unresolved:
            report.unresolved_properties[name] = unresolved
    return "\n".join(lines) + "\n", report


def import_template(text: str, name: str, *, project: str, environment: str, account: str,
                    region: str, reference_catalog=None) -> tuple[Design, ConversionReport]:
    """Convert template text into a validated Design with unresolved fields marked."""
    template = load_template(text)
    if template.get("Transform"):
        raise ValueError(f"template transform is not expanded: {template['Transform']}")
    template_id = re.sub(r"[^A-Za-z0-9_.-]", "-", name)
    notes, report = template_to_lines(template, template_id=template_id,
                                      account=account, region=region)
    source = TextSource(id="doc-1", name=name, version="1", text=notes)
    design = LineExtractor(reference_catalog).extract(
        [source], project=project, environment=environment, account=account, region=region)
    data = design.model_dump(mode="json")
    for resource in data["resources"]:
        for item in resource["fields"]:
            selected = next((c for c in item["candidates"]
                             if c["id"] == item.get("selected_candidate_id")), None)
            # Only a wholly unknown value is UNRESOLVED; nested unknown parts stay
            # marked inside the known value so the resolved parts remain checkable.
            if item["state"] == "KNOWN" and selected and selected["value"] == UNRESOLVED:
                item["state"] = "UNRESOLVED"
                item["selected_candidate_id"] = None
    return Design.model_validate(data), report
