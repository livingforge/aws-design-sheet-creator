"""Checks for AWS::AgentRegistry::Registry, AWS::AgentRegistry::RegistryRecord."""
from __future__ import annotations

from ...models import ValueState
from ..registry import resource_check


SOURCES = {
    "AGENT_REGISTRY_CUSTOM_JWT_AUTHORIZER": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-agentregistry-registry-discoveryconfiguration.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-agentregistry-registry-authorizerconfiguration.html"],
    "AGENT_REGISTRY_RECORD_DESCRIPTOR": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-agentregistry-registryrecord.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-agentregistry-registryrecord-descriptors.html"],
}


def _value(field: FieldValue | None):
    return field.selected().value if field and field.state == ValueState.KNOWN else None


def _evidence(*fields: FieldValue | None) -> list[str]:
    return list(dict.fromkeys(e for field in fields if field is not None
                              for e in [*field.intent_evidence_ids,
                                        *(e for candidate in field.candidates
                                          for e in candidate.evidence_ids)]))


def _result(rule: str, resource: Resource, path: str, verdict: str, reason: str,
            fields: tuple[FieldValue | None, ...], dependencies: list[str] | None = None) -> dict:
    return {"rule_id": rule, "resource_id": resource.id, "path": path,
            "verdict": verdict, "reason": reason, "evidence_ids": _evidence(*fields),
            "dependencies": dependencies or []}


@resource_check('AWS::AgentRegistry::Registry')
def evaluate_registry_custom_jwt(resource: Resource) -> dict:
    type_path = "/properties/AuthorizerType"
    configuration_path = "/properties/DiscoveryConfiguration"
    authorizer = resource.field(type_path)
    configuration = resource.field(configuration_path)
    fields = (authorizer, configuration)
    rule = "AGENT_REGISTRY_CUSTOM_JWT_AUTHORIZER"
    if authorizer is None or authorizer.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return _result(rule, resource, configuration_path, "NOT_APPLICABLE",
                       "custom JWT authorizer is not explicitly selected", fields)
    if authorizer.state != ValueState.KNOWN:
        return _result(rule, resource, type_path, "NEEDS_REVIEW",
                       "authorizer type is unresolved", fields, [type_path])
    if _value(authorizer) != "CUSTOM_JWT":
        return _result(rule, resource, configuration_path, "NOT_APPLICABLE",
                       "authorizer type is not CUSTOM_JWT", fields)
    if configuration is None or configuration.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return _result(rule, resource, configuration_path, "FAIL",
                       "CUSTOM_JWT requires an authorizer configuration", fields)
    if configuration.state != ValueState.KNOWN:
        return _result(rule, resource, configuration_path, "NEEDS_REVIEW",
                       "discovery configuration is unresolved", fields, [configuration_path])
    value = _value(configuration)
    if not isinstance(value, dict):
        return _result(rule, resource, configuration_path, "NEEDS_REVIEW",
                       "discovery configuration is not an object", fields, [configuration_path])
    authorizer_value = value.get("AuthorizerConfiguration")
    if not isinstance(authorizer_value, dict) or "CustomJWTAuthorizer" not in authorizer_value:
        return _result(rule, resource, configuration_path, "FAIL",
                       "CUSTOM_JWT requires DiscoveryConfiguration.AuthorizerConfiguration.CustomJWTAuthorizer", fields)
    return _result(rule, resource, configuration_path, "PASS",
                   "CUSTOM_JWT authorizer configuration is specified", fields)


@resource_check('AWS::AgentRegistry::RegistryRecord')
def evaluate_registry_record_descriptor(resource: Resource) -> dict:
    type_path = "/properties/RecordType"
    descriptors_path = "/properties/Descriptors"
    record_type = resource.field(type_path)
    descriptors = resource.field(descriptors_path)
    fields = (record_type, descriptors)
    rule = "AGENT_REGISTRY_RECORD_DESCRIPTOR"
    if record_type is None or record_type.state != ValueState.KNOWN or descriptors is None or descriptors.state != ValueState.KNOWN:
        return _result(rule, resource, descriptors_path, "NEEDS_REVIEW",
                       "record type or descriptors are unresolved", fields,
                       [path for path, field in ((type_path, record_type), (descriptors_path, descriptors))
                        if field is None or field.state != ValueState.KNOWN])
    content = _value(descriptors)
    if not isinstance(content, dict):
        return _result(rule, resource, descriptors_path, "NEEDS_REVIEW",
                       "descriptors are not an object", fields, [descriptors_path])
    members = {"McpServer", "A2aAgentCard", "AgentSkillsDefinition", "Custom", "Http", "Agui"} & content.keys()
    if len(members) != 1:
        return _result(rule, resource, descriptors_path, "FAIL",
                       "exactly one descriptor must be specified", fields)
    expected = {"MCP": "McpServer", "AGENT": "A2aAgentCard",
                "SKILL": "AgentSkillsDefinition", "CUSTOM": "Custom"}.get(_value(record_type))
    if expected is None or members & {"Http", "Agui"}:
        return _result(rule, resource, descriptors_path, "NEEDS_REVIEW",
                       "descriptor and record type mapping is not documented for this case",
                       fields, [type_path, descriptors_path])
    if expected not in members:
        return _result(rule, resource, descriptors_path, "FAIL",
                       "descriptor does not match record type", fields)
    return _result(rule, resource, descriptors_path, "PASS",
                   "one descriptor matches record type", fields)
