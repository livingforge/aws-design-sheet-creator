"""Selected Agent Registry and Amazon MQ conditions absent from the pinned schema."""
from __future__ import annotations

from .models import FieldValue, Resource, ValueState


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


def evaluate_broker_replication_primary(resource: Resource) -> dict:
    mode_path = "/properties/DataReplicationMode"
    primary_path = "/properties/DataReplicationPrimaryBrokerArn"
    mode = resource.field(mode_path)
    primary = resource.field(primary_path)
    fields = (mode, primary)
    rule = "AMAZONMQ_CRDR_PRIMARY_BROKER"
    if mode is None or mode.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return _result(rule, resource, primary_path, "NOT_APPLICABLE",
                       "CRDR replication is not explicitly selected", fields)
    if mode.state != ValueState.KNOWN:
        return _result(rule, resource, mode_path, "NEEDS_REVIEW",
                       "replication mode is unresolved", fields, [mode_path])
    if not isinstance(_value(mode), str) or _value(mode).upper() != "CRDR":
        return _result(rule, resource, primary_path, "NOT_APPLICABLE",
                       "replication mode is not CRDR", fields)
    if primary is None or primary.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return _result(rule, resource, primary_path, "FAIL",
                       "CRDR requires a primary broker ARN", fields)
    if primary.state != ValueState.KNOWN:
        return _result(rule, resource, primary_path, "NEEDS_REVIEW",
                       "primary broker ARN is unresolved", fields, [primary_path])
    return _result(rule, resource, primary_path, "PASS",
                   "primary broker ARN is specified", fields)
