"""API Gateway V2 checks whose answer depends on another design resource."""
from __future__ import annotations

import re
from ...models import ValueState
from ..registry import resource_check
from .targets import payload_v2_target
from ..common.context import Context
from ..common.context_values import value as read_value, linked as safe_linked
from ..common.field_reads import ABSENT, UNKNOWN

PREFIX = "AWS::ApiGatewayV2::"


SOURCES = {
    "APIGATEWAYV2_PROTOCOL_PROPERTY": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-authorizer.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-integration.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-route.html"],
    "APIGATEWAYV2_MANAGED_OVERRIDES_HTTP": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-apigatewaymanagedoverrides.html"],
    "APIGATEWAYV2_INTEGRATION_PAYLOAD_PROTOCOL": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-integration.html"],
    "APIGATEWAYV2_INTEGRATION_TIMEOUT_PROTOCOL": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-integration.html"],
    "APIGATEWAYV2_AUTHORIZER_PAYLOAD_PROTOCOL": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-authorizer.html"],
    "APIGATEWAYV2_ROUTE_KEY_PROTOCOL": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-route.html"],
    "APIGATEWAYV2_MAPPING_PROTOCOL_CONSISTENCY": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-apimapping.html"],
    "APIGATEWAYV2_MAPPING_KEY_UNIQUE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-apimapping.html",
        "https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-mappings.html"],
    "APIGATEWAYV2_AUTHORIZER_TTL_PROTOCOL": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-authorizer.html"],
    "APIGATEWAYV2_STAGE_ROUTE_SETTINGS_PROTOCOL": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigatewayv2-stage-routesettings.html"],
    "APIGATEWAYV2_ROUTING_REST_TARGET": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-routingrule.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigatewayv2-routingrule-actioninvokeapi.html"],
    "APIGATEWAYV2_ROUTING_PRIORITY_UNIQUE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-routingrule.html"],
    "APIGATEWAYV2_OPENAPI_RESOURCE_CONFLICT": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-api.html"],
}


class _Context(Context):
    def finding(self, rule_id: str, path: str, verdict: str, reason: str) -> dict:
        return {**super().finding(rule_id, path, verdict, reason),
                "source_checked_at": "2026-10-01"}


def _property(ctx: _Context, resource: Resource, name: str):
    return ctx.value(resource, "/properties/" + name)


def _specified(resource: Resource, name: str) -> bool:
    field = resource.field("/properties/" + name)
    return field is not None and field.state not in (ValueState.MISSING, ValueState.NOT_APPLICABLE)


def _protocol(ctx: _Context, resource: Resource) -> str | None:
    api = safe_linked(ctx, resource, "/properties/ApiId", PREFIX + "Api")
    if api is None:
        return None
    protocol = _property(ctx, api, "ProtocolType")
    return protocol if protocol in ("HTTP", "WEBSOCKET") else None


ONLY_FOR = {
    "Authorizer": {"HTTP": ("JwtConfiguration", "EnableSimpleResponses",
                            "AuthorizerPayloadFormatVersion")},
    "Integration": {
        "HTTP": ("ConnectionId", "ResponseParameters", "TlsConfig"),
        "WEBSOCKET": ("ContentHandlingStrategy", "PassthroughBehavior", "RequestTemplates",
                      "TemplateSelectionExpression"),
    },
    "IntegrationResponse": {"WEBSOCKET": ("ContentHandlingStrategy", "TemplateSelectionExpression")},
    "Route": {"WEBSOCKET": ("ApiKeyRequired", "ModelSelectionExpression", "RequestModels",
                              "RequestParameters", "RouteResponseSelectionExpression")},
    "RouteResponse": {"WEBSOCKET": ("ModelSelectionExpression",)},
    "Stage": {"WEBSOCKET": ("ClientCertificateId",)},
}


@resource_check('AWS::ApiGatewayV2::*')
def evaluate_protocol_constraints(design: Design, resource: Resource) -> list[dict]:
    ctx = _Context(design, resource)
    kind = resource.type.removeprefix(PREFIX)
    checks = [(name, protocol) for protocol, names in ONLY_FOR.get(kind, {}).items()
              for name in names if _specified(resource, name)]
    if kind == "Authorizer":
        if _property(ctx, resource, "AuthorizerType") == "JWT":
            checks.append(("AuthorizerType", "HTTP"))
    if kind == "Route" and _property(ctx, resource, "AuthorizationType") == "JWT":
        checks.append(("AuthorizationType", "HTTP"))
    if kind == "Integration" and _property(ctx, resource, "IntegrationType") in ("AWS", "HTTP", "MOCK"):
        checks.append(("IntegrationType", "WEBSOCKET"))
    if not checks and kind not in ("Integration", "ApiGatewayManagedOverrides", "Authorizer", "Route"):
        return []
    protocol = _protocol(ctx, resource)
    result = []
    for name, required in checks:
        path = "/properties/" + name
        if protocol is None:
            verdict, reason = "NEEDS_REVIEW", "referenced API protocol is unresolved"
        elif protocol != required:
            verdict, reason = "FAIL", f"{name} is supported only for {required} APIs"
        else:
            verdict, reason = "PASS", f"{name} is allowed for {protocol} APIs"
        result.append(ctx.finding("APIGATEWAYV2_PROTOCOL_PROPERTY", path, verdict, reason))
    if kind == "ApiGatewayManagedOverrides":
        result.append(ctx.finding("APIGATEWAYV2_MANAGED_OVERRIDES_HTTP", "/properties/ApiId",
                                  "NEEDS_REVIEW" if protocol is None else
                                  "PASS" if protocol == "HTTP" else "FAIL",
                                  "referenced API protocol is unresolved" if protocol is None else
                                  "managed overrides require an HTTP API" if protocol != "HTTP" else
                                  "referenced API is HTTP"))
    if kind == "Integration":
        version = read_value(ctx, resource, "/properties/PayloadFormatVersion")
        if version in (ABSENT, UNKNOWN):
            version = None
        if protocol == "HTTP" or _specified(resource, "PayloadFormatVersion"):
            if protocol is None or (_specified(resource, "PayloadFormatVersion") and version is None):
                verdict, reason = "NEEDS_REVIEW", "API protocol or payload format version is unresolved"
            elif protocol == "HTTP" and not _specified(resource, "PayloadFormatVersion"):
                verdict, reason = "FAIL", "HTTP API integration requires PayloadFormatVersion"
            elif protocol == "HTTP" and version == "2.0":
                verdict, reason = payload_v2_target(ctx, resource)
            else:
                verdict, reason = "PASS", "payload format is compatible with the API protocol"
            result.append({**ctx.finding("APIGATEWAYV2_INTEGRATION_PAYLOAD_PROTOCOL",
                                      "/properties/PayloadFormatVersion", verdict, reason),
                           "source_checked_at": "2026-10-03"})
        timeout = _property(ctx, resource, "TimeoutInMillis") if _specified(resource, "TimeoutInMillis") else None
        if timeout is not None:
            if protocol is None or type(timeout) is not int:
                verdict, reason = "NEEDS_REVIEW", "API protocol or timeout is unresolved"
            elif protocol == "WEBSOCKET" and timeout > 29000:
                verdict, reason = "FAIL", "WebSocket integration timeout exceeds 29,000 ms"
            else:
                verdict, reason = "PASS", "timeout is within the protocol limit"
            result.append(ctx.finding("APIGATEWAYV2_INTEGRATION_TIMEOUT_PROTOCOL",
                                      "/properties/TimeoutInMillis", verdict, reason))
    if kind == "Authorizer":
        authorizer_type = _property(ctx, resource, "AuthorizerType")
        if authorizer_type == "REQUEST":
            if protocol is None:
                verdict, reason = "NEEDS_REVIEW", "referenced API protocol is unresolved"
            elif protocol == "HTTP" and not _specified(resource, "AuthorizerPayloadFormatVersion"):
                verdict, reason = "FAIL", "HTTP API Lambda authorizer requires a payload format version"
            elif protocol == "HTTP" and _property(ctx, resource, "AuthorizerPayloadFormatVersion") is None:
                verdict, reason = "NEEDS_REVIEW", "authorizer payload format version is unresolved"
            else:
                verdict, reason = "PASS", "authorizer payload requirement is satisfied"
            result.append(ctx.finding("APIGATEWAYV2_AUTHORIZER_PAYLOAD_PROTOCOL",
                                      "/properties/AuthorizerPayloadFormatVersion", verdict, reason))
        if _specified(resource, "AuthorizerResultTtlInSeconds"):
            ttl = _property(ctx, resource, "AuthorizerResultTtlInSeconds")
            if protocol is None or authorizer_type is None or ttl is None:
                verdict, reason = "NEEDS_REVIEW", "API protocol, authorizer type, or TTL is unresolved"
            elif protocol != "HTTP" or authorizer_type != "REQUEST":
                verdict, reason = "FAIL", "authorizer TTL is supported only for HTTP API Lambda authorizers"
            else:
                verdict, reason = "PASS", "authorizer TTL belongs to an HTTP API Lambda authorizer"
            result.append(ctx.finding("APIGATEWAYV2_AUTHORIZER_TTL_PROTOCOL",
                                      "/properties/AuthorizerResultTtlInSeconds", verdict, reason))
    if kind == "Route":
        key = _property(ctx, resource, "RouteKey")
        if protocol is None or not isinstance(key, str):
            verdict, reason = "NEEDS_REVIEW", "referenced API protocol or route key is unresolved"
        elif protocol == "HTTP" and key != "$default" and not re.fullmatch(
                r"(?:ANY|DELETE|GET|HEAD|OPTIONS|PATCH|POST|PUT) /\S*", key):
            verdict, reason = "FAIL", "HTTP API route key must be $default or a method and path"
        else:
            verdict, reason = "PASS", "route key is compatible with the API protocol"
        result.append(ctx.finding("APIGATEWAYV2_ROUTE_KEY_PROTOCOL",
                                  "/properties/RouteKey", verdict, reason))
    return result


@resource_check('AWS::ApiGatewayV2::ApiMapping')
def evaluate_mapping_protocols(design: Design, resource: Resource) -> dict:
    ctx = _Context(design, resource)
    path = "/properties/ApiId"
    domain = _property(ctx, resource, "DomainName")
    own_protocol = _protocol(ctx, resource)
    uncertain = own_protocol is None or not isinstance(domain, str)
    for other in design.resources:
        if other.id == resource.id or other.type != resource.type or other.scope != resource.scope:
            continue
        other_domain = _property(ctx, other, "DomainName")
        if not isinstance(other_domain, str):
            uncertain = True
            continue
        if other_domain.casefold() != domain.casefold():
            continue
        other_protocol = _protocol(ctx, other)
        if own_protocol and other_protocol and own_protocol != other_protocol:
            return ctx.finding("APIGATEWAYV2_MAPPING_PROTOCOL_CONSISTENCY", path,
                               "FAIL", f"mapping {other.id} on the same domain uses a different API protocol")
        if other_protocol is None:
            uncertain = True
    return ctx.finding("APIGATEWAYV2_MAPPING_PROTOCOL_CONSISTENCY", path,
                       "NEEDS_REVIEW" if uncertain else "PASS",
                       "mapping domain or API protocol is unresolved" if uncertain else
                       "mapped APIs on this domain use the same protocol")


@resource_check('AWS::ApiGatewayV2::ApiMapping')
def evaluate_mapping_key_unique(design: Design, resource: Resource) -> dict:
    ctx = _Context(design, resource)
    path = "/properties/ApiMappingKey"
    domain = _property(ctx, resource, "DomainName")

    def key(item: Resource):
        if not _specified(item, "ApiMappingKey"):
            return ""  # The omitted key maps the root path.
        value = _property(ctx, item, "ApiMappingKey")
        return value if isinstance(value, str) else None

    own_key = key(resource)
    if not isinstance(domain, str) or own_key is None:
        return ctx.finding("APIGATEWAYV2_MAPPING_KEY_UNIQUE", path,
                           "NEEDS_REVIEW", "mapping domain or key is unresolved")
    uncertain = False
    for other in design.resources:
        if other.id == resource.id or other.type != resource.type or other.scope != resource.scope:
            continue
        other_domain = _property(ctx, other, "DomainName")
        if not isinstance(other_domain, str):
            uncertain = True
            continue
        if other_domain.casefold() != domain.casefold():
            continue
        other_key = key(other)
        if other_key == own_key:
            return ctx.finding("APIGATEWAYV2_MAPPING_KEY_UNIQUE", path,
                               "FAIL", f"mapping {other.id} has the same domain and path")
        if other_key is None:
            uncertain = True
    return ctx.finding("APIGATEWAYV2_MAPPING_KEY_UNIQUE", path,
                       "NEEDS_REVIEW" if uncertain else "PASS",
                       "another mapping domain or key is unresolved" if uncertain else
                       "mapping path is unique for this domain in the design")


@resource_check('AWS::ApiGatewayV2::Stage')
def evaluate_stage_route_settings(design: Design, resource: Resource) -> list[dict]:
    ctx = _Context(design, resource)
    settings = []
    represented = set()
    for name in ("DefaultRouteSettings", "RouteSettings"):
        if not _specified(resource, name):
            continue
        value = _property(ctx, resource, name)
        if not isinstance(value, dict):
            settings.append(("/properties/" + name, None))
        elif name == "DefaultRouteSettings":
            settings.append(("/properties/" + name, value))
            represented.update("/properties/DefaultRouteSettings/" + item for item in value)
        else:
            for route_key, config in value.items():
                escaped = str(route_key).replace("~", "~0").replace("/", "~1")
                base = "/properties/RouteSettings/" + escaped
                settings.append((base, config))
                if isinstance(config, dict):
                    represented.update(base + "/" + item for item in config)
    for field in resource.fields:
        if field.path in represented or not field.path.endswith(("/DataTraceEnabled", "/LoggingLevel")):
            continue
        if field.path.startswith(("/properties/DefaultRouteSettings/", "/properties/RouteSettings/")):
            base, name = field.path.rsplit("/", 1)
            settings.append((base, {name: ctx.value(resource, field.path)}))
    if not settings:
        return []
    protocol = _protocol(ctx, resource)
    results = []
    for path, value in settings:
        if not isinstance(value, dict):
            results.append(ctx.finding("APIGATEWAYV2_STAGE_ROUTE_SETTINGS_PROTOCOL", path,
                                       "NEEDS_REVIEW", "route settings are unresolved"))
            continue
        for name in ("DataTraceEnabled", "LoggingLevel"):
            if name not in value:
                continue
            setting = value[name]
            if protocol is None or setting is None or isinstance(setting, dict):
                verdict, reason = "NEEDS_REVIEW", "API protocol or route setting is unresolved"
            elif protocol != "WEBSOCKET":
                verdict, reason = "FAIL", f"{name} is supported only for WebSocket APIs"
            elif name == "LoggingLevel" and setting not in ("INFO", "ERROR", "OFF"):
                verdict, reason = "FAIL", "LoggingLevel must be INFO, ERROR, or OFF"
            elif name == "DataTraceEnabled" and type(setting) is not bool:
                verdict, reason = "NEEDS_REVIEW", "DataTraceEnabled value is unresolved"
            else:
                verdict, reason = "PASS", f"{name} is valid for a WebSocket API"
            results.append(ctx.finding("APIGATEWAYV2_STAGE_ROUTE_SETTINGS_PROTOCOL",
                                       path + "/" + name, verdict, reason))
    return results


@resource_check('AWS::ApiGatewayV2::RoutingRule')
def evaluate_routing_target_type(design: Design, resource: Resource) -> list[dict]:
    ctx = _Context(design, resource)
    actions = _property(ctx, resource, "Actions")
    paths = []
    if isinstance(actions, list):
        paths.extend(f"/properties/Actions/{index}/InvokeApi/ApiId"
                     for index, action in enumerate(actions)
                     if isinstance(action, dict) and "InvokeApi" in action)
    paths.extend(field.path for field in resource.fields
                 if re.fullmatch(r"/properties/Actions/\d+/InvokeApi/ApiId", field.path))
    paths.extend(ref.source_path for ref in design.relations
                 if ref.source_resource_id == resource.id and
                 re.fullmatch(r"/properties/Actions/\d+/InvokeApi/ApiId", ref.source_path))
    paths = list(dict.fromkeys(paths))
    if not paths:
        return [ctx.finding("APIGATEWAYV2_ROUTING_REST_TARGET", "/properties/Actions",
                            "NEEDS_REVIEW", "InvokeApi target is unresolved")]
    results = []
    for path in paths:
        refs = [ref for ref in design.relations
                if ref.source_resource_id == resource.id and ref.source_path == path]
        ctx.evidence.extend(item for ref in refs for item in ref.evidence_ids)
        if len(refs) != 1 or refs[0].target_resource_id is None:
            verdict, reason = "NEEDS_REVIEW", "InvokeApi target is not explicitly linked"
            ctx.dependencies.append(resource.id + path)
        else:
            target = ctx.by_id.get(refs[0].target_resource_id)
            if target is None or target.scope != resource.scope:
                verdict, reason = "NEEDS_REVIEW", "InvokeApi target resource is unresolved"
                ctx.dependencies.append(resource.id + path)
            elif target.type != "AWS::ApiGateway::RestApi":
                verdict, reason = "FAIL", "routing rule InvokeApi target must be a REST API"
            else:
                verdict, reason = "PASS", "InvokeApi target is a REST API"
        results.append(ctx.finding("APIGATEWAYV2_ROUTING_REST_TARGET", path, verdict, reason))
    return results


@resource_check('AWS::ApiGatewayV2::RoutingRule')
def evaluate_routing_priority(design: Design, resource: Resource) -> dict:
    ctx = _Context(design, resource)
    path = "/properties/Priority"
    own_domain = _property(ctx, resource, "DomainNameArn")
    priority = _property(ctx, resource, "Priority")
    if not isinstance(own_domain, str) or type(priority) is not int:
        return ctx.finding("APIGATEWAYV2_ROUTING_PRIORITY_UNIQUE", path,
                           "NEEDS_REVIEW", "domain ARN or priority is unresolved")
    uncertain = False
    for other in design.resources:
        if other.id == resource.id or other.type != resource.type or other.scope != resource.scope:
            continue
        domain = _property(ctx, other, "DomainNameArn")
        number = _property(ctx, other, "Priority")
        if domain == own_domain and number == priority:
            return ctx.finding("APIGATEWAYV2_ROUTING_PRIORITY_UNIQUE", path,
                               "FAIL", f"routing rule {other.id} has the same domain and priority")
        if domain is None or (domain == own_domain and number is None):
            uncertain = True
    return ctx.finding("APIGATEWAYV2_ROUTING_PRIORITY_UNIQUE", path,
                       "NEEDS_REVIEW" if uncertain else "PASS",
                       "another routing rule is unresolved" if uncertain else
                       "priority is unique for this domain in the design")


@resource_check('AWS::ApiGatewayV2::Api')
def evaluate_openapi_resource_conflict(design: Design, resource: Resource) -> dict:
    ctx = _Context(design, resource)
    path = "/properties/Body" if _specified(resource, "Body") else "/properties/BodyS3Location"
    if not any(_specified(resource, name) for name in ("Body", "BodyS3Location")):
        return ctx.finding("APIGATEWAYV2_OPENAPI_RESOURCE_CONFLICT", path,
                           "NOT_APPLICABLE", "API has no OpenAPI body")
    uncertain = False
    for other in design.resources:
        if other.scope != resource.scope or other.type not in (PREFIX + "Authorizer", PREFIX + "Route"):
            continue
        refs = [ref for ref in design.relations if ref.source_resource_id == other.id
                and ref.source_path == "/properties/ApiId"]
        ctx.evidence.extend(item for ref in refs for item in ref.evidence_ids)
        if len(refs) == 1 and refs[0].target_resource_id == resource.id:
            return ctx.finding("APIGATEWAYV2_OPENAPI_RESOURCE_CONFLICT", path, "FAIL",
                               f"OpenAPI body conflicts with separate {other.type} {other.id}")
        if not refs or len(refs) != 1 or refs[0].target_resource_id is None:
            uncertain = True
            ctx.dependencies.append(other.id + "/properties/ApiId")
    return ctx.finding("APIGATEWAYV2_OPENAPI_RESOURCE_CONFLICT", path,
                       "NEEDS_REVIEW" if uncertain else "PASS",
                       "another authorizer or route API reference is unresolved" if uncertain else
                       "no separate authorizer or route references this OpenAPI API")
