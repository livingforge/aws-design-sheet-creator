"""Linked API protocols and same-domain API Gateway V2 resources."""
import hashlib
from pathlib import Path

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import Candidate, Design, Document, Evidence, FieldValue, Relation, Resource, Scope, ValueState
from aws_design_sheet.checks.apigatewayv2.cross_resource import evaluate_mapping_protocols, evaluate_protocol_constraints, evaluate_routing_priority, evaluate_openapi_resource_conflict, evaluate_mapping_key_unique, evaluate_stage_route_settings, evaluate_routing_target_type

ROOT = Path(__file__).resolve().parents[1]
SCOPE = Scope(environment="prod", account="111111111111", region="ap-northeast-1")


def item(name, kind, **properties):
    fields = []
    for key, value in properties.items():
        path = "/properties/" + key
        fields.append(FieldValue(path=path, state=ValueState.KNOWN,
                                 candidates=[Candidate(id=path, raw=str(value), value=value, evidence_ids=["e1"])],
                                 selected_candidate_id=path))
    return Resource(id=name, name=name, type="AWS::ApiGatewayV2::" + kind, scope=SCOPE, fields=fields)


def design(resources, relations=()):
    text = "API Gateway V2 design"
    return Design(project="pilot", environment="prod", account=SCOPE.account,
                  documents=[Document(id="d1", name="input", version="1", text=text,
                                      sha256=hashlib.sha256(text.encode()).hexdigest())],
                  evidence=[Evidence(id="e1", document_id="d1", start_line=1, end_line=1, excerpt=text)],
                  resources=list(resources), relations=list(relations))


def link(source, api):
    return Relation(id=source.id + "-api", source_resource_id=source.id,
                    source_path="/properties/ApiId", target_resource_id=api.id, evidence_ids=["e1"])


def verdicts(rows):
    return {row["rule_id"] + row["path"]: row["verdict"] for row in rows}


def test_protocol_checks_use_linked_api_and_leave_unlinked_reference_open():
    integration = item("integration", "Integration", ApiId="api", IntegrationType="HTTP",
                       PayloadFormatVersion="2.0", TimeoutInMillis=30000)
    websocket = item("api", "Api", Name="socket", ProtocolType="WEBSOCKET")
    http = item("api", "Api", Name="web", ProtocolType="HTTP")
    failed = verdicts(evaluate_protocol_constraints(design([integration, websocket], [link(integration, websocket)]), integration))
    assert failed["APIGATEWAYV2_INTEGRATION_TIMEOUT_PROTOCOL/properties/TimeoutInMillis"] == "FAIL"
    allowed = verdicts(evaluate_protocol_constraints(design([integration, http], [link(integration, http)]), integration))
    assert allowed["APIGATEWAYV2_PROTOCOL_PROPERTY/properties/IntegrationType"] == "FAIL"
    assert allowed["APIGATEWAYV2_INTEGRATION_PAYLOAD_PROTOCOL/properties/PayloadFormatVersion"] == "FAIL"
    unknown = verdicts(evaluate_protocol_constraints(design([integration]), integration))
    assert unknown["APIGATEWAYV2_PROTOCOL_PROPERTY/properties/IntegrationType"] == "NEEDS_REVIEW"


def test_http_payload_required_and_http_only_authorizer():
    api = item("api", "Api", Name="web", ProtocolType="HTTP")
    integration = item("integration", "Integration", ApiId="api", IntegrationType="AWS_PROXY")
    rows = verdicts(evaluate_protocol_constraints(design([api, integration], [link(integration, api)]), integration))
    assert rows["APIGATEWAYV2_INTEGRATION_PAYLOAD_PROTOCOL/properties/PayloadFormatVersion"] == "FAIL"
    proxy = item("proxy", "Integration", ApiId="api", IntegrationType="AWS_PROXY",
                 PayloadFormatVersion="2.0")
    rows = verdicts(evaluate_protocol_constraints(design([api, proxy], [link(proxy, api)]), proxy))
    assert rows["APIGATEWAYV2_INTEGRATION_PAYLOAD_PROTOCOL/properties/PayloadFormatVersion"] == "NEEDS_REVIEW"
    websocket = item("api", "Api", Name="socket", ProtocolType="WEBSOCKET")
    authorizer = item("auth", "Authorizer", ApiId="api", Name="auth", AuthorizerType="JWT")
    rows = verdicts(evaluate_protocol_constraints(design([websocket, authorizer], [link(authorizer, websocket)]), authorizer))
    assert rows["APIGATEWAYV2_PROTOCOL_PROPERTY/properties/AuthorizerType"] == "FAIL"
    request = item("request", "Authorizer", ApiId="api", Name="auth", AuthorizerType="REQUEST")
    rows = verdicts(evaluate_protocol_constraints(design([api, request], [link(request, api)]), request))
    assert rows["APIGATEWAYV2_AUTHORIZER_PAYLOAD_PROTOCOL/properties/AuthorizerPayloadFormatVersion"] == "FAIL"
    route = item("route", "Route", ApiId="api", RouteKey="invalid")
    rows = verdicts(evaluate_protocol_constraints(design([api, route], [link(route, api)]), route))
    assert rows["APIGATEWAYV2_ROUTE_KEY_PROTOCOL/properties/RouteKey"] == "FAIL"


def test_mapping_protocols_and_routing_priority_compare_same_domain():
    http = item("http", "Api", Name="web", ProtocolType="HTTP")
    websocket = item("socket", "Api", Name="socket", ProtocolType="WEBSOCKET")
    a = item("a", "ApiMapping", ApiId="http", DomainName="example.com", Stage="prod")
    b = item("b", "ApiMapping", ApiId="socket", DomainName="example.com", Stage="prod")
    linked = design([a, b, http, websocket], [link(a, http), link(b, websocket)])
    assert evaluate_mapping_protocols(linked, a)["verdict"] == "FAIL"
    assert evaluate_mapping_protocols(design([a, b, http], [link(a, http)]), a)["verdict"] == "NEEDS_REVIEW"
    r1 = item("r1", "RoutingRule", DomainNameArn="arn:domain:one", Priority=10)
    r2 = item("r2", "RoutingRule", DomainNameArn="arn:domain:one", Priority=10)
    assert evaluate_routing_priority(design([r1, r2]), r1)["verdict"] == "FAIL"
    r3 = item("r3", "RoutingRule", DomainNameArn="arn:domain:two", Priority=10)
    assert evaluate_routing_priority(design([r1, r3]), r1)["verdict"] == "PASS"


def test_checker_includes_cross_resource_finding():
    api = item("api", "Api", Name="web", ProtocolType="HTTP")
    route = item("route", "Route", ApiId="api", RouteKey="GET /", AuthorizationType="JWT",
                 ApiKeyRequired=True)
    result = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(
        design([api, route], [link(route, api)]))
    findings = [row for row in result["results"] if row["rule_id"] == "APIGATEWAYV2_PROTOCOL_PROPERTY"
                and row["resource_id"] == "route"]
    assert any(row["path"] == "/properties/ApiKeyRequired" and row["verdict"] == "FAIL"
               for row in findings)
    assert any(row["path"] == "/properties/AuthorizationType" and row["verdict"] == "PASS"
               for row in findings)


def test_openapi_body_conflicts_with_linked_route():
    api = item("api", "Api", Name="web", ProtocolType="HTTP", Body={"openapi": "3.0.1"})
    route = item("route", "Route", ApiId="api", RouteKey="GET /")
    assert evaluate_openapi_resource_conflict(design([api, route], [link(route, api)]), api)["verdict"] == "FAIL"
    assert evaluate_openapi_resource_conflict(design([api, route]), api)["verdict"] == "NEEDS_REVIEW"
    assert evaluate_openapi_resource_conflict(design([api]), api)["verdict"] == "PASS"


def test_mapping_keys_reject_exact_duplicate_but_allow_longest_prefix():
    a = item("a", "ApiMapping", DomainName="example.com", ApiId="api", Stage="prod",
             ApiMappingKey="orders")
    duplicate = item("b", "ApiMapping", DomainName="EXAMPLE.COM", ApiId="api", Stage="prod",
                     ApiMappingKey="orders")
    child = item("c", "ApiMapping", DomainName="example.com", ApiId="api", Stage="prod",
                 ApiMappingKey="orders/v1")
    assert evaluate_mapping_key_unique(design([a, duplicate]), a)["verdict"] == "FAIL"
    assert evaluate_mapping_key_unique(design([a, child]), a)["verdict"] == "PASS"
    root = item("root", "ApiMapping", DomainName="example.com", ApiId="api", Stage="prod")
    second_root = item("second-root", "ApiMapping", DomainName="example.com", ApiId="api", Stage="test")
    assert evaluate_mapping_key_unique(design([root, second_root]), root)["verdict"] == "FAIL"


def test_authorizer_ttl_requires_http_request_authorizer():
    http = item("api", "Api", Name="web", ProtocolType="HTTP")
    websocket = item("api", "Api", Name="socket", ProtocolType="WEBSOCKET")
    authorizer = item("auth", "Authorizer", ApiId="api", Name="auth", AuthorizerType="REQUEST",
                      AuthorizerResultTtlInSeconds=30)
    key = "APIGATEWAYV2_AUTHORIZER_TTL_PROTOCOL/properties/AuthorizerResultTtlInSeconds"
    assert verdicts(evaluate_protocol_constraints(design([http, authorizer], [link(authorizer, http)]), authorizer))[key] == "PASS"
    assert verdicts(evaluate_protocol_constraints(design([websocket, authorizer], [link(authorizer, websocket)]), authorizer))[key] == "FAIL"
    assert verdicts(evaluate_protocol_constraints(design([authorizer]), authorizer))[key] == "NEEDS_REVIEW"


def test_stage_nested_route_settings_use_api_protocol():
    http = item("api", "Api", Name="web", ProtocolType="HTTP")
    websocket = item("api", "Api", Name="socket", ProtocolType="WEBSOCKET")
    stage = item("stage", "Stage", ApiId="api", StageName="prod",
                 RouteSettings={"GET /pets": {"LoggingLevel": "INFO", "DataTraceEnabled": True}})
    failed = verdicts(evaluate_stage_route_settings(design([http, stage], [link(stage, http)]), stage))
    assert failed["APIGATEWAYV2_STAGE_ROUTE_SETTINGS_PROTOCOL/properties/RouteSettings/GET ~1pets/LoggingLevel"] == "FAIL"
    passed = verdicts(evaluate_stage_route_settings(design([websocket, stage], [link(stage, websocket)]), stage))
    assert set(passed.values()) == {"PASS"}
    unknown = verdicts(evaluate_stage_route_settings(design([stage]), stage))
    assert set(unknown.values()) == {"NEEDS_REVIEW"}
    leaf = "/properties/DefaultRouteSettings/LoggingLevel"
    stage_with_leaf = Resource(id="leaf-stage", name="leaf-stage", type=stage.type, scope=SCOPE,
                               fields=[*item("leaf-stage", "Stage", ApiId="api", StageName="prod").fields,
                                       FieldValue(path=leaf, state=ValueState.KNOWN,
                                                  candidates=[Candidate(id=leaf, raw="INFO", value="INFO",
                                                                        evidence_ids=["e1"])],
                                                  selected_candidate_id=leaf)])
    rows = verdicts(evaluate_stage_route_settings(
        design([http, stage_with_leaf], [link(stage_with_leaf, http)]), stage_with_leaf))
    assert rows["APIGATEWAYV2_STAGE_ROUTE_SETTINGS_PROTOCOL" + leaf] == "FAIL"


def test_routing_rule_action_requires_linked_rest_api():
    rule = item("rule", "RoutingRule", DomainNameArn="arn:domain:one", Priority=1,
                Actions=[{"InvokeApi": {"ApiId": "api", "Stage": "prod"}}],
                Conditions=[{"MatchBasePaths": {"AnyOf": ["v1"]}}])
    rest = Resource(id="api", name="api", type="AWS::ApiGateway::RestApi", scope=SCOPE)
    http = item("api", "Api", Name="web", ProtocolType="HTTP")
    relation = Relation(id="target", source_resource_id="rule",
                        source_path="/properties/Actions/0/InvokeApi/ApiId",
                        target_resource_id="api", evidence_ids=["e1"])
    assert evaluate_routing_target_type(design([rule, rest], [relation]), rule)[0]["verdict"] == "PASS"
    assert evaluate_routing_target_type(design([rule, http], [relation]), rule)[0]["verdict"] == "FAIL"
    assert evaluate_routing_target_type(design([rule]), rule)[0]["verdict"] == "NEEDS_REVIEW"
