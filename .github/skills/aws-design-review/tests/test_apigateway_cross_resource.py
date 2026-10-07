"""API Gateway rules that use explicit design relations."""
import hashlib
from pathlib import Path

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import Candidate, Design, Document, Evidence, FieldValue, Relation, Resource, Scope, ValueState
from aws_design_sheet.checks.apigateway.cross_resource import evaluate_base_path_mapping_public_domain, evaluate_method_timeout_endpoint, evaluate_vpc_link_target_ownership


ROOT = Path(__file__).resolve().parents[1]
SCOPE = Scope(environment="prod", account="111111111111", region="ap-northeast-1")


def resource(name, kind, **properties):
    fields = []
    for key, value in properties.items():
        path = "/properties/" + key
        fields.append(FieldValue(path=path, state=ValueState.KNOWN,
                                 candidates=[Candidate(id=path, raw=str(value), value=value, evidence_ids=["e1"])],
                                 selected_candidate_id=path))
    return Resource(id=name, name=name, type="AWS::ApiGateway::" + kind, scope=SCOPE, fields=fields)


def design(resources, relations=()):
    message = "API Gateway design"
    return Design(project="pilot", environment="prod", account=SCOPE.account,
                  documents=[Document(id="d1", name="input", version="1", text=message,
                                      sha256=hashlib.sha256(message.encode()).hexdigest())],
                  evidence=[Evidence(id="e1", document_id="d1", start_line=1, end_line=1,
                                     excerpt=message)], resources=list(resources), relations=list(relations))


def link(source, path, target):
    return Relation(id="relation", source_resource_id=source.id, source_path="/properties/" + path,
                    target_resource_id=target.id, evidence_ids=["e1"])


def test_base_path_mapping_requires_linked_public_domain():
    mapping = resource("mapping", "BasePathMapping", DomainName="example.com")
    private = resource("domain", "DomainName", EndpointConfiguration={"Types": ["PRIVATE"]})
    public = resource("domain", "DomainName", EndpointConfiguration={"Types": ["REGIONAL"]})
    assert evaluate_base_path_mapping_public_domain(design([mapping, private], [link(mapping, "DomainName", private)]),
                                                    mapping)["verdict"] == "FAIL"
    assert evaluate_base_path_mapping_public_domain(design([mapping, public], [link(mapping, "DomainName", public)]),
                                                    mapping)["verdict"] == "PASS"
    assert evaluate_base_path_mapping_public_domain(design([mapping]), mapping)["verdict"] == "NEEDS_REVIEW"


def test_method_timeout_uses_linked_api_endpoint_type():
    method = resource("method", "Method", Integration={"Type": "HTTP", "TimeoutInMillis": 30000}, RestApiId="api")
    edge = resource("api", "RestApi", EndpointConfiguration={"Types": ["EDGE"]})
    regional = resource("api", "RestApi", EndpointConfiguration={"Types": ["REGIONAL"]})
    assert evaluate_method_timeout_endpoint(design([method, edge], [link(method, "RestApiId", edge)]), method)["verdict"] == "FAIL"
    assert evaluate_method_timeout_endpoint(design([method, regional], [link(method, "RestApiId", regional)]), method)["verdict"] == "PASS"
    assert evaluate_method_timeout_endpoint(design([method]), method)["verdict"] == "NEEDS_REVIEW"
    short = resource("short", "Method", Integration={"Type": "HTTP", "TimeoutInMillis": 29000})
    assert evaluate_method_timeout_endpoint(design([short]), short)["verdict"] == "NOT_APPLICABLE"


def test_cross_resource_findings_are_in_normal_checker_results():
    mapping = resource("mapping", "BasePathMapping", DomainName="example.com")
    domain = resource("domain", "DomainName", EndpointConfiguration={"Types": ["PRIVATE"]})
    result = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(
        design([mapping, domain], [link(mapping, "DomainName", domain)]))
    findings = [row for row in result["results"]
                if row["rule_id"] == "APIGATEWAY_BASE_PATH_MAPPING_PUBLIC_DOMAIN"]
    assert len(findings) == 1
    assert findings[0]["verdict"] == "FAIL"
    assert findings[0]["source_checked_at"] == "2026-10-01"


def test_vpc_link_target_owner_from_literal_arn_or_link():
    own_arn = "arn:aws:elasticloadbalancing:ap-northeast-1:111111111111:loadbalancer/net/nlb/abc"
    other_arn = "arn:aws:elasticloadbalancing:ap-northeast-1:222222222222:loadbalancer/net/nlb/abc"
    own = resource("link", "VpcLink", Name="link", TargetArns=[own_arn])
    other = resource("link", "VpcLink", Name="link", TargetArns=[other_arn])
    assert evaluate_vpc_link_target_ownership(design([own]), own)["verdict"] == "PASS"
    assert evaluate_vpc_link_target_ownership(design([other]), other)["verdict"] == "FAIL"
    application = resource("link", "VpcLink", Name="link", TargetArns=[
        "arn:aws:elasticloadbalancing:ap-northeast-1:111111111111:loadbalancer/app/alb/abc"])
    assert evaluate_vpc_link_target_ownership(design([application]), application)["verdict"] == "FAIL"
    linked = resource("link", "VpcLink", Name="link", TargetArns=["@AWS::ElasticLoadBalancingV2::LoadBalancer/lb"])
    lb = Resource(id="lb", name="lb", type="AWS::ElasticLoadBalancingV2::LoadBalancer", scope=SCOPE,
                  fields=resource("unused", "VpcLink", Type="network").fields)
    relation = Relation(id="lb-relation", source_resource_id="link", source_path="/properties/TargetArns/0",
                        target_resource_id="lb", evidence_ids=["e1"])
    assert evaluate_vpc_link_target_ownership(design([linked, lb], [relation]), linked)["verdict"] == "PASS"
    assert evaluate_vpc_link_target_ownership(design([linked]), linked)["verdict"] == "NEEDS_REVIEW"
