"""API Gateway constraints that need an explicitly linked design resource."""
from __future__ import annotations

import re
from ...models import ValueState
from ..registry import resource_check
from ..common.context import Context


SOURCES = {
    "APIGATEWAY_BASE_PATH_MAPPING_PUBLIC_DOMAIN": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-basepathmapping.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-domainname-endpointconfiguration.html"],
    "APIGATEWAY_METHOD_TIMEOUT_ENDPOINT": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-method-integration.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-restapi-endpointconfiguration.html"],
    "APIGATEWAY_VPC_LINK_TARGET_OWNERSHIP": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-vpclink.html"],
}


class _Context(Context):
    def finding(self, rule_id: str, path: str, verdict: str, reason: str) -> dict:
        return {**super().finding(rule_id, path, verdict, reason),
                "source_checked_at": "2026-10-01"}


def _endpoint_types(ctx: Context, target: Resource) -> list[str] | None:
    path = "/properties/EndpointConfiguration/Types"
    if target.field(path) is not None:
        types = ctx.value(target, path)
    else:
        configuration = ctx.value(target, "/properties/EndpointConfiguration")
        types = configuration.get("Types") if isinstance(configuration, dict) else None
    if not isinstance(types, list) or not types or any(not isinstance(item, str) for item in types):
        ctx.dependencies.append(f"{target.id}{path}")
        return None
    return types


@resource_check('AWS::ApiGateway::BasePathMapping')
def evaluate_base_path_mapping_public_domain(design: Design, resource: Resource) -> dict:
    ctx = _Context(design, resource)
    path = "/properties/DomainName"
    domain = ctx.target(resource, path, "AWS::ApiGateway::DomainName")
    if domain is None:
        return ctx.finding("APIGATEWAY_BASE_PATH_MAPPING_PUBLIC_DOMAIN", path,
                           "NEEDS_REVIEW", "domain is not linked in the design")
    types = _endpoint_types(ctx, domain)
    if types is None:
        verdict, reason = "NEEDS_REVIEW", "domain endpoint type is unresolved"
    elif "PRIVATE" in types:
        verdict, reason = "FAIL", "BasePathMapping requires a public domain"
    elif set(types) <= {"EDGE", "REGIONAL"}:
        verdict, reason = "PASS", "linked domain has a public endpoint type"
    else:
        verdict, reason = "NEEDS_REVIEW", "domain endpoint type is not recognized"
    return ctx.finding("APIGATEWAY_BASE_PATH_MAPPING_PUBLIC_DOMAIN", path, verdict, reason)


@resource_check('AWS::ApiGateway::Method')
def evaluate_method_timeout_endpoint(design: Design, resource: Resource) -> dict:
    ctx = _Context(design, resource)
    path = "/properties/Integration"
    timeout_path = path + "/TimeoutInMillis"
    field = resource.field(timeout_path) or resource.field(path)
    if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return ctx.finding("APIGATEWAY_METHOD_TIMEOUT_ENDPOINT", path,
                           "NOT_APPLICABLE", "integration timeout is not specified")
    if resource.field(timeout_path) is not None:
        timeout = ctx.value(resource, timeout_path)
    else:
        integration = ctx.value(resource, path)
        if not isinstance(integration, dict):
            return ctx.finding("APIGATEWAY_METHOD_TIMEOUT_ENDPOINT", path,
                               "NEEDS_REVIEW", "integration is unresolved")
        timeout = integration.get("TimeoutInMillis")
    if timeout is None:
        return ctx.finding("APIGATEWAY_METHOD_TIMEOUT_ENDPOINT", path + "/TimeoutInMillis",
                           "NOT_APPLICABLE", "integration timeout is not specified")
    if type(timeout) is not int:
        ctx.dependencies.append(resource.id + path + "/TimeoutInMillis")
        return ctx.finding("APIGATEWAY_METHOD_TIMEOUT_ENDPOINT", path + "/TimeoutInMillis",
                           "NEEDS_REVIEW", "integration timeout is unresolved")
    if timeout <= 29000:
        return ctx.finding("APIGATEWAY_METHOD_TIMEOUT_ENDPOINT", path + "/TimeoutInMillis",
                           "NOT_APPLICABLE", "timeout is at most 29 seconds")
    api = ctx.target(resource, "/properties/RestApiId", "AWS::ApiGateway::RestApi")
    if api is None:
        verdict, reason = "NEEDS_REVIEW", "REST API is not linked in the design"
    else:
        types = _endpoint_types(ctx, api)
        if types is None:
            verdict, reason = "NEEDS_REVIEW", "REST API endpoint type is unresolved"
        elif set(types) <= {"REGIONAL", "PRIVATE"}:
            verdict, reason = "PASS", "REST API is regional or private"
        elif set(types) == {"EDGE"}:
            verdict, reason = "FAIL", "edge-optimized API cannot use a timeout above 29 seconds"
        else:
            verdict, reason = "NEEDS_REVIEW", "REST API endpoint type is ambiguous"
    return ctx.finding("APIGATEWAY_METHOD_TIMEOUT_ENDPOINT", path + "/TimeoutInMillis",
                       verdict, reason)


@resource_check('AWS::ApiGateway::VpcLink')
def evaluate_vpc_link_target_ownership(design: Design, resource: Resource) -> dict:
    ctx = _Context(design, resource)
    path = "/properties/TargetArns"
    targets = ctx.value(resource, path)
    if targets is None:
        return ctx.finding("APIGATEWAY_VPC_LINK_TARGET_OWNERSHIP", path,
                           "NEEDS_REVIEW", "load balancer targets are unresolved")
    if not isinstance(targets, list) or not targets:
        return ctx.finding("APIGATEWAY_VPC_LINK_TARGET_OWNERSHIP", path,
                           "NOT_APPLICABLE", "no load balancer target is specified")
    unknown = False
    for index, arn in enumerate(targets):
        target_path = f"{path}/{index}"
        match = (re.fullmatch(r"arn:[^:]+:elasticloadbalancing:[^:]+:(\d{12}):loadbalancer/net/[^/]+/[^/]+", arn)
                 if isinstance(arn, str) else None)
        if match is not None and match.group(1) != resource.scope.account:
            return ctx.finding("APIGATEWAY_VPC_LINK_TARGET_OWNERSHIP", target_path,
                               "FAIL", "network load balancer belongs to another account")
        if isinstance(arn, str) and re.match(r"arn:[^:]+:elasticloadbalancing:", arn) and match is None:
            return ctx.finding("APIGATEWAY_VPC_LINK_TARGET_OWNERSHIP", target_path,
                               "FAIL", "VPC link target must be a network load balancer ARN")
        linked = (ctx.target(resource, target_path, "AWS::ElasticLoadBalancingV2::LoadBalancer")
                  if any(ref.source_resource_id == resource.id and ref.source_path == target_path
                         for ref in design.relations) else None)
        if linked is not None:
            lb_type = ctx.value(linked, "/properties/Type")
            if lb_type == "application" or lb_type == "gateway":
                return ctx.finding("APIGATEWAY_VPC_LINK_TARGET_OWNERSHIP", target_path,
                                   "FAIL", "VPC link target must be a network load balancer")
            if lb_type != "network":
                unknown = True
            continue
        if match is None:
            unknown = True
    if unknown:
        return ctx.finding("APIGATEWAY_VPC_LINK_TARGET_OWNERSHIP", path,
                           "NEEDS_REVIEW", "a target load balancer type or account is unresolved")
    return ctx.finding("APIGATEWAY_VPC_LINK_TARGET_OWNERSHIP", path,
                       "PASS", "all network load balancer targets belong to the API account")
