"""One bounded cfn-lint schema-gap correction, not a second schema engine.

The pinned CFN snapshot and cfn-lint1.57.2 omit DomainName.SecurityPolicy's
enum. Keep AWS's documented values here, versioned independently, and let
cfn-lint's intrinsic/unknown-aware JSON-schema validator evaluate them.
No provider schema/cache or installed dependency is mutated.
"""
from __future__ import annotations

import re
from cfnlint.api import ManualArgs, lint
from cfnlint.core import get_rules
from cfnlint.rules.jsonschema import CfnLintJsonSchema

VERSION = "2026-10-11.1"
SOURCE_URL = "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-domainname.html"
SECURITY_POLICIES = (
    "TLS_1_0", "TLS_1_2",
    "SecurityPolicy_TLS13_1_3_2025_09", "SecurityPolicy_TLS13_1_3_FIPS_2025_09",
    "SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09", "SecurityPolicy_TLS13_1_2_FIPS_PQ_2025_09",
    "SecurityPolicy_TLS13_1_2_PQ_2025_09", "SecurityPolicy_TLS13_1_2_2021_06",
    "SecurityPolicy_TLS13_2025_EDGE", "SecurityPolicy_TLS12_PFS_2025_EDGE",
    "SecurityPolicy_TLS12_2018_EDGE",
)


class ApiGatewaySecurityPolicy(CfnLintJsonSchema):
    id = "E9001"
    shortdesc = "API Gateway domain security policy must be a documented AWS value"
    description = "Bounded correction for a missing provider-schema enum; AWS documentation snapshot " + VERSION
    source_url = SOURCE_URL
    tags = ["properties", "apigateway"]

    def __init__(self):
        super().__init__(keywords=["Resources/AWS::ApiGateway::DomainName/Properties/SecurityPolicy"])
        self._schema = {"enum": list(SECURITY_POLICIES)}
        self._use_schema_arg = False

    def message(self, instance, err):
        return err.message


def lint_template(template: str, *, regions: list[str], config: ManualArgs | None = None):
    """Same cfn-lint engine plus the explicitly versioned compatibility rule."""
    options = config or ManualArgs(regions=regions)
    rules = get_rules([], options.get("ignore_checks", []), options.get("include_checks", []),
                      configure_rules=options.get("configure_rules"),
                      include_experimental=options.get("include_experimental", False),
                      mandatory_rules=options.get("mandatory_checks"))
    rules.register(ApiGatewaySecurityPolicy())
    return lint(template, rules=rules, regions=regions, config=options)


def reference_format_gap(rule_id: str, template: dict, logical: str, path: str) -> str | None:
    """Documented upstream format gaps, narrowly bounded to exact expressions.

    Return a source URL for an unverified format diagnostic, never a PASS.
    Other properties, resource types and attributes retain their diagnostics.
    """
    resources = template['Resources']
    owner = resources.get(logical, {})
    value = owner.get('Properties', {})
    try:
        for token in path.removeprefix('/properties/').split('/'):
            token = token.replace('~1', '/').replace('~0', '~')
            value = value[int(token)] if isinstance(value, list) else value[token]
    except (KeyError, TypeError, IndexError, ValueError):
        return None
    if (rule_id == 'E1041' and owner.get('Type') == 'AWS::EC2::LaunchTemplate'
            and re.fullmatch('/properties/LaunchTemplateData/SecurityGroups/[0-9]+', path)
            and isinstance(value, dict) and set(value) == {'Ref'}):
        target = resources.get(value['Ref'], {})
        if target.get('Type') == 'AWS::EC2::SecurityGroup' and 'VpcId' not in target.get('Properties', {}):
            return 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ec2-launchtemplate-launchtemplatedata.html'
    if (rule_id == 'E1040' and owner.get('Type') == 'AWS::EC2::SecurityGroup'
            and re.fullmatch('/properties/SecurityGroupIngress/[0-9]+/SourceSecurityGroupName', path)
            and isinstance(value, dict) and set(value) == {'Fn::GetAtt'}):
        att = value['Fn::GetAtt']
        if (isinstance(att, list) and len(att) == 2 and att[1] == 'SourceSecurityGroup.GroupName'
                and resources.get(att[0], {}).get('Type') == 'AWS::ElasticLoadBalancing::LoadBalancer'):
            return 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticloadbalancing-loadbalancer.html'
    return None
