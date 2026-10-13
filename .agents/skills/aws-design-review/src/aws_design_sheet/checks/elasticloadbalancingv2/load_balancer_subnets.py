"""Load-balancer subnet placement supported by explicit subnet declarations."""
import re
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.vpc_membership import classic_subnet_zones

URL = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticloadbalancingv2-loadbalancer.html'
SOURCES = {rule:[URL] for rule in ('ELBV2_SUBNET_ZONES','ELBV2_ALB_SUBNET_COUNT')}


def load_balancer_subnets(design, resource):
    ctx = _Context(design, resource)
    sources = [(path,child) for path,child in [('/properties/Subnets',''),('/properties/SubnetMappings','/SubnetId')]
               if value(ctx, resource, path) is not ABSENT]
    if not sources:
        return []
    if len(sources) != 1:
        return [ctx.finding('ELBV2_SUBNET_ZONES','/properties','NEEDS_REVIEW','both subnet representations are present; do not choose one')]
    path, child = sources[0]
    results = classic_subnet_zones(ctx, resource, path, 'ELBV2_SUBNET_ZONES', child)
    kind = value(ctx, resource, '/properties/Type')
    if kind in ('network','gateway'):
        return results
    subnets = value(ctx, resource, path)
    classes = []
    for i in range(len(subnets) if isinstance(subnets,list) else 0):
        subnet = linked(ctx, resource, path + f'/{i}' + child, 'AWS::EC2::Subnet')
        category = 'unknown'
        if subnet:
            outpost = value(ctx, subnet, '/properties/OutpostArn')
            zone = value(ctx, subnet, '/properties/AvailabilityZone')
            if isinstance(outpost,str) and re.fullmatch(r'arn:[a-z0-9-]+:outposts:[a-z0-9-]+:\d{12}:outpost/op-[a-zA-Z0-9]+',outpost):
                category = 'outpost'
            elif outpost is ABSENT and isinstance(zone,str) and re.fullmatch(r'[a-z]+(?:-[a-z]+)+-\d+',resource.scope.region) and re.fullmatch(re.escape(resource.scope.region)+r'[a-z]',zone):
                category = 'regional'
        classes.append(category)
    verdict = 'NEEDS_REVIEW'
    if kind in (ABSENT,'application') and isinstance(subnets,list):
        if 'outpost' in classes:
            verdict = 'PASS' if len(subnets)==1 else 'FAIL'
        elif all(category=='regional' for category in classes):
            verdict = 'PASS' if len(subnets)>=2 else 'FAIL'
    results.append(ctx.finding('ELBV2_ALB_SUBNET_COUNT',path,verdict,
        'regional ALBs require at least two subnets and Outpost ALBs require one; zone uniqueness is separate and Local Zone/unknown placement needs review'))
    return results
