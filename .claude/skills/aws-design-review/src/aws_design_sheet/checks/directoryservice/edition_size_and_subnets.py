"""Checks for AWS::DirectoryService::MicrosoftAD, AWS::DirectoryService::SimpleAD."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import known_scope, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SIMPLEAD_SIZE': [CF+'aws-resource-directoryservice-simplead.html'],
    'MICROSOFTAD_SUBNET_AZS': [CF+'aws-properties-directoryservice-microsoftad-vpcsettings.html'],
    'SIMPLEAD_SUBNET_AZS': [CF+'aws-properties-directoryservice-simplead-vpcsettings.html'],
}


def _emitter(ctx, results):
    def emit(rule, path, verdict, reason):
        finding = ctx.finding(rule, path, verdict, reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    return emit


def _enum(ctx, resource, emit, rule, field, allowed):
    path = '/properties/'+field
    raw = value(ctx,resource,path)
    if raw is not ABSENT:
        emit(rule,path,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL','explicit published allowed values only; omitted defaults and other property constraints remain separate')


@resource_check('AWS::DirectoryService::MicrosoftAD', 'AWS::DirectoryService::SimpleAD')
def evaluate_directoryservice_edition_size_and_subnets(design, resource):
    ctx = _Context(design, resource)
    results = []
    emit = _emitter(ctx, results)
    if resource.type == 'AWS::DirectoryService::SimpleAD':
        _enum(ctx, resource, emit, 'SIMPLEAD_SIZE', 'Size', ('Small', 'Large'))
    path = '/properties/VpcSettings/SubnetIds'
    raw = value(ctx,resource,path)
    if raw is not ABSENT:
        zones = []
        if isinstance(raw,list) and len(raw)==2 and known_scope(resource):
            for i in range(2):
                subnet = linked(ctx,resource,path+'/'+str(i),'AWS::EC2::Subnet')
                zone = value(ctx,subnet,'/properties/AvailabilityZone') if subnet else None
                if literal(zone) and re.fullmatch(re.escape(resource.scope.region)+r'[a-z]',zone):
                    zones.append(zone)
        verdict = 'NEEDS_REVIEW' if len(zones)!=2 else 'PASS' if zones[0]!=zones[1] else 'FAIL'
        rule = 'MICROSOFTAD_SUBNET_AZS' if resource.type.endswith('MicrosoftAD') else 'SIMPLEAD_SUBNET_AZS'
        emit(rule,path,verdict,'two uniquely linked subnets with explicit standard AvailabilityZones must differ; other cardinalities, AZ IDs, VPC identity and external subnets remain held')
    return results
