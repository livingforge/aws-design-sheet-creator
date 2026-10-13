"""Checks for AWS::DocDB::DBCluster, AWS::DocDB::DBSubnetGroup."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import known_scope, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DOCDB_CLUSTER_MODES': [CF+'aws-resource-docdb-dbcluster.html'],
    'DOCDB_SUBNET_AZ_SPREAD': [CF+'aws-resource-docdb-dbsubnetgroup.html'],
}


@resource_check('AWS::DocDB::DBCluster', 'AWS::DocDB::DBSubnetGroup')
def evaluate_docdb_cluster_and_subnet_group(design, resource):
    ctx = _Context(design, resource)
    results = []
    def emit(rule, path, verdict, reason):
        finding = ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    enums = {
        'AWS::DocDB::DBCluster': ('DOCDB_CLUSTER_MODES', [('NetworkType',('IPV4','DUAL')),('StorageType',('standard','iopt1'))]),
    }
    if resource.type in enums:
        rule, fields = enums[resource.type]
        for field, allowed in fields:
            path = '/properties/'+field
            raw = value(ctx,resource,path)
            if raw is not ABSENT:
                emit(rule,path,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL','explicit documented allowed values only; defaults, conditional applicability and related resource compatibility remain separate')
    if resource.type == 'AWS::DocDB::DBSubnetGroup':
        path = '/properties/SubnetIds'
        raw = value(ctx,resource,path)
        if raw is not ABSENT:
            verdict = 'NEEDS_REVIEW'
            if isinstance(raw,list):
                if len(raw)<2:
                    verdict = 'FAIL'
                elif len(raw)<=20 and known_scope(resource):
                    zones = []
                    for i in range(len(raw)):
                        subnet = linked(ctx,resource,path+'/'+str(i),'AWS::EC2::Subnet')
                        zone = value(ctx,subnet,'/properties/AvailabilityZone') if subnet else None
                        if literal(zone) and re.fullmatch(re.escape(resource.scope.region)+r'[a-z]',zone):
                            zones.append(zone)
                    if len(zones)==len(raw):
                        verdict = 'PASS' if len(set(zones))>=2 else 'FAIL'
            emit('DOCDB_SUBNET_AZ_SPREAD',path,verdict,'at least two AZs from uniquely linked same-scope subnets with explicit standard AZ names; unknown members, AZ IDs, VPC membership and oversized input remain separate')
    return results
