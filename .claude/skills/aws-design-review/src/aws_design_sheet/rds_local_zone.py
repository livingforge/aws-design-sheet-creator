"""Bound the existing RDS subnet-count rule to its documented Local Zone exception."""
from .checks.common.context_values import _Context, linked, value
from .checks.common.literals import known_scope
from .models import ValueState
from .rule_engine import reference_view
from .checks.common.index import relations_from

RULE='RDS.DBSUBNETGROUP.SUBNET_IDS_MIN_TWO'
SOURCE='https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html'
REGIONS='https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.RegionsAndAvailabilityZones.html'


def guard_local_zone(rule, design, resource, findings):
    if rule.id!=RULE or resource.type!='AWS::RDS::DBSubnetGroup':
        return findings
    if rule.assertion!={'op':'cardinality','path':'/properties/SubnetIds','min':2}:
        return findings
    if not known_scope(resource) or resource.scope.region!='us-west-2':
        return findings
    template=resource.template
    if not template or template.state!=ValueState.KNOWN or template.property_presence is None:
        return findings
    ctx=_Context(design,resource)
    view=reference_view(resource,relations_from(design, resource.id),
                        {r.id:r.type for r in design.resources})
    raw=value(ctx,view,'/properties/SubnetIds')
    if not isinstance(raw,list) or len(raw)!=1:
        return findings
    subnet=linked(ctx,resource,'/properties/SubnetIds/0','AWS::EC2::Subnet')
    if (not subnet or not subnet.template or subnet.template.state!=ValueState.KNOWN
            or subnet.template.id!=template.id or subnet.template.property_presence is None):
        return findings
    zone=value(ctx,subnet,'/properties/AvailabilityZone')
    if zone not in ('us-west-2-lax-1a','us-west-2-lax-1b'):
        return findings
    rows=[]
    for finding in findings:
        if finding['verdict']!='FAIL':
            rows.append(finding);continue
        rows.append({**finding,'verdict':'PASS',
            'reason':'One explicitly linked Los Angeles Local Zone subnet satisfies the documented DB subnet group count exception; database engine support and live availability are not proven.',
            'source_urls':list(dict.fromkeys([*finding.get('source_urls',[]),SOURCE,REGIONS])),
            'source_checked_at':'2026-10-10',
            'evidence_ids':list(dict.fromkeys([*finding.get('evidence_ids',[]),*ctx.evidence])),
            'dependencies':list(dict.fromkeys([*finding.get('dependencies',[]),*ctx.dependencies])),
            'local_zone_exception':{'zone':zone,'subnet_id':subnet.id,'scope':'subnet count only'}})
    return rows
