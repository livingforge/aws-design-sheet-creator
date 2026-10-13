"""Declared parent resource-configuration group precedes its child."""
from ...template_dependencies import members, ordering
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'LATTICE_CHILD_GROUP_ORDER':[CF+'aws-resource-vpclattice-resourceconfiguration.html',CF+'aws-attribute-dependson.html']}


def parent(ctx,r):
    if not resolved(r):return 'NEEDS_REVIEW'
    kind=value(ctx,r,'/properties/ResourceConfigurationType')
    if kind in ('GROUP','SINGLE','ARN','CIDR'):return 'NOT_APPLICABLE'
    if kind!='CHILD' or read(ctx,r,'/properties/ResourceConfigurationGroupId') is not ABSENT:return 'NEEDS_REVIEW'
    group=linked(ctx,r,'/properties/ResourceConfigurationGroupId',r.type)
    if not resolved(group):return 'NEEDS_REVIEW'
    if group.id==r.id:return 'FAIL'
    group_kind=value(ctx,group,'/properties/ResourceConfigurationType')
    if group_kind in ('CHILD','SINGLE','ARN','CIDR'):return 'FAIL'
    if group_kind!='GROUP' or group not in members(ctx.design,r):return 'NEEDS_REVIEW'
    try:return ordering(ctx,'LATTICE_CHILD_GROUP_ORDER',[group])['verdict']
    except RecursionError:return 'NEEDS_REVIEW'


@resource_check('AWS::VpcLattice::ResourceConfiguration')
def evaluate_vpclattice_group_order(design,resource):
    if resource.type!='AWS::VpcLattice::ResourceConfiguration':return []
    ctx=_Context(design,resource)
    f=ctx.finding('LATTICE_CHILD_GROUP_ORDER','/properties/ResourceConfigurationGroupId',parent(ctx,resource),'A CHILD configuration refers to a GROUP configuration created first. Explicit same-template reference/dependency establishes order; self-reference, wrong parent type and cycles fail. External identities and unknown template membership remain reviewable. PASS covers declared order only, not live creation state.')
    f['source_checked_at']='2026-10-04';return [f]
