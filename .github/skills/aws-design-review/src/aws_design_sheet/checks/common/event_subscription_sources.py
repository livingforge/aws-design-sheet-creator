"""Source-type mapping for database event subscriptions."""
from .context_values import _Context, linked, value
from .field_reads import ABSENT, read
from .literals import literal
from .scoped_resolution import resolved

MAPPING={
    'Redshift':{'cluster':'AWS::Redshift::Cluster','cluster-parameter-group':'AWS::Redshift::ClusterParameterGroup','cluster-security-group':'AWS::Redshift::ClusterSecurityGroup','scheduled-action':'AWS::Redshift::ScheduledAction'},
    'Neptune':{'db-instance':'AWS::Neptune::DBInstance','db-cluster':'AWS::Neptune::DBCluster'},
}


def source_types(ctx,r,service):
    rows=value(ctx,r,'/properties/SourceIds')
    if rows is ABSENT:return 'NOT_APPLICABLE'
    if not resolved(r) or not isinstance(rows,list) or not 1<=len(rows)<=1000:return 'NEEDS_REVIEW'
    kind=value(ctx,r,'/properties/SourceType')
    if kind is ABSENT:return 'FAIL'
    if not isinstance(kind,str) or kind not in MAPPING[service]:return 'NEEDS_REVIEW'
    expected=MAPPING[service][kind];pending=False
    for i in range(len(rows)):
        path=f'/properties/SourceIds/{i}';raw=read(ctx,r,path)
        if raw is not ABSENT and not literal(raw):pending=True;continue
        refs=[ref for ref in ctx.design.relations if ref.source_resource_id==r.id and ref.source_path==path]
        if len(refs)!=1 or refs[0].condition:pending=True;continue
        matches=[other for other in ctx.design.resources if other.id==refs[0].target_resource_id]
        if len(matches)!=1 or not resolved(matches[0]):pending=True;continue
        other=matches[0]
        if linked(ctx,r,path,other.type) is not other:pending=True;continue
        if other.type!=expected:return 'FAIL'
    return 'NEEDS_REVIEW' if pending else 'PASS'


def event_source_finding(design,resource):
    service=resource.type.split('::')[1] if resource.type in ('AWS::Redshift::EventSubscription','AWS::Neptune::EventSubscription') else None
    if service is None:return []
    ctx=_Context(design,resource);rule=service.upper()+'_EVENT_SOURCE_TYPE'
    f=ctx.finding(rule,'/properties/SourceIds',source_types(ctx,resource,service),'Every explicit source ID reference must target the declared SourceType. Supported mappings are Redshift clusters, parameter/security groups and scheduled actions, and Neptune DB instances/clusters. Other source kinds, unresolved references and external identities remain reviewable. PASS covers declared resource type only; source existence, categories, SNS delivery and live authorization remain separate.')
    f['source_checked_at']='2026-10-04';return [f]
