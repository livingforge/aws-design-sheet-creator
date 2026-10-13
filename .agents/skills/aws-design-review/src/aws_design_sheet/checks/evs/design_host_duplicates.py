"""Checks for AWS::EVS::Environment."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, known_scope, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'EVS_DESIGN_HOST_DUPLICATES': [CF+'aws-properties-evs-environment-hostinfoforcreate.html'],
}


@resource_check('AWS::EVS::Environment')
def evaluate_evs_design_host_duplicates(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
    if resource.type=='AWS::EVS::Environment':
        own=[get(p) for p in expand(ctx,resource,'/properties/Hosts/*/HostName')];names={x for x in own if literal(x)};duplicate=False
        if known_scope(resource):
            for other in design.resources:
                if other.id==resource.id or other.type!=resource.type or other.scope!=resource.scope:continue
                othernames=[value(ctx,other,p) for p in expand(ctx,other,'/properties/Hosts/*/HostName')]
                if names&{x for x in othernames if literal(x)}:duplicate=True
        if own:emit('EVS_DESIGN_HOST_DUPLICATES','/properties/Hosts','FAIL' if duplicate else 'NEEDS_REVIEW','proves exact duplicate hostnames across explicit same-scope EVS environments only; absent conflicts do not certify external uniqueness; license/core minimums held')
    return results
