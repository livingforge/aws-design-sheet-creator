"""Checks for AWS::IoTSiteWise::Portal."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal
from ..common.map_cardinality import map_paths

SOURCES = {
    'IOTSITEWISE_PORTAL_TOOLS': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-iotsitewise-portal-portaltypeentry.html',
    ],
}


@resource_check('AWS::IoTSiteWise::Portal')
def evaluate_iotsitewise_portal_tools(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::IoTSiteWise::Portal':
  for base in map_paths(ctx,resource,'/properties/PortalTypeConfiguration'):
   for p in expand(ctx,resource,base+'/PortalTools/*'):
    raw=get(p);v='NEEDS_REVIEW' if not literal(raw) or base=='/properties/PortalTypeConfiguration' else 'PASS' if raw in ('ASSISTANT','DASHBOARD') else 'FAIL'
    emit('IOTSITEWISE_PORTAL_TOOLS',p,v,'explicit portal tools are ASSISTANT/DASHBOARD; unresolved map keys or values held')
 return results
