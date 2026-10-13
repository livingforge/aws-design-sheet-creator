"""Checks for AWS::OpenSearchService::Domain."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.map_cardinality import cardinality

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'OPENSEARCH_SUBNET_AZ_COUNT': [CF+'aws-properties-opensearchservice-domain-vpcoptions.html'],
}


@resource_check('AWS::OpenSearchService::Domain')
def evaluate_opensearchservice_subnet_az_count(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::OpenSearchService::Domain':
  p='/properties/VPCOptions/SubnetIds';raw=get(p)
  if isinstance(raw,list) and len(raw)>1:
   config=get('/properties/ClusterConfig/ZoneAwarenessConfig')
   v='FAIL' if config is ABSENT else cardinality(raw,get('/properties/ClusterConfig/ZoneAwarenessConfig/AvailabilityZoneCount'))
   emit('OPENSEARCH_SUBNET_AZ_COUNT',p,v,'multiple explicit subnet slots require ZoneAwarenessConfig and matching explicit AZ count; actual subnet AZ uniqueness is external')
 return results
