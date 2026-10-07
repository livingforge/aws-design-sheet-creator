"""Checks for AWS::DAX::Cluster, AWS::DAX::ParameterGroup."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DAX_AZ_COUNT': [CF+'aws-resource-dax-cluster.html'],
    'DAX_PARAMETER_KEYS': [CF+'aws-resource-dax-parametergroup.html'],
}


@resource_check('AWS::DAX::Cluster', 'AWS::DAX::ParameterGroup')
def evaluate_dax_cluster_az_and_parameter_keys(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::DAX::Cluster':
  p='/properties/AvailabilityZones';zones=get(p);count=get('/properties/ReplicationFactor')
  if zones is not ABSENT:
   v='PASS' if isinstance(zones,list) and type(count) is int and len(zones)==count else 'FAIL' if isinstance(zones,list) and type(count) is int else 'NEEDS_REVIEW'
   emit('DAX_AZ_COUNT',p,v,'explicit array cardinality must equal ReplicationFactor; AZ values/existence and allowed replication counts are separate')
 if resource.type=='AWS::DAX::ParameterGroup':
  p='/properties/ParameterNameValues';raw=get(p)
  if raw is not ABSENT:
   known=isinstance(raw,dict) and all(literal(k) and '/' not in k and '~' not in k for k in raw)
   v='PASS' if known and set(raw)<= {'record-ttl-millis','query-ttl-millis'} else 'FAIL' if known else 'NEEDS_REVIEW'
   emit('DAX_PARAMETER_KEYS',p,v,'only record-ttl-millis/query-ttl-millis map keys are supported; unresolved/escaped keys and alternate JSON shapes held; values are separate')
 return results
