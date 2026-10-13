"""Checks for AWS::ODB::CloudVmCluster."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'ODB_SCAN_PORT_EXCLUSIONS': [CF+'aws-resource-odb-cloudvmcluster.html'],
}


@resource_check('AWS::ODB::CloudVmCluster')
def evaluate_odb_scan_port_exclusions(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::ODB::CloudVmCluster':
  p='/properties/ScanListenerPortTcp';port=get(p)
  if port is not ABSENT:
   v='NEEDS_REVIEW' if type(port) is not int else 'FAIL' if port in (2484,6100,6200,7060,7070,7085,7879) or not 1024<=port<=8999 else 'PASS'
   emit('ODB_SCAN_PORT_EXCLUSIONS',p,v,'explicit integer SCAN TCP port must be 1024..8999 excluding seven documented reserved values; omitted defaults and unresolved values remain separate')
 return results
