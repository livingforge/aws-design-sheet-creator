"""Checks for AWS::FSx::FileSystem, AWS::FSx::Volume."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

SOURCES = {
    'FSX_LUSTRE_CAPACITY_INCREMENT': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-fsx-filesystem.html',
    ],
    'FSX_RETENTION_SAME_UNIT': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-fsx-volume-snaplockretentionperiod.html',
    ],
}


@resource_check('AWS::FSx::FileSystem', 'AWS::FSx::Volume')
def evaluate_fsx_capacity_and_retention(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::FSx::FileSystem' and get('/properties/FileSystemType')=='LUSTRE':
  p='/properties/StorageCapacity';size=get(p);storage=get('/properties/StorageType');deployment=get('/properties/LustreConfiguration/DeploymentType');throughput=get('/properties/LustreConfiguration/PerUnitStorageThroughput');valid=None
  if type(size) is int:
   if deployment=='SCRATCH_1':valid=size in (1200,2400) or size>0 and size%3600==0
   elif deployment in ('SCRATCH_2','PERSISTENT_1','PERSISTENT_2') and storage=='SSD':valid=size==1200 or size>0 and size%2400==0
   elif deployment=='PERSISTENT_1' and storage=='HDD' and throughput in (12,40):valid=size>0 and size%(6000 if throughput==12 else 1800)==0
  emit('FSX_LUSTRE_CAPACITY_INCREMENT',p,'NEEDS_REVIEW' if valid is None else 'PASS' if valid else 'FAIL','checks documented Lustre capacity increments for explicit supported deployment/storage/throughput; defaults, unknown/future combinations and restore size remain separate')
 if resource.type=='AWS::FSx::Volume':
  p='/properties/OntapConfiguration/SnaplockConfiguration/RetentionPeriod'
  if get(p) is not ABSENT:
   types=[get(p+'/'+k+'/Type') for k in ('MinimumRetention','DefaultRetention','MaximumRetention')];values=[get(p+'/'+k+'/Value') for k in ('MinimumRetention','DefaultRetention','MaximumRetention')]
   known=all(type(v) is int for v in values) and types[0] in ('SECONDS','MINUTES','HOURS','DAYS','MONTHS','YEARS') and all(t==types[0] for t in types)
   emit('FSX_RETENTION_SAME_UNIT',p,'PASS' if known and values[0]<=values[1]<=values[2] else 'FAIL' if known else 'NEEDS_REVIEW','compares explicit same-unit minimum/default/maximum retention; cross-unit calendar conversion, special values and audit-log six-month rule remain held')
 return results
