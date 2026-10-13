"""Map paths and cardinality helpers shared by several service checks."""
from .context_values import _Context, value
from .field_reads import ABSENT
from .literals import literal
from .maintenance_windows import window

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DOCDBELASTIC_MAINTENANCE_DURATION': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-docdbelastic-cluster.html',
    ],
    'REDSHIFT_MAINTENANCE_DURATION': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-redshift-cluster.html',
    ],
}


def source(rule,page):SOURCES[rule]=[CF+page+'.html']


for rule,page in [
 ('COGNITO_RISK_CIDRS','aws-properties-cognito-userpoolriskconfigurationattachment-riskexceptionconfigurationtype'),
 ('CONFIG_POLICY_MESSAGES','aws-properties-config-configrule-source'),
 ('CONFIG_ORG_POLICY_MESSAGES','aws-properties-config-organizationconfigrule-organizationcustompolicyrulemetadata'),
 ('ELASTICACHE_NODE_AZ_COUNT','aws-resource-elasticache-cachecluster'),
 ('ELASTICACHE_CLUSTER_AZ_COUNT','aws-resource-elasticache-replicationgroup'),
 ('ELASTICACHE_REPLICA_AZ_COUNT','aws-properties-elasticache-replicationgroup-nodegroupconfiguration'),
 ('FIS_TARGET_SELECTION','aws-properties-fis-experimenttemplate-experimenttemplatetarget'),
 ('IOTSITEWISE_PORTAL_TOOLS','aws-properties-iotsitewise-portal-portaltypeentry'),
 ('MEDIATAILOR_CHILD_NAMESPACE','aws-properties-mediatailor-function-functionref'),
 ('DOCDBELASTIC_MAINTENANCE_DURATION','aws-resource-docdbelastic-cluster'),
 ('REDSHIFT_MAINTENANCE_DURATION','aws-resource-redshift-cluster')]:source(rule,page)


def map_paths(ctx,resource,path):
 raw=value(ctx,resource,path)
 if not isinstance(raw,dict):return [path] if raw is not ABSENT else []
 return [path+'/'+key if literal(key) and '/' not in key and '~' not in key else path for key in raw]


def cardinality(items,count):
 return 'NEEDS_REVIEW' if not isinstance(items,list) or type(count) is not int else 'PASS' if len(items)==count else 'FAIL'


def maintenance_duration(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type in ('AWS::DocDBElastic::Cluster','AWS::Redshift::Cluster'):
  p='/properties/PreferredMaintenanceWindow';raw=get(p)
  if raw is not ABSENT:
   span=window(raw,True);v='NEEDS_REVIEW' if span is None else 'PASS' if span[1]-span[0]>=30 else 'FAIL'
   emit('DOCDBELASTIC_MAINTENANCE_DURATION' if resource.type.startswith('AWS::DocDBElastic') else 'REDSHIFT_MAINTENANCE_DURATION',p,v,'explicit weekly window requires at least thirty minutes; wraparound supported; equal endpoints and unsupported formats held')
 return results
