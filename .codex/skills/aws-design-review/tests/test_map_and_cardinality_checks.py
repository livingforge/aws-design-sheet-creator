from pathlib import Path
import pytest
from aws_design_sheet.checks.cognito.risk_cidrs import evaluate_cognito_risk_cidrs
from aws_design_sheet.checks.config.policy_messages import evaluate_config_policy_messages
from aws_design_sheet.checks.elasticache.az_counts import evaluate_elasticache_az_counts
from aws_design_sheet.checks.awsexternalanthropic.anthropic_inference_geo import evaluate_awsexternalanthropic_anthropic_inference_geo
from aws_design_sheet.checks.fis.target_selection import evaluate_fis_target_selection
from aws_design_sheet.checks.iotsitewise.portal_tools import evaluate_iotsitewise_portal_tools
from aws_design_sheet.checks.mediatailor.child_namespace import evaluate_mediatailor_child_namespace
from aws_design_sheet.checks.docdbelastic.cluster_constraints import evaluate_docdbelastic_cluster_constraints
from aws_design_sheet.checks.redshift.cluster import evaluate_redshift_cluster
from aws_design_sheet.checks.registry import combine
from aws_design_sheet.checks.securityhub.custom_values import evaluate_securityhub_custom_values
from aws_design_sheet.checks.sagemaker.package_env_count import evaluate_sagemaker_package_env_count
from aws_design_sheet.checks.synthetics.env_keys import evaluate_synthetics_env_keys
from aws_design_sheet.checks.scheduler.template_json import evaluate_scheduler_template_json
from aws_design_sheet.checks.imagebuilder.ssm_account_member import evaluate_imagebuilder_ssm_account_member
from aws_design_sheet.checks.opensearchservice.subnet_az_count import evaluate_opensearchservice_subnet_az_count
from aws_design_sheet.checks.s3tables.source_id_member import evaluate_s3tables_source_id_member
from aws_design_sheet.checks.registry import combine
triage_maps_checks = combine(evaluate_securityhub_custom_values, evaluate_sagemaker_package_env_count, evaluate_synthetics_env_keys, evaluate_scheduler_template_json, evaluate_imagebuilder_ssm_account_member, evaluate_opensearchservice_subnet_az_count, evaluate_s3tables_source_id_member)
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
triage_checks=combine(evaluate_cognito_risk_cidrs,evaluate_config_policy_messages,evaluate_elasticache_az_counts,evaluate_awsexternalanthropic_anthropic_inference_geo,evaluate_fis_target_selection,evaluate_iotsitewise_portal_tools,evaluate_mediatailor_child_namespace,evaluate_docdbelastic_cluster_constraints,evaluate_redshift_cluster)

def check(kind,rule,props):
 r=target('subject','AWS::'+kind,**props);d=linked_design(r)
 return [x for x in triage_checks(d,r)+triage_maps_checks(d,r) if x['rule_id']==rule]

@pytest.mark.parametrize('key',['BlockedIPRangeList','SkippedIPRangeList'])
@pytest.mark.parametrize('raw,expected',[('10.0.0.0/24','PASS'),('10.0.0.1/24','PASS'),('::/0','PASS'),('10.0.0.1','FAIL'),('::/129','FAIL'),('bad','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_cidr(key,raw,expected):
 assert check('Cognito::UserPoolRiskConfigurationAttachment','COGNITO_RISK_CIDRS',{'RiskExceptionConfiguration':{key:[raw]}})[0]['verdict']==expected

@pytest.mark.parametrize('owner,expected',[('CUSTOM_POLICY','FAIL'),('AWS','NOT_APPLICABLE'),('CUSTOM_LAMBDA','NOT_APPLICABLE'),(UNKNOWN,'NEEDS_REVIEW')])
def test_config(owner,expected):
 assert check('Config::ConfigRule','CONFIG_POLICY_MESSAGES',{'Source':{'Owner':owner,'SourceDetails':[{'MessageType':'ScheduledNotification'}]}})[0]['verdict']==expected

@pytest.mark.parametrize('raw,expected',[('ConfigurationItemChangeNotification','PASS'),('OversizedConfigurationItemChangeNotification','PASS'),('ScheduledNotification','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_orgconfig(raw,expected):
 assert check('Config::OrganizationConfigRule','CONFIG_ORG_POLICY_MESSAGES',{'OrganizationCustomPolicyRuleMetadata':{'OrganizationConfigRuleTriggerTypes':[raw]}})[0]['verdict']==expected

@pytest.mark.parametrize('kind,rule,key,count',[('CacheCluster','ELASTICACHE_NODE_AZ_COUNT','PreferredAvailabilityZones','NumCacheNodes'),('ReplicationGroup','ELASTICACHE_CLUSTER_AZ_COUNT','PreferredCacheClusterAZs','NumCacheClusters')])
@pytest.mark.parametrize('zones,n,expected',[(['a'],1,'PASS'),(['a'],2,'FAIL'),([UNKNOWN],1,'PASS'),(UNKNOWN,1,'NEEDS_REVIEW'),(['a'],True,'NEEDS_REVIEW')])
def test_counts(kind,rule,key,count,zones,n,expected):
 assert check('ElastiCache::'+kind,rule,{key:zones,count:n})[0]['verdict']==expected

@pytest.mark.parametrize('override,root,expected',[(None,2,'PASS'),(1,2,'FAIL'),(UNKNOWN,2,'NEEDS_REVIEW'),(None,UNKNOWN,'NEEDS_REVIEW')])
def test_replica_override(override,root,expected):
 group={'ReplicaAvailabilityZones':['a','b']}
 if override is not None:group['ReplicaCount']=override
 assert check('ElastiCache::ReplicationGroup','ELASTICACHE_REPLICA_AZ_COUNT',{'NodeGroupConfiguration':[group],'ReplicasPerNodeGroup':root})[0]['verdict']==expected

@pytest.mark.parametrize('choice,allowed,expected',[('us',['us'],'PASS'),('us',['eu'],'FAIL'),('us',[UNKNOWN],'NEEDS_REVIEW'),('us',['us',UNKNOWN],'PASS'),(UNKNOWN,['us'],'NEEDS_REVIEW')])
def test_geo(choice,allowed,expected):
 assert check('AWSExternalAnthropic::Workspace','ANTHROPIC_INFERENCE_GEO',{'DataResidency':{'DefaultInferenceGeo':choice,'AllowedInferenceGeos':allowed}})[0]['verdict']==expected

@pytest.mark.parametrize('a,b,expected',[(['arn'],{},'PASS'),([] ,{'tag':'value'},'PASS'),(['arn'],{'tag':'value'},'FAIL'),([],{},'FAIL'),(UNKNOWN,{},'NEEDS_REVIEW')])
def test_fis(a,b,expected):
 assert check('FIS::ExperimentTemplate','FIS_TARGET_SELECTION',{'Targets':{'target':{'ResourceArns':a,'ResourceTags':b}}})[0]['verdict']==expected

@pytest.mark.parametrize('tool,expected',[('ASSISTANT','PASS'),('DASHBOARD','PASS'),('BAD','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_portal(tool,expected):
 assert check('IoTSiteWise::Portal','IOTSITEWISE_PORTAL_TOOLS',{'PortalTypeConfiguration':{'entry':{'PortalTools':[tool]}}})[0]['verdict']==expected

@pytest.mark.parametrize('key',['ConcurrentExecutorConfiguration','SequentialExecutorConfiguration'])
@pytest.mark.parametrize('alias,expected',[(None,'FAIL'),('different','PASS'),('same','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_child_namespace(key,alias,expected):
 child={'FunctionId':'same'}
 if alias is not None:child['Alias']=alias
 assert check('MediaTailor::Function','MEDIATAILOR_CHILD_NAMESPACE',{key:{'FunctionList':[{'Alias':'same'},child]}})[0]['verdict']==expected

@pytest.mark.parametrize('kind,rule',[('DocDBElastic::Cluster','DOCDBELASTIC_MAINTENANCE_DURATION'),('Redshift::Cluster','REDSHIFT_MAINTENANCE_DURATION')])
@pytest.mark.parametrize('raw,expected',[('mon:00:00-mon:00:29','FAIL'),('mon:00:00-mon:00:30','PASS'),('sun:23:45-mon:00:15','PASS'),('mon:00:00-mon:00:00','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_windows(kind,rule,raw,expected):
 assert check(kind,rule,{'PreferredMaintenanceWindow':raw})[0]['verdict']==expected

@pytest.mark.parametrize('policy',[False,True])
@pytest.mark.parametrize('mode,val,expected',[('CUSTOM',None,'FAIL'),('CUSTOM',{},'FAIL'),('CUSTOM',{'Boolean':False},'PASS'),('CUSTOM',UNKNOWN,'NEEDS_REVIEW'),('DEFAULT',None,'NOT_APPLICABLE'),(UNKNOWN,{},'NEEDS_REVIEW')])
def test_security_value(policy,mode,val,expected):
 param={'ValueType':mode}
 if val is not None:param['Value']=val
 props={'Parameters':{'plain':param}}
 if policy:props={'ConfigurationPolicy':{'SecurityHub':{'SecurityControlsConfiguration':{'SecurityControlCustomParameters':[props]}}}}
 assert check('SecurityHub::'+('ConfigurationPolicy' if policy else 'SecurityControl'),'SECURITYHUB_'+('POLICY' if policy else 'CONTROL')+'_CUSTOM_VALUE',props)[0]['verdict']==expected

@pytest.mark.parametrize('n,expected',[(16,'PASS'),(17,'FAIL')])
def test_environment_count(n,expected):
 assert check('SageMaker::ModelPackage','SAGEMAKER_PACKAGE_ENV_COUNT',{'InferenceSpecification':{'Containers':[{'Environment':{str(i):UNKNOWN for i in range(n)}}]}})[0]['verdict']==expected

@pytest.mark.parametrize('key,expected',[('AB','PASS'),('A_1','PASS'),('A!','FAIL'),('A','FAIL'),('1A','FAIL'),('${key}','NEEDS_REVIEW')])
def test_synthetics(key,expected):
 assert check('Synthetics::Canary','SYNTHETICS_ENV_KEYS',{'RunConfig':{'EnvironmentVariables':{key:'x'}}})[0]['verdict']==expected

@pytest.mark.parametrize('service,resource',[('lambda','function:fn'),('states','stateMachine:machine'),('events','event-bus/default')])
@pytest.mark.parametrize('raw,expected',[('{}','PASS'),('null','PASS'),('bad','FAIL'),('NaN','FAIL'),('${json}','NEEDS_REVIEW')])
def test_json(service,resource,raw,expected):
 assert check('Scheduler::Schedule','SCHEDULER_TEMPLATE_JSON',{'Target':{'Arn':'arn:aws:'+service+':us-east-1:111111111111:'+resource,'Input':raw}})[0]['verdict']==expected

@pytest.mark.parametrize('accounts,expected',[(['111111111111'],'PASS'),(['222222222222'],'FAIL'),([UNKNOWN],'NEEDS_REVIEW')])
def test_ami_accounts(accounts,expected):
 assert check('ImageBuilder::DistributionConfiguration','IMAGEBUILDER_SSM_ACCOUNT_MEMBER',{'Distributions':[{'AmiDistributionConfiguration':{'TargetAccountIds':accounts},'SsmParameterConfigurations':[{'AmiAccountId':'111111111111'}]}]})[0]['verdict']==expected

@pytest.mark.parametrize('config,expected',[(None,'FAIL'),({'AvailabilityZoneCount':2},'PASS'),({'AvailabilityZoneCount':3},'FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_subnet_count(config,expected):
 props={'VPCOptions':{'SubnetIds':['a','b']}}
 if config is not None:props['ClusterConfig']={'ZoneAwarenessConfig':config}
 assert check('OpenSearchService::Domain','OPENSEARCH_SUBNET_AZ_COUNT',props)[0]['verdict']==expected

@pytest.mark.parametrize('ident,expected',[(1,'PASS'),(2,'FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_schema_id(ident,expected):
 assert check('S3Tables::Table','S3TABLES_SOURCE_ID_MEMBER',{'IcebergMetadata':{'IcebergSchema':{'SchemaFieldList':[{'Id':1}]},'IcebergPartitionSpec':{'Fields':[{'SourceId':ident}]}}})[0]['verdict']==expected

def test_checker():
 from aws_design_sheet.checker import Checker
 root=Path(__file__).resolve().parents[1]
 r=target('subject','AWS::ElastiCache::CacheCluster',PreferredAvailabilityZones=['a'],NumCacheNodes=2)
 row=next(x for x in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'] if x['rule_id']=='ELASTICACHE_NODE_AZ_COUNT')
 assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
