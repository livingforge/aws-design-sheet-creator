from pathlib import Path
import pytest
from aws_design_sheet.checks.kinesisanalyticsv2.sql_application_links import LIMITS, evaluate_kinesisanalyticsv2_sql_application_links
from aws_design_sheet.checks.personalize.dataset_links import evaluate_personalize_dataset_links
from aws_design_sheet.checks.route53profiles.vpc_single import evaluate_route53profiles_vpc_single
from aws_design_sheet.checks.securitylake.notification_single import evaluate_securitylake_notification_single
from aws_design_sheet.checks.acmpca.signing_key_family import evaluate_acmpca_signing_key_family
from aws_design_sheet.checks.datasync.hdfs_basic_namenodes import evaluate_datasync_hdfs_basic_namenodes
from aws_design_sheet.checks.efs.mount_ip_subnet import evaluate_efs_mount_ip_subnet
from aws_design_sheet.checks.forecast.dataset_domains import evaluate_forecast_dataset_domains
from aws_design_sheet.checks.scheduler.fifo_dedup import evaluate_scheduler_fifo_dedup
from aws_design_sheet.checks.wisdom.template_hash_match import evaluate_wisdom_template_hash_match
from aws_design_sheet.checks.workspacesweb.vpc_tenancy import evaluate_workspacesweb_vpc_tenancy
from aws_design_sheet.checks.registry import combine
remaining_links_checks = combine(evaluate_kinesisanalyticsv2_sql_application_links, evaluate_personalize_dataset_links, evaluate_route53profiles_vpc_single, evaluate_securitylake_notification_single, evaluate_acmpca_signing_key_family, evaluate_datasync_hdfs_basic_namenodes, evaluate_efs_mount_ip_subnet, evaluate_forecast_dataset_domains, evaluate_scheduler_fifo_dedup, evaluate_wisdom_template_hash_match, evaluate_workspacesweb_vpc_tenancy)
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def evaluate(kind,rule,props,parent_kind,parent_props,path,mode='linked'):
    r=target('one','AWS::'+kind,**props);p=target('parent','AWS::'+parent_kind,**parent_props)
    d=linked_design(r,[p],[(path,p.id)] if mode!='literal' else [])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='cross_scope':p.scope.account='222222222222'
    return next(x for x in remaining_links_checks(d,r) if x['rule_id']==rule)


@pytest.mark.parametrize('kind',list(LIMITS))
@pytest.mark.parametrize('mode',['same','different','conditional','literal','unknown_scope'])
def test_single_parent_limits(kind,mode):
    rule,key,parent_kind,variant=LIMITS[kind];props={variant:'Interactions'} if variant else {}
    r=target('one',kind,**props);other=target('two',kind,**props);p=target('parent',parent_kind);q=target('otherparent',parent_kind)
    d=linked_design(r,[other,p,q],[(key,p.id)] if mode!='literal' else [])
    if d.relations:
        rel=d.relations[0].model_copy(deep=True);rel.id='two';rel.source_resource_id=other.id;rel.target_resource_id=q.id if mode=='different' else p.id
        if mode=='conditional':rel.condition='Maybe'
        d.relations.append(rel)
    if mode=='unknown_scope':r.scope.region=other.scope.region=p.scope.region='unknown'
    assert remaining_links_checks(d,r)[0]['verdict']==('FAIL' if mode=='same' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('sign,key,expected',[('SHA256WITHRSA','RSA_2048','PASS'),('SHA256WITHECDSA','RSA_2048','FAIL'),('SHA384WITHECDSA','EC_secp384r1','PASS'),('ML_DSA_44','ML_DSA_44','NEEDS_REVIEW'),(UNKNOWN,'RSA_2048','NEEDS_REVIEW')])
def test_ca_family(sign,key,expected):
    assert evaluate('ACMPCA::Certificate','ACMPCA_SIGNING_KEY_FAMILY',{'SigningAlgorithm':sign},'ACMPCA::CertificateAuthority',{'KeyAlgorithm':key},'CertificateAuthorityArn')['verdict']==expected


@pytest.mark.parametrize('mode',['literal','conditional','cross_scope'])
def test_ca_reference_holds(mode):
    assert evaluate('ACMPCA::Certificate','ACMPCA_SIGNING_KEY_FAMILY',{'SigningAlgorithm':'SHA256WITHRSA'},'ACMPCA::CertificateAuthority',{'KeyAlgorithm':'RSA_2048'},'CertificateAuthorityArn',mode)['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('count,mode,expected',[(2,'BASIC','FAIL'),(1,'BASIC','NEEDS_REVIEW'),(2,'ENHANCED','NEEDS_REVIEW'),(2,UNKNOWN,'NEEDS_REVIEW')])
def test_hdfs_reverse_task_link(count,mode,expected):
    loc=target('loc','AWS::DataSync::LocationHDFS',NameNodes=[{}]*count);task=target('task','AWS::DataSync::Task',TaskMode=mode)
    d=linked_design(task,[loc],[('SourceLocationArn',loc.id)])
    assert remaining_links_checks(d,loc)[0]['verdict']==expected


@pytest.mark.parametrize('key,cidrkey,ip,cidr,expected',[
 ('IpAddress','CidrBlock','10.0.0.1','10.0.0.0/24','PASS'),('IpAddress','CidrBlock','10.0.1.1','10.0.0.0/24','FAIL'),
 ('Ipv6Address','Ipv6CidrBlock','2001:db8::1','2001:db8::/64','PASS'),('Ipv6Address','Ipv6CidrBlock','2001:db9::1','2001:db8::/64','FAIL'),
 ('IpAddress','CidrBlock',UNKNOWN,'10.0.0.0/24','NEEDS_REVIEW'),('IpAddress','CidrBlock','10.0.0.1','10.0.0.2/24','NEEDS_REVIEW')])
def test_efs_subnet(key,cidrkey,ip,cidr,expected):
    assert evaluate('EFS::MountTarget','EFS_MOUNT_IP_SUBNET',{key:ip},'EC2::Subnet',{cidrkey:cidr},'SubnetId')['verdict']==expected


@pytest.mark.parametrize('domain,expected',[('RETAIL','PASS'),('CUSTOM','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_forecast(domain,expected):
    assert evaluate('Forecast::DatasetGroup','FORECAST_DATASET_DOMAINS',{'Domain':'RETAIL','DatasetArns':['dataset']},'Forecast::Dataset',{'Domain':domain},'DatasetArns/0')['verdict']==expected


@pytest.mark.parametrize('kind,rule',[('ApplicationOutput','KINESISANALYTICS_OUTPUT_SQL'),('ApplicationReferenceDataSource','KINESISANALYTICS_REFERENCE_SQL')])
@pytest.mark.parametrize('runtime,expected',[('SQL-1_0','PASS'),('FLINK-1_20','FAIL'),('ZEPPELIN-FLINK-3_0','FAIL'),('FUTURE','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_sql(kind,rule,runtime,expected):
    assert evaluate('KinesisAnalyticsV2::'+kind,rule,{},'KinesisAnalyticsV2::Application',{'RuntimeEnvironment':runtime},'ApplicationName')['verdict']==expected


@pytest.mark.parametrize('fifo,dedup,expected',[(True,True,'PASS'),(True,False,'FAIL'),(False,False,'NOT_APPLICABLE'),(True,UNKNOWN,'NEEDS_REVIEW'),(UNKNOWN,False,'NEEDS_REVIEW')])
def test_fifo(fifo,dedup,expected):
    assert evaluate('Scheduler::Schedule','SCHEDULER_FIFO_DEDUP',{},'SQS::Queue',{'FifoQueue':fifo,'ContentBasedDeduplication':dedup},'Target/Arn')['verdict']==expected


@pytest.mark.parametrize('other,expected',[('a'*64,'PASS'),('b'*64,'FAIL'),('A'*64,'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_hash(other,expected):
    assert evaluate('Wisdom::MessageTemplateVersion','WISDOM_TEMPLATE_HASH_MATCH',{'MessageTemplateContentSha256':'a'*64},'Wisdom::MessageTemplate',{'MessageTemplateContentSha256':other},'MessageTemplateArn')['verdict']==expected


@pytest.mark.parametrize('tenancy,expected',[('default','PASS'),('dedicated','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_vpc_tenancy(tenancy,expected):
    assert evaluate('WorkSpacesWeb::NetworkSettings','WORKSPACESWEB_VPC_TENANCY',{},'EC2::VPC',{'InstanceTenancy':tenancy},'VpcId')['verdict']==expected


def test_checker_integration():
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1];r=target('one','AWS::WorkSpacesWeb::NetworkSettings');p=target('vpc','AWS::EC2::VPC',InstanceTenancy='dedicated')
    row=next(x for x in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r,[p],[('VpcId','vpc')]))['results'] if x['rule_id']=='WORKSPACESWEB_VPC_TENANCY')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
