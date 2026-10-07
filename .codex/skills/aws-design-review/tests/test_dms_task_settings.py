import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.dms.task_settings import evaluate_dms_task_settings
from test_autoscaling_group_and_scaling_policy import target,linked_design
from test_template_dependencies import link


def consumer(r,side,kind='AWS::DMS::ReplicationTask',mode='cdc'):
    task=target('task',kind,**{('MigrationType' if kind.endswith('ReplicationTask') else 'ReplicationType'):mode,side+'EndpointArn':r.id})
    d=linked_design(r,[task],[]);link(d,task,side+'EndpointArn',r)
    return d,task


@pytest.mark.parametrize('kind',['AWS::DMS::ReplicationTask','AWS::DMS::ReplicationConfig'])
@pytest.mark.parametrize('mode',['full-load','cdc','full-load-and-cdc','future',{'$state':'UNRESOLVED'}])
@pytest.mark.parametrize('path',['missing','','cdc-files',{'$state':'UNRESOLVED'}])
def test_cdc_path(kind,mode,path):
    r=target('source','AWS::DMS::Endpoint',EngineName='s3',EndpointType='source',S3Settings={} if path=='missing' else {'CdcPath':path})
    d,_=consumer(r,'Source',kind,mode)
    expected='NOT_APPLICABLE' if mode=='full-load' else 'NEEDS_REVIEW'
    if mode in ('cdc','full-load-and-cdc'):expected='FAIL' if path in ('missing','') else 'PASS' if path=='cdc-files' else 'NEEDS_REVIEW'
    assert evaluate_dms_task_settings(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('mode',['conditional','task_template','endpoint_template','region','external','extra'])
def test_cdc_unknown_evidence(mode):
    r=target('source','AWS::DMS::Endpoint',EngineName='s3',EndpointType='source',S3Settings={})
    d,task=consumer(r,'Source')
    if mode=='conditional':d.relations[0].condition='maybe'
    if mode=='task_template':task.template=TemplateContext(state='UNRESOLVED')
    if mode=='endpoint_template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='region':task.scope.region='us-east-1'
    if mode=='external':d.relations=[]
    if mode=='extra':r.fields.append(target('x',r.type,ExtraConnectionAttributes='cdcPath=somewhere').fields[0])
    assert evaluate_dms_task_settings(d,r)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('flag',[True,False,{'$state':'UNRESOLVED'},'missing'])
@pytest.mark.parametrize('mode',['full-load','cdc','full-load-and-cdc'])
def test_explicit_ids_applicability(flag,mode):
    r=target('target','AWS::DMS::Endpoint',EngineName='redshift',EndpointType='target',RedshiftSettings={} if flag=='missing' else {'ExplicitIds':flag})
    d,_=consumer(r,'Target',mode=mode)
    expected='NOT_APPLICABLE' if flag is False or flag=='missing' else 'NEEDS_REVIEW'
    if flag is True:expected={'full-load':'PASS','cdc':'NOT_APPLICABLE','full-load-and-cdc':'NEEDS_REVIEW'}[mode]
    assert next(f for f in evaluate_dms_task_settings(d,r) if f['rule_id']=='DMS_REDSHIFT_EXPLICIT_IDS_APPLICABILITY')['verdict']==expected


@pytest.mark.parametrize('source_flag',[True,False,{'$state':'UNRESOLVED'},'missing'])
@pytest.mark.parametrize('target_flag',[True,False,{'$state':'UNRESOLVED'},'missing'])
def test_boolean_pair(source_flag,target_flag):
    source=target('source','AWS::DMS::Endpoint',EngineName='postgres',EndpointType='source',PostgreSqlSettings={} if source_flag=='missing' else {'MapBooleanAsBoolean':source_flag})
    dest=target('target',source.type,EngineName='redshift',EndpointType='target',RedshiftSettings={} if target_flag=='missing' else {'MapBooleanAsBoolean':target_flag})
    d,task=consumer(source,'Source');d.resources.append(dest);link(d,task,'TargetEndpointArn',dest)
    actual=evaluate_dms_task_settings(d,source)[0]['verdict']
    expected='NOT_APPLICABLE' if source_flag is False or source_flag=='missing' else 'NEEDS_REVIEW'
    if source_flag is True:expected='PASS' if target_flag is True else 'NOT_APPLICABLE' if target_flag is False or target_flag=='missing' else 'NEEDS_REVIEW'
    assert actual==expected


def test_cdc_failure_survives_conditional_other_consumer():
    r=target('source','AWS::DMS::Endpoint',EngineName='s3',EndpointType='source')
    d,task=consumer(r,'Source')
    other=target('other',task.type,MigrationType='cdc');d.resources.append(other);link(d,other,'SourceEndpointArn',r,'maybe')
    assert evaluate_dms_task_settings(d,r)[0]['verdict']=='FAIL'


def test_explicit_ids_mixed_consumers_are_not_all_applicable():
    r=target('target','AWS::DMS::Endpoint',EngineName='redshift',EndpointType='target',RedshiftSettings={'ExplicitIds':True})
    d,task=consumer(r,'Target',mode='full-load')
    other=target('other',task.type,MigrationType='cdc');d.resources.append(other);link(d,other,'TargetEndpointArn',r)
    assert evaluate_dms_task_settings(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('source','AWS::DMS::Endpoint',EngineName='s3',EndpointType='source')
    d,_=consumer(r,'Source')
    assert any(f['rule_id']=='DMS_SOURCE_CDC_PATH' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results'])


@pytest.mark.parametrize('fmt',['parquet','Parquet'])
@pytest.mark.parametrize('mode',['full-load','cdc','full-load-and-cdc'])
@pytest.mark.parametrize('path,expected',[('missing','PASS'),('cdc-files','FAIL'),({'$state':'UNRESOLVED'},'NEEDS_REVIEW')])
def test_parquet_must_not_use_cdc_path(fmt,mode,path,expected):
    settings={'DataFormat':fmt}
    if path!='missing':settings['CdcPath']=path
    r=target('source','AWS::DMS::Endpoint',EngineName='s3',EndpointType='source',S3Settings=settings)
    d,_=consumer(r,'Source',mode=mode)
    assert evaluate_dms_task_settings(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('fmt',['future',{'$state':'UNRESOLVED'}])
def test_unknown_s3_format_is_not_assumed_csv(fmt):
    r=target('source','AWS::DMS::Endpoint',EngineName='s3',EndpointType='source',S3Settings={'DataFormat':fmt})
    d,_=consumer(r,'Source')
    assert evaluate_dms_task_settings(d,r)[0]['verdict']=='NEEDS_REVIEW'
