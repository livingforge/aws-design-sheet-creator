from pathlib import Path
import pytest
from aws_design_sheet.checks.docdb.windows import evaluate_docdb_windows
from aws_design_sheet.checks.dms.windows import evaluate_dms_windows
from aws_design_sheet.checks.entityresolution.windows import evaluate_entityresolution_windows
from aws_design_sheet.checks.fsx.preferred_subnet import evaluate_fsx_preferred_subnet
from aws_design_sheet.checks.registry import combine
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
windows_checks = combine(evaluate_docdb_windows, evaluate_dms_windows, evaluate_entityresolution_windows, evaluate_fsx_preferred_subnet)


def check(kind,**props):
    r=target('subject',kind,**props)
    return windows_checks(linked_design(r),r)


@pytest.mark.parametrize('kind',['AWS::DocDB::DBCluster','AWS::DocDB::DBInstance','AWS::DMS::ReplicationConfig','AWS::DMS::ReplicationInstance'])
@pytest.mark.parametrize('text,expected',[('mon:00:00-mon:00:29','FAIL'),('Mon:00:00-Mon:00:30','PASS'),
    ('sun:23:45-mon:00:15','PASS'),('sun:23:45-mon:00:14','FAIL'),('mon:23:45-tue:00:15','PASS'),
    ('mon:00:00-mon:00:00','NEEDS_REVIEW'),('mon:24:00-mon:00:30','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_weekly(kind,text,expected):
    props={'PreferredMaintenanceWindow':text}
    if kind=='AWS::DMS::ReplicationConfig':props={'ComputeConfig':props}
    assert check(kind,**props)[0]['verdict']==expected


@pytest.mark.parametrize('backup,maintenance,expected',[
    ('01:00-01:30','mon:01:30-mon:02:00','PASS'),('01:00-01:30','mon:00:30-mon:01:00','PASS'),
    ('01:00-01:30','mon:01:29-mon:02:00','FAIL'),('23:45-00:15','sun:23:55-mon:00:25','FAIL'),
    ('23:45-00:15','mon:00:00-mon:00:30','FAIL'),('23:45-00:15','sun:00:15-sun:00:45','PASS'),
    ('01:00-01:30','sun:23:00-mon:02:00','FAIL'),('01:00-01:30',UNKNOWN,'NEEDS_REVIEW')])
def test_backup_overlap(backup,maintenance,expected):
    rows=check('AWS::DocDB::DBCluster',PreferredBackupWindow=backup,PreferredMaintenanceWindow=maintenance)
    assert rows[-1]['verdict']==expected


@pytest.mark.parametrize('backup,expected',[('23:45-00:14','FAIL'),('23:45-00:15','PASS'),('02:00-02:00','NEEDS_REVIEW')])
def test_backup_minimum(backup,expected):
    rows=check('AWS::DocDB::DBCluster',PreferredBackupWindow=backup)
    assert rows[0]['verdict']==expected and rows[-1]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('namespace',[False,True])
@pytest.mark.parametrize('mode,expected',[('present','PASS'),('missing','FAIL'),('field_only','FAIL'),('unknown','NEEDS_REVIEW'),
    ('external','NEEDS_REVIEW'),('conditional','NEEDS_REVIEW'),('multiple','NEEDS_REVIEW')])
def test_schema_keys(namespace,mode,expected):
    kind='AWS::EntityResolution::'+('IdNamespace' if namespace else 'IdMappingWorkflow')
    key='SchemaName' if namespace else 'SchemaArn'
    rules={'RuleBasedProperties':{'Rules':[{'MatchingKeys':['email']}]}}
    props={'IdMappingWorkflowProperties':[rules]} if namespace else {'IdMappingTechniques':rules}
    props['InputSourceConfig']=[{key:'schema'}]
    r=target('subject',kind,**props)
    field={'FieldName':'email'} if mode=='field_only' else {'MatchKey':UNKNOWN if mode=='unknown' else 'other' if mode=='missing' else 'email'}
    schema=target('schema','AWS::EntityResolution::SchemaMapping',MappedInputFields=[field])
    second=target('second','AWS::EntityResolution::SchemaMapping',MappedInputFields=[{'MatchKey':'email'}])
    d=linked_design(r,[schema,second],[] if mode=='external' else [('InputSourceConfig/0/'+key,'schema')])
    if mode=='conditional':d.relations[0].condition='flag'
    if mode=='multiple':
        # Recreate the resource so the second input is represented in normal field data.
        props['InputSourceConfig'].append({key:'second'})
        r=target('subject',kind,**props)
        d=linked_design(r,[schema,second],[('InputSourceConfig/0/'+key,'schema'),('InputSourceConfig/1/'+key,'second')])
    assert windows_checks(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('owner',['WindowsConfiguration','OntapConfiguration'])
@pytest.mark.parametrize('subnets,preferred,expected',[(['a','b'],'a','PASS'),(['a','b'],'c','FAIL'),
    (['a',UNKNOWN],'c','NEEDS_REVIEW'),(['a',UNKNOWN],'a','PASS'),(['a'],UNKNOWN,'NEEDS_REVIEW')])
def test_preferred_subnet(owner,subnets,preferred,expected):
    assert check('AWS::FSx::FileSystem',SubnetIds=subnets,**{owner:{'DeploymentType':'MULTI_AZ_1','PreferredSubnetId':preferred}})[0]['verdict']==expected


def test_other_fsx_deployment_held():
    assert check('AWS::FSx::FileSystem',SubnetIds=['a'],OpenZFSConfiguration={'PreferredSubnetId':'b'})[0]['verdict']=='NEEDS_REVIEW'


def test_checker_integration():
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('subject','AWS::DocDB::DBInstance',PreferredMaintenanceWindow='mon:00:00-mon:00:29')
    result=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))
    row=next(r for r in result['results'] if r['rule_id']=='DOCDB_INSTANCE_WINDOW')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
