import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(kind,rule,**props):
    resource=target('resource','AWS::'+kind,**props)
    return [f for f in run_resource_checks(linked_design(resource),resource) if f['rule_id']==rule]


@pytest.mark.parametrize('parameter,expected',[
    ({'Dynamic':True,'Required':True},'FAIL'),({'Dynamic':True,'Required':False},'PASS'),
    ({'Dynamic':False,'Required':True},'PASS'),({'Dynamic':UNKNOWN,'Required':True},'NEEDS_REVIEW'),
    ({'Required':True},'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_extension(parameter,expected):
    assert check('AppConfig::Extension','APPCONFIG_DYNAMIC_REQUIRED',Parameters={'parameter':parameter})[0]['verdict']==expected


def test_escaped_map_keys_held():
    assert check('AppConfig::Extension','APPCONFIG_DYNAMIC_REQUIRED',Parameters={'key/with~escape':{'Dynamic':True,'Required':True}})[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('attribute,expected',[
    ({'BooleanValue':False,'NumberValue':0},'FAIL'),({'StringValue':'','StringArray':[]},'FAIL'),
    ({'BooleanValue':False},'PASS'),({},'PASS'),({'NumberValue':UNKNOWN},'NEEDS_REVIEW'),
    ({'Future':1},'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
@pytest.mark.parametrize('container',['Control','Treatments'])
def test_attribute_members(attribute,expected,container):
    treatment={'AttributeValues':{'key':attribute}}
    props={container:[treatment] if container=='Treatments' else treatment}
    assert check('AppConfig::ExperimentDefinition','APPCONFIG_ATTRIBUTE_UNION',**props)[0]['verdict']==expected


@pytest.mark.parametrize('event',[True,False])
@pytest.mark.parametrize('types,expected',[(['AWS_LAMBDA','AWS_LAMBDA'],'FAIL'),
    (['AWS_LAMBDA','AWS_IAM'],'PASS'),(['AWS_IAM'],'PASS'),(['AWS_LAMBDA',UNKNOWN],'NEEDS_REVIEW'),
    (['AWS_LAMBDA','FUTURE'],'NEEDS_REVIEW'),(['AWS_LAMBDA','AWS_LAMBDA',UNKNOWN],'FAIL')])
def test_authorizers(event,types,expected):
    if event:
        props={'EventConfig':{'AuthProviders':[{'AuthType':t} for t in types]}}
    else:
        props={'AuthenticationType':types[0],'AdditionalAuthenticationProviders':[{'AuthenticationType':t} for t in types[1:]]}
    assert check('AppSync::Api' if event else 'AppSync::GraphQLApi',
        'APPSYNC_EVENT_LAMBDA_COUNT' if event else 'APPSYNC_GRAPHQL_LAMBDA_COUNT',**props)[0]['verdict']==expected


@pytest.mark.parametrize('key,expected',[('Ab','PASS'),('A_1','PASS'),('A'*64,'PASS'),('A','FAIL'),
    ('A'*65,'FAIL'),('1A','FAIL'),('A-B','FAIL'),('Aé','NEEDS_REVIEW'),('${Name}','NEEDS_REVIEW')])
def test_environment_keys(key,expected):
    assert check('AppSync::GraphQLApi','APPSYNC_ENVIRONMENT_KEYS',EnvironmentVariables={key:'value'})[0]['verdict']==expected


@pytest.mark.parametrize('values,expected',[
    (['*'],'PASS'),(['arn:aws:s3:::example'],'PASS'),(['*','arn:aws:s3:::example'],'FAIL'),
    (['*',UNKNOWN],'NEEDS_REVIEW'),(['*','not-arn'],'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_restore_selection(values,expected):
    assert check('Backup::RestoreTestingSelection','BACKUP_RESTORE_SELECTION_EXCLUSIVE',ProtectedResourceArns=values)[0]['verdict']==expected


@pytest.mark.parametrize('copy',[False,True])
@pytest.mark.parametrize('cold,delete,expected',[(0,89,'FAIL'),(0,90,'PASS'),(30,119,'FAIL'),
    (30,120,'PASS'),(-1,-1,'NEEDS_REVIEW'),(30,-1,'NEEDS_REVIEW'),(UNKNOWN,120,'NEEDS_REVIEW'),
    (True,90,'NEEDS_REVIEW'),(0,90.0,'NEEDS_REVIEW')])
def test_backup_retention(copy,cold,delete,expected):
    lifecycle={'Lifecycle':{'MoveToColdStorageAfterDays':cold,'DeleteAfterDays':delete}}
    rule={'CopyActions':[lifecycle]} if copy else lifecycle
    assert check('Backup::BackupPlan','BACKUP_COLD_RETENTION',BackupPlan={'BackupPlanRule':[rule]})[0]['verdict']==expected


@pytest.mark.parametrize('count,wildcard,expected',[(30,True,'PASS'),(31,True,'FAIL'),
    (500,False,'PASS'),(501,False,'FAIL')])
def test_exclusion_limit(count,wildcard,expected):
    arns=['arn:aws:s3:::bucket'+str(i) for i in range(count)]
    if wildcard:arns[0]+='*'
    assert check('Backup::BackupSelection','BACKUP_EXCLUSION_WILDCARD_LIMIT',BackupSelection={'NotResources':arns})[0]['verdict']==expected


@pytest.mark.parametrize('values,expected',[([UNKNOWN],'NEEDS_REVIEW'),(['arn:aws:s3:::a?'],'NEEDS_REVIEW'),
    (['arn:aws:s3:::a*']+[UNKNOWN]*30,'FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_exclusion_unresolved(values,expected):
    assert check('Backup::BackupSelection','BACKUP_EXCLUSION_WILDCARD_LIMIT',BackupSelection={'NotResources':values})[0]['verdict']==expected


@pytest.mark.parametrize('identifiers,expected',[
    (['UserA*','UserA1'],'FAIL'),(['UserA1','UserA*'],'FAIL'),(['User*','UserA*'],'FAIL'),
    (['UserA','UserA'],'FAIL'),(['UserA*','UserB*'],'PASS'),(['UserA','UserA1'],'PASS'),
    (['UserA*','userA1'],'PASS'),(['UserA',UNKNOWN],'NEEDS_REVIEW'),
    (['UserA*','UserA1',UNKNOWN],'FAIL'),(['User_A','UserB'],'NEEDS_REVIEW'),
    (['*','UserA'],'NEEDS_REVIEW'),([], 'PASS')])
def test_share_overlap(identifiers,expected):
    assert check('Batch::SchedulingPolicy','BATCH_SHARE_NONOVERLAP',FairsharePolicy={
        'ShareDistribution':[{'ShareIdentifier':s} for s in identifiers]})[0]['verdict']==expected


@pytest.mark.parametrize('selections,expected',[
    ([['*']],'PASS'),([['*','arn:aws:s3:::bucket']],'FAIL'),([[UNKNOWN]],'NEEDS_REVIEW'),
    ([['arn:aws:s3:::a'],['arn:aws:s3:::b']],'PASS'),([['arn:aws:s3:::a?']],'NEEDS_REVIEW')])
def test_tiering_selection(selections,expected):
    assert check('Backup::TieringConfiguration','BACKUP_TIERING_SELECTION',ResourceSelection=[{'Resources':s} for s in selections])[0]['verdict']==expected


@pytest.mark.parametrize('count,expected',[(100,'PASS'),(101,'FAIL')])
def test_tiering_total(count,expected):
    arns=['arn:aws:s3:::bucket'+str(i) for i in range(count)]
    assert check('Backup::TieringConfiguration','BACKUP_TIERING_SELECTION',ResourceSelection=[
        {'Resources':arns[:50]},{'Resources':arns[50:]}])[0]['verdict']==expected


def test_tiering_duplicate_count_held():
    assert check('Backup::TieringConfiguration','BACKUP_TIERING_SELECTION',ResourceSelection=[
        {'Resources':['arn:aws:s3:::bucket']*101}])[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('parents,overrides,expected',[
    (['m5','g5'],[['m5.large'],['m5.2xlarge']],'PASS'),
    (['m5'],[['c5.large']],'FAIL'),(['m5.large'],[['m5']],'FAIL'),
    (['m5'],[['m5'],['m5.large']],'FAIL'),(['m5'],[['m5.large','m5.large']],'FAIL'),
    (['m5'],[['optimal']],'FAIL'),(['m5'],[['default_x86_64']],'FAIL'),
    (['m5'],[['default_arm64']],'FAIL'),([UNKNOWN],[['m5.large']],'NEEDS_REVIEW'),
    (['m5'],[[UNKNOWN]],'NEEDS_REVIEW'),(['optimal'],[['m5.large']],'NEEDS_REVIEW'),
    (['m5',UNKNOWN],[['m5.large']],'PASS'),(['m5'],[['m5.large',UNKNOWN],['m5.large']],'FAIL'),
    (['m5'],[['unsupported']],'NEEDS_REVIEW'),(['m5.large'],[['m5.large']],'PASS'),
    (['m5'],[[]],'NEEDS_REVIEW')])
def test_override_targets(parents,overrides,expected):
    assert check('Batch::ComputeEnvironment','BATCH_OVERRIDE_TARGETS',ComputeResources={
        'InstanceTypes':parents,'LaunchTemplate':{'Overrides':[{'TargetInstanceTypes':s} for s in overrides]}})[0]['verdict']==expected
