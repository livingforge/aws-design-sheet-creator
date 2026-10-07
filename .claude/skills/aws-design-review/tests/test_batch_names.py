import pytest
from aws_design_sheet.checks.batch.names import evaluate_batch_names
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(rule,**props):
    r=target('job','AWS::Batch::JobDefinition',**props)
    return [f for f in evaluate_batch_names(linked_design(r),r) if f['rule_id']==rule]


@pytest.mark.parametrize('container,expected',[
    ({'LogConfiguration':{'LogDriver':'awslogs'}},'PASS'),
    ({'LogConfiguration':{'LogDriver':'logentries'}},'NEEDS_REVIEW'),
    ({'LogConfiguration':{'LogDriver':'custom'}},'FAIL'),
    ({'ResourceRequirements':[{'Type':'GPU'}]},'PASS'),
    ({'ResourceRequirements':[{'Type':'CPU'}]},'FAIL'),
    ({'ResourceRequirements':[{'Type':UNKNOWN}]},'NEEDS_REVIEW'),
    ({'Ulimits':[{'Name':'nofile'}]},'PASS'),({'Ulimits':[{'Name':'file'}]},'FAIL')])
@pytest.mark.parametrize('node',[False,True])
def test_nested_enums(container,expected,node):
    props={'NodeProperties':{'NodeRangeProperties':[{'Container':container}]}} if node else {'EcsProperties':{'TaskProperties':[{'Containers':[container]}]}}
    assert check('BATCH_NESTED_ENUM',**props)[0]['verdict']==expected


@pytest.mark.parametrize('driver,expected',[('awslogs','PASS'),('splunk','PASS'),('awsfirelens','FAIL'),('logentries','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_fargate_log(driver,expected):
    assert check('BATCH_NESTED_FARGATE_LOG',PlatformCapabilities=['FARGATE'],EcsProperties={'TaskProperties':[
        {'Containers':[{'LogConfiguration':{'LogDriver':driver}}]}]})[0]['verdict']==expected


@pytest.mark.parametrize('name,expected',[('Volume_1','PASS'),('a'*255,'PASS'),('a'*256,'FAIL'),
    ('a/b','FAIL'),('a.b','FAIL'),('','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_volume_name(name,expected):
    assert check('BATCH_VOLUME_NAME',ContainerProperties={'Volumes':[{'Name':name}]})[0]['verdict']==expected


@pytest.mark.parametrize('secret',[False,True])
@pytest.mark.parametrize('name,expected',[('volume-1','PASS'),('Bad','FAIL'),('bad_name','FAIL'),
    ('-bad','FAIL'),('a..b','FAIL'),('a'*254,'FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_eks_dns(name,expected,secret):
    volume={'Secret':{'SecretName':name}} if secret else {'Name':name}
    assert check('BATCH_EKS_DNS_NAMES',EksProperties={'PodProperties':{'Volumes':[volume]}})[0]['verdict']==expected


def test_eks_volume_subdomain_disagreement():
    rows=check('BATCH_EKS_DNS_NAMES',EksProperties={'PodProperties':{
        'Volumes':[{'Name':'a.b','Secret':{'SecretName':'a.b'}}]}})
    assert [r['verdict'] for r in rows]==['NEEDS_REVIEW','PASS']


@pytest.mark.parametrize('key,val,expected',[
    ('name','a'*255,'PASS'),('name','a'*256,'FAIL'),('prefix/name','a'*256,'NEEDS_REVIEW'),
    ('name',UNKNOWN,'NEEDS_REVIEW'),('name','','PASS')])
def test_annotation_values(key,val,expected):
    assert check('BATCH_EKS_ANNOTATION_VALUES',EksProperties={'PodProperties':{
        'Metadata':{'Annotations':{key:val}}}})[0]['verdict']==expected


@pytest.mark.parametrize('key,val,expected',[
    ('app','release_1','PASS'),('app','','PASS'),('app','a'*64,'FAIL'),('a'*64,'v','FAIL'),
    ('app','bad?','FAIL'),('app','a.b','NEEDS_REVIEW'),('prefix/app','v','NEEDS_REVIEW'),
    ('app','-v','NEEDS_REVIEW'),('app',UNKNOWN,'NEEDS_REVIEW')])
def test_labels(key,val,expected):
    assert check('BATCH_EKS_LABELS',EksProperties={'PodProperties':{'Metadata':{'Labels':{key:val}}}})[0]['verdict']==expected
