import pytest
from aws_design_sheet.checks.batch.metadata import evaluate_batch_metadata
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(rule,**props):
    r=target('job','AWS::Batch::JobDefinition',**props)
    return [f for f in evaluate_batch_metadata(linked_design(r),r) if f['rule_id']==rule]


@pytest.mark.parametrize('key',['LinuxParameters','Privileged','User','Ulimits','ReadonlyRootFilesystem'])
def test_windows_task_fields(key):
    rows=check('BATCH_NESTED_WINDOWS_FIELDS',EcsProperties={'TaskProperties':[{
        'RuntimePlatform':{'OperatingSystemFamily':'WINDOWS_SERVER_2022_CORE'},'Containers':[{key:False}]}]})
    assert rows[0]['verdict']=='FAIL'


@pytest.mark.parametrize('arch,expected',[('X86_64','PASS'),('ARM64','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_nested_windows_arch(arch,expected):
    assert check('BATCH_NESTED_WINDOWS_FIELDS',NodeProperties={'NodeRangeProperties':[{'Container':{
        'RuntimePlatform':{'OperatingSystemFamily':'WINDOWS_SERVER_2019_FULL','CpuArchitecture':arch}}}]})[0]['verdict']==expected


@pytest.mark.parametrize('os,expected',[('WINDOWS_SERVER_2022_FULL','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('FUTURE','NEEDS_REVIEW')])
def test_windows_efs(os,expected):
    assert check('BATCH_NESTED_WINDOWS_FIELDS',ContainerProperties={
        'RuntimePlatform':{'OperatingSystemFamily':os},'Volumes':[{'EfsVolumeConfiguration':{}}]})[0]['verdict']==expected


@pytest.mark.parametrize('key,expected',[
    ('name','PASS'),('example.com/My_Name.1','PASS'),('a'*63,'PASS'),('a'*64,'FAIL'),
    ('/name','FAIL'),('example.com/','FAIL'),('a/b/c','FAIL'),('Upper.com/name','FAIL'),
    ('bad_.com/name','FAIL'),('example.com/-name','FAIL'),('${Key}','NEEDS_REVIEW'),
    ('.name','FAIL'),('a'*63+'.com/name','PASS'),('a'*64+'.com/name','PASS'),
    ('a'*253+'/name','PASS'),('a'*254+'/name','FAIL')])
def test_annotation_keys(key,expected):
    assert check('BATCH_EKS_ANNOTATION_KEYS',EksProperties={'PodProperties':{
        'Metadata':{'Annotations':{key:UNKNOWN}}}})[0]['verdict']==expected
