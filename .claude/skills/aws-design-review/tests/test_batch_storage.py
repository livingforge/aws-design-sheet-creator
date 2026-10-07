import pytest
from aws_design_sheet.checks.batch.storage import evaluate_batch_storage
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(rule,**props):
    r=target('job','AWS::Batch::JobDefinition',**props)
    return [f for f in evaluate_batch_storage(linked_design(r),r) if f['rule_id']==rule]


@pytest.mark.parametrize('task',[False,True])
@pytest.mark.parametrize('version,expected',[('1.3.0','FAIL'),('1.4.0','PASS'),('1.10.0','PASS'),('2.0.0','PASS'),('1.04.0','NEEDS_REVIEW'),('LATEST','NEEDS_REVIEW'),(None,'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_efs_version(task,version,expected):
    owner={'Volumes':[{'EfsVolumeConfiguration':{'FileSystemId':'fs-123'}}]}
    if version is not None:
        if task:owner['PlatformVersion']=version
        else:owner['FargatePlatformConfiguration']={'PlatformVersion':version}
    props={'EcsProperties':{'TaskProperties':[owner]}} if task else {'ContainerProperties':owner}
    assert check('BATCH_EFS_FARGATE_VERSION',PlatformCapabilities=['FARGATE'],**props)[0]['verdict']==expected


@pytest.mark.parametrize('platform,host,expected',[(['FARGATE'],{},'FAIL'),(['FARGATE'],{'SourcePath':'/data'},'FAIL'),(['FARGATE'],UNKNOWN,'NEEDS_REVIEW'),(UNKNOWN,{},'NEEDS_REVIEW')])
def test_host(platform,host,expected):
    assert check('BATCH_FARGATE_HOST_VOLUME',PlatformCapabilities=platform,ContainerProperties={'Volumes':[{'Host':host}]})[0]['verdict']==expected


def test_ec2_efs_and_host_do_not_apply():
    assert not check('BATCH_EFS_FARGATE_VERSION',PlatformCapabilities=['EC2'],ContainerProperties={'Volumes':[{'Host':{},'EfsVolumeConfiguration':{}}]})
    assert not check('BATCH_FARGATE_HOST_VOLUME',PlatformCapabilities=['EC2'],ContainerProperties={'Volumes':[{'Host':{}}]})


@pytest.mark.parametrize('options,expected',[
    ({},'PASS'),({'enable-ecs-log-metadata':'false'},'PASS'),({'enable-ecs-log-metadata':'yes'},'FAIL'),
    ({'enable-ecs-log-metadata':UNKNOWN},'NEEDS_REVIEW'),({'future-option':'yes'},'NEEDS_REVIEW'),
    ({'config-file-type':'s3','config-file-value':'arn:aws:s3:::bucket/custom.conf'},'FAIL'),
    ({'config-file-type':'file','config-file-value':'/custom.conf'},'NEEDS_REVIEW'),
    ({'config-file-type':'file'},'FAIL'),({'config-file-value':'/custom.conf'},'FAIL'),
    ({'config-file-type':'file','config-file-value':'/fluent-bit/etc/fluent-bit.conf'},'FAIL'),
    ({'config-file-type':'file','config-file-value':'/fluentd/etc/fluent.conf'},'FAIL'),
    (UNKNOWN,'NEEDS_REVIEW')])
def test_firelens_options(options,expected):
    assert check('BATCH_FIRELENS_OPTIONS',PlatformCapabilities=['FARGATE'],EcsProperties={'TaskProperties':[
        {'Containers':[{'FirelensConfiguration':{'Type':'fluentbit','Options':options}}]}]})[0]['verdict']==expected


@pytest.mark.parametrize('router,expected',[('fluentbit','PASS'),('fluentd','PASS'),('other','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_node_firelens(router,expected):
    assert check('BATCH_FIRELENS_OPTIONS',NodeProperties={'NodeRangeProperties':[{'EcsProperties':{'TaskProperties':[
        {'Containers':[{'FirelensConfiguration':{'Type':router}}]}]}}]})[0]['verdict']==expected
