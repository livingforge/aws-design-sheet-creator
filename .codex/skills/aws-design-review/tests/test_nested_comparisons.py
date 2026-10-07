import pytest
from aws_design_sheet.checks.emr.cluster_nested_limits import evaluate_emr_cluster_nested_limits
from aws_design_sheet.checks.evs.design_host_duplicates import evaluate_evs_design_host_duplicates
from aws_design_sheet.checks.medialive.channel_and_input import evaluate_medialive_channel_and_input
from aws_design_sheet.checks.registry import combine
local97_nested_checks = combine(evaluate_emr_cluster_nested_limits, evaluate_evs_design_host_duplicates, evaluate_medialive_channel_and_input)
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(kind,rule,props):
    r=target('one','AWS::'+kind,**props)
    return [x for x in local97_nested_checks(linked_design(r),r) if x['rule_id']==rule]


@pytest.mark.parametrize('fleet',['MasterInstanceFleet','CoreInstanceFleet','TaskInstanceFleets'])
@pytest.mark.parametrize('path,maximum',[('LaunchSpecifications/SpotSpecification',1440),('ResizeSpecifications/SpotResizeSpecification',10080),('ResizeSpecifications/OnDemandResizeSpecification',10080)])
@pytest.mark.parametrize('case',['below','minimum','maximum','above','unknown'])
def test_emr_timeout_bounds(fleet,path,maximum,case):
    values={'below':4,'minimum':5,'maximum':maximum,'above':maximum+1,'unknown':UNKNOWN};a,b=path.split('/')
    item={a:{b:{'TimeoutDurationMinutes':values[case]}}}
    rows=check('EMR::Cluster','EMR_CLUSTER_NESTED_LIMITS',{'Instances':{fleet:[item] if fleet.startswith('Task') else item}})
    assert rows[0]['verdict']==('FAIL' if case in ('below','above') else 'NEEDS_REVIEW' if case=='unknown' else 'PASS')


@pytest.mark.parametrize('group',['MasterInstanceGroup','CoreInstanceGroup','TaskInstanceGroups'])
@pytest.mark.parametrize('name,expected',[('one','FAIL'),('two','PASS'),(UNKNOWN,'NEEDS_REVIEW')])
def test_emr_scaling_names(group,name,expected):
    item={'AutoScalingPolicy':{'Rules':[{'Name':'one'},{'Name':name}]}}
    assert check('EMR::Cluster','EMR_CLUSTER_NESTED_LIMITS',{'Instances':{group:[item] if group.startswith('Task') else item}})[0]['verdict']==expected


@pytest.mark.parametrize('fleet',[False,True])
@pytest.mark.parametrize('kind,expected',[('gp3','PASS'),('gp2','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_emr_throughput(fleet,kind,expected):
    config={'EbsConfiguration':{'EbsBlockDeviceConfigs':[{'VolumeSpecification':{'VolumeType':kind,'Throughput':200}}]}}
    if fleet:config={'InstanceTypeConfigs':[config]}
    assert check('EMR::Cluster','EMR_CLUSTER_NESTED_LIMITS',{'Instances':{'CoreInstanceFleet' if fleet else 'CoreInstanceGroup':config}})[0]['verdict']==expected


@pytest.mark.parametrize('name,expected',[('same','FAIL'),('different','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_evs_across_environments(name,expected):
    r=target('one','AWS::EVS::Environment',Hosts=[{'HostName':'same'}]);other=target('two',r.type,Hosts=[{'HostName':name}])
    row=next(x for x in local97_nested_checks(linked_design(r,[other]),r) if x['rule_id']=='EVS_DESIGN_HOST_DUPLICATES')
    assert row['verdict']==expected


@pytest.mark.parametrize('name,expected',[('same','FAIL'),('different','PASS'),(UNKNOWN,'NEEDS_REVIEW')])
def test_caption_names_across_attachments(name,expected):
    props={'InputAttachments':[{'InputSettings':{'CaptionSelectors':[{'Name':'same'}]}},{'InputSettings':{'CaptionSelectors':[{'Name':name}]}}]}
    assert check('MediaLive::Channel','MEDIALIVE_CHANNEL_CAPTION_NAMES',props)[0]['verdict']==expected


@pytest.mark.parametrize('bitrate,mode,expected',[(1999,'CBR','FAIL'),(2000,'VBR','PASS'),(1999,'QVBR','NEEDS_REVIEW'),(UNKNOWN,'CBR','NEEDS_REVIEW')])
def test_smooth_rounding_and_ignored_modes(bitrate,mode,expected):
    videos=[{'Name':'one','CodecSettings':{'H264Settings':{'Bitrate':1000,'RateControlMode':'CBR'}}},{'Name':'two','CodecSettings':{'H265Settings':{'Bitrate':bitrate,'RateControlMode':mode}}}]
    props={'EncoderSettings':{'VideoDescriptions':videos,'OutputGroups':[{'OutputGroupSettings':{'MsSmoothGroupSettings':{}},'Outputs':[{'VideoDescriptionName':'one'},{'VideoDescriptionName':'two'}]}]}}
    assert check('MediaLive::Channel','MEDIALIVE_SMOOTH_BITRATE_DUPLICATES',props)[0]['verdict']==expected


@pytest.mark.parametrize('kind',['Channel','Input'])
@pytest.mark.parametrize('mode,expected',[('same','FAIL'),('different','PASS'),('unknown','NEEDS_REVIEW'),('conditional','NEEDS_REVIEW'),('cross_scope','NEEDS_REVIEW')])
def test_subnet_az_links(kind,mode,expected):
    r=target('one','AWS::MediaLive::'+kind,Vpc={'SubnetIds':['first','second']},**({'ChannelClass':'STANDARD'} if kind=='Channel' else {}))
    a=target('first','AWS::EC2::Subnet',AvailabilityZone='ap-northeast-1a');b=target('second',a.type,AvailabilityZone='ap-northeast-1c' if mode=='different' else UNKNOWN if mode=='unknown' else 'ap-northeast-1a')
    d=linked_design(r,[a,b],[('Vpc/SubnetIds/0','first'),('Vpc/SubnetIds/1','second')])
    if mode=='conditional':d.relations[1].condition='Maybe'
    if mode=='cross_scope':b.scope.account='222222222222'
    row=next(x for x in local97_nested_checks(d,r) if x['rule_id']=='MEDIALIVE_'+kind.upper()+'_SUBNET_AZS')
    assert row['verdict']==expected
