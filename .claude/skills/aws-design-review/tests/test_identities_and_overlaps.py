"""Identity comparison and inclusive network boundaries with unresolved inputs."""
from pathlib import Path
import pytest
from aws_design_sheet.checks.evs.environment import VLANS, HOSTNAMES, evaluate_evs_environment
from aws_design_sheet.checks.kinesis.consumer_name_unique import evaluate_kinesis_consumer_name_unique
from aws_design_sheet.checks.autoscalingplans.scaling_plan import evaluate_autoscalingplans_scaling_plan
from aws_design_sheet.checks.codepipeline.output_and_trigger_names import evaluate_codepipeline_output_and_trigger_names
from aws_design_sheet.checks.gamelift.ports_and_process_total import evaluate_gamelift_ports_and_process_total
from aws_design_sheet.checks.registry import combine
local_identities_checks = combine(evaluate_kinesis_consumer_name_unique, evaluate_autoscalingplans_scaling_plan, evaluate_codepipeline_output_and_trigger_names, evaluate_evs_environment, evaluate_gamelift_ports_and_process_total)
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(kind,rule,**props):
    r=target('subject','AWS::'+kind,**props)
    return [x for x in local_identities_checks(linked_design(r),r) if x['rule_id']==rule]


def predefined(kind='ASGAverageCPUUtilization',label=None):
    obj={'PredefinedScalingMetricType':kind}
    if label is not None:obj['ResourceLabel']=label
    return {'PredefinedScalingMetricSpecification':obj}


@pytest.mark.parametrize('counts,expected',[
    ([1,48],'PASS'),([49],'PASS'),([25,25],'NEEDS_REVIEW'),([50],'NEEDS_REVIEW'),
    ([25,26],'FAIL'),([51,UNKNOWN],'FAIL'),([49,UNKNOWN],'NEEDS_REVIEW'),
    ([0],'FAIL'),([-1],'FAIL'),([True],'NEEDS_REVIEW'),(['1'],'NEEDS_REVIEW'),
    ([1.5],'NEEDS_REVIEW'),([],'NEEDS_REVIEW')])
def test_process_total(counts,expected):
    processes=[{'ConcurrentExecutions':n} for n in counts]
    assert check('GameLift::Fleet','GAMELIFT_PROCESS_TOTAL',RuntimeConfiguration={'ServerProcesses':processes})[0]['verdict']==expected


@pytest.mark.parametrize('metrics,expected',[
    ([predefined(),predefined()],'FAIL'),
    ([predefined(),predefined('ASGAverageNetworkIn')],'PASS'),
    ([predefined(),UNKNOWN],'NEEDS_REVIEW'),([predefined(),predefined(),UNKNOWN],'FAIL'),
    ([predefined('ALBRequestCountPerTarget','same'),predefined('ALBRequestCountPerTarget','same')],'FAIL'),
    ([predefined('ALBRequestCountPerTarget','a'),predefined('ALBRequestCountPerTarget','b')],'PASS'),
    ([predefined('ALBRequestCountPerTarget'),predefined('ALBRequestCountPerTarget')],'NEEDS_REVIEW'),
    ([predefined('FutureMetric')],'NEEDS_REVIEW'),
    ([{'CustomizedScalingMetricSpecification':{}},predefined()],'NEEDS_REVIEW'),
    ([{**predefined(),'CustomizedScalingMetricSpecification':{}}],'NEEDS_REVIEW'),
    ([predefined(label='unexpected')],'NEEDS_REVIEW')])
def test_metric_identity(metrics,expected):
    assert check('AutoScalingPlans::ScalingPlan','SCALINGPLAN_METRIC_UNIQUE',ScalingInstructions=[{'TargetTrackingConfigurations':metrics}])[0]['verdict']==expected


@pytest.mark.parametrize('namespace,expected',[
    ('autoscaling','PASS'),('ec2','PASS'),('ecs','PASS'),('rds','FAIL'),('dynamodb','FAIL'),
    (UNKNOWN,'NEEDS_REVIEW'),('Future','NEEDS_REVIEW')])
def test_alb_service(namespace,expected):
    props={'ScalingInstructions':[{'ServiceNamespace':namespace,'TargetTrackingConfigurations':[predefined('ALBRequestCountPerTarget','label')]}]}
    assert check('AutoScalingPlans::ScalingPlan','SCALINGPLAN_ALB_SERVICE',**props)[0]['verdict']==expected


def test_metric_identity_is_per_instruction():
    props={'ScalingInstructions':[{'TargetTrackingConfigurations':[predefined()]} for _ in range(2)]}
    assert all(x['verdict']=='PASS' for x in check('AutoScalingPlans::ScalingPlan','SCALINGPLAN_METRIC_UNIQUE',**props))


def source(name='Source',provider='CodeStarSourceConnection',category='Source'):
    return {'Name':name,'ActionTypeId':{'Provider':provider,'Category':category}}


@pytest.mark.parametrize('actions,name,expected',[
    ([source()],'Source','PASS'),([source('Other')],'Source','FAIL'),
    ([source(provider='S3')],'Source','FAIL'),([source(category='Build')],'Source','FAIL'),
    ([source(provider=UNKNOWN)],'Source','NEEDS_REVIEW'),
    ([source(),source()],'Source','NEEDS_REVIEW'),([source(),UNKNOWN],'Source','NEEDS_REVIEW'),
    ([source()],UNKNOWN,'NEEDS_REVIEW'),([], 'Source','FAIL'),(UNKNOWN,'Source','NEEDS_REVIEW')])
def test_pipeline_source(actions,name,expected):
    props={'Stages':[{'Actions':actions}],'Triggers':[{'ProviderType':'CodeStarSourceConnection','GitConfiguration':{'SourceActionName':name}}]}
    assert check('CodePipeline::Pipeline','CODEPIPELINE_TRIGGER_SOURCE',**props)[0]['verdict']==expected


def test_duplicate_triggers():
    trigger={'ProviderType':'CodeStarSourceConnection','GitConfiguration':{'SourceActionName':'Source'}}
    rows=check('CodePipeline::Pipeline','CODEPIPELINE_TRIGGER_SOURCE',Stages=[{'Actions':[source()]}],Triggers=[trigger,trigger])
    assert len(rows)==2 and all(x['verdict']=='FAIL' for x in rows)


def vlans():return {key:{'Cidr':f'10.0.{i}.0/24'} for i,key in enumerate(VLANS)}


@pytest.mark.parametrize('cidr,expected',[
    ('10.0.0.0/24','FAIL'),('10.0.0.0/28','FAIL'),('10.1.0.0/24','PASS'),
    ('10.0.0.1/24','NEEDS_REVIEW'),('10.0.0.0','NEEDS_REVIEW'),
    ('10.000.0.0/24','NEEDS_REVIEW'),('::/64','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_vlan_overlap(cidr,expected):
    values=vlans();values[VLANS[-1]]={'Cidr':cidr}
    assert check('EVS::Environment','EVS_VLAN_NONOVERLAP',InitialVlans=values)[0]['verdict']==expected


def test_adjacent_vlan_ranges():
    values={key:{'Cidr':f'10.0.0.{i*16}/28'} for i,key in enumerate(VLANS)}
    assert check('EVS::Environment','EVS_VLAN_NONOVERLAP',InitialVlans=values)[0]['verdict']=='PASS'


def test_proven_overlap_despite_other_unknown_vlan():
    values=vlans();values[VLANS[1]]=values[VLANS[0]];values[VLANS[2]]=UNKNOWN
    assert check('EVS::Environment','EVS_VLAN_NONOVERLAP',InitialVlans=values)[0]['verdict']=='FAIL'


@pytest.mark.parametrize('name,expected',[
    ('host-0','FAIL'),('HOST-0','NEEDS_REVIEW'),('unique','PASS'),
    ('host.domain','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_vcf_hostname_uniqueness(name,expected):
    values={key:'host-'+str(i) for i,key in enumerate(HOSTNAMES)};values[HOSTNAMES[-1]]=name
    assert check('EVS::Environment','EVS_VCF_HOSTNAMES',VcfHostnames=values)[0]['verdict']==expected


@pytest.mark.parametrize('start,end,expected',[
    (1,4091,'PASS'),(1,4092,'FAIL'),(4092,4191,'FAIL'),(4191,5000,'FAIL'),
    (4192,60000,'PASS'),(4000,5000,'FAIL'),(4092,4092,'FAIL'),
    (4000,4000,'NEEDS_REVIEW'),(5000,4000,'NEEDS_REVIEW'),
    (True,4000,'NEEDS_REVIEW'),('4000',4091,'NEEDS_REVIEW'),(UNKNOWN,5000,'NEEDS_REVIEW'),
    (0,4091,'FAIL'),(4192,60001,'FAIL')])
def test_reserved_ports(start,end,expected):
    assert check('GameLift::ContainerFleet','GAMELIFT_RESERVED_PORTS',InstanceConnectionPortRange={'FromPort':start,'ToPort':end})[0]['verdict']==expected


def test_checker_integration():
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('fleet','AWS::GameLift::ContainerFleet',InstanceConnectionPortRange={'FromPort':4000,'ToPort':5000})
    rows=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    row=next(x for x in rows if x['rule_id']=='GAMELIFT_RESERVED_PORTS')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
