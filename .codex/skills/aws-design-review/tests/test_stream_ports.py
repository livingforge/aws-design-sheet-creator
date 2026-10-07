from pathlib import Path
import pytest
from aws_design_sheet.checks.kinesis.consumer_name_unique import evaluate_kinesis_consumer_name_unique
from aws_design_sheet.checks.autoscalingplans.scaling_plan import evaluate_autoscalingplans_scaling_plan
from aws_design_sheet.checks.codepipeline.output_and_trigger_names import evaluate_codepipeline_output_and_trigger_names
from aws_design_sheet.checks.evs.environment import evaluate_evs_environment
from aws_design_sheet.checks.gamelift.ports_and_process_total import evaluate_gamelift_ports_and_process_total
from aws_design_sheet.checks.registry import combine
local_identities_checks = combine(evaluate_kinesis_consumer_name_unique, evaluate_autoscalingplans_scaling_plan, evaluate_codepipeline_output_and_trigger_names, evaluate_evs_environment, evaluate_gamelift_ports_and_process_total)
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN

ARN='arn:aws:kinesis:ap-northeast-1:111111111111:stream/'
def result(d,r,rule):
    return next(x for x in local_identities_checks(d,r) if x['rule_id']==rule)['verdict']

@pytest.mark.parametrize('name,stream,expected',[
 ('a','one','FAIL'),('b','one','PASS'),('a','two','PASS'),
 (UNKNOWN,'one','NEEDS_REVIEW'),('a',None,'NEEDS_REVIEW')])
def test_consumers(name,stream,expected):
 r=target('one','AWS::Kinesis::StreamConsumer',ConsumerName='a',StreamARN=ARN+'one')
 other=target('two','AWS::Kinesis::StreamConsumer',ConsumerName=name,StreamARN=ARN+stream if stream else UNKNOWN)
 assert result(linked_design(r,[other]),r,'KINESIS_CONSUMER_NAME_UNIQUE')==expected

@pytest.mark.parametrize('mode,expected',[('same','FAIL'),('conditional','NEEDS_REVIEW'),('cross','NEEDS_REVIEW'),('mixed','NEEDS_REVIEW')])
def test_stream_links(mode,expected):
 r=target('one','AWS::Kinesis::StreamConsumer',ConsumerName='a')
 other=target('two','AWS::Kinesis::StreamConsumer',ConsumerName='a',StreamARN=ARN+'one')
 stream=target('stream','AWS::Kinesis::Stream')
 d=linked_design(r,[other,stream],[('StreamARN','stream')])
 if mode!='mixed':
  rel=d.relations[0].model_copy(deep=True);rel.id='other';rel.source_resource_id=other.id;d.relations.append(rel)
 if mode=='conditional':d.relations[0].condition='Maybe'
 if mode=='cross':stream.scope.region='us-east-1'
 assert result(d,r,'KINESIS_CONSUMER_NAME_UNIQUE')==expected

@pytest.mark.parametrize('os', ['AMAZON_LINUX','AMAZON_LINUX_2','AMAZON_LINUX_2023','WINDOWS_2012','WINDOWS_2016','WINDOWS_2022'])
@pytest.mark.parametrize('start,end',[(22,22),(22,1026),(1025,1026),(1026,60000),(60000,60000),(60000,60001),(2000,1000)])
def test_ports(os,start,end):
 r=target('fleet','AWS::GameLift::Fleet',EC2InboundPermissions=[{'FromPort':start,'ToPort':end}])
 b=target('build','AWS::GameLift::Build',OperatingSystem=os)
 valid=1026<=start<=end<=60000 or os.startswith('AMAZON_LINUX') and start==end==22
 assert result(linked_design(r,[b],[('BuildId','build')]),r,'GAMELIFT_OS_PORTS')==('PASS' if valid else 'FAIL')

@pytest.mark.parametrize('mode',['external','conditional','scope','unknown_os','unknown_port','bool'])
def test_ports_hold(mode):
 r=target('fleet','AWS::GameLift::Fleet',EC2InboundPermissions=[{'FromPort':True if mode=='bool' else UNKNOWN if mode=='unknown_port' else 22,'ToPort':22}])
 b=target('build','AWS::GameLift::Build',OperatingSystem=UNKNOWN if mode=='unknown_os' else 'WINDOWS_2022')
 d=linked_design(r,[b],[] if mode=='external' else [('BuildId','build')])
 if mode=='conditional':d.relations[0].condition='Maybe'
 if mode=='scope':b.scope.region='us-east-1'
 assert result(d,r,'GAMELIFT_OS_PORTS')=='NEEDS_REVIEW'

@pytest.mark.parametrize('names,expected',[(['a','b'],'PASS'),(['a','a'],'FAIL'),(['a',UNKNOWN],'NEEDS_REVIEW'),(['a','a',UNKNOWN],'FAIL')])
def test_outputs(names,expected):
 r=target('pipeline','AWS::CodePipeline::Pipeline',Stages=[{'Actions':[{'OutputArtifacts':[{'Name':n}]}]} for n in names])
 assert result(linked_design(r),r,'CODEPIPELINE_OUTPUT_UNIQUE')==expected

@pytest.mark.parametrize('stages',[UNKNOWN,[UNKNOWN],[{'Actions':UNKNOWN}],[{'Actions':[{'OutputArtifacts':UNKNOWN}]}]])
def test_unknown_arrays(stages):
 r=target('pipeline','AWS::CodePipeline::Pipeline',Stages=stages)
 assert result(linked_design(r),r,'CODEPIPELINE_OUTPUT_UNIQUE')=='NEEDS_REVIEW'

def test_checker():
 from aws_design_sheet.checker import Checker
 root=Path(__file__).resolve().parents[1]
 r=target('fleet','AWS::GameLift::Fleet',EC2InboundPermissions=[{'FromPort':22,'ToPort':22}])
 b=target('build','AWS::GameLift::Build',OperatingSystem='WINDOWS_2022')
 rows=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r,[b],[('BuildId','build')]))['results']
 row=next(x for x in rows if x['rule_id']=='GAMELIFT_OS_PORTS')
 assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
