from pathlib import Path
import pytest
from aws_design_sheet.checks.arcregionswitch.workflow_blocks import evaluate_arcregionswitch_workflow_blocks, BLOCKS
from aws_design_sheet.checks.amazonmq.mq_configuration import evaluate_amazonmq_mq_configuration
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_template_dependencies import link


@pytest.mark.parametrize('kind,key',list(BLOCKS.items()))
@pytest.mark.parametrize('case',['match','mismatch','multiple','unknown'])
def test_block_union(kind,key,case):
    other='ParallelConfig' if key!='ParallelConfig' else 'ExecutionApprovalConfig'
    config={key:{}} if case=='match' else {other:{}} if case=='mismatch' else {key:{},other:{}} if case=='multiple' else UNKNOWN
    r=target('main','AWS::ARCRegionSwitch::Plan',Workflows=[{'Steps':[{'ExecutionBlockType':kind,'ExecutionBlockConfiguration':config}]}])
    f=evaluate_arcregionswitch_workflow_blocks(linked_design(r),r)
    assert f[0]['verdict']==('PASS' if case=='match' else 'NEEDS_REVIEW' if case=='unknown' else 'FAIL')


@pytest.mark.parametrize('case',['unknown_type','unknown_member','null','empty','unknown_steps','unknown_step','deep','wide'])
def test_block_uncertainty(case):
    step={'ExecutionBlockType':'ManualApproval','ExecutionBlockConfiguration':{'ExecutionApprovalConfig':{}}}
    if case=='unknown_type':step['ExecutionBlockType']=UNKNOWN
    if case=='unknown_member':step['ExecutionBlockConfiguration']={'ExecutionApprovalConfig':UNKNOWN}
    if case=='null':step['ExecutionBlockConfiguration']=None
    if case=='empty':step['ExecutionBlockConfiguration']={}
    if case=='deep':
        for _ in range(34):step={'ExecutionBlockType':'Parallel','ExecutionBlockConfiguration':{'ParallelConfig':{'Steps':[step]}}}
    steps=UNKNOWN if case=='unknown_steps' else [UNKNOWN] if case=='unknown_step' else [step]*1001 if case=='wide' else [step]
    r=target('main','AWS::ARCRegionSwitch::Plan',Workflows=[{'Steps':steps}])
    f=evaluate_arcregionswitch_workflow_blocks(linked_design(r),r)
    assert any(row['verdict']==('FAIL' if case=='empty' else 'NEEDS_REVIEW') for row in f)


@pytest.mark.parametrize('name,alarms,expected',[('a',{'a':{}},'PASS'),('a',{'b':{}},'FAIL'),('a',{},'FAIL'),('a',UNKNOWN,'NEEDS_REVIEW'),(UNKNOWN,{'a':{}},'NEEDS_REVIEW'),('a',{'b/c':{}},'NEEDS_REVIEW')])
def test_trigger_reference(name,alarms,expected):
    r=target('main','AWS::ARCRegionSwitch::Plan',AssociatedAlarms=alarms,Triggers=[{'Conditions':[{'AssociatedAlarmName':name}]}])
    assert evaluate_arcregionswitch_workflow_blocks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('association',[False,True])
@pytest.mark.parametrize('case',['same','different','unknown','external','conditional','scope','no_reference','version_difference'])
def test_mq_engine(association,case):
    c=target('config','AWS::AmazonMQ::Configuration',EngineType='RABBITMQ',EngineVersion='3.13')
    b=target('broker','AWS::AmazonMQ::Broker',EngineType='ACTIVEMQ' if case=='different' else UNKNOWN if case=='unknown' else 'RABBITMQ',EngineVersion='4.0' if case=='version_difference' else '3.13',Configuration={'Id':'config','Revision':1})
    a=target('assoc','AWS::AmazonMQ::ConfigurationAssociation',Broker='broker',Configuration={'Id':'config','Revision':2})
    d=linked_design(c,[b,a] if association else [b])
    if association:link(d,a,'Broker',b)
    if case not in ('external','no_reference'):link(d,a if association else b,'Configuration/Id',c)
    if case=='conditional':d.relations[-1].condition='maybe'
    if case=='scope':b.scope.account='222222222222'
    r=a if association else c
    found=evaluate_amazonmq_mq_configuration(d,r)
    assert found[0]['verdict']==('PASS' if case in ('same','version_difference') else 'FAIL' if case=='different' else 'NEEDS_REVIEW')


def test_checker_nested_failure():
    root=Path(__file__).resolve().parents[1]
    bad={'ExecutionBlockType':'ManualApproval','ExecutionBlockConfiguration':{'GlobalAuroraConfig':{}}}
    outer={'ExecutionBlockType':'Parallel','ExecutionBlockConfiguration':{'ParallelConfig':{'Steps':[bad]}}}
    r=target('main','AWS::ARCRegionSwitch::Plan',Workflows=[{'Steps':[outer]}])
    found=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    rows=[f for f in found if f['rule_id']=='ARC_EXECUTION_BLOCK_UNION']
    assert [f['verdict'] for f in rows]==['PASS','FAIL']
