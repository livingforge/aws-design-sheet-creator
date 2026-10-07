from pathlib import Path
import pytest
from aws_design_sheet.checks.vpclattice.actions import evaluate_vpclattice_actions
from aws_design_sheet.checks.pipes.accelerator_device_member import evaluate_pipes_accelerator_device_member
from aws_design_sheet.checks.registry import combine
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
lattice_actions_checks = combine(evaluate_vpclattice_actions, evaluate_pipes_accelerator_device_member)


@pytest.mark.parametrize('kind,key',[('AWS::VpcLattice::Listener','DefaultAction'),('AWS::VpcLattice::Rule','Action')])
@pytest.mark.parametrize('raw,expected',[
 ({'Forward':{}},'PASS'),({'FixedResponse':{}},'PASS'),({'Forward':{},'FixedResponse':{}},'FAIL'),
 ({},'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),({'Forward':UNKNOWN},'NEEDS_REVIEW'),
 ({'Forward':{},'FixedResponse':UNKNOWN},'NEEDS_REVIEW'),({'Forward':None},'NEEDS_REVIEW')],ids=['forward','fixed','both','empty','unknown_parent','unknown_member','partly_unknown','null'])
def test_action(kind,key,raw,expected):
 r=target('main',kind,**{key:raw});assert lattice_actions_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('case',['match','mismatch','empty','unknown','default','external','conditional','duplicate','unknown_name'])
def test_device(case):
 name=UNKNOWN if case=='unknown_name' else 'device'
 r=target('main','AWS::Pipes::Pipe',TargetParameters={'EcsTaskParameters':{'TaskDefinitionArn':'task','Overrides':{'InferenceAcceleratorOverrides':[{'DeviceName':name}]}}})
 devices=[] if case=='empty' else UNKNOWN if case=='unknown' else [{'DeviceName':'other' if case=='mismatch' else 'device'}]
 t=target('task','AWS::ECS::TaskDefinition',**({} if case=='default' else {'InferenceAccelerators':devices}))
 links=[] if case=='external' else [('TargetParameters/EcsTaskParameters/TaskDefinitionArn','task')]*(2 if case=='duplicate' else 1)
 d=linked_design(r,[t],links)
 if case=='conditional':d.relations[0].condition='condition'
 assert lattice_actions_checks(d,r)[0]['verdict']==('PASS' if case=='match' else 'FAIL' if case in ('mismatch','empty') else 'NEEDS_REVIEW')


@pytest.mark.parametrize('kind',['AWS::VpcLattice::Listener','AWS::VpcLattice::Rule','AWS::Pipes::Pipe'])
def test_absent(kind):
 r=target('main',kind);assert not lattice_actions_checks(linked_design(r),r)


def test_checker():
 r=target('main','AWS::VpcLattice::Listener',DefaultAction={'Forward':{},'FixedResponse':{}})
 root=Path(__file__).resolve().parents[1]
 found=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
 assert any(f['rule_id']=='VPCLATTICE_LISTENER_ACTION_EXCLUSION' and f['verdict']=='FAIL' for f in found)
