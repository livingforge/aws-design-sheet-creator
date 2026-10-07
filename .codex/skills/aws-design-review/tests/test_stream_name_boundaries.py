from pathlib import Path
import pytest
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design


@pytest.mark.parametrize('name,valid',[('',False),('a',True),('a'*128,True),('a'*129,False),('a!',False),('!a',False)])
def test_combined_name_constraints(name,valid):
    r=target('main','AWS::Rekognition::StreamProcessor',Name=name)
    root=Path(__file__).resolve().parents[1]
    # Name length comes from the resource schema, which cfn-lint validates.
    found=Checker(root/'schemas',root/'profiles/vpc-subnet.json',cfn_lint=True).check(linked_design(r))['results']
    relevant=[f for f in found if f['path']=='/properties/Name']
    assert relevant
    assert any(f['verdict']=='FAIL' for f in relevant)==(not valid)
