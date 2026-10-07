import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('keys,expected',[
    ([f'key{i}' for i in range(50)],'NEEDS_REVIEW'),
    ([f'key{i}' for i in range(51)],'FAIL'),
    (['same']*51,'NEEDS_REVIEW'),
    ([f'aws:key{i}' for i in range(51)],'NEEDS_REVIEW'),
    ([f'key{i}' for i in range(50)]+[UNKNOWN],'NEEDS_REVIEW'),
    ([f'key{i}' for i in range(51)]+[UNKNOWN],'FAIL'),
    ([f'key{i}' for i in range(49)]+['Case','case'],'FAIL'),
])
def test_known_distinct_user_tag_lower_bound(keys,expected):
    main=target('secret','AWS::SecretsManager::Secret',Tags=[{'Key':key,'Value':'v'} for key in keys])
    assert run_resource_checks(linked_design(main),main)[0]['verdict']==expected


def test_unresolved_tag_array():
    main=target('secret','AWS::SecretsManager::Secret',Tags=UNKNOWN)
    assert run_resource_checks(linked_design(main),main)[0]['verdict']=='NEEDS_REVIEW'
