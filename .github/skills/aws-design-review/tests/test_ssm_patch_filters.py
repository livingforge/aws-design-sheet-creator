import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(os,key,values,nested=False):
    filters={'PatchFilters':[{'Key':key,'Values':values}]}
    properties={'ApprovalRules':{'PatchRules':[{'PatchFilterGroup':filters}]}} if nested else {'GlobalFilters':filters}
    if os is not None:properties['OperatingSystem']=os
    resource=target('baseline','AWS::SSM::PatchBaseline',**properties)
    return {f['rule_id']:f['verdict'] for f in run_resource_checks(linked_design(resource),resource)}


@pytest.mark.parametrize('nested',[False,True])
@pytest.mark.parametrize('os,key,expected',[
    ('WINDOWS','MSRC_SEVERITY','PASS'),(None,'MSRC_SEVERITY','PASS'),('WINDOWS','PATCH_SET','PASS'),
    ('WINDOWS','SEVERITY','FAIL'),('UBUNTU','PRIORITY','PASS'),('DEBIAN','CLASSIFICATION','FAIL'),
    ('MACOS','CLASSIFICATION','PASS'),('MACOS','SEVERITY','FAIL'),('AMAZON_LINUX_2023','SEVERITY','PASS'),
    ('REDHAT_ENTERPRISE_LINUX','MSRC_SEVERITY','FAIL'),('SUSE','PRODUCT','PASS'),
    ('ROCKY_LINUX','PRODUCT','NEEDS_REVIEW'),('AMAZON_LINUX_2022','PRODUCT','NEEDS_REVIEW'),
    ('WINDOWS','ARCH','NEEDS_REVIEW'),(UNKNOWN,'PRODUCT','NEEDS_REVIEW'),('WINDOWS',UNKNOWN,'NEEDS_REVIEW')])
def test_os_matrix(nested,os,key,expected):
    assert check(os,key,['*'],nested)['SSM_PATCH_FILTER_OS_PROPERTY']==expected


@pytest.mark.parametrize('values,expected', [(['a']*20,'PASS'),(['a']*21,'FAIL'),
    (['a'*64],'PASS'),(['a'*65],'FAIL'),([],'NEEDS_REVIEW'),([''],'NEEDS_REVIEW'),
    (UNKNOWN,'NEEDS_REVIEW'),([UNKNOWN],'NEEDS_REVIEW'),(['a'*65,UNKNOWN],'FAIL'),(['${value}'],'NEEDS_REVIEW')])
def test_value_bounds(values,expected):
    assert check('WINDOWS','PRODUCT',values)['SSM_PATCH_FILTER_VALUE_BOUNDS']==expected


@pytest.mark.parametrize('field',['ApprovedPatches','RejectedPatches'])
@pytest.mark.parametrize('os,patch,expected',[
    ('MACOS','MRTConfigData','PASS'),('MACOS','MRT*','FAIL'),('MACOS','MRT?','NEEDS_REVIEW'),
    ('AMAZON_LINUX_2','dbus*','PASS'),('AMAZON_LINUX_2023','dbus-*-*','FAIL'),
    ('SUSE','example*.rpm','PASS'),('UBUNTU','pkg*','NEEDS_REVIEW'),
    ('WINDOWS','KB2032276','NEEDS_REVIEW'),('MACOS',UNKNOWN,'NEEDS_REVIEW')])
def test_patch_wildcards(field,os,patch,expected):
    resource=target('baseline','AWS::SSM::PatchBaseline',OperatingSystem=os,**{field:[patch]})
    verdict=next(f['verdict'] for f in run_resource_checks(linked_design(resource),resource) if f['rule_id']=='SSM_PATCH_LIST_WILDCARDS')
    assert verdict==expected
