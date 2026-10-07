import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.fsx.capabilities_and_links import evaluate_fsx_capabilities_and_links
from aws_design_sheet.checks.emr.studio_vpc_links import evaluate_emr_studio_vpc_links
from aws_design_sheet.checks.registry import combine
fsx_links_checks = combine(evaluate_fsx_capabilities_and_links, evaluate_emr_studio_vpc_links)
from aws_design_sheet.checks.ivs.storage_bucket_region import evaluate_ivs_storage_bucket_region
from aws_design_sheet.checks.grafana.workspace_vpc_members import evaluate_grafana_workspace_vpc_members
from aws_design_sheet.checks.registry import combine
media_placement_checks = combine(evaluate_ivs_storage_bucket_region, evaluate_grafana_workspace_vpc_members)
from test_autoscaling_group_and_scaling_policy import target, linked_design
from test_template_dependencies import link


@pytest.mark.parametrize('field',['SubnetIds/0','EngineSecurityGroupId','WorkspaceSecurityGroupId'])
@pytest.mark.parametrize('unknown',['main','member','vpc','scope'])
def test_studio_unresolved_context(field,unknown):
    props={'SubnetIds':['member']} if field.startswith('SubnetIds') else {field:'member'}
    r=target('main','AWS::EMR::Studio',VpcId='vpc',**props)
    m=target('member','AWS::EC2::Subnet' if field.startswith('SubnetIds') else 'AWS::EC2::SecurityGroup',VpcId='vpc')
    v=target('vpc','AWS::EC2::VPC')
    d=linked_design(r,[m,v],[('VpcId','vpc'),(field,'member')]);link(d,m,'VpcId',v)
    if unknown=='scope':
        for item in (r,m,v):item.scope.account='unknown'
    else:next(item for item in (r,m,v) if item.id==unknown).template=TemplateContext(state='UNRESOLVED')
    assert fsx_links_checks(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_grafana_matching_unknown_scope_does_not_prove_membership():
    r=target('main','AWS::Grafana::Workspace',VpcConfiguration={'SubnetIds':['subnet'],'SecurityGroupIds':['sg']})
    s=target('subnet','AWS::EC2::Subnet',VpcId='vpc');sg=target('sg','AWS::EC2::SecurityGroup',VpcId='vpc');v=target('vpc','AWS::EC2::VPC')
    d=linked_design(r,[s,sg,v],[('VpcConfiguration/SubnetIds/0','subnet'),('VpcConfiguration/SecurityGroupIds/0','sg')])
    link(d,s,'VpcId',v);link(d,sg,'VpcId',v)
    for item in (r,s,sg,v):item.scope.account='unknown'
    assert media_placement_checks(d,r)[0]['verdict']=='NEEDS_REVIEW'
