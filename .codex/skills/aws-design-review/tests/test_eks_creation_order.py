import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('forward,reverse,expected',[
    ([],[],'FAIL'),(['idp'],[],'PASS'),([],['profile'],'PASS'),
    (None,[],'NEEDS_REVIEW'),(['idp'],['profile'],'FAIL'),
])
def test_explicit_creation_order(forward,reverse,expected):
    main=target('profile','AWS::EKS::FargateProfile',ClusterName='cluster')
    other=target('idp','AWS::EKS::IdentityProviderConfig',ClusterName='cluster')
    main.template=TemplateContext(id='stack',depends_on=forward,evidence_ids=['e1'])
    other.template=TemplateContext(id='stack',depends_on=reverse,evidence_ids=['e1'])
    findings={r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(main,[other]),main)}
    assert findings['EKS_FARGATE_IDP_ORDER']==expected


@pytest.mark.parametrize('other_cluster,other_stack,expected',[
    ('other','stack',None), ('cluster','other',None), (UNKNOWN,'stack','NEEDS_REVIEW'),
    ('cluster',None,'NEEDS_REVIEW'),
])
def test_template_and_cluster_boundaries(other_cluster,other_stack,expected):
    main=target('profile','AWS::EKS::FargateProfile',ClusterName='cluster')
    other=target('idp','AWS::EKS::IdentityProviderConfig',ClusterName=other_cluster)
    main.template=TemplateContext(id='stack',depends_on=[],evidence_ids=['e1'])
    if other_stack:
        other.template=TemplateContext(id=other_stack,depends_on=[],evidence_ids=['e1'])
    findings={r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(main,[other]),main)}
    assert findings.get('EKS_FARGATE_IDP_ORDER')==expected


def test_transitive_dependency_is_sufficient():
    main=target('profile','AWS::EKS::FargateProfile',ClusterName='cluster')
    middle=target('middle','AWS::S3::Bucket')
    other=target('idp','AWS::EKS::IdentityProviderConfig',ClusterName='cluster')
    for resource,deps in [(main,['middle']),(middle,['idp']),(other,[])]:
        resource.template=TemplateContext(id='stack',depends_on=deps,evidence_ids=['e1'])
    findings={r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(main,[middle,other]),main)}
    assert findings['EKS_FARGATE_IDP_ORDER']=='PASS'


def test_mixed_cluster_name_and_reference_may_be_aliases():
    from aws_design_sheet.models import Relation
    main=target('profile','AWS::EKS::FargateProfile',ClusterName='cluster')
    other=target('idp','AWS::EKS::IdentityProviderConfig',ClusterName={'Ref':'cluster'})
    cluster=target('cluster','AWS::EKS::Cluster',Name='cluster')
    for resource in (main,other):
        resource.template=TemplateContext(id='stack',depends_on=[],evidence_ids=['e1'])
    data=linked_design(main,[other,cluster])
    data.relations.append(Relation(id='cluster-ref',source_resource_id='idp',source_path='/properties/ClusterName',target_resource_id='cluster',evidence_ids=['e1']))
    findings={r['rule_id']:r['verdict'] for r in run_resource_checks(data,main)}
    assert findings['EKS_FARGATE_IDP_ORDER']=='NEEDS_REVIEW'
