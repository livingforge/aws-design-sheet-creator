import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('kind,props,count,rule',[
    ('AccessEntry',{'PrincipalArn':'arn:aws:iam::123456789012:role/app'},2,'EKS_ACCESS_PRINCIPAL_DUPLICATE'),
    ('Capability',{'CapabilityName':'app'},2,'EKS_CAPABILITY_NAME_DUPLICATE'),
    ('CertificateAuthority',{},3,'EKS_CERTIFICATE_AUTHORITY_COUNT'),
])
@pytest.mark.parametrize('different_scope',[False,True])
def test_design_duplicates(kind,props,count,rule,different_scope):
    resources=[target(str(i),'AWS::EKS::'+kind,ClusterName='cluster',**props) for i in range(count)]
    if different_scope:
        resources[-1].scope.region='us-west-2'
    data=linked_design(resources[0],resources[1:])
    result={r['rule_id']:r['verdict'] for r in run_resource_checks(data,resources[0])}
    assert result[rule] == ('NEEDS_REVIEW' if different_scope else 'FAIL')


@pytest.mark.parametrize('name',['different',UNKNOWN])
def test_unknown_and_different_clusters_do_not_prove_collision(name):
    main=target('main','AWS::EKS::Capability',ClusterName='cluster',CapabilityName='app')
    other=target('other','AWS::EKS::Capability',ClusterName=name,CapabilityName='app')
    result=run_resource_checks(linked_design(main,[other]),main)
    assert next(r for r in result if r['rule_id']=='EKS_CAPABILITY_NAME_DUPLICATE')['verdict']=='NEEDS_REVIEW'


def test_linked_cluster_and_principal_identities():
    from aws_design_sheet.models import Relation
    props={'ClusterName':{'Ref':'cluster'},'PrincipalArn':{'Ref':'role'}}
    main=target('main','AWS::EKS::AccessEntry',**props)
    other=target('other','AWS::EKS::AccessEntry',**props)
    cluster=target('cluster','AWS::EKS::Cluster')
    role=target('role','AWS::IAM::Role')
    data=linked_design(main,[other,cluster,role],[('ClusterName','cluster'),('PrincipalArn','role')])
    for path,dest in [('ClusterName','cluster'),('PrincipalArn','role')]:
        data.relations.append(Relation(id=path,source_resource_id='other',source_path='/properties/'+path,target_resource_id=dest,evidence_ids=['e1']))
    findings={r['rule_id']:r['verdict'] for r in run_resource_checks(data,main)}
    assert findings['EKS_ACCESS_PRINCIPAL_DUPLICATE']=='FAIL'
    data.relations[-1].condition='condition'
    findings={r['rule_id']:r['verdict'] for r in run_resource_checks(data,main)}
    assert findings['EKS_ACCESS_PRINCIPAL_DUPLICATE']=='NEEDS_REVIEW'


@pytest.mark.parametrize('node_version,cluster_version,expected',[
    ('1.34','1.34','PASS'),('1.33','1.34','FAIL'),(UNKNOWN,'1.34','NEEDS_REVIEW'),
    ('1.34',UNKNOWN,'NEEDS_REVIEW'),('latest','1.34','NEEDS_REVIEW'),
])
def test_nodegroup_version(node_version,cluster_version,expected):
    main=target('nodes','AWS::EKS::Nodegroup',ClusterName={'Ref':'cluster'},Version=node_version)
    cluster=target('cluster','AWS::EKS::Cluster',Version=cluster_version)
    data=linked_design(main,[cluster],[('ClusterName','cluster')])
    findings={r['rule_id']:r['verdict'] for r in run_resource_checks(data,main)}
    assert findings['EKS_NODEGROUP_CLUSTER_VERSION']==expected
