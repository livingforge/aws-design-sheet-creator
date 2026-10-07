import pytest
from aws_design_sheet.models import Relation
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def results(data, resource):
    return {f['rule_id']:f for f in run_resource_checks(data, resource)}


@pytest.mark.parametrize('members,expected', [(['FARGATE'],'PASS'), (['FARGATE_SPOT'],'NEEDS_REVIEW'),
    ([], 'NEEDS_REVIEW'), (UNKNOWN, 'NEEDS_REVIEW')])
@pytest.mark.parametrize('kind', ['Cluster','ClusterCapacityProviderAssociations'])
def test_membership(kind,members,expected):
    resource=target('cluster','AWS::ECS::'+kind,CapacityProviders=members,
        DefaultCapacityProviderStrategy=[{'CapacityProvider':'FARGATE'}])
    assert results(linked_design(resource),resource)['ECS_CLUSTER_PROVIDER_MEMBERSHIP']['verdict']==expected


def test_separate_association_and_condition():
    cluster=target('cluster','AWS::ECS::Cluster',DefaultCapacityProviderStrategy=[{'CapacityProvider':'FARGATE'}])
    association=target('association','AWS::ECS::ClusterCapacityProviderAssociations',Cluster={'Ref':'cluster'},CapacityProviders=['FARGATE'])
    data=linked_design(cluster,[association])
    data.relations.append(Relation(id='owner',source_resource_id='association',source_path='/properties/Cluster',target_resource_id='cluster'))
    assert results(data,cluster)['ECS_CLUSTER_PROVIDER_MEMBERSHIP']['verdict']=='PASS'
    data.relations[0].condition='UseAssociation'
    assert results(data,cluster)['ECS_CLUSTER_PROVIDER_MEMBERSHIP']['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('weights,expected', [([0,0],'FAIL'), ([None,None],'FAIL'), ([0,1],'PASS'),
    ([UNKNOWN,0],'NEEDS_REVIEW'), ([UNKNOWN,1],'PASS'), ([-1,0],'NEEDS_REVIEW')])
def test_default_weights(weights,expected):
    resource=target('cluster','AWS::ECS::Cluster',DefaultCapacityProviderStrategy=[
        {'CapacityProvider':str(i),**({'Weight':w} if w is not None else {})} for i,w in enumerate(weights)])
    finding=results(linked_design(resource),resource)['ECS_CLUSTER_DEFAULT_WEIGHT']
    assert finding['verdict']==expected
    assert finding['severity']=='WARNING'


@pytest.mark.parametrize('other_name,expected', [('other','FAIL'), ('same','NEEDS_REVIEW'), (UNKNOWN,'NEEDS_REVIEW')])
def test_asg_provider_shared(other_name,expected):
    cluster=target('cluster','AWS::ECS::Cluster',ClusterName='same',CapacityProviders=[{'Ref':'provider'}],
        DefaultCapacityProviderStrategy=[{'CapacityProvider':{'Ref':'provider'}}])
    other=target('other','AWS::ECS::Cluster',ClusterName=other_name,CapacityProviders=[{'Ref':'provider'}])
    provider=target('provider','AWS::ECS::CapacityProvider',AutoScalingGroupProvider={'AutoScalingGroupArn':'asg'})
    data=linked_design(cluster,[other,provider],[('CapacityProviders/0','provider'),('DefaultCapacityProviderStrategy/0/CapacityProvider','provider')])
    data.relations.append(Relation(id='other-provider',source_resource_id='other',source_path='/properties/CapacityProviders/0',target_resource_id='provider'))
    findings=results(data,cluster)
    assert findings['ECS_CLUSTER_PROVIDER_MEMBERSHIP']['verdict']=='PASS'
    assert findings['ECS_CLUSTER_ASG_PROVIDER_UNIQUE']['verdict']==expected
    data.relations[-1].condition='UseOther'
    assert results(data,cluster)['ECS_CLUSTER_ASG_PROVIDER_UNIQUE']['verdict']=='NEEDS_REVIEW'


def test_literal_logical_alias_not_inferred():
    provider=target('provider','AWS::ECS::CapacityProvider',Name='named')
    cluster=target('cluster','AWS::ECS::Cluster',CapacityProviders=['named'],
        DefaultCapacityProviderStrategy=[{'CapacityProvider':{'Ref':'provider'}}])
    data=linked_design(cluster,[provider],[('DefaultCapacityProviderStrategy/0/CapacityProvider','provider')])
    assert results(data,cluster)['ECS_CLUSTER_PROVIDER_MEMBERSHIP']['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('left_assoc,right_assoc',[(True,True),(True,False),(False,True)])
def test_association_conflicts(left_assoc,right_assoc):
    clusters=[target('left','AWS::ECS::Cluster',ClusterName='left'),target('right','AWS::ECS::Cluster',ClusterName='right')]
    provider=target('provider','AWS::ECS::CapacityProvider',AutoScalingGroupProvider={'AutoScalingGroupArn':'asg'})
    declarations=[]
    relations=[]
    for cluster,assoc in zip(clusters,[left_assoc,right_assoc]):
        declaration=target(cluster.id+'-association','AWS::ECS::ClusterCapacityProviderAssociations',Cluster={'Ref':cluster.id},CapacityProviders=[{'Ref':'provider'}]) if assoc else target(cluster.id,'AWS::ECS::Cluster',ClusterName=cluster.id,CapacityProviders=[{'Ref':'provider'}])
        if not assoc:clusters[0 if cluster.id=='left' else 1]=declaration
        declarations.append(declaration)
        relations.append(Relation(id=declaration.id+'-provider',source_resource_id=declaration.id,source_path='/properties/CapacityProviders/0',target_resource_id='provider'))
        if assoc:relations.append(Relation(id=declaration.id+'-owner',source_resource_id=declaration.id,source_path='/properties/Cluster',target_resource_id=cluster.id))
    data=linked_design(declarations[0])
    data.resources=list({r.id:r for r in [*clusters,*declarations,provider]}.values())
    data.relations=relations
    for declaration in declarations:
        assert results(data,declaration)['ECS_CLUSTER_ASG_PROVIDER_UNIQUE']['verdict']=='FAIL'
    # Unknown ownership cannot prove two distinct clusters.
    owner=next(r for r in data.relations if r.source_path=='/properties/Cluster')
    owner.condition='UseCluster'
    for declaration in declarations:
        finding=results(data,declaration).get('ECS_CLUSTER_ASG_PROVIDER_UNIQUE')
        assert finding is None or finding['verdict']=='NEEDS_REVIEW'
