import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from aws_design_sheet.models import Relation


def setup(multi):
    replica=target('replica','AWS::KMS::ReplicaKey',PrimaryKeyArn={'Ref':'primary'})
    primary=target('primary','AWS::KMS::Key',**({'MultiRegion':multi} if multi is not None else {}))
    primary.scope.region='us-west-2'
    return replica,primary,linked_design(replica,[primary],[('PrimaryKeyArn','primary')])


def result(data,replica):
    return next(f['verdict'] for f in run_resource_checks(data,replica) if f['rule_id']=='KMS_REPLICA_PRIMARY_DECLARATION')


@pytest.mark.parametrize('multi,expected',[(True,'PASS'),(False,'FAIL'),(None,'FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('true','NEEDS_REVIEW')])
def test_primary_multi_region(multi,expected):
    replica,primary,data=setup(multi)
    before=replica.model_dump()
    assert result(data,replica)==expected
    assert replica.model_dump()==before


@pytest.mark.parametrize('boundary',['conditional','account','environment','partition','same-region','unknown-region','type','unlinked'])
def test_primary_boundaries(boundary):
    replica,primary,data=setup(True)
    if boundary=='conditional':data.relations[0].condition='UsePrimary'
    elif boundary=='account':primary.scope.account='999999999999'
    elif boundary=='environment':primary.scope.environment='other'
    elif boundary=='partition':primary.scope.region='cn-north-1'
    elif boundary=='same-region':primary.scope.region=replica.scope.region
    elif boundary=='unknown-region':primary.scope.region='unknown'
    elif boundary=='type':primary.type='AWS::KMS::ReplicaKey'
    elif boundary=='unlinked':data.relations=[]
    assert result(data,replica)=='NEEDS_REVIEW'


@pytest.mark.parametrize('variation', ['same','different-region','different-environment','conditional','unlinked'])
def test_linked_replica_duplicates(variation):
    replica,primary,data=setup(True)
    other=target('other','AWS::KMS::ReplicaKey',PrimaryKeyArn={'Ref':'primary'})
    data.resources.append(other)
    relation=Relation(id='other-primary',source_resource_id='other',source_path='/properties/PrimaryKeyArn',target_resource_id='primary')
    if variation!='unlinked':data.relations.append(relation)
    if variation=='different-region':other.scope.region='eu-west-1'
    elif variation=='different-environment':other.scope.environment='other'
    elif variation=='conditional':relation.condition='UseOther'
    findings=run_resource_checks(data,replica)
    verdict=next(f['verdict'] for f in findings if f['rule_id']=='KMS_REPLICA_DESIGN_DUPLICATE')
    assert verdict==('FAIL' if variation=='same' else 'NEEDS_REVIEW')
