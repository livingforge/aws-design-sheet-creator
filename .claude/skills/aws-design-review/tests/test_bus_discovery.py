import pytest
from aws_design_sheet.models import Relation
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('key,conditional,region,expected',[
    ('alias/customer-events',False,'ap-northeast-1','FAIL'),
    ('arn:aws:kms:ap-northeast-1:111111111111:key/1234',False,'ap-northeast-1','FAIL'),
    (UNKNOWN,False,'ap-northeast-1','NEEDS_REVIEW'),
    ('',False,'ap-northeast-1','NEEDS_REVIEW'),
    ('alias/customer-events',True,'ap-northeast-1','NEEDS_REVIEW'),
    ('alias/customer-events',False,'us-west-2','NEEDS_REVIEW'),
])
def test_customer_key_and_discoverer(key,conditional,region,expected):
    main=target('bus','AWS::Events::EventBus',Name='bus',KmsKeyIdentifier=key)
    discoverer=target('discoverer','AWS::EventSchemas::Discoverer',SourceArn={'Ref':'bus'})
    discoverer.scope.region=region
    data=linked_design(main,[discoverer])
    data.relations.append(Relation(id='discoverer-bus',source_resource_id='discoverer',source_path='/properties/SourceArn',target_resource_id='bus',evidence_ids=['e1'],condition='optional' if conditional else None))
    assert run_resource_checks(data,main)[0]['verdict']==expected


def test_no_discoverer_does_not_prove_live_state():
    main=target('bus','AWS::Events::EventBus',Name='bus',KmsKeyIdentifier='alias/customer-events')
    assert run_resource_checks(linked_design(main),main)[0]['verdict']=='NEEDS_REVIEW'


def test_omitted_key_does_not_trigger_customer_encryption_check():
    main=target('bus','AWS::Events::EventBus',Name='bus')
    assert run_resource_checks(linked_design(main),main)==[]
