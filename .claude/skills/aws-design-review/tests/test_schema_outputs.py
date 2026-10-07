from pathlib import Path
import pytest
from aws_design_sheet.checks.elasticsearch.subnet_zone_count import evaluate_elasticsearch_subnet_zone_count
from aws_design_sheet.checks.entityresolution.output_field import evaluate_entityresolution_output_field
from aws_design_sheet.checks.eventschemas.type_values import evaluate_eventschemas_type_values
from aws_design_sheet.checks.config.bucket_kms_region import evaluate_config_bucket_kms_region
from aws_design_sheet.checks.registry import combine
schema_outputs_checks = combine(evaluate_elasticsearch_subnet_zone_count, evaluate_entityresolution_output_field, evaluate_eventschemas_type_values, evaluate_config_bucket_kms_region)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('count',[2,3,UNKNOWN,True,4])
@pytest.mark.parametrize('mode',['match','short','long','unknown','disabled'])
def test_zone_count(count,mode):
    length=count if type(count) is int else 2
    if mode=='short':length-=1
    if mode=='long':length+=1
    r=target('main','AWS::Elasticsearch::Domain',ElasticsearchClusterConfig={'ZoneAwarenessEnabled':mode!='disabled','ZoneAwarenessConfig':{'AvailabilityZoneCount':count}},VPCOptions={'SubnetIds':UNKNOWN if mode=='unknown' else ['subnet']*length})
    expected='NEEDS_REVIEW' if type(count) is not int or count not in (2,3) or mode in ('unknown','disabled') else 'PASS' if mode=='match' else 'FAIL'
    assert schema_outputs_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('mode',['match','missing','unknown_output','unknown_field','duplicate_field','empty_fields','literal','conditional','scope','multi_source','unknown_inputs','unknown_outputs'])
def test_output_name(mode):
    inputs=UNKNOWN if mode=='unknown_inputs' else [{'SchemaArn':'schema'}]*(2 if mode=='multi_source' else 1)
    outputs=UNKNOWN if mode=='unknown_outputs' else [{'Output':[{'Name':UNKNOWN if mode=='unknown_output' else 'other' if mode=='missing' else 'email'}]}]
    r=target('main','AWS::EntityResolution::MatchingWorkflow',InputSourceConfig=inputs,OutputSourceConfig=outputs)
    fields=[] if mode=='empty_fields' else [{'FieldName':UNKNOWN if mode=='unknown_field' else 'email'}]*(2 if mode=='duplicate_field' else 1)
    schema=target('schema','AWS::EntityResolution::SchemaMapping',MappedInputFields=fields)
    d=linked_design(r,[schema],[] if mode=='literal' else [('InputSourceConfig/0/SchemaArn','schema')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='scope':schema.scope.region='us-east-1'
    assert schema_outputs_checks(d,r)[0]['verdict']==('PASS' if mode=='match' else 'FAIL' if mode=='missing' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('raw,expected',[('OpenApi3','PASS'),('JSONSchemaDraft4','PASS'),('OpenAPI3','FAIL'),('JSONSchemaDraft7','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),({'Ref':'Type'},'NEEDS_REVIEW'),('','NEEDS_REVIEW')])
def test_schema_type(raw,expected):
    r=target('main','AWS::EventSchemas::Schema',Type=raw)
    assert schema_outputs_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('mode',['same','region','alias','unknown','literal','conditional','scope','missing_bucket'])
def test_kms_region(mode):
    raw=UNKNOWN if mode=='unknown' else 'arn:aws:kms:'+('us-east-1' if mode=='region' else 'ap-northeast-1')+':111111111111:'+('alias/name' if mode=='alias' else 'key/example-key')
    r=target('main','AWS::Config::DeliveryChannel',S3BucketName='bucket',S3KmsKeyArn=raw)
    bucket=target('bucket','AWS::S3::Bucket')
    d=linked_design(r,[] if mode=='missing_bucket' else [bucket],[] if mode in ('literal','missing_bucket') else [('S3BucketName','bucket')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='scope':bucket.scope.region='us-east-1'
    assert schema_outputs_checks(d,r)[0]['verdict']==('PASS' if mode=='same' else 'FAIL' if mode=='region' else 'NEEDS_REVIEW')


def test_checker_schema_type():
    r=target('main','AWS::EventSchemas::Schema',Type='invalid')
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='EVENTSCHEMAS_TYPE_VALUES' and f['verdict']=='FAIL' for f in results)
