import pytest
from aws_design_sheet.checks.route53globalresolver.private_zone import evaluate_route53globalresolver_private_zone
from aws_design_sheet.checks.rekognition.stream_name_characters import evaluate_rekognition_stream_name_characters
from aws_design_sheet.checks.registry import combine
group_inputs_checks = combine(evaluate_route53globalresolver_private_zone, evaluate_rekognition_stream_name_characters)
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('case',['private','omitted','empty','unknown','unknown_id','external','conditional','duplicate','wrong_type'])
def test_zone(case):
 r=target('main','AWS::Route53GlobalResolver::HostedZoneAssociation',HostedZoneId='zone')
 raw=[] if case=='empty' else UNKNOWN if case=='unknown' else [{'VPCId':UNKNOWN if case=='unknown_id' else 'vpc-12345678','VPCRegion':'ap-northeast-1'}]
 z=target('zone','AWS::S3::Bucket' if case=='wrong_type' else 'AWS::Route53::HostedZone',**({} if case=='omitted' else {'VPCs':raw}))
 links=[] if case=='external' else [('HostedZoneId','zone')]
 if case=='duplicate':links+=links
 d=linked_design(r,[z],links)
 if case=='conditional':d.relations[0].condition='condition'
 assert group_inputs_checks(d,r)[0]['verdict']==('PASS' if case=='private' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('raw,verdict',[('Stream_01.test-a','PASS'),('a b','FAIL'),('a/b','FAIL'),('valid!','FAIL'),('a\n','FAIL'),('é','FAIL'),('${name}','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_name(raw,verdict):
 r=target('main','AWS::Rekognition::StreamProcessor',Name=raw)
 assert group_inputs_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('kind',['AWS::Route53GlobalResolver::HostedZoneAssociation','AWS::Rekognition::StreamProcessor'])
def test_absent(kind):
 r=target('main',kind);assert not group_inputs_checks(linked_design(r),r)

