import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('group', [False, True])
@pytest.mark.parametrize('health,private,expected_health,expected_zone', [
    (True, True, 'FAIL', 'FAIL'), (False, True, 'PASS', 'FAIL'),
    (False, False, 'PASS', 'PASS'), (UNKNOWN, False, 'NEEDS_REVIEW', 'PASS'),
])
def test_linked_cloudfront_alias(group, health, private, expected_health, expected_zone):
    alias={'AliasTarget': {'DNSName': {'Fn::GetAtt': ['cf','DomainName']}, 'EvaluateTargetHealth': health}}
    props={'RecordSets': [alias]} if group else alias
    resource=target('records', 'AWS::Route53::RecordSetGroup' if group else 'AWS::Route53::RecordSet',
        HostedZoneId={'Ref': 'zone'}, **props)
    cf=target('cf','AWS::CloudFront::Distribution')
    zone=target('zone','AWS::Route53::HostedZone', **({'VPCs':[{'VPCId':'vpc-a','VPCRegion':'ap-northeast-1'}]} if private else {}))
    prefix='RecordSets/0/' if group else ''
    data=linked_design(resource,[cf,zone],[(prefix+'AliasTarget/DNSName','cf'),('HostedZoneId','zone')])
    results={r['rule_id']:r['verdict'] for r in run_resource_checks(data,resource)}
    assert results['ROUTE53_CLOUDFRONT_ALIAS_HEALTH']==expected_health
    assert results['ROUTE53_CLOUDFRONT_PRIVATE_ZONE']==expected_zone


def test_cloudfront_suffix_does_not_prove_target_type():
    # API Gateway edge-optimized endpoints also use CloudFront DNS names.
    resource=target('record','AWS::Route53::RecordSet', AliasTarget={'DNSName':'d123.cloudfront.net','EvaluateTargetHealth':True})
    results=run_resource_checks(linked_design(resource),resource)
    assert all(r['verdict']=='NEEDS_REVIEW' for r in results)
