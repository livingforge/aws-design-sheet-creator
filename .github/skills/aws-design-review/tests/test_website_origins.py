import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('domain',['bucket.s3-website-us-east-1.amazonaws.com','bucket.s3-website.ap-northeast-1.amazonaws.com','BUCKET.s3-website.us-west-2.amazonaws.com.'])
@pytest.mark.parametrize('props,expected',[
    ({'CustomOriginConfig':{'OriginProtocolPolicy':'http-only'}},'PASS'),
    ({'S3OriginConfig':{}},'FAIL'),
    ({'CustomOriginConfig':{},'S3OriginConfig':{}},'FAIL'),
    ({'CustomOriginConfig':UNKNOWN},'NEEDS_REVIEW'),
])
def test_literal_website_requires_custom_origin(domain,props,expected):
    main=target('distribution','AWS::CloudFront::Distribution',DistributionConfig={'Origins':[{'DomainName':domain,**props}]})
    row=next(r for r in run_resource_checks(linked_design(main),main) if r['rule_id']=='CLOUDFRONT_WEBSITE_CUSTOM_ORIGIN')
    assert row['verdict']==expected


@pytest.mark.parametrize('domain',['bucket.s3.amazonaws.com','website.example.com',UNKNOWN,'bucket.s3-website.us-east-1.amazonaws.com.attacker.example'])
def test_unknown_or_nonwebsite_domain_not_inferred(domain):
    main=target('distribution','AWS::CloudFront::Distribution',DistributionConfig={'Origins':[{'DomainName':domain,'S3OriginConfig':{}}]})
    assert not any(r['rule_id']=='CLOUDFRONT_WEBSITE_CUSTOM_ORIGIN' for r in run_resource_checks(linked_design(main),main))
