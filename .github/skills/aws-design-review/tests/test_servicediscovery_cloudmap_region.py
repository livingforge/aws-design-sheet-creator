import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.servicediscovery.cloudmap_region import evaluate_servicediscovery_cloudmap_region
from test_autoscaling_group_and_scaling_policy import target,linked_design


@pytest.mark.parametrize('region,want',[('us-gov-east-1','FAIL'),('us-gov-west-1','FAIL'),('ap-northeast-1','PASS'),('us-east-1','PASS'),('cn-north-1','PASS'),('UNKNOWN','NEEDS_REVIEW'),('${Region}','NEEDS_REVIEW')])
def test_region_exclusion(region,want):
    r=target('namespace','AWS::ServiceDiscovery::PublicDnsNamespace');r.scope.region=region
    assert evaluate_servicediscovery_cloudmap_region(linked_design(r),r)[0]['verdict']==want


def test_unresolved_template():
    r=target('namespace','AWS::ServiceDiscovery::PublicDnsNamespace');r.template=TemplateContext(state='UNRESOLVED')
    assert evaluate_servicediscovery_cloudmap_region(linked_design(r),r)[0]['verdict']=='NEEDS_REVIEW'


def test_private_namespace_out_of_scope():
    r=target('namespace','AWS::ServiceDiscovery::PrivateDnsNamespace');r.scope.region='us-gov-east-1'
    assert evaluate_servicediscovery_cloudmap_region(linked_design(r),r)==[]


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    r=target("namespace","AWS::ServiceDiscovery::PublicDnsNamespace");d=linked_design(r);root=Path(__file__).resolve().parents[1]
    results=Checker(root/"schemas",root/"profiles/vpc-subnet.json").check(d)["results"]
    assert any(f["rule_id"]=="CLOUDMAP_PUBLIC_DNS_GOVCLOUD" and f["verdict"]=="PASS" for f in results)
