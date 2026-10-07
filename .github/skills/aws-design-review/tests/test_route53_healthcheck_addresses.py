import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('address',[
    '0.1.2.3','10.255.255.255','100.64.0.0','100.127.255.255','127.0.0.1',
    '169.254.1.1','172.16.0.0','172.31.255.255','192.168.0.1','224.0.0.1',
    '239.255.255.255','::','::1','fc00::1','fdff::1','fe80::1','febf::1',
    'fec0::1','ff02::1','2001:db8::1','::ffff:10.1.2.3','fe80::1%eth0','bad-ip',
])
def test_blocked_endpoint_ranges(address):
    main=target('health','AWS::Route53::HealthCheck',HealthCheckConfig={'IPAddress':address})
    assert run_resource_checks(linked_design(main),main)[0]['verdict']=='FAIL'


@pytest.mark.parametrize('address',[
    '100.63.255.255','100.128.0.0','172.15.255.255','172.32.0.0','8.8.8.8',
    '2001:4860:4860::8888','::ffff:8.8.8.8','192.0.0.9',UNKNOWN,'${Address}',
])
def test_other_ranges_and_unresolved_are_not_certified(address):
    main=target('health','AWS::Route53::HealthCheck',HealthCheckConfig={'IPAddress':address})
    assert run_resource_checks(linked_design(main),main)[0]['verdict']=='NEEDS_REVIEW'


def test_domain_only_no_ip_check():
    main=target('health','AWS::Route53::HealthCheck',HealthCheckConfig={'FullyQualifiedDomainName':'example.com'})
    assert run_resource_checks(linked_design(main),main)==[]
