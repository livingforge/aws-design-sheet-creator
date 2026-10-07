import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('region,expected',[
    ('cn-north-1','FAIL'),('cn-northwest-1','FAIL'),('ap-northeast-1','PASS'),
    ('us-gov-west-1','PASS'),('unknown','NEEDS_REVIEW'),
])
def test_ipv6_region(region,expected):
    main=target('cluster','AWS::EKS::Cluster',KubernetesNetworkConfig={'IpFamily':'ipv6'})
    main.scope.region=region
    findings={r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(main),main)}
    assert findings['EKS_IPV6_CHINA_REGION']==expected


@pytest.mark.parametrize('version,expected',[
    ('1.20','FAIL'),('1.21','PASS'),('1.34','PASS'),(UNKNOWN,'NEEDS_REVIEW'),
    (None,'NEEDS_REVIEW'),('latest','NEEDS_REVIEW'),
])
def test_ipv6_cluster_version(version,expected):
    main=target('cluster','AWS::EKS::Cluster',KubernetesNetworkConfig={'IpFamily':'ipv6'},**({'Version':version} if version is not None else {}))
    findings={r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(main),main)}
    assert findings['EKS_IPV6_CLUSTER_VERSION']==expected


def test_ipv4_does_not_trigger_ipv6_checks():
    main=target('cluster','AWS::EKS::Cluster',KubernetesNetworkConfig={'IpFamily':'ipv4'},Version='1.20')
    findings={r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(main),main)}
    assert 'EKS_IPV6_CLUSTER_VERSION' not in findings
