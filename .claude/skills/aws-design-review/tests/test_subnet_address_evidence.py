import pytest
from aws_design_sheet.checks.kinesis.channel_on_demand import evaluate_kinesis_channel_on_demand
from aws_design_sheet.checks.kinesisanalytics.json_column_mapping import evaluate_kinesisanalytics_json_column_mapping
from aws_design_sheet.checks.apprunner.connector_subnet_types import evaluate_apprunner_connector_subnet_types
from aws_design_sheet.checks.registry import combine
stream_inputs_checks = combine(evaluate_kinesis_channel_on_demand, evaluate_kinesisanalytics_json_column_mapping, evaluate_apprunner_connector_subnet_types)
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_template_dependencies import link


@pytest.mark.parametrize('native',[None,False,True,UNKNOWN])
@pytest.mark.parametrize('cidr',['10.0.0.0/24','2001:db8::/64','invalid',UNKNOWN])
def test_address_evidence(native,cidr):
    props={'VpcId':'vpc','CidrBlock':cidr}
    if native is not None:props['Ipv6Native']=native
    r=target('main','AWS::AppRunner::VpcConnector',Subnets=['subnet'])
    s=target('subnet','AWS::EC2::Subnet',**props);v=target('vpc','AWS::EC2::VPC')
    d=linked_design(r,[s,v],[('Subnets/0','subnet')]);link(d,s,'VpcId',v)
    expected='FAIL' if native is True else 'PASS' if native is False or native is None and cidr=='10.0.0.0/24' else 'NEEDS_REVIEW'
    assert stream_inputs_checks(d,r)[0]['verdict']==expected
