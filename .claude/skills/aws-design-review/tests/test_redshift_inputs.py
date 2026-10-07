from pathlib import Path
import pytest
from aws_design_sheet.checks.redshift.port_and_wlm_json import evaluate_redshift_port_and_wlm_json
from aws_design_sheet.checks.pinpoint.campaign_hook_mode import evaluate_pinpoint_campaign_hook_mode
from aws_design_sheet.checks.registry import combine
redshift_inputs_checks = combine(evaluate_redshift_port_and_wlm_json, evaluate_pinpoint_campaign_hook_mode)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('node,port,verdict',[
 ('dc2.large',1150,'PASS'),('dc2.8xlarge',65535,'PASS'),('dc2.large',1149,'FAIL'),('dc2.large',65536,'FAIL'),
 ('ra3.large',5431,'PASS'),('ra3.xlplus',5455,'PASS'),('ra3.4xlarge',8191,'PASS'),('ra3.16xlarge',8215,'PASS'),
 ('rg.xlarge',5430,'NEEDS_REVIEW'),('rg.4xlarge',8216,'NEEDS_REVIEW'),('ra3.large',5456,'NEEDS_REVIEW'),
 ('dc1.large',5439,'NEEDS_REVIEW'),('ra3.future',5439,'NEEDS_REVIEW'),(UNKNOWN,5439,'NEEDS_REVIEW'),
 ('dc2.large',UNKNOWN,'NEEDS_REVIEW'),('dc2.large',True,'NEEDS_REVIEW'),('dc2.large',5439.0,'NEEDS_REVIEW'),
])
def test_ports(node,port,verdict):
 r=target('main','AWS::Redshift::Cluster',NodeType=node,Port=port)
 assert redshift_inputs_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('raw,verdict',[('[]','PASS'),('[{"query_concurrency":5}]','PASS'),('null','PASS'),('{','FAIL'),('[NaN]','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${json}','NEEDS_REVIEW')])
def test_json(raw,verdict):
 r=target('main','AWS::Redshift::ClusterParameterGroup',Parameters=[{'ParameterName':'wlm_json_configuration','ParameterValue':raw}])
 assert redshift_inputs_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('raw,verdict',[('FILTER','PASS'),('DELIVERY','NEEDS_REVIEW'),('filter','FAIL'),('OTHER','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${mode}','NEEDS_REVIEW')])
def test_hook(raw,verdict):
 r=target('main','AWS::Pinpoint::Campaign',Hook={'Mode':raw})
 assert redshift_inputs_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('kind',['AWS::Redshift::Cluster','AWS::Redshift::ClusterParameterGroup','AWS::Pinpoint::Campaign'])
def test_absent(kind):
 r=target('main',kind);assert not redshift_inputs_checks(linked_design(r),r)


def test_other_parameter():
 r=target('main','AWS::Redshift::ClusterParameterGroup',Parameters=[{'ParameterName':'other','ParameterValue':'not JSON'}])
 assert not redshift_inputs_checks(linked_design(r),r)


def test_unknown_parameters():
 r=target('main','AWS::Redshift::ClusterParameterGroup',Parameters=UNKNOWN)
 assert redshift_inputs_checks(linked_design(r),r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker():
 r=target('main','AWS::Redshift::Cluster',NodeType='dc2.large',Port=1149)
 root=Path(__file__).resolve().parents[1]
 results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
 assert any(f['rule_id']=='REDSHIFT_NODE_PORT_RANGE' and f['verdict']=='FAIL' for f in results)
