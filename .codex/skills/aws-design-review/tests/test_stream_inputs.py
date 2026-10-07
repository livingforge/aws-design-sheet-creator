from pathlib import Path
import pytest
from aws_design_sheet.checks.kinesis.channel_on_demand import evaluate_kinesis_channel_on_demand
from aws_design_sheet.checks.kinesisanalytics.json_column_mapping import evaluate_kinesisanalytics_json_column_mapping
from aws_design_sheet.checks.apprunner.connector_subnet_types import evaluate_apprunner_connector_subnet_types
from aws_design_sheet.checks.registry import combine
stream_inputs_checks = combine(evaluate_kinesis_channel_on_demand, evaluate_kinesisanalytics_json_column_mapping, evaluate_apprunner_connector_subnet_types)
from aws_design_sheet.models import Relation, TemplateContext
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('mode',['on_demand','provisioned','unknown','omitted','missing','conditional','ambiguous','scope','template','source_template'])
def test_channel(mode):
    r=target('main','AWS::Kinesis::Channel',StreamConfigurationList=[{'StreamARN':'stream'}])
    s=target('stream','AWS::Kinesis::Stream',**({} if mode=='omitted' else {'StreamModeDetails':{'StreamMode':'ON_DEMAND' if mode=='on_demand' else UNKNOWN if mode=='unknown' else 'PROVISIONED'}}))
    d=linked_design(r,[s],[] if mode=='missing' else [('StreamConfigurationList/0/StreamARN','stream')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='ambiguous':d.relations.append(d.relations[0].model_copy(update={'id':'duplicate'}))
    if mode=='scope':s.scope.region='us-east-1'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='source_template':s.template=TemplateContext(state='UNRESOLVED')
    assert stream_inputs_checks(d,r)[0]['verdict']==('PASS' if mode=='on_demand' else 'FAIL' if mode=='provisioned' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('mode',['present','missing','unknown_mapping','unknown_column','unknown_columns','unknown_format','csv','empty','mixed','unknown_input'])
def test_mapping(mode):
    columns=UNKNOWN if mode=='unknown_columns' else [] if mode=='empty' else [UNKNOWN] if mode=='unknown_column' else [{}] if mode=='missing' else [{'Mapping':UNKNOWN if mode=='unknown_mapping' else '$.value'}]
    if mode=='mixed':columns.extend([UNKNOWN,{}])
    item=UNKNOWN if mode=='unknown_input' else {'InputSchema':{'RecordFormat':{'RecordFormatType':UNKNOWN if mode=='unknown_format' else 'CSV' if mode=='csv' else 'JSON'},'RecordColumns':columns}}
    r=target('main','AWS::KinesisAnalytics::Application',Inputs=[item])
    assert stream_inputs_checks(linked_design(r),r)[0]['verdict']==('PASS' if mode=='present' else 'FAIL' if mode in ('missing','mixed') else 'NEEDS_REVIEW')


@pytest.mark.parametrize('mode',['same','different_vpc','ipv6','omitted_native','unknown_native','missing_subnet','missing_vpc','conditional','scope','template','subnet_template','vpc_template','unknown_list','empty'])
def test_connector(mode):
    r=target('main','AWS::AppRunner::VpcConnector',Subnets=UNKNOWN if mode=='unknown_list' else [] if mode=='empty' else ['one','two'])
    one=target('one','AWS::EC2::Subnet',VpcId='vpc',Ipv6Native=False)
    two=target('two','AWS::EC2::Subnet',VpcId='other' if mode=='different_vpc' else 'vpc',**({} if mode=='omitted_native' else {'Ipv6Native':True if mode=='ipv6' else UNKNOWN if mode=='unknown_native' else False}))
    vpc=target('vpc','AWS::EC2::VPC');other=target('other','AWS::EC2::VPC')
    d=linked_design(r,[one,two,vpc,other],[('Subnets/0','one')]+([] if mode=='missing_subnet' else [('Subnets/1','two')]))
    for s,owner in [(one,'vpc'),(two,'other' if mode=='different_vpc' else 'vpc')]:
        if mode=='missing_vpc' and s.id=='two':continue
        d.relations.append(Relation(id=s.id+'-vpc',source_resource_id=s.id,source_path='/properties/VpcId',target_resource_id=owner,evidence_ids=[]))
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='scope':two.scope.region='us-east-1'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='subnet_template':two.template=TemplateContext(state='UNRESOLVED')
    if mode=='vpc_template':vpc.template=TemplateContext(state='UNRESOLVED')
    assert stream_inputs_checks(d,r)[0]['verdict']==('PASS' if mode=='same' else 'FAIL' if mode in ('different_vpc','ipv6') else 'NEEDS_REVIEW')


@pytest.mark.parametrize('kind',['AWS::Kinesis::Channel','AWS::KinesisAnalytics::Application','AWS::AppRunner::VpcConnector'])
def test_omitted(kind):
    r=target('main',kind)
    assert not stream_inputs_checks(linked_design(r),r)


def test_checker_mapping():
    r=target('main','AWS::KinesisAnalytics::Application',Inputs=[{'InputSchema':{'RecordFormat':{'RecordFormatType':'JSON'},'RecordColumns':[{}]}}])
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='KINESIS_ANALYTICS_JSON_COLUMN_MAPPING' and f['verdict']=='FAIL' for f in results)
