"""Local string structure, IP boundaries, retention limits and explicit AZ links."""
from pathlib import Path
import pytest
from aws_design_sheet.checks.timestream.network_shapes import evaluate_timestream_network_shapes
from aws_design_sheet.checks.transfer.host_key_text import evaluate_transfer_host_key_text
from aws_design_sheet.checks.vpclattice.target_id_form import evaluate_vpclattice_target_id_form
from aws_design_sheet.checks.wafv2.ipset_cidrs import evaluate_wafv2_ipset_cidrs
from aws_design_sheet.checks.xray.sampling_attributes import evaluate_xray_sampling_attributes
from aws_design_sheet.checks.registry import combine
network_shapes_checks = combine(evaluate_timestream_network_shapes, evaluate_transfer_host_key_text, evaluate_vpclattice_target_id_form, evaluate_wafv2_ipset_cidrs, evaluate_xray_sampling_attributes)
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(kind,**props):
    r=target('subject','AWS::'+kind,**props)
    return network_shapes_checks(linked_design(r),r)


@pytest.mark.parametrize('left,right,expected',[
    ({'AvailabilityZone':'ap-northeast-1a'},{'AvailabilityZone':'ap-northeast-1c'},'PASS'),
    ({'AvailabilityZone':'ap-northeast-1a'},{'AvailabilityZone':'ap-northeast-1a'},'FAIL'),
    ({'AvailabilityZoneId':'apne1-az1'},{'AvailabilityZoneId':'apne1-az2'},'PASS'),
    ({'AvailabilityZoneId':'apne1-az1'},{'AvailabilityZoneId':'apne1-az1'},'FAIL'),
    ({'AvailabilityZone':'ap-northeast-1a'},{'AvailabilityZoneId':'apne1-az1'},'NEEDS_REVIEW'),
    ({'AvailabilityZone':UNKNOWN},{'AvailabilityZone':'ap-northeast-1a'},'NEEDS_REVIEW'),
    ({'AvailabilityZone':'ap-northeast-1a','AvailabilityZoneId':'apne1-az1'},{'AvailabilityZone':'ap-northeast-1c'},'NEEDS_REVIEW'),
    ({},{'AvailabilityZone':'ap-northeast-1c'},'NEEDS_REVIEW')])
def test_influx_az(left,right,expected):
    r=target('instance','AWS::Timestream::InfluxDBInstance',DeploymentType='WITH_MULTIAZ_STANDBY',VpcSubnetIds=['a','b'])
    a=target('a','AWS::EC2::Subnet',**left);b=target('b','AWS::EC2::Subnet',**right)
    assert network_shapes_checks(linked_design(r,[a,b],[('VpcSubnetIds/0','a'),('VpcSubnetIds/1','b')]),r)[0]['verdict']==expected


@pytest.mark.parametrize('mode',['unlinked','conditional','cross_scope','three_subnets','unknown_mode','unknown_scope'])
def test_influx_az_holds(mode):
    r=target('instance','AWS::Timestream::InfluxDBInstance',DeploymentType=UNKNOWN if mode=='unknown_mode' else 'WITH_MULTIAZ_STANDBY',VpcSubnetIds=['a','b','c'] if mode=='three_subnets' else ['a','b'])
    a=target('a','AWS::EC2::Subnet',AvailabilityZone='ap-northeast-1a');b=target('b','AWS::EC2::Subnet',AvailabilityZone='ap-northeast-1a')
    d=linked_design(r,[a,b],[] if mode=='unlinked' else [('VpcSubnetIds/0','a'),('VpcSubnetIds/1','b')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='cross_scope':b.scope.region='us-east-1'
    if mode=='unknown_scope':r.scope.region=a.scope.region=b.scope.region='unknown'
    assert network_shapes_checks(d,r)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('key,bound',[('MemoryStoreRetentionPeriodInHours',8766),('MagneticStoreRetentionPeriodInDays',73000)])
@pytest.mark.parametrize('mode',['minimum','maximum','over','zero','huge','leading_zero','float_string','number','unknown'])
def test_retention(key,bound,mode):
    raw={'minimum':'1','maximum':str(bound),'over':str(bound+1),'zero':'0','huge':'9'*5000,'leading_zero':'01','float_string':'1.0','number':1,'unknown':UNKNOWN}[mode]
    expected='PASS' if mode in ('minimum','maximum') else 'FAIL' if mode in ('over','zero','huge') else 'NEEDS_REVIEW'
    assert check('Timestream::Table',RetentionProperties={key:raw})[0]['verdict']==expected


# Synthetic Base64 text exercises syntax only, never a real key or credential.
@pytest.mark.parametrize('key,egress,expected',[
    ('ssh-rsa YQ==','VPC_LATTICE','PASS'),('ecdsa-sha2-nistp256 YQ==','SERVICE_MANAGED','PASS'),
    ('ecdsa-sha2-nistp384 YQ==',UNKNOWN,'PASS'),('ecdsa-sha2-nistp521 YQ==','VPC_LATTICE','PASS'),
    ('ssh-ed25519 YQ==','SERVICE_MANAGED','FAIL'),('ssh-dss YQ==','SERVICE_MANAGED','FAIL'),
    ('ssh-rsa YQ== comment','SERVICE_MANAGED','FAIL'),
    ('host.example ssh-rsa YQ==','SERVICE_MANAGED','PASS'),
    ('host.example ssh-rsa YQ==','VPC_LATTICE','FAIL'),
    ('host.example ssh-rsa YQ==',UNKNOWN,'NEEDS_REVIEW'),
    ('host.example ssh-rsa YQ== comment','SERVICE_MANAGED','FAIL'),
    ('ssh-rsa ???','VPC_LATTICE','NEEDS_REVIEW'),('ssh-rsa YQ','VPC_LATTICE','NEEDS_REVIEW'),
    ('ssh-rsa\nYQ==','VPC_LATTICE','NEEDS_REVIEW'),('ssh-rsa','SERVICE_MANAGED','NEEDS_REVIEW'),
    (UNKNOWN,'SERVICE_MANAGED','NEEDS_REVIEW'),('${public_key}','VPC_LATTICE','NEEDS_REVIEW')])
def test_host_key_text(key,egress,expected):
    assert check('Transfer::Connector',EgressType=egress,SftpConfig={'TrustedHostKeys':[key]})[0]['verdict']==expected


LAMBDA='arn:aws:lambda:ap-northeast-1:111111111111:function:worker'
ALB='arn:aws:elasticloadbalancing:ap-northeast-1:111111111111:loadbalancer/app/app-name/0123456789abcdef'


@pytest.mark.parametrize('kind,id,expected',[
    ('INSTANCE','i-01234567','PASS'),('INSTANCE','i-0123456789abcdef0','PASS'),
    ('INSTANCE','i-future','NEEDS_REVIEW'),('INSTANCE','subnet-01234567','FAIL'),
    ('IP','192.0.2.1','PASS'),('IP','2001:db8::1','PASS'),('IP','192.0.2.0/24','FAIL'),
    ('IP','999.0.0.1','FAIL'),('IP','fe80::1%eth0','NEEDS_REVIEW'),
    ('LAMBDA',LAMBDA,'PASS'),('LAMBDA',LAMBDA+':prod','NEEDS_REVIEW'),('LAMBDA',ALB,'FAIL'),
    ('LAMBDA','worker','FAIL'),('LAMBDA',LAMBDA.replace('arn:aws:','arn:aws-future:'),'NEEDS_REVIEW'),
    ('ALB',ALB,'PASS'),('ALB',ALB.replace('/app/','/net/'),'FAIL'),('ALB',LAMBDA,'FAIL'),
    ('ALB',ALB.replace('0123456789abcdef','new-form'),'NEEDS_REVIEW'),
    (UNKNOWN,LAMBDA,'NEEDS_REVIEW'),('IP',UNKNOWN,'NEEDS_REVIEW')])
def test_target_id_forms(kind,id,expected):
    assert check('VpcLattice::TargetGroup',Type=kind,Targets=[{'Id':id}])[0]['verdict']==expected


@pytest.mark.parametrize('address,version,expected',[
    ('192.0.2.44/32','IPV4','PASS'),('192.0.2.0/24','IPV4','PASS'),
    ('2001:db8::/64','IPV6','PASS'),('2001:db8::1/128','IPV6','PASS'),
    ('192.0.2.0/24','IPV6','FAIL'),('2001:db8::/64','IPV4','FAIL'),
    ('0.0.0.0/0','IPV4','FAIL'),('::/0','IPV6','FAIL'),('192.0.2.44','IPV4','FAIL'),
    ('192.0.2.1/24','IPV4','NEEDS_REVIEW'),('192.0.2.0/255.255.255.0','IPV4','NEEDS_REVIEW'),
    ('fe80::1%eth0/128','IPV6','NEEDS_REVIEW'),('192.0.2.0/33','IPV4','FAIL'),
    ('','IPV4','FAIL'),(UNKNOWN,'IPV4','NEEDS_REVIEW'),('192.0.2.0/24',UNKNOWN,'NEEDS_REVIEW'),
    ('::/0',UNKNOWN,'FAIL')])
def test_waf_cidrs(address,version,expected):
    assert check('WAFv2::IPSet',IPAddressVersion=version,Addresses=[address])[0]['verdict']==expected


@pytest.mark.parametrize('attributes,expected',[
    ({str(i):'x' for i in range(5)},'PASS'),({str(i):'x' for i in range(6)},'FAIL'),
    ({'a'*32:'b'*32},'PASS'),({'a'*33:'x'},'FAIL'),({'a':'b'*33},'FAIL'),
    ({'':'x'},'FAIL'),({'a':''},'FAIL'),({'a':UNKNOWN},'NEEDS_REVIEW'),
    ({'a/b':'x'},'NEEDS_REVIEW'),({'a~b':'x'},'NEEDS_REVIEW'),
    (UNKNOWN,'NEEDS_REVIEW'),({**{str(i):UNKNOWN for i in range(6)}},'FAIL')])
def test_xray_attributes(attributes,expected):
    assert check('XRay::SamplingRule',SamplingRule={'Attributes':attributes})[0]['verdict']==expected


def test_absent_or_empty_collections():
    assert check('Transfer::Connector',SftpConfig={})==[]
    assert check('WAFv2::IPSet',IPAddressVersion='IPV4',Addresses=[])==[]
    assert check('Timestream::InfluxDBInstance',DeploymentType='SINGLE_AZ',VpcSubnetIds=['one'])==[]


def test_checker_integration():
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('subject','AWS::WAFv2::IPSet',IPAddressVersion='IPV4',Addresses=['0.0.0.0/0'])
    row=next(x for x in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'] if x['rule_id']=='WAFV2_IPSET_CIDRS')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
