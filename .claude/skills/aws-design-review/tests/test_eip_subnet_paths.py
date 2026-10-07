"""Primary NIC and initial launch-template version paths for EIP ordering."""
import pytest

from test_template_dependencies import template, link, findings
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_autoscaling_group_nested_constraints import group


def setup_path(mode='inline', version='1', deps=('attach',)):
    main = template(target('eip', 'AWS::EC2::EIP'), deps)
    instance = template(target('instance', 'AWS::EC2::Instance'))
    subnet = template(target('subnet', 'AWS::EC2::Subnet'))
    vpc = template(target('vpc', 'AWS::EC2::VPC'))
    attach = template(target('attach', 'AWS::EC2::VPCGatewayAttachment'))
    gateway = template(target('gateway', 'AWS::EC2::InternetGateway'))
    nic = template(target('nic', 'AWS::EC2::NetworkInterface'))
    lt = template(target('lt', 'AWS::EC2::LaunchTemplate'))
    data = linked_design(main, [instance, subnet, vpc, attach, gateway, nic, lt])
    link(data, main, 'InstanceId', instance)
    link(data, subnet, 'VpcId', vpc)
    link(data, attach, 'VpcId', vpc)
    link(data, attach, 'InternetGatewayId', gateway)
    owner = instance
    prefix = 'NetworkInterfaces'
    items = [{'DeviceIndex': '0', 'SubnetId': 'subnet'}]
    if mode.startswith('lt'):
        instance.fields = group(LaunchTemplate={'LaunchTemplateId': 'lt', 'Version': version}).fields
        link(data, instance, 'LaunchTemplate/LaunchTemplateId', lt)
        owner = lt
        prefix = 'LaunchTemplateData/NetworkInterfaces'
        lt.fields = group(LaunchTemplateData={'NetworkInterfaces': items}).fields
    else:
        instance.fields = group(NetworkInterfaces=items).fields
    if mode.endswith('existing'):
        items[0] = {'DeviceIndex': 0, 'NetworkInterfaceId': 'nic'}
        link(data, owner, prefix + '/0/NetworkInterfaceId', nic)
        link(data, nic, 'SubnetId', subnet)
    else:
        link(data, owner, prefix + '/0/SubnetId', subnet)
    return data, main, instance, owner, items


@pytest.mark.parametrize('mode', ['inline', 'existing', 'lt-inline', 'lt-existing'])
@pytest.mark.parametrize('deps,expected', [(['attach'], 'PASS'), ([], 'FAIL'), (None, 'NEEDS_REVIEW')])
def test_primary_network_paths(mode, deps, expected):
    data, main, *_ = setup_path(mode, deps=deps)
    assert findings(data, main)['EC2_EIP_GATEWAY_DEPENDENCY']['verdict'] == expected


@pytest.mark.parametrize('version', ['2', '$Latest', '$Default', UNKNOWN, None])
def test_unproven_template_version_is_not_resolved(version):
    data, main, *_ = setup_path('lt-inline', version=version)
    assert findings(data, main)['EC2_EIP_GATEWAY_DEPENDENCY']['verdict'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('mode', ['inline', 'lt-inline'])
@pytest.mark.parametrize('mutation', ['unknown-index', 'secondary-only', 'duplicate-primary', 'unknown-item', 'condition', 'both', 'unknown-override'])
def test_ambiguous_interfaces_do_not_choose_a_subnet(mode, mutation):
    data, main, instance, owner, items = setup_path(mode)
    if mutation == 'unknown-index':
        items[0]['DeviceIndex'] = UNKNOWN
    elif mutation == 'secondary-only':
        items[0]['DeviceIndex'] = 1
    elif mutation == 'duplicate-primary':
        items.append({'DeviceIndex': 0, 'SubnetId': 'other'})
    elif mutation == 'unknown-item':
        items.append(UNKNOWN)
    elif mutation == 'condition':
        data.relations[-1].condition = 'Maybe'
    elif mutation == 'both':
        items[0]['NetworkInterfaceId'] = 'nic'
    elif mutation == 'unknown-override':
        instance.fields.extend(group(SubnetId=UNKNOWN).fields)
    assert findings(data, main)['EC2_EIP_GATEWAY_DEPENDENCY']['verdict'] == 'NEEDS_REVIEW'


def test_secondary_nic_does_not_change_primary_selection():
    data, main, _, _, items = setup_path()
    items.append({'DeviceIndex': 1, 'SubnetId': 'external'})
    assert findings(data, main)['EC2_EIP_GATEWAY_DEPENDENCY']['verdict'] == 'PASS'


def test_launch_template_scope_and_membership_are_required():
    data, main, _, lt, _ = setup_path('lt-inline')
    lt.template.id = 'another-stack'
    assert findings(data, main)['EC2_EIP_GATEWAY_DEPENDENCY']['verdict'] == 'NEEDS_REVIEW'
