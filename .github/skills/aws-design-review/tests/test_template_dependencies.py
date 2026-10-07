"""Template boundaries, missing information, ordering and extraction end to end."""
from pathlib import Path

import pytest

from aws_design_sheet.checker import Checker
from aws_design_sheet.extractor import LineExtractor, TextSource
from aws_design_sheet.models import Design, Relation, TemplateContext
from aws_design_sheet.template_dependencies import evaluate_template_dependencies
from aws_design_sheet.excel_report import build_workbook
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN

ROOT = Path(__file__).resolve().parents[1]


def template(resource, deps=(), id='stack'):
    resource.template = TemplateContext(id=id, depends_on=None if deps is None else list(deps), evidence_ids=['e1'])
    return resource


def link(data, source, path, dest, condition=None):
    data.relations.append(Relation(id=f'rel-{len(data.relations)}', source_resource_id=source.id,
        source_path='/properties/' + path, target_resource_id=dest.id, condition=condition, evidence_ids=['e1']))


def findings(data, resource):
    return {r['rule_id']: r for r in evaluate_template_dependencies(data, resource)}


def vpn(deps):
    route = template(target('route', 'AWS::EC2::ClientVpnRoute'), deps)
    assoc = template(target('assoc', 'AWS::EC2::ClientVpnTargetNetworkAssociation'))
    endpoint = template(target('endpoint', 'AWS::EC2::ClientVpnEndpoint'))
    subnet = template(target('subnet', 'AWS::EC2::Subnet'))
    data = linked_design(route, [assoc, endpoint, subnet])
    link(data, route, 'ClientVpnEndpointId', endpoint)
    link(data, route, 'TargetVpcSubnetId', subnet)
    link(data, assoc, 'ClientVpnEndpointId', endpoint)
    link(data, assoc, 'SubnetId', subnet)
    return data, route, assoc


@pytest.mark.parametrize('deps,expected', [(None, 'NEEDS_REVIEW'), ([], 'FAIL'),
    (['assoc'], 'PASS'), (['missing'], 'NEEDS_REVIEW')])
def test_vpn_explicit_or_missing_dependencies(deps, expected):
    data, route, assoc = vpn(deps)
    row = findings(data, route)['EC2_CLIENT_VPN_ROUTE_DEPENDENCY']
    assert row['verdict'] == expected
    assert row['evidence_ids']
    if expected == 'NEEDS_REVIEW':
        assert row['dependencies']


@pytest.mark.parametrize('change', ['stack', 'scope', 'condition', 'unknown', 'duplicate', 'unlinked'])
def test_no_false_match(change):
    data, route, assoc = vpn(['assoc'])
    if change == 'stack':
        assoc.template.id = 'other'
    elif change == 'scope':
        assoc.scope.region = 'us-east-1'
    elif change == 'condition':
        data.relations[2].condition = 'Maybe'
    elif change == 'unknown':
        assoc.template.state = 'UNRESOLVED'
    elif change == 'duplicate':
        other = template(target('other', assoc.type))
        other.name = 'assoc'
        data.resources.append(other)
    elif change == 'unlinked':
        data.relations[2].target_resource_id = 'outside'
    assert findings(data, route)['EC2_CLIENT_VPN_ROUTE_DEPENDENCY']['verdict'] == 'NEEDS_REVIEW'


def test_transitive_order_cycle_and_incomplete_graph():
    data, route, assoc = vpn(['middle'])
    middle = template(target('middle', 'AWS::S3::Bucket'), ['assoc'])
    data.resources.append(middle)
    assert findings(data, route)['EC2_CLIENT_VPN_ROUTE_DEPENDENCY']['verdict'] == 'PASS'
    assoc.template.depends_on = ['route']
    assert findings(data, route)['TEMPLATE_DEPENDENCY_GRAPH']['verdict'] == 'FAIL'
    assert findings(data, route)['EC2_CLIENT_VPN_ROUTE_DEPENDENCY']['verdict'] == 'FAIL'
    middle.template.depends_on = None
    assert findings(data, route)['EC2_CLIENT_VPN_ROUTE_DEPENDENCY']['verdict'] == 'NEEDS_REVIEW'


def test_implicit_reference_can_establish_transitive_order():
    data, route, assoc = vpn([])
    middle = template(target('middle', 'AWS::S3::Bucket'), ['assoc'])
    data.resources.append(middle)
    link(data, route, 'Description', middle)
    assert findings(data, route)['EC2_CLIENT_VPN_ROUTE_DEPENDENCY']['verdict'] == 'PASS'


def test_conflicting_and_nested_unknown_references_do_not_establish_order():
    data, route, assoc = vpn(['assoc'])
    from test_autoscaling_group_nested_constraints import group
    route.fields = group(TargetVpcSubnetId=UNKNOWN).fields
    assert findings(data, route)['EC2_CLIENT_VPN_ROUTE_DEPENDENCY']['verdict'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('deps,expected', [([], 'FAIL'), (['attach'], 'PASS'), (None, 'NEEDS_REVIEW')])
def test_vpn_gateway_order(deps, expected):
    main = template(target('propagation', 'AWS::EC2::VPNGatewayRoutePropagation'), deps)
    attach = template(target('attach', 'AWS::EC2::VPCGatewayAttachment'))
    gateway = template(target('gw', 'AWS::EC2::VPNGateway'))
    data = linked_design(main, [attach, gateway])
    link(data, main, 'VpnGatewayId', gateway)
    link(data, attach, 'VpnGatewayId', gateway)
    assert findings(data, main)['EC2_VPN_PROPAGATION_DEPENDENCY']['verdict'] == expected


@pytest.mark.parametrize('deps,expected', [([], 'FAIL'), (['attach'], 'PASS'), (None, 'NEEDS_REVIEW')])
def test_eip_instance_subnet_vpc_gateway_chain(deps, expected):
    main = template(target('eip', 'AWS::EC2::EIP'), deps)
    instance = template(target('instance', 'AWS::EC2::Instance'))
    subnet = template(target('subnet', 'AWS::EC2::Subnet'))
    vpc = template(target('vpc', 'AWS::EC2::VPC'))
    attach = template(target('attach', 'AWS::EC2::VPCGatewayAttachment'))
    gateway = template(target('gw', 'AWS::EC2::InternetGateway'))
    data = linked_design(main, [instance, subnet, vpc, attach, gateway])
    for a, p, b in [(main, 'InstanceId', instance), (instance, 'SubnetId', subnet),
                    (subnet, 'VpcId', vpc), (attach, 'VpcId', vpc), (attach, 'InternetGatewayId', gateway)]:
        link(data, a, p, b)
    assert findings(data, main)['EC2_EIP_GATEWAY_DEPENDENCY']['verdict'] == expected


@pytest.mark.parametrize('consumer_type', ['AWS::EC2::NatGateway', 'AWS::EC2::EIPAssociation'])
def test_eip_indirect_consumers(consumer_type):
    main = template(target('eip', 'AWS::EC2::EIP'), ['attach'])
    consumer = template(target('consumer', consumer_type))
    nic = template(target('nic', 'AWS::EC2::NetworkInterface'))
    subnet = template(target('subnet', 'AWS::EC2::Subnet'))
    vpc = template(target('vpc', 'AWS::EC2::VPC'))
    attach = template(target('attach', 'AWS::EC2::VPCGatewayAttachment'))
    gateway = template(target('gw', 'AWS::EC2::InternetGateway'))
    data = linked_design(main, [consumer, nic, subnet, vpc, attach, gateway])
    link(data, consumer, 'AllocationId', main)
    if consumer_type.endswith('EIPAssociation'):
        link(data, consumer, 'NetworkInterfaceId', nic)
        link(data, nic, 'SubnetId', subnet)
    else:
        link(data, consumer, 'SubnetId', subnet)
    link(data, subnet, 'VpcId', vpc)
    link(data, attach, 'VpcId', vpc)
    link(data, attach, 'InternetGatewayId', gateway)
    assert findings(data, main)['EC2_EIP_GATEWAY_DEPENDENCY']['verdict'] == 'PASS'
    main.template.depends_on = []
    assert findings(data, main)['EC2_EIP_GATEWAY_DEPENDENCY']['verdict'] == 'FAIL'


def test_client_vpn_local_route_needs_an_association():
    data, route, assoc = vpn(['assoc'])
    from test_autoscaling_group_nested_constraints import group
    route.fields = group(TargetVpcSubnetId='local').fields
    data.relations = [r for r in data.relations if not (r.source_resource_id == route.id and r.source_path.endswith('TargetVpcSubnetId'))]
    assert findings(data, route)['EC2_CLIENT_VPN_ROUTE_DEPENDENCY']['verdict'] == 'PASS'


@pytest.mark.parametrize('deps,expected', [([], 'FAIL'), (['policy'], 'PASS'), (None, 'NEEDS_REVIEW')])
def test_role_consumer_depends_on_external_policy(deps, expected):
    main = template(target('service', 'AWS::ECS::Service'), deps)
    role = template(target('role', 'AWS::IAM::Role'))
    policy = template(target('policy', 'AWS::IAM::Policy'))
    data = linked_design(main, [role, policy])
    link(data, main, 'Role', role)
    link(data, policy, 'Roles/0', role)
    assert findings(data, main)['IAM_ROLE_POLICY_DEPENDENCY']['verdict'] == expected


@pytest.mark.parametrize('deps,expected', [([], 'FAIL'), (['mount'], 'PASS'), (None, 'NEEDS_REVIEW')])
def test_lambda_mount_order(deps, expected):
    main = template(target('function', 'AWS::Lambda::Function', FileSystemConfigs=[{'Arn': 'ap'}]), deps)
    ap = template(target('ap', 'AWS::EFS::AccessPoint'))
    fs = template(target('fs', 'AWS::EFS::FileSystem'))
    mount = template(target('mount', 'AWS::EFS::MountTarget'))
    data = linked_design(main, [ap, fs, mount])
    for a, p, b in [(main, 'FileSystemConfigs/0/Arn', ap), (ap, 'FileSystemId', fs), (mount, 'FileSystemId', fs)]:
        link(data, a, p, b)
    assert findings(data, main)['LAMBDA_MOUNT_TARGET_DEPENDENCY']['verdict'] == expected


def test_template_extraction_conflict_roundtrip_and_checker():
    text = '\n'.join([
        'AWS::EC2::ClientVpnRoute route: @Template={"id":"stack","depends_on":[]}; ClientVpnEndpointId=@AWS::EC2::ClientVpnEndpoint/endpoint; TargetVpcSubnetId=@AWS::EC2::Subnet/subnet',
        'AWS::EC2::ClientVpnTargetNetworkAssociation assoc: @Template={"id":"stack","depends_on":[]}; ClientVpnEndpointId=@AWS::EC2::ClientVpnEndpoint/endpoint; SubnetId=@AWS::EC2::Subnet/subnet',
        'AWS::EC2::ClientVpnEndpoint endpoint: @Template={"id":"stack","depends_on":[]}',
        'AWS::EC2::Subnet subnet: @Template={"id":"stack","depends_on":[]}',
    ])
    def extract(text):
        return LineExtractor().extract([TextSource('d', 'input', '1', text)], project='p', environment='prod', account='111111111111')
    data = extract(text)
    assert data.extractor_version == 'line-v5'
    assert all(r.field('/properties/Template') is None for r in data.resources)
    restored = Design.model_validate_json(data.model_dump_json())
    result = Checker(ROOT / 'schemas', ROOT / 'profiles/vpc-subnet.json').check(restored)
    assert any(r['rule_id'] == 'EC2_CLIENT_VPN_ROUTE_DEPENDENCY' and r['verdict'] == 'FAIL' and r['source_urls'] for r in result['results'])
    workbook = build_workbook(result, restored)
    assert any(row[3].value == '/template' for row in workbook['設計値'].iter_rows(min_row=2))
    conflict = extract(text + '\nAWS::EC2::ClientVpnRoute route: @Template={"id":"other"}')
    assert conflict.resources[0].template.state == 'CONFLICT'
    assert findings(conflict, conflict.resources[0])['EC2_CLIENT_VPN_ROUTE_DEPENDENCY']['verdict'] == 'NEEDS_REVIEW'
    repeat = extract(text + '\n' + text.splitlines()[0])
    assert repeat.resources[0].template.state == 'KNOWN'


def test_template_model_rejects_missing_evidence_and_unknown_fields():
    with pytest.raises(ValueError):
        TemplateContext(id='stack')
    data, route, _ = vpn([])
    raw = data.model_dump(mode='json')
    raw['resources'][0]['template']['evidence_ids'] = ['not-found']
    with pytest.raises(ValueError, match='unknown evidence'):
        Design.model_validate(raw)
    route.template = None
    assert findings(data, route) == {}


def test_real_cloudformation_template_property_is_not_reserved():
    text = 'AWS::SES::Template mail: Template={"TemplateName":"welcome","SubjectPart":"Hello"}'
    data = LineExtractor().extract([TextSource('d', 'input', '1', text)], project='p', environment='prod', account='111111111111')
    assert data.resources[0].template is None
    assert data.resources[0].field('/properties/Template').selected().value['TemplateName'] == 'welcome'


def internet_route(deps, gateway_kind='AWS::EC2::InternetGateway'):
    route = template(target('route', 'AWS::EC2::Route'), deps)
    gateway = template(target('igw', gateway_kind))
    attach = template(target('attach', 'AWS::EC2::VPCGatewayAttachment'))
    vpc = template(target('vpc', 'AWS::EC2::VPC'))
    data = linked_design(route, [gateway, attach, vpc])
    link(data, route, 'GatewayId', gateway)
    link(data, attach, 'InternetGatewayId' if gateway_kind.endswith('InternetGateway') else 'VpnGatewayId', gateway)
    link(data, attach, 'VpcId', vpc)
    return data, route


@pytest.mark.parametrize('deps,expected', [(None, 'NEEDS_REVIEW'), ([], 'FAIL'),
    (['attach'], 'PASS'), (['missing'], 'NEEDS_REVIEW')])
def test_route_to_internet_gateway_depends_on_attachment(deps, expected):
    data, route = internet_route(deps)
    assert findings(data, route)['EC2_ROUTE_GATEWAY_DEPENDENCY']['verdict'] == expected


def test_route_to_vpn_gateway_or_other_template_gateway_is_not_checked():
    data, route = internet_route([], 'AWS::EC2::VPNGateway')
    assert 'EC2_ROUTE_GATEWAY_DEPENDENCY' not in findings(data, route)
    data, route = internet_route([])
    next(r for r in data.resources if r.name == 'igw').template.id = 'other'
    assert 'EC2_ROUTE_GATEWAY_DEPENDENCY' not in findings(data, route)
