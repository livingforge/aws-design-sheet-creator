"""Checks for these resource types:

- AWS::EC2::Instance
- AWS::EC2::LaunchTemplate
- AWS::EC2::Route
- AWS::EC2::VerifiedAccessEndpoint
- AWS::EC2::VerifiedAccessTrustProvider
- AWS::EC2::Host
- AWS::EC2::IPAMPool
- AWS::EC2::PlacementGroup
- AWS::EC2::RouteServer
- AWS::EC2::TransitGateway
"""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.required_values import required_value, uncertain

API = 'https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_'
SOURCES = {
    'EC2_HOST_INSTANCE_TYPE_FAMILY_EXCLUSIVE': [API + 'AllocateHosts.html'],
    'EC2_IPAM_PUBLIC_ADVERTISEMENT_SOURCE': [API + 'CreateIpamPool.html'],
    'EC2_PLACEMENT_PARENT_CLUSTER': [API + 'CreatePlacementGroup.html'],
    'EC2_TRANSIT_GATEWAY_PRIVATE_ASN': [API + 'TransitGatewayRequestOptions.html'],
    'EC2_ROUTE_SERVER_PERSIST_DURATION': [API + 'CreateRouteServer.html'],
    'EC2_EXISTING_NIC_LAUNCH_FLAGS': [API + 'InstanceNetworkInterfaceSpecification.html'],
    'EC2_VERIFIED_ACCESS_ENDPOINT_OPTIONS': [API + 'CreateVerifiedAccessEndpoint.html'],
    'EC2_VERIFIED_ACCESS_TRUST_OPTIONS': [API + 'CreateVerifiedAccessTrustProvider.html'],
    'EC2_ROUTE_ENDPOINT_TARGET_TYPE': [API + 'CreateRoute.html'],
    'EC2_T3_HOST_CREDITS': ['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-instance.html'],
    'EC2_RETIRED_ACCELERATORS': ['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-instance.html'],
    'EC2_TEMPLATE_CPU_CAPABILITIES': [API + 'CpuOptionsRequest.html', API + 'CreditSpecificationRequest.html'],
}


@resource_check('AWS::EC2::Instance')
def evaluate_instance_accelerator_capabilities(design, resource):
    rows = []
    ctx = _Context(design, resource)
    instance_type = value(ctx, resource, '/properties/InstanceType')
    tenancy = value(ctx, resource, '/properties/Tenancy')
    credits = value(ctx, resource, '/properties/CreditSpecification/CPUCredits')
    if tenancy == 'host' and isinstance(instance_type, str) and instance_type.startswith('t3.'):
        verdict = 'PASS' if credits == 'standard' else 'FAIL' if credits in ('unlimited', ABSENT) else 'NEEDS_REVIEW'
        rows.append({**ctx.finding('EC2_T3_HOST_CREDITS', '/properties/CreditSpecification/CPUCredits', verdict,
            'explicit T3 host tenancy supports standard credits only; omitted T3 credits default to unlimited; T3a is not inferred'), 'severity': 'WARNING'})
    for name in ('ElasticGpuSpecifications', 'ElasticInferenceAccelerators'):
        local = _Context(design, resource)
        path = '/properties/' + name
        v = value(local, resource, path)
        if v is ABSENT or v == []:
            continue
        verdict = ('FAIL' if isinstance(v, list) and any(isinstance(item, dict) and
                   '$state' not in item and '$ref' not in item for item in v) else 'NEEDS_REVIEW')
        rows.append({**local.finding('EC2_RETIRED_ACCELERATORS', path, verdict,
            'the documented accelerator service has ended; CloudFormation handling of legacy properties is not established'), 'severity': 'WARNING'})
    return rows


@resource_check('AWS::EC2::LaunchTemplate')
def evaluate_launch_template_cpu_capabilities(design, resource):
    rows = []
    root = '/properties/LaunchTemplateData/'
    for feature in ('CreditSpecification', 'CpuOptions/AmdSevSnp'):
        ctx = _Context(design, resource)
        path = root + feature
        v = value(ctx, resource, path)
        if v is ABSENT or (feature.endswith('AmdSevSnp') and v == 'disabled'):
            continue
        instance_type = value(ctx, resource, root + 'InstanceType')
        verdict = 'NEEDS_REVIEW'
        if isinstance(instance_type, str) and re.fullmatch(r'[a-z][a-z0-9-]*\.[a-z0-9]+', instance_type):
            family = instance_type.split('.')[0]
            if feature == 'CreditSpecification' and isinstance(v, dict):
                verdict = 'PASS' if family in ('t2', 't3', 't3a', 't4g') else 'FAIL'
            elif feature.endswith('AmdSevSnp') and v == 'enabled':
                verdict = 'PASS' if family in ('m6a', 'r6a', 'c6a') else 'FAIL'
        rows.append({**ctx.finding('EC2_TEMPLATE_CPU_CAPABILITIES', path, verdict,
            'compares explicit template instance types with documented feature families; launch-time overrides and changing capabilities require separate review'), 'severity': 'WARNING'})
    return rows


@resource_check('AWS::EC2::Route')
def evaluate_route_endpoint_target_type(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/VpcEndpointId'
    endpoint_id = value(ctx, resource, path)
    if endpoint_id is ABSENT:
        return []
    endpoint = linked(ctx, resource, path, 'AWS::EC2::VPCEndpoint')
    kind = value(ctx, endpoint, '/properties/VpcEndpointType') if endpoint else UNKNOWN
    if endpoint is not None and kind is ABSENT:
        kind = 'Gateway'
    if kind == 'GatewayLoadBalancer':
        verdict = 'PASS'
    elif kind in ('Interface', 'Gateway', 'Resource', 'ServiceNetwork', 'Tunnel'):
        verdict = 'FAIL'
    else:
        verdict = 'NEEDS_REVIEW'
    return [ctx.finding('EC2_ROUTE_ENDPOINT_TARGET_TYPE', path, verdict,
                       'a route VpcEndpointId target must be a Gateway Load Balancer endpoint; reachability and gateway attachments require separate review')]


@resource_check('AWS::EC2::VerifiedAccessEndpoint')
def evaluate_verified_access_endpoint_options(design, resource):
    ctx = _Context(design, resource)
    kind = value(ctx, resource, '/properties/EndpointType')
    mapping = {'load-balancer': 'LoadBalancerOptions', 'network-interface': 'NetworkInterfaceOptions',
               'rds': 'RdsOptions', 'cidr': 'CidrOptions'}
    rule = 'EC2_VERIFIED_ACCESS_ENDPOINT_OPTIONS'
    if not isinstance(kind, str) or kind not in mapping:
        return [ctx.finding(rule, '/properties/EndpointType', 'NEEDS_REVIEW', 'endpoint type is unresolved')]
    path = '/properties/' + mapping[kind]
    verdict = required_value(ctx, resource, path)
    return [ctx.finding(rule, path, verdict, 'the matching endpoint options block is required; other blocks are not prohibited by this check')]


@resource_check('AWS::EC2::VerifiedAccessTrustProvider')
def evaluate_verified_access_trust_options(design, resource):
    ctx = _Context(design, resource)
    kind = value(ctx, resource, '/properties/TrustProviderType')
    rule = 'EC2_VERIFIED_ACCESS_TRUST_OPTIONS'
    if kind not in ('user', 'device'):
        return [ctx.finding(rule, '/properties/TrustProviderType', 'NEEDS_REVIEW', 'trust provider type is unresolved')]
    names = ['DeviceTrustProviderType', 'DeviceOptions'] if kind == 'device' else ['UserTrustProviderType']
    subtype = value(ctx, resource, '/properties/UserTrustProviderType') if kind == 'user' else ABSENT
    if subtype == 'oidc':
        names.append('OidcOptions')
    rows = []
    for name in names:
        path = '/properties/' + name
        rows.append(ctx.finding(rule, path, required_value(ctx, resource, path),
                                'matching provider fields are required; native OIDC and opposite-kind options remain outside this check'))
    return rows


@resource_check('AWS::EC2::Host')
def evaluate_ec2_host_instance_type_family(design, resource):
    ctx = _Context(design, resource)
    paths = ['/properties/InstanceType', '/properties/InstanceFamily']
    values = [value(ctx, resource, p) for p in paths]
    if any(v is ABSENT for v in values):
        verdict = 'PASS'
    elif any(uncertain(v) or not isinstance(v, str) or not v for v in values):
        verdict = 'NEEDS_REVIEW'
    else:
        verdict = 'FAIL'
    return [ctx.finding('EC2_HOST_INSTANCE_TYPE_FAMILY_EXCLUSIVE', paths[0], verdict,
                       'InstanceType and InstanceFamily cannot coexist; this does not assert that either is required')]


@resource_check('AWS::EC2::IPAMPool')
def evaluate_ipam_public_advertisement_source(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/PubliclyAdvertisable'
    enabled = value(ctx, resource, path)
    if enabled is ABSENT:
        return []
    source = value(ctx, resource, '/properties/PublicIpSource')
    family = value(ctx, resource, '/properties/AddressFamily')
    if source is ABSENT:
        source = 'byoip'  # Documented request default.
    if type(enabled) is not bool:
        verdict = 'NEEDS_REVIEW'
    elif family == 'ipv4' or source == 'amazon':
        verdict = 'FAIL'
    elif family == 'ipv6' and source == 'byoip' and type(enabled) is bool:
        verdict = 'PASS'
    else:
        verdict = 'NEEDS_REVIEW'
    return [ctx.finding('EC2_IPAM_PUBLIC_ADVERTISEMENT_SOURCE', path, verdict,
                       'PubliclyAdvertisable may be specified only for IPv6 BYOIP pools, including an explicit false value')]


@resource_check('AWS::EC2::PlacementGroup')
def evaluate_placement_parent_cluster(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/ParentGroupId'
    parent = value(ctx, resource, path)
    if parent is ABSENT:
        return []
    strategy = value(ctx, resource, '/properties/Strategy')
    if strategy == 'cluster':
        verdict = 'PASS'
    elif strategy in ('spread', 'partition', 'precision-time') and not uncertain(parent):
        verdict = 'FAIL'
    else:
        verdict = 'NEEDS_REVIEW'
    return [ctx.finding('EC2_PLACEMENT_PARENT_CLUSTER', path, verdict,
                       'ParentGroupId is valid only for the cluster strategy; parent existence and ownership need separate review')]


@resource_check('AWS::EC2::TransitGateway', 'AWS::EC2::RouteServer')
def evaluate_transit_gateway_asn_or_route_server_duration(design, resource):
    ctx = _Context(design, resource)
    transit = resource.type.endswith('::TransitGateway')
    path = '/properties/AmazonSideAsn' if transit else '/properties/PersistRoutesDuration'
    v = value(ctx, resource, path)
    if v is ABSENT:
        return []
    if type(v) is not int:
        verdict = 'NEEDS_REVIEW'
    else:
        valid = (64512 <= v <= 65534 or 4200000000 <= v <= 4294967294) if transit else 1 <= v <= 5
        verdict = 'PASS' if valid else 'FAIL'
    rule = 'EC2_TRANSIT_GATEWAY_PRIVATE_ASN' if transit else 'EC2_ROUTE_SERVER_PERSIST_DURATION'
    reason = ('Amazon-side ASN must be in the documented 16-bit or 32-bit private ASN range' if transit else
              'API documents a persistence duration of 1-5 minutes; the pinned schema also accepts zero, so this is advisory')
    row = ctx.finding(rule, path, verdict, reason)
    if not transit:
        row['severity'] = 'WARNING'
    return [row]


@resource_check('AWS::EC2::Instance')
def evaluate_instance_existing_nic_launch_flags(design, resource):
    ctx = _Context(design, resource)
    root = '/properties/NetworkInterfaces'
    interfaces = value(ctx, resource, root)
    if interfaces is ABSENT:
        return []
    rule = 'EC2_EXISTING_NIC_LAUNCH_FLAGS'
    reason = 'an existing network interface cannot be assigned a public IP or deleted on termination through these launch flags'
    if not isinstance(interfaces, list):
        return [ctx.finding(rule, root, 'NEEDS_REVIEW', reason)]
    rows = []
    for i in range(len(interfaces)):
        prefix = f'{root}/{i}'
        for key in ('AssociatePublicIpAddress', 'DeleteOnTermination'):
            local = _Context(design, resource)
            path = prefix + '/' + key
            flag = value(local, resource, path)
            nic_path = prefix + '/NetworkInterfaceId'
            nic = value(local, resource, nic_path)
            # A definite logical relation establishes that this is an existing NIC.
            reference = any(r.source_resource_id == resource.id and r.source_path == nic_path
                            and not r.condition for r in design.relations)
            known_nic = reference or (isinstance(nic, str) and bool(nic) and not uncertain(nic))
            if flag is ABSENT or flag is False or nic is ABSENT:
                verdict = 'NOT_APPLICABLE'
            elif flag is True and known_nic:
                verdict = 'FAIL'
            else:
                verdict = 'NEEDS_REVIEW'
            rows.append(local.finding(rule, path, verdict, reason))
    return rows
