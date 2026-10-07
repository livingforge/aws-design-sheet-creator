"""Checks for these resource types:

- AWS::EC2::VPCPeeringConnection
- AWS::EC2::VPNConnection
- AWS::EC2::EnclaveCertificateIamRoleAssociation
- AWS::EC2::EC2Fleet
- AWS::EC2::SpotFleet
- AWS::EC2::Volume
- AWS::EC2::LaunchTemplate
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from email import policy
from email.parser import BytesParser
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN, read

CFN = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'EC2_PEERING_CROSS_ACCOUNT_ROLE': [CFN + 'aws-resource-ec2-vpcpeeringconnection.html'],
    'EC2_VPN_CUSTOMER_GATEWAY_ADDRESS_TYPE': [CFN + 'aws-resource-ec2-customergateway.html',
                                             CFN + 'aws-resource-ec2-vpnconnection.html'],
    'EC2_ENCLAVE_CERTIFICATE_ROLE_LIMIT': [CFN + 'aws-resource-ec2-enclavecertificateiamroleassociation.html'],
    'EC2_EBS_SIZE_BY_TYPE': [CFN + 'aws-resource-ec2-volume.html',
                            CFN + 'aws-properties-ec2-ec2fleet-ebsblockdevice.html',
                            CFN + 'aws-properties-ec2-spotfleet-ebsblockdevice.html'],
    'EC2_EBS_IOPS_BY_TYPE': [CFN + 'aws-resource-ec2-volume.html',
                            CFN + 'aws-properties-ec2-ec2fleet-ebsblockdevice.html',
                            CFN + 'aws-properties-ec2-spotfleet-ebsblockdevice.html'],
    'EC2_TEMPLATE_PARTITION_PLACEMENT': [CFN + 'aws-properties-ec2-launchtemplate-placement.html'],
    'EC2_TEMPLATE_ASG_PROFILE_EXCLUSIVE': [CFN + 'aws-properties-ec2-launchtemplate-iaminstanceprofile.html'],
    'EC2_TEMPLATE_BATCH_USER_DATA_MIME': [CFN + 'aws-properties-ec2-launchtemplate-launchtemplatedata.html',
                                         'https://docs.aws.amazon.com/batch/latest/userguide/launch-templates.html'],
}


@resource_check('AWS::EC2::VPCPeeringConnection')
def peering_role(design, resource):
    ctx = _Context(design, resource)
    owner = value(ctx, resource, '/properties/PeerOwnerId')
    role = value(ctx, resource, '/properties/PeerRoleArn')
    if owner is ABSENT or owner == resource.scope.account:
        verdict = 'NOT_APPLICABLE'
    elif not isinstance(owner, str) or not re.fullmatch(r'\d{12}', owner) or not re.fullmatch(r'\d{12}', resource.scope.account):
        verdict = 'NEEDS_REVIEW'
    elif role is ABSENT:
        verdict = 'FAIL'
    elif isinstance(role, str) and role:
        verdict = 'PASS'
    else:
        verdict = 'NEEDS_REVIEW'
    return ctx.finding('EC2_PEERING_CROSS_ACCOUNT_ROLE', '/properties/PeerRoleArn', verdict,
                       'cross-account peering requires PeerRoleArn; role permissions are outside this check')


@resource_check('AWS::EC2::VPNConnection')
def vpn_address_type(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/CustomerGatewayId'
    gateway = linked(ctx, resource, path, 'AWS::EC2::CustomerGateway')
    address = value(ctx, gateway, '/properties/IpAddress') if gateway else UNKNOWN
    mode = value(ctx, resource, '/properties/OutsideIpAddressType')
    if mode is ABSENT:
        mode = 'PublicIpv4'
    verdict = 'NEEDS_REVIEW'
    if isinstance(address, str) and mode in ('PublicIpv4', 'PrivateIpv4', 'Ipv6'):
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            verdict = 'FAIL'
        else:
            private4 = ip.version == 4 and any(ip in ipaddress.ip_network(net) for net in
                                              ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'))
            mismatch = ((ip.version == 6) != (mode == 'Ipv6') or
                        (private4 and mode != 'PrivateIpv4'))
            verdict = 'FAIL' if mismatch else 'PASS'
    return ctx.finding('EC2_VPN_CUSTOMER_GATEWAY_ADDRESS_TYPE', path, verdict,
                       'customer gateway IPv6 and RFC1918/RFC6598 addresses require matching VPN outside address types')


def _identity(ctx, resource, path, expected):
    target = linked(ctx, resource, path, expected)
    if target:
        return ('resource', target.id)
    known = value(ctx, resource, path)
    return ('arn', known) if isinstance(known, str) and known.startswith('arn:') else UNKNOWN


@resource_check('AWS::EC2::EnclaveCertificateIamRoleAssociation')
def enclave_roles(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/CertificateArn'
    certificate = _identity(ctx, resource, path, 'AWS::CertificateManager::Certificate')
    roles = set()
    uncertain = 0
    if certificate is UNKNOWN:
        return ctx.finding('EC2_ENCLAVE_CERTIFICATE_ROLE_LIMIT', path, 'NEEDS_REVIEW',
                           'certificate identity is unresolved')
    for item in design.resources:
        if item.type != resource.type or item.scope != resource.scope:
            continue
        other = _identity(ctx, item, path, 'AWS::CertificateManager::Certificate')
        if other == certificate:
            role = _identity(ctx, item, '/properties/RoleArn', 'AWS::IAM::Role')
            if role is UNKNOWN:
                uncertain += 1
            else:
                roles.add(role)
        elif other is UNKNOWN or other[0] != certificate[0]:
            uncertain += 1
    # A known ARN may alias a linked resource; do not count it twice for FAIL.
    lower = max((sum(kind == token[0] for token in roles) for kind in ('arn', 'resource')), default=0)
    upper = len(roles) + uncertain
    verdict = 'FAIL' if lower > 16 else 'NEEDS_REVIEW' if upper > 16 else 'PASS'
    return ctx.finding('EC2_ENCLAVE_CERTIFICATE_ROLE_LIMIT', path, verdict,
                       'at most 16 distinct IAM roles per certificate in the design; external associations are not counted')


SIZE_RANGES = {'gp2': (1, 16384), 'gp3': (1, 65536), 'io1': (4, 16384),
               'io2': (4, 65536), 'st1': (125, 16384), 'sc1': (125, 16384), 'standard': (1, 1024)}
IOPS_RANGES = {'gp3': (3000, 80000), 'io1': (100, 64000), 'io2': (100, 256000)}


def _expand(ctx, resource, pattern):
    if '*' not in pattern:
        if read(ctx, resource, pattern) is not ABSENT:
            yield pattern
        return
    prefix, suffix = pattern.split('*', 1)
    array_path = prefix.rstrip('/')
    array = read(ctx, resource, array_path)
    if isinstance(array, list):
        for index in range(len(array)):
            yield from _expand(ctx, resource, prefix + str(index) + suffix)
    elif array is not ABSENT:
        yield array_path  # Unknown-length collection; retain a review finding.


@resource_check('AWS::EC2::Volume', 'AWS::EC2::EC2Fleet', 'AWS::EC2::SpotFleet')
def ebs_ranges(design, resource):
    pattern = {
        'AWS::EC2::EC2Fleet': '/properties/LaunchTemplateConfigs/*/Overrides/*/BlockDeviceMappings/*/Ebs',
        'AWS::EC2::SpotFleet': '/properties/SpotFleetRequestConfigData/LaunchSpecifications/*/BlockDeviceMappings/*/Ebs',
    }.get(resource.type)
    ctx = _Context(design, resource)
    roots = list(_expand(ctx, resource, pattern)) if pattern else ['/properties']
    results = []
    for root in roots:
        volume = resource.type == 'AWS::EC2::Volume'
        kind = value(ctx, resource, root + '/VolumeType')
        if volume and kind is ABSENT:
            source = value(ctx, resource, '/properties/SourceVolumeId')
            kind = 'gp2' if source is ABSENT else UNKNOWN
        for key, ranges, rule in (('Size' if volume else 'VolumeSize', SIZE_RANGES, 'EC2_EBS_SIZE_BY_TYPE'),
                                   ('Iops', IOPS_RANGES, 'EC2_EBS_IOPS_BY_TYPE')):
            path = root + '/' + key
            number = value(ctx, resource, path)
            if number is ABSENT:
                continue  # Defaults, required fields and source inheritance are separate checks.
            bounds = ranges.get(kind) if isinstance(kind, str) else None
            if bounds is None:
                verdict = 'NOT_APPLICABLE' if isinstance(kind, str) and kind in SIZE_RANGES else 'NEEDS_REVIEW'
            elif type(number) is not int:
                verdict = 'NEEDS_REVIEW'
            else:
                verdict = 'PASS' if bounds[0] <= number <= bounds[1] else 'FAIL'
            results.append(ctx.finding(rule, path, verdict,
                                       f'{key} must be within the documented {kind if isinstance(kind, str) else "volume-type"} range; instance capability is separate'))
    return results


@resource_check('AWS::EC2::LaunchTemplate')
def template_placement(design, resource):
    ctx = _Context(design, resource)
    base = '/properties/LaunchTemplateData/Placement'
    part = value(ctx, resource, base + '/PartitionNumber')
    if part is ABSENT:
        return []
    selectors = [base + '/' + key for key in ('GroupId', 'GroupName')]
    targets = [linked(ctx, resource, path, 'AWS::EC2::PlacementGroup')
               for path in selectors if value(ctx, resource, path) is not ABSENT]
    resolved = {target.id: target for target in targets if target is not None}
    strategy = (value(ctx, next(iter(resolved.values())), '/properties/Strategy')
                if targets and all(target is not None for target in targets) and len(resolved) == 1 else UNKNOWN)
    verdict = ('NEEDS_REVIEW' if part is UNKNOWN or not isinstance(strategy, str) else
               'PASS' if strategy == 'partition' else 'FAIL' if strategy in ('cluster', 'spread') else 'NEEDS_REVIEW')
    return [ctx.finding('EC2_TEMPLATE_PARTITION_PLACEMENT', base + '/PartitionNumber', verdict,
                        'PartitionNumber requires a linked placement group with partition strategy')]


def _template_consumers(ctx, template, consumer_type, pattern):
    known = False
    uncertain = False
    for relation in ctx.design.relations:
        if relation.target_resource_id != template.id or not re.fullmatch(pattern, relation.source_path):
            continue
        consumer = ctx.by_id.get(relation.source_resource_id)
        if consumer is None or consumer.type != consumer_type or consumer.scope != template.scope:
            continue
        ctx.evidence.extend(relation.evidence_ids)
        if linked(ctx, consumer, relation.source_path, template.type) is None:
            uncertain = True
            continue
        version = value(ctx, consumer, relation.source_path.rsplit('/', 1)[0] + '/Version')
        if version in ('1', '$Latest'):
            known = True
        else:
            uncertain = True
    return known, uncertain


@resource_check('AWS::EC2::LaunchTemplate')
def template_consumers(design, resource):
    ctx = _Context(design, resource)
    base = '/properties/LaunchTemplateData'
    results = []
    asg, asg_unknown = _template_consumers(ctx, resource, 'AWS::AutoScaling::AutoScalingGroup',
        r'/properties/(?:LaunchTemplate|MixedInstancesPolicy/LaunchTemplate/(?:LaunchTemplateSpecification|Overrides/\d+/LaunchTemplateSpecification))/(?:LaunchTemplateId|LaunchTemplateName)')
    if asg or asg_unknown:
        arn = value(ctx, resource, base + '/IamInstanceProfile/Arn')
        name = value(ctx, resource, base + '/IamInstanceProfile/Name')
        if not asg:
            verdict = 'NEEDS_REVIEW'
        elif arn is ABSENT or name is ABSENT:
            verdict = 'PASS'
        elif asg and arn is not UNKNOWN and name is not UNKNOWN:
            verdict = 'FAIL'
        else:
            verdict = 'NEEDS_REVIEW'
        results.append(ctx.finding('EC2_TEMPLATE_ASG_PROFILE_EXCLUSIVE', base + '/IamInstanceProfile', verdict,
                                   'a launch template used by Auto Scaling may not specify both profile Arn and Name'))
    batch, batch_unknown = _template_consumers(ctx, resource, 'AWS::Batch::ComputeEnvironment',
        r'/properties/ComputeResources/LaunchTemplate(?:/Overrides/\d+)?/(?:LaunchTemplateId|LaunchTemplateName)')
    if batch or batch_unknown:
        data = value(ctx, resource, base + '/UserData')
        if not batch:
            verdict = 'NEEDS_REVIEW'
        elif data is ABSENT:
            verdict = 'NOT_APPLICABLE'
        elif not isinstance(data, str):
            verdict = 'NEEDS_REVIEW'
        else:
            try:
                decoded = base64.b64decode(data, validate=True)
                message = BytesParser(policy=policy.default).parsebytes(decoded)
                valid = (message.is_multipart() and message.get_content_maintype() == 'multipart' and
                         message.get('MIME-Version') == '1.0' and
                         not any(part.defects for part in message.walk()))
                verdict = 'PASS' if valid else 'FAIL'
            except (ValueError, binascii.Error):
                verdict = 'FAIL'
        results.append(ctx.finding('EC2_TEMPLATE_BATCH_USER_DATA_MIME', base + '/UserData', verdict,
                                   'AWS Batch launch-template user data must be a base64-encoded MIME multipart archive'))
    return results
