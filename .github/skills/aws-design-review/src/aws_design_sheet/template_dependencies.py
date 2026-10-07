"""Template ordering checks, enabled only by explicit template membership.

Dependency names are logical names, never physical identifiers. A design may
contain several stacks; sharing a design or an AWS scope does not imply sharing
a CloudFormation template. Missing metadata never proves missing DependsOn.
"""
from .models import ValueState
from .checks.common.context_values import _Context, linked, value, CFN
from .checks.common.field_reads import ABSENT, UNKNOWN


SOURCES = {
    'EC2_CLIENT_VPN_ROUTE_DEPENDENCY': [CFN + 'aws-resource-ec2-clientvpnroute.html'],
    'EC2_EIP_GATEWAY_DEPENDENCY': [CFN + 'aws-resource-ec2-eip.html',
        CFN + 'aws-properties-ec2-instance-networkinterface.html',
        CFN + 'aws-properties-ec2-instance-launchtemplatespecification.html',
        CFN + 'aws-properties-ec2-launchtemplate-networkinterface.html'],
    'EC2_VPN_PROPAGATION_DEPENDENCY': [CFN + 'aws-resource-ec2-vpngatewayroutepropagation.html'],
    'EC2_ROUTE_GATEWAY_DEPENDENCY': [CFN + 'aws-attribute-dependson.html', CFN + 'aws-resource-ec2-route.html'],
    'IAM_ROLE_POLICY_DEPENDENCY': [CFN + 'aws-resource-iam-role.html'],
    'LAMBDA_MOUNT_TARGET_DEPENDENCY': [CFN + 'aws-resource-lambda-function.html'],
    'TEMPLATE_DEPENDENCY_GRAPH': [CFN + 'aws-attribute-dependson.html'],
}


def members(design, resource):
    template = resource.template
    if not template or template.state != ValueState.KNOWN:
        return []
    return [r for r in design.resources if r.template and r.template.state == ValueState.KNOWN
            and r.template.id == template.id and r.scope == resource.scope]


def explicit_dependencies(ctx, resource):
    """Return reachable explicit/known property-reference dependencies."""
    pool = members(ctx.design, resource)
    visited, active, reached = set(), set(), set()
    uncertain = False
    invalid = False

    def walk(node):
        nonlocal uncertain, invalid
        if node.id in active:
            invalid = True
            return
        if node.id in visited:
            return
        visited.add(node.id)
        active.add(node.id)
        meta = node.template
        if meta:
            ctx.evidence.extend(meta.evidence_ids)
        if not meta or meta.state != ValueState.KNOWN or meta.depends_on is None:
            uncertain = True
            ctx.dependencies.append(node.id + '/template/depends_on')
        else:
            for name in meta.depends_on:
                matches = [r for r in pool if r.name == name]
                if len(matches) != 1:
                    # The design can be an excerpt of a template.
                    uncertain = True
                    ctx.dependencies.append(node.id + '/template/depends_on/' + name)
                    continue
                target = matches[0]
                reached.add(target.id)
                walk(target)
        for ref in ctx.design.relations:
            if ref.source_resource_id != node.id or not ref.source_path.startswith('/properties/'):
                continue
            matches = [r for r in pool if r.id == ref.target_resource_id]
            if len(matches) != 1 or ref.condition:
                uncertain = True
                continue
            target = linked(ctx, node, ref.source_path, matches[0].type)
            if target is None:
                uncertain = True
                continue
            reached.add(target.id)
            walk(target)
        active.remove(node.id)

    walk(resource)
    return reached, uncertain, invalid


def ordering(ctx, rule, targets, *, any_target=False):
    reached, uncertain, invalid = explicit_dependencies(ctx, ctx.resource)
    if invalid:
        verdict = 'FAIL'
    elif not targets:
        verdict = 'NEEDS_REVIEW'
    elif (any if any_target else all)(t.id in reached for t in targets):
        verdict = 'PASS'
    else:
        verdict = 'NEEDS_REVIEW' if uncertain else 'FAIL'
    for target in targets:
        ctx.evidence.extend(target.template.evidence_ids)
    return ctx.finding(rule, '/template/depends_on', verdict,
        'explicit template dependency must precede the consumer; unresolved membership or dependency lists require review')


def same_target(ctx, left, left_path, right, right_path, kind):
    a = linked(ctx, left, '/properties/' + left_path, kind)
    b = linked(ctx, right, '/properties/' + right_path, kind)
    return a is not None and b is not None and a.id == b.id


def instance_subnet(ctx, instance):
    """Resolve the primary NIC, never a secondary NIC or an unknown LT version."""
    if instance is None:
        return None
    root = '/properties/'
    owner = instance
    subnet = value(ctx, owner, root + 'SubnetId')
    interfaces = value(ctx, owner, root + 'NetworkInterfaces')
    if subnet is not ABSENT:
        if interfaces is not ABSENT:
            return None  # Conflicting sources; do not choose one.
        return linked(ctx, owner, root + 'SubnetId', 'AWS::EC2::Subnet')
    if interfaces is ABSENT:
        base = '/properties/LaunchTemplate/'
        # The input represents a newly created template. Its version 1 is the
        # supplied data; other numeric/default/latest versions need history or
        # an attribute-aware reference model, which is not available here.
        if value(ctx, instance, base + 'Version') != '1':
            return None
        paths = [base + name for name in ('LaunchTemplateId', 'LaunchTemplateName')
                 if value(ctx, instance, base + name) is not ABSENT]
        if len(paths) != 1:
            return None
        owner = linked(ctx, instance, paths[0], 'AWS::EC2::LaunchTemplate')
        if owner is None or owner not in members(ctx.design, instance):
            return None
        root = '/properties/LaunchTemplateData/'
        interfaces = value(ctx, owner, root + 'NetworkInterfaces')
    if not isinstance(interfaces, list) or not interfaces:
        return None
    primary = []
    for i in range(len(interfaces)):
        index = value(ctx, owner, root + f'NetworkInterfaces/{i}/DeviceIndex')
        if isinstance(index, bool) or index is ABSENT or index is UNKNOWN:
            return None
        if index in (0, '0'):
            primary.append(i)
        elif not ((isinstance(index, int) and index > 0) or
                  (isinstance(index, str) and index.isdecimal() and int(index) > 0)):
            return None
    if len(primary) != 1:
        return None
    base = root + f'NetworkInterfaces/{primary[0]}/'
    direct = value(ctx, owner, base + 'SubnetId')
    nic = value(ctx, owner, base + 'NetworkInterfaceId')
    if direct is not ABSENT and nic is not ABSENT:
        return None
    if direct is not ABSENT:
        return linked(ctx, owner, base + 'SubnetId', 'AWS::EC2::Subnet')
    interface = linked(ctx, owner, base + 'NetworkInterfaceId', 'AWS::EC2::NetworkInterface')
    return linked(ctx, interface, '/properties/SubnetId', 'AWS::EC2::Subnet') if interface else None


def evaluate_template_dependencies(design, resource):
    # Older designs have no template membership. Their ledger coverage continues
    # to report this unchecked scope, without inventing a template boundary.
    if resource.template is None:
        return []
    ctx = _Context(design, resource)
    pool = members(design, resource)
    results = []
    reached, uncertain, invalid = explicit_dependencies(ctx, resource)
    results.append(ctx.finding('TEMPLATE_DEPENDENCY_GRAPH', '/template/depends_on',
        'FAIL' if invalid else 'NEEDS_REVIEW' if uncertain else 'PASS',
        'template dependency graph must be acyclic; known property references also establish ordering; unresolved logical names remain reviewable'))
    if resource.type == 'AWS::EC2::ClientVpnRoute':
        local = value(ctx, resource, '/properties/TargetVpcSubnetId') == 'local'
        targets = [r for r in pool if r.type == 'AWS::EC2::ClientVpnTargetNetworkAssociation'
                   and same_target(ctx, resource, 'ClientVpnEndpointId', r, 'ClientVpnEndpointId', 'AWS::EC2::ClientVpnEndpoint')
                   and (local or same_target(ctx, resource, 'TargetVpcSubnetId', r, 'SubnetId', 'AWS::EC2::Subnet'))]
        results.append(ordering(ctx, 'EC2_CLIENT_VPN_ROUTE_DEPENDENCY', targets, any_target=local))
    elif resource.type == 'AWS::EC2::VPNGatewayRoutePropagation':
        targets = [r for r in pool if r.type == 'AWS::EC2::VPCGatewayAttachment'
                   and same_target(ctx, resource, 'VpnGatewayId', r, 'VpnGatewayId', 'AWS::EC2::VPNGateway')]
        results.append(ordering(ctx, 'EC2_VPN_PROPAGATION_DEPENDENCY', targets))
    elif resource.type == 'AWS::EC2::Route':
        # Routes that include the internet gateway depend on its VPC attachment.
        gateway = linked(ctx, resource, '/properties/GatewayId', 'AWS::EC2::InternetGateway')
        if gateway is not None and gateway in pool:
            targets = [r for r in pool if r.type == 'AWS::EC2::VPCGatewayAttachment'
                       and same_target(ctx, resource, 'GatewayId', r, 'InternetGatewayId', 'AWS::EC2::InternetGateway')]
            results.append(ordering(ctx, 'EC2_ROUTE_GATEWAY_DEPENDENCY', targets))
    elif resource.type == 'AWS::EC2::EIP':
        instance = linked(ctx, resource, '/properties/InstanceId', 'AWS::EC2::Instance')
        subnet = instance_subnet(ctx, instance)
        subnets = [subnet] if subnet else []
        for consumer in pool:
            if consumer.type not in ('AWS::EC2::EIPAssociation', 'AWS::EC2::NatGateway'):
                continue
            paths = [ref.source_path for ref in design.relations if ref.source_resource_id == consumer.id
                     and (ref.source_path in ('/properties/AllocationId', '/properties/EIP')
                          or ref.source_path.startswith('/properties/SecondaryAllocationIds/'))]
            if not any((dest := linked(ctx, consumer, p, 'AWS::EC2::EIP')) and dest.id == resource.id for p in paths):
                continue
            node = consumer
            if consumer.type == 'AWS::EC2::EIPAssociation':
                node = (linked(ctx, consumer, '/properties/InstanceId', 'AWS::EC2::Instance') or
                        linked(ctx, consumer, '/properties/NetworkInterfaceId', 'AWS::EC2::NetworkInterface'))
            found = (instance_subnet(ctx, node) if node and node.type == 'AWS::EC2::Instance' else
                     linked(ctx, node, '/properties/SubnetId', 'AWS::EC2::Subnet') if node else None)
            if found:
                subnets.append(found)
        vpcs = [vpc for subnet in subnets if (vpc := linked(ctx, subnet, '/properties/VpcId', 'AWS::EC2::VPC')) and vpc in pool]
        targets = []
        for vpc in vpcs:
            for r in pool:
                if r.type != 'AWS::EC2::VPCGatewayAttachment':
                    continue
                attached = linked(ctx, r, '/properties/VpcId', 'AWS::EC2::VPC')
                gateway = linked(ctx, r, '/properties/InternetGatewayId', 'AWS::EC2::InternetGateway')
                if attached and attached.id == vpc.id and gateway:
                    targets.append(r)
        results.append({**ordering(ctx, 'EC2_EIP_GATEWAY_DEPENDENCY', targets), 'rule_version': '1.1'})
    elif resource.type == 'AWS::Lambda::Function':
        configs = value(ctx, resource, '/properties/FileSystemConfigs')
        if configs is not ABSENT and configs != []:
            targets = []
            if isinstance(configs, list):
                for i, _ in enumerate(configs):
                    ap = linked(ctx, resource, f'/properties/FileSystemConfigs/{i}/Arn', 'AWS::EFS::AccessPoint')
                    fs = linked(ctx, ap, '/properties/FileSystemId', 'AWS::EFS::FileSystem') if ap else None
                    for r in pool:
                        if r.type != 'AWS::EFS::MountTarget' or not fs:
                            continue
                        mounted = linked(ctx, r, '/properties/FileSystemId', 'AWS::EFS::FileSystem')
                        if mounted and mounted.id == fs.id:
                            targets.append(r)
            results.append(ordering(ctx, 'LAMBDA_MOUNT_TARGET_DEPENDENCY', targets))

    # Only explicit, unconditional property references establish role consumers.
    if resource.type not in ('AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy', 'AWS::IAM::Role'):
        roles = set()
        for ref in design.relations:
            if ref.source_resource_id != resource.id or not ref.source_path.startswith('/properties/'):
                continue
            role = linked(ctx, resource, ref.source_path, 'AWS::IAM::Role')
            if role and role in pool:
                roles.add(role.id)
        policies = []
        for policy in pool:
            if policy.type not in ('AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy'):
                continue
            for ref in design.relations:
                if ref.source_resource_id != policy.id or not ref.source_path.startswith('/properties/Roles/'):
                    continue
                role = linked(ctx, policy, ref.source_path, 'AWS::IAM::Role')
                if role and role.id in roles:
                    policies.append(policy)
        if policies:
            results.append(ordering(ctx, 'IAM_ROLE_POLICY_DEPENDENCY', policies))
    return results
