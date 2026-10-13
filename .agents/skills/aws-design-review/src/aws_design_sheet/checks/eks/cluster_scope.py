"""Checks for AWS::EKS::Cluster."""
import re
import ipaddress
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.scope import scope_findings, symmetric_key_verdict

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'EKS_ENCRYPTION_KEY_REGION': [CF + 'aws-properties-eks-cluster-provider.html'],
    'EKS_REMOTE_PRIVATE_CIDR': [CF + 'aws-properties-eks-cluster-remotenodenetwork.html', CF + 'aws-properties-eks-cluster-remotepodnetwork.html'],
    'EKS_REMOTE_SERVICE_CIDR': [CF + 'aws-properties-eks-cluster-remotenodenetwork.html', CF + 'aws-properties-eks-cluster-remotepodnetwork.html'],
    'EKS_PUBLIC_CIDR_FAMILY': [CF + 'aws-properties-eks-cluster-resourcesvpcconfig.html'],
    'EKS_IPV6_CHINA_REGION': [CF + 'aws-properties-eks-cluster-kubernetesnetworkconfig.html'],
    'EKS_IPV6_CLUSTER_VERSION': [CF + 'aws-properties-eks-cluster-kubernetesnetworkconfig.html'],
    'EKS_SERVICE_VPC_CIDR_OVERLAP': [CF + 'aws-properties-eks-cluster-kubernetesnetworkconfig.html'],
    'EKS_ENCRYPTION_KEY_TYPE': [CF + 'aws-properties-eks-cluster-provider.html', CF + 'aws-resource-kms-key.html'],
}


@resource_check('AWS::EKS::Cluster')
def eks_cluster_scope(design, resource):
    ctx = _Context(design, resource)
    specs = []
    configs = value(ctx, resource, '/properties/EncryptionConfig')
    if isinstance(configs, list):
        specs = [(f'/properties/EncryptionConfig/{i}/Provider/KeyArn', 'kms', 'AWS::KMS::Key', 'region',
                  'EKS_ENCRYPTION_KEY_REGION') for i in range(len(configs))]
    results = scope_findings(ctx, resource, specs)
    results.extend(eks_network(ctx, resource))
    results.extend(eks_encryption_key_type(ctx, resource))
    return results


def eks_encryption_key_type(ctx, resource):
    root = '/properties/EncryptionConfig'
    configs = value(ctx, resource, root)
    if configs is ABSENT:
        return []
    if not isinstance(configs, list):
        return [ctx.finding('EKS_ENCRYPTION_KEY_TYPE', root, 'NEEDS_REVIEW', 'encryption configurations are unresolved')]
    results = []
    for i in range(len(configs)):
        path = root + f'/{i}/Provider/KeyArn'
        if value(ctx, resource, path) is ABSENT:
            continue
        key = linked(ctx, resource, path, 'AWS::KMS::Key')
        verdict = symmetric_key_verdict(ctx, key)
        results.append(ctx.finding('EKS_ENCRYPTION_KEY_TYPE', path, verdict,
            'EKS requires a symmetric encryption key; linked KMS KeySpec/KeyUsage use documented defaults only when absent, with permissions and key state remaining external'))
    return results


def network(raw):
    if not isinstance(raw, str) or '{{' in raw:
        return None
    try:
        return ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None


def eks_network(ctx, resource):
    results = []
    results.extend(eks_vpc_cidrs(ctx, resource))
    private = [ipaddress.ip_network(cidr) for cidr in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    service = network(value(ctx, resource, '/properties/KubernetesNetworkConfig/ServiceIpv4Cidr'))
    for kind in ('RemoteNodeNetworks', 'RemotePodNetworks'):
        base = '/properties/RemoteNetworkConfig/' + kind
        groups = value(ctx, resource, base)
        if groups is ABSENT:
            continue
        for i in range(len(groups) if isinstance(groups, list) else 1):
            path = base + f'/{i}/Cidrs'
            raw = value(ctx, resource, path)
            bad, unknown, overlap = False, not isinstance(raw, list), False
            for entry in raw if isinstance(raw, list) else []:
                net = network(entry)
                if net is None:
                    if isinstance(entry, str) and '{{' not in entry:
                        bad = True
                    else:
                        unknown = True
                elif net.version != 4 or not 8 <= net.prefixlen <= 32 or not any(net.subnet_of(p) for p in private):
                    bad = True
                elif service is not None and net.overlaps(service):
                    overlap = True
            results.append(ctx.finding('EKS_REMOTE_PRIVATE_CIDR', path,
                'FAIL' if bad else 'NEEDS_REVIEW' if unknown else 'PASS',
                'remote node/pod networks must fit an RFC1918 IPv4 range with prefixes /8 through /32'))
            results.append(ctx.finding('EKS_REMOTE_SERVICE_CIDR', path,
                'FAIL' if overlap else 'NEEDS_REVIEW' if unknown or bad or service is None else 'PASS',
                'remote CIDRs cannot overlap the explicit Kubernetes service IPv4 range; VPC routes and ranges require separate evidence'))
    path = '/properties/ResourcesVpcConfig/PublicAccessCidrs'
    cidrs = value(ctx, resource, path)
    family = value(ctx, resource, '/properties/KubernetesNetworkConfig/IpFamily')
    if family == 'ipv6':
        region = resource.scope.region
        verdict = 'NEEDS_REVIEW'
        if re.fullmatch(r'[a-z]+(?:-[a-z]+)+-\d+', region):
            verdict = 'FAIL' if region.startswith('cn-') else 'PASS'
        results.append(ctx.finding('EKS_IPV6_CHINA_REGION', '/properties/KubernetesNetworkConfig/IpFamily', verdict,
            'IPv6 clusters are not supported in China Regions; other regional capabilities remain separate'))
        version = value(ctx, resource, '/properties/Version')
        verdict = 'NEEDS_REVIEW'
        if isinstance(version, str) and re.fullmatch(r'\d+\.\d+', version):
            verdict = 'PASS' if tuple(map(int, version.split('.'))) >= (1, 21) else 'FAIL'
        results.append(ctx.finding('EKS_IPV6_CLUSTER_VERSION', '/properties/Version', verdict,
            'IPv6 requires Kubernetes 1.21 or later; omitted versions and VPC CNI versions are not inferred'))
    if cidrs is not ABSENT:
        parsed = [network(cidr) for cidr in cidrs] if isinstance(cidrs, list) else [None]
        bad = family == 'ipv4' and any(net is not None and net.version == 6 for net in parsed)
        unknown = family not in ('ipv4', 'ipv6') or None in parsed
        results.append(ctx.finding('EKS_PUBLIC_CIDR_FAMILY', path,
            'FAIL' if bad else 'NEEDS_REVIEW' if unknown else 'PASS',
            'IPv4 clusters cannot accept IPv6 public access CIDRs; historical IPv6 cluster creation dates are not checked'))
    return results


def eks_vpc_cidrs(ctx, resource):
    path = '/properties/KubernetesNetworkConfig/ServiceIpv4Cidr'
    raw = value(ctx, resource, path)
    if raw is ABSENT:
        return []
    service = network(raw)
    subnets_path = '/properties/ResourcesVpcConfig/SubnetIds'
    subnets = value(ctx, resource, subnets_path)
    vpcs, ranges, pending = {}, [], not isinstance(subnets, list)
    for i in range(len(subnets) if isinstance(subnets, list) else 0):
        subnet = linked(ctx, resource, subnets_path + f'/{i}', 'AWS::EC2::Subnet')
        vpc = linked(ctx, subnet, '/properties/VpcId', 'AWS::EC2::VPC') if subnet else None
        if vpc:
            vpcs[vpc.id] = vpc
        else:
            pending = True
    for vpc in vpcs.values():
        cidr = network(value(ctx, vpc, '/properties/CidrBlock'))
        if cidr is not None and cidr.version == 4:
            ranges.append(cidr)
        else:
            pending = True
    for association in ctx.design.resources:
        if association.type != 'AWS::EC2::VPCCidrBlock' or association.scope != resource.scope:
            continue
        associated_vpc = linked(ctx, association, '/properties/VpcId', 'AWS::EC2::VPC')
        cidr_value = value(ctx, association, '/properties/CidrBlock')
        pool = value(ctx, association, '/properties/Ipv4IpamPoolId')
        if cidr_value is ABSENT and pool is ABSENT:
            continue  # An IPv6-only association cannot overlap an IPv4 service range.
        if not associated_vpc:
            pending = True
        elif associated_vpc.id in vpcs:
            cidr = network(cidr_value)
            if cidr is not None and cidr.version == 4:
                ranges.append(cidr)
            else:
                pending = True
    valid_service = service is not None and service.version == 4
    overlap = valid_service and any(service.overlaps(cidr) for cidr in ranges)
    verdict = 'FAIL' if overlap else 'NEEDS_REVIEW' if pending or not ranges or not valid_service else 'PASS'
    return [ctx.finding('EKS_SERVICE_VPC_CIDR_OVERLAP', path, verdict,
        'compares service IPv4 range with explicit linked VPC primary and IPv4 association CIDRs; external CIDRs and unresolved IPAM allocations are not inferred')]
