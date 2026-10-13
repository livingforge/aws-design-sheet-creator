"""Declared cluster/provider membership, separate from live associations."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'ECS_CLUSTER_PROVIDER_MEMBERSHIP': [CF + 'aws-resource-ecs-cluster.html', CF + 'aws-resource-ecs-clustercapacityproviderassociations.html'],
    'ECS_CLUSTER_DEFAULT_WEIGHT': [CF + 'aws-properties-ecs-cluster-capacityproviderstrategyitem.html', CF + 'aws-properties-ecs-clustercapacityproviderassociations-capacityproviderstrategy.html'],
    'ECS_CLUSTER_ASG_PROVIDER_UNIQUE': [CF + 'aws-resource-ecs-cluster.html'],
}


def identity(ctx, resource, path):
    provider = linked(ctx, resource, path, 'AWS::ECS::CapacityProvider')
    if provider:
        return ('resource', provider.id)
    raw = value(ctx, resource, path)
    return ('name', raw) if isinstance(raw, str) and re.fullmatch(r'[A-Za-z0-9_-]+', raw) else None


@resource_check('AWS::ECS::Cluster', 'AWS::ECS::ClusterCapacityProviderAssociations')
def capacity_declarations(design, resource):
    ctx = _Context(design, resource)
    strategy_path = '/properties/DefaultCapacityProviderStrategy'
    strategy = value(ctx, resource, strategy_path)
    results = []
    declarations = [resource]
    cluster = resource if resource.type == 'AWS::ECS::Cluster' else linked(ctx, resource, '/properties/Cluster', 'AWS::ECS::Cluster')
    if cluster:
        if cluster.id != resource.id:
            declarations.append(cluster)
        for candidate in design.resources:
            if candidate.type != 'AWS::ECS::ClusterCapacityProviderAssociations' or candidate.id == resource.id:
                continue
            owner = linked(ctx, candidate, '/properties/Cluster', 'AWS::ECS::Cluster')
            if owner and owner.id == cluster.id:
                declarations.append(candidate)
    members = set()
    for declaration in declarations:
        providers = value(ctx, declaration, '/properties/CapacityProviders')
        for i in range(len(providers) if isinstance(providers, list) else 0):
            member = identity(ctx, declaration, f'/properties/CapacityProviders/{i}')
            if member:
                members.add(member)
    if strategy is not ABSENT and not isinstance(strategy, list):
        results.append(ctx.finding('ECS_CLUSTER_PROVIDER_MEMBERSHIP', strategy_path, 'NEEDS_REVIEW', 'default strategy is unresolved'))
    for i in range(len(strategy) if isinstance(strategy, list) else 0):
        path = strategy_path + f'/{i}/CapacityProvider'
        provider = identity(ctx, resource, path)
        results.append(ctx.finding('ECS_CLUSTER_PROVIDER_MEMBERSHIP', path,
            'PASS' if provider and provider in members else 'NEEDS_REVIEW',
            'checks a declared provider association only; missing declarations, unproven aliases, deployment ordering and external associations need review'))
    if isinstance(strategy, list) and len(strategy) > 1:
        weights = [value(ctx, resource, strategy_path + f'/{i}/Weight') for i in range(len(strategy))]
        verdict = ('PASS' if any(type(w) is int and w > 0 for w in weights) else
                   'FAIL' if all(w is ABSENT or type(w) is int and w == 0 for w in weights) else 'NEEDS_REVIEW')
        results.append({**ctx.finding('ECS_CLUSTER_DEFAULT_WEIGHT', strategy_path, verdict,
            'multiple default providers need a positive weight for subsequent RunTask/CreateService use; this is not a cluster-creation failure'), 'severity': 'WARNING'})
    if cluster:
        providers = value(ctx, resource, '/properties/CapacityProviders')
        own_name = value(ctx, cluster, '/properties/ClusterName')
        for i in range(len(providers) if isinstance(providers, list) else 0):
            path = f'/properties/CapacityProviders/{i}'
            provider = linked(ctx, resource, path, 'AWS::ECS::CapacityProvider')
            if not provider or not isinstance(value(ctx, provider, '/properties/AutoScalingGroupProvider'), dict):
                continue
            conflict = False
            for other in design.resources:
                if other.type not in ('AWS::ECS::Cluster', 'AWS::ECS::ClusterCapacityProviderAssociations') or other.id == resource.id or other.scope != resource.scope:
                    continue
                owner = other if other.type == 'AWS::ECS::Cluster' else linked(ctx, other, '/properties/Cluster', 'AWS::ECS::Cluster')
                if not owner or owner.id == cluster.id:
                    continue
                other_name = value(ctx, owner, '/properties/ClusterName')
                if not all(isinstance(n, str) and re.fullmatch(r'[A-Za-z0-9_-]+', n) for n in (own_name, other_name)) or own_name == other_name:
                    continue
                other_providers = value(ctx, other, '/properties/CapacityProviders')
                for j in range(len(other_providers) if isinstance(other_providers, list) else 0):
                    matched = linked(ctx, other, f'/properties/CapacityProviders/{j}', 'AWS::ECS::CapacityProvider')
                    conflict |= matched is not None and matched.id == provider.id
            results.append(ctx.finding('ECS_CLUSTER_ASG_PROVIDER_UNIQUE', path,
                'FAIL' if conflict else 'NEEDS_REVIEW',
                'an ASG-backed provider cannot serve distinct named clusters; absence of a design conflict does not prove external uniqueness'))
    return results
