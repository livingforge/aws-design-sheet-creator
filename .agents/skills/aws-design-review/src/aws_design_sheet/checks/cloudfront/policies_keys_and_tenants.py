"""CloudFront checks using explicit ARNs and relationships in the design."""
import re
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CLOUDFRONT_WEBSITE_CUSTOM_ORIGIN': [
        'https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_S3OriginConfig.html',
        'https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteEndpoints.html'],
    'CLOUDFRONT_OAC_AUTHORIZATION_CACHE': [CF + 'aws-properties-cloudfront-originaccesscontrol-originaccesscontrolconfig.html', CF + 'aws-properties-cloudfront-cachepolicy-headersconfig.html', CF + 'aws-properties-cloudfront-distribution-origingroup.html', CF + 'aws-properties-cloudfront-distribution-origingroupmembers.html'],
    'CLOUDFRONT_ACM_REGION': [CF + 'aws-properties-cloudfront-distribution-viewercertificate.html'],
    'CLOUDFRONT_S3_COOKIE_FORWARDING': [CF + 'aws-properties-cloudfront-distribution-cookies.html'],
    'CLOUDFRONT_TENANT_REQUIRED_PARAMETERS': [CF + 'aws-resource-cloudfront-distributiontenant.html'],
    'CLOUDFRONT_PUBLIC_KEY_MATERIAL': [CF + 'aws-properties-cloudfront-publickey-publickeyconfig.html',
        'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-trusted-signers.html'],
    'CLOUDFRONT_STAGING_DISTRIBUTION': [CF + 'aws-properties-cloudfront-continuousdeploymentpolicy-continuousdeploymentpolicyconfig.html'],
}


@resource_check('AWS::CloudFront::ContinuousDeploymentPolicy')
def staging_distributions(design, resource):
    ctx = _Context(design, resource)
    base = '/properties/ContinuousDeploymentPolicyConfig/StagingDistributionDnsNames'
    names = value(ctx, resource, base)
    if names is ABSENT:
        return []
    if not isinstance(names, list):
        return [ctx.finding('CLOUDFRONT_STAGING_DISTRIBUTION', base, 'NEEDS_REVIEW', 'staging names are unresolved')]
    results = []
    for i in range(len(names)):
        path = base + f'/{i}'
        distribution = linked(ctx, resource, path, 'AWS::CloudFront::Distribution')
        staging = value(ctx, distribution, '/properties/DistributionConfig/Staging') if distribution else UNKNOWN
        results.append(ctx.finding('CLOUDFRONT_STAGING_DISTRIBUTION', path,
            'PASS' if staging is True else 'FAIL' if staging is False else 'NEEDS_REVIEW',
            'an explicitly linked distribution must be a staging distribution; unlinked names or unknown staging state require review'))
    return results


@resource_check('AWS::CloudFront::PublicKey')
def public_key_material(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/PublicKeyConfig/EncodedKey'
    raw = value(ctx, resource, path)
    if raw is ABSENT:
        return []
    verdict = 'NEEDS_REVIEW'
    if isinstance(raw, str) and '{{' not in raw and len(raw) <= 65536:
        # Examine only the included public material. Never open a path or URL.
        try:
            key = serialization.load_pem_public_key(raw.encode('ascii'))
        except (ValueError, TypeError, UnicodeError):
            verdict = 'FAIL'
        except UnsupportedAlgorithm:
            verdict = 'NEEDS_REVIEW'
        else:
            if isinstance(key, rsa.RSAPublicKey):
                verdict = 'PASS' if key.key_size == 2048 else 'FAIL'
            elif isinstance(key, ec.EllipticCurvePublicKey):
                verdict = ('PASS' if isinstance(key.curve, ec.SECP256R1) else
                           'NEEDS_REVIEW' if key.key_size == 256 else 'FAIL')
            else:
                verdict = 'FAIL'
    return [ctx.finding('CLOUDFRONT_PUBLIC_KEY_MATERIAL', path, verdict,
        'included PEM public keys must be RSA 2048 or ECDSA 256; the documented P-256 curve is recognized, other 256-bit curves and field-level encryption usage require review')]


def cloudfront_distribution(design, resource):
    ctx = _Context(design, resource)
    base = '/properties/DistributionConfig'
    results = website_origins(ctx, resource)
    cert_path = base + '/ViewerCertificate/AcmCertificateArn'
    cert = value(ctx, resource, cert_path)
    if cert is not ABSENT:
        match = re.fullmatch(r'arn:[a-z0-9-]+:acm:([a-z0-9-]+):\d{12}:certificate/[^{}\s]+', cert) if isinstance(cert, str) else None
        results.append(ctx.finding('CLOUDFRONT_ACM_REGION', cert_path,
            ('PASS' if match[1] == 'us-east-1' else 'FAIL') if match else 'NEEDS_REVIEW',
            'a literal viewer ACM certificate ARN must be in us-east-1; certificate existence and status are not checked'))
    origins = value(ctx, resource, base + '/Origins')
    known_origins, pending = {}, not isinstance(origins, list)
    for i in range(len(origins) if isinstance(origins, list) else 0):
        path = base + f'/Origins/{i}'
        identifier = value(ctx, resource, path + '/Id')
        if not isinstance(identifier, str) or '{{' in identifier:
            pending = True
        else:
            known_origins.setdefault(identifier, []).append(path)
    paths = [base + '/DefaultCacheBehavior']
    behaviors = value(ctx, resource, base + '/CacheBehaviors')
    if isinstance(behaviors, list):
        paths.extend(base + f'/CacheBehaviors/{i}' for i in range(len(behaviors)))
    for path in paths:
        results.extend(oac_authorization_cache(ctx, resource, path, known_origins, pending))
        forward = value(ctx, resource, path + '/ForwardedValues/Cookies/Forward')
        if forward is ABSENT:
            continue
        verdict = 'PASS' if forward == 'none' else 'NEEDS_REVIEW'
        identifier = value(ctx, resource, path + '/TargetOriginId')
        matches = known_origins.get(identifier, []) if isinstance(identifier, str) else []
        if not pending and len(matches) == 1 and forward in ('all', 'whitelist'):
            s3 = value(ctx, resource, matches[0] + '/S3OriginConfig')
            custom = value(ctx, resource, matches[0] + '/CustomOriginConfig')
            if isinstance(s3, dict) and s3 is not UNKNOWN and custom is ABSENT:
                verdict = 'FAIL'
            # A custom S3 website endpoint is not reliably established by this shape.
        results.append(ctx.finding('CLOUDFRONT_S3_COOKIE_FORWARDING', path + '/ForwardedValues/Cookies/Forward', verdict,
            'a behavior with an unambiguous S3OriginConfig target must use none; origin groups, duplicate IDs and custom origins require review'))
    return results


def oac_authorization_cache(ctx, resource, path, origins, pending):
    identifier = value(ctx, resource, path + '/TargetOriginId')
    if identifier is ABSENT:
        return []
    matches = origins.get(identifier, []) if isinstance(identifier, str) else []
    groups_path = '/properties/DistributionConfig/OriginGroups/Items'
    groups = value(ctx, resource, groups_path)
    group_matches = []
    if isinstance(groups, list):
        for i in range(len(groups)):
            group_path = groups_path + '/' + str(i)
            group_id = value(ctx, resource, group_path + '/Id')
            if not isinstance(group_id, str) or '{' in group_id:
                pending = True
            elif group_id == identifier:
                group_matches.append(group_path)
    elif groups is not ABSENT:
        pending = True
    if not matches and len(group_matches) == 1:
        members_path = group_matches[0] + '/Members/Items'
        members = value(ctx, resource, members_path)
        if isinstance(members, list) and len(members) == 2:
            for i in range(2):
                member = value(ctx, resource, members_path + '/' + str(i) + '/OriginId')
                found = origins.get(member, []) if isinstance(member, str) else []
                if len(found) == 1:
                    matches.extend(found)
                else:
                    pending = True
        else:
            pending = True
    elif len(matches) != 1 or group_matches:
        pending = True
    if pending:
        if not any(value(ctx, resource, origin + '/OriginAccessControlId') is not ABSENT for paths in origins.values() for origin in paths):
            return []
        row = ctx.finding('CLOUDFRONT_OAC_AUTHORIZATION_CACHE', path + '/CachePolicyId', 'NEEDS_REVIEW',
            'origin or origin-group membership is unresolved or ambiguous; Authorization forwarding cannot be established')
        row['severity'] = 'WARNING'
        return [row]
    rows = [row for origin in matches for row in oac_origin_authorization(ctx, resource, path, origin)]
    if not rows:
        return []
    verdict = 'FAIL' if any(r['verdict'] == 'FAIL' for r in rows) else 'NEEDS_REVIEW' if any(r['verdict'] == 'NEEDS_REVIEW' for r in rows) else 'PASS'
    rows[-1]['verdict'] = verdict
    return [rows[-1]]


def oac_origin_authorization(ctx, resource, path, origin):
    oac_path = origin + '/OriginAccessControlId'
    if value(ctx, resource, oac_path) is ABSENT:
        return []
    oac = linked(ctx, resource, oac_path, 'AWS::CloudFront::OriginAccessControl')
    signing = value(ctx, oac, '/properties/OriginAccessControlConfig/SigningBehavior') if oac else UNKNOWN
    if signing in ('always','never','always-amz-auth'):
        return []
    policy_path = path + '/CachePolicyId'
    policy = linked(ctx, resource, policy_path, 'AWS::CloudFront::CachePolicy')
    verdict = 'NEEDS_REVIEW'
    if signing == 'no-override' and policy:
        base = '/properties/CachePolicyConfig/ParametersInCacheKeyAndForwardedToOrigin/HeadersConfig'
        behavior = value(ctx, policy, base + '/HeaderBehavior')
        headers = value(ctx, policy, base + '/Headers')
        if behavior == 'none':
            verdict = 'FAIL'
        elif behavior == 'whitelist' and isinstance(headers, list):
            names = [value(ctx, policy, base + '/Headers/' + str(i)) for i in range(len(headers))]
            if any(isinstance(name, str) and name.lower() == 'authorization' for name in names):
                verdict = 'PASS'
            elif all(isinstance(name, str) and '{' not in name for name in names):
                verdict = 'FAIL'
    row = ctx.finding('CLOUDFRONT_OAC_AUTHORIZATION_CACHE', policy_path, verdict,
        'forwarding viewer Authorization with no-override on any targeted origin requires Authorization in this behavior cache policy; viewer intent and external policies remain unverified')
    row['severity'] = 'WARNING'
    return [row]


@resource_check('AWS::CloudFront::DistributionTenant')
def tenant_parameters(design, resource):
    ctx = _Context(design, resource)
    distribution = linked(ctx, resource, '/properties/DistributionId', 'AWS::CloudFront::Distribution')
    path = '/properties/Parameters'
    if not distribution:
        return [ctx.finding('CLOUDFRONT_TENANT_REQUIRED_PARAMETERS', path, 'NEEDS_REVIEW', 'distribution reference is unresolved')]
    definition_path = '/properties/DistributionConfig/TenantConfig/ParameterDefinitions'
    definitions = value(ctx, distribution, definition_path)
    parameters = value(ctx, resource, path)
    if parameters is ABSENT:
        parameters = []
    names, pending, bad = {}, not isinstance(parameters, list), False
    for i in range(len(parameters) if isinstance(parameters, list) else 0):
        name = value(ctx, resource, path + f'/{i}/Name')
        supplied = value(ctx, resource, path + f'/{i}/Value')
        if not isinstance(name, str) or '{{' in name:
            pending = True
        else:
            names.setdefault(name, []).append(supplied)
    if definitions is not ABSENT and not isinstance(definitions, list):
        pending = True
    for i in range(len(definitions) if isinstance(definitions, list) else 0):
        base = definition_path + f'/{i}'
        name = value(ctx, distribution, base + '/Name')
        required = value(ctx, distribution, base + '/Definition/StringSchema/Required')
        if required is False:
            continue
        if required is not True or not isinstance(name, str) or '{{' in name:
            pending = True
            continue
        supplied = names.get(name, [])
        if not supplied:
            default = value(ctx, distribution, base + '/Definition/StringSchema/DefaultValue')
            if default is ABSENT and not pending:
                bad = True
            else:
                pending = True
        elif len(supplied) != 1 or not isinstance(supplied[0], str) or '{{' in supplied[0]:
            pending = True
    return [ctx.finding('CLOUDFRONT_TENANT_REQUIRED_PARAMETERS', path,
        'FAIL' if bad else 'NEEDS_REVIEW' if pending else 'PASS',
        'required parameter names need explicit string values; defaults, duplicate names, unknown flags and unresolved values require review')]


def website_origins(ctx, resource):
    root = '/properties/DistributionConfig/Origins'
    items = value(ctx, resource, root)
    results = []
    for i in range(len(items) if isinstance(items, list) else 0):
        path = root + f'/{i}'
        domain = value(ctx, resource, path + '/DomainName')
        website = isinstance(domain, str) and re.fullmatch(
            r'[a-z0-9][a-z0-9.-]*\.s3-website[.-][a-z]{2}(?:-[a-z]+)+-\d+\.amazonaws\.com\.?', domain.lower()) is not None
        if not website:
            continue
        custom = value(ctx, resource, path + '/CustomOriginConfig')
        s3 = value(ctx, resource, path + '/S3OriginConfig')
        verdict = 'FAIL' if custom is ABSENT or isinstance(s3, dict) and s3 is not UNKNOWN else 'PASS' if isinstance(custom, dict) and custom is not UNKNOWN and s3 is ABSENT else 'NEEDS_REVIEW'
        results.append(ctx.finding('CLOUDFRONT_WEBSITE_CUSTOM_ORIGIN', path, verdict,
            'a literal standard S3 website endpoint requires CustomOriginConfig rather than S3OriginConfig; custom CNAMEs, other partitions, bucket configuration and reachability remain unverified'))
    return results
