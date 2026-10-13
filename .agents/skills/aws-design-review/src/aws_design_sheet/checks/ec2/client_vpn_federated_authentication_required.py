"""Checks for AWS::EC2::ClientVpnEndpoint."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

SOURCES = {
    'EC2_CLIENT_VPN_FEDERATED_AUTHENTICATION_REQUIRED': [
        'https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ClientVpnAuthenticationRequest.html'],
}


@resource_check('AWS::EC2::ClientVpnEndpoint')
def evaluate_client_vpn_federated_authentication(design, resource):
    ctx = _Context(design, resource)
    root = '/properties/AuthenticationOptions'
    options = value(ctx, resource, root)
    rule = 'EC2_CLIENT_VPN_FEDERATED_AUTHENTICATION_REQUIRED'
    reason = ('federated-authentication requires FederatedAuthentication; '
              'provider contents and external trust are checked separately')
    if options is ABSENT:
        return []  # Collection presence belongs to the schema.
    if not isinstance(options, list):
        return [ctx.finding(rule, root, 'NEEDS_REVIEW', reason)]
    rows = []
    for i in range(len(options)):
        local = _Context(design, resource)
        prefix = f'{root}/{i}'
        kind = value(local, resource, prefix + '/Type')
        path = prefix + '/FederatedAuthentication'
        if kind in ('certificate-authentication', 'directory-service-authentication'):
            verdict = 'NOT_APPLICABLE'
        elif kind != 'federated-authentication':
            verdict = 'NEEDS_REVIEW'
        else:
            authentication = value(local, resource, path)
            if authentication is ABSENT:
                verdict = 'FAIL'
            elif isinstance(authentication, dict):
                verdict = 'PASS'
            else:
                verdict = 'NEEDS_REVIEW'
        rows.append(local.finding(rule, path, verdict, reason))
    return rows
