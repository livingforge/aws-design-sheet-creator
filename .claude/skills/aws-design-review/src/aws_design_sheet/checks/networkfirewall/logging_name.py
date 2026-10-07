"""Checks for AWS::NetworkFirewall::LoggingConfiguration."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'NETWORKFIREWALL_LOGGING_NAME': [CF+'aws-resource-networkfirewall-loggingconfiguration.html'],
}


def firewall_name(ctx,resource):
    if not resolved(resource):return 'NEEDS_REVIEW'
    firewall=linked(ctx,resource,'/properties/FirewallArn','AWS::NetworkFirewall::Firewall')
    if not resolved(firewall):return 'NEEDS_REVIEW'
    names=[value(ctx,r,'/properties/FirewallName') for r in (resource,firewall)]
    if not all(literal(n) for n in names):return 'NEEDS_REVIEW'
    return 'PASS' if names[0]==names[1] else 'FAIL'


@resource_check('AWS::NetworkFirewall::LoggingConfiguration')
def evaluate_networkfirewall_logging_name(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::NetworkFirewall::LoggingConfiguration' and value(ctx,resource,'/properties/FirewallName') is not ABSENT:
        emit('NETWORKFIREWALL_LOGGING_NAME','/properties/FirewallName',firewall_name(ctx,resource),'explicit logging FirewallName must match the unique FirewallArn target name; unknown names, unresolved/external links and update lifecycle remain held')
    return results
