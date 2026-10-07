"""Design-local scheduled audit checks and account enablement consistency."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
DG='https://docs.aws.amazon.com/iot-device-defender/latest/devguide/'
URLS=[CF+'aws-resource-iot-scheduledaudit.html',CF+'aws-resource-iot-accountauditconfiguration.html',CF+'aws-properties-iot-accountauditconfiguration-auditcheckconfigurations.html',DG+'audit-chk-active-intermediary-device-revoked-CA.html',DG+'audit-chk-iot-misconfigured-policies.html',DG+'device-certificate-age-check.html']
SOURCES={rule:URLS for rule in ('IOT_SCHEDULED_AUDIT_ENABLED_CHECKS','IOT_ACCOUNT_AUDIT_USED_CHECKS')}
CHECKS={
 'AUTHENTICATED_COGNITO_ROLE_OVERLY_PERMISSIVE_CHECK':'AuthenticatedCognitoRoleOverlyPermissiveCheck',
 'CA_CERTIFICATE_EXPIRING_CHECK':'CaCertificateExpiringCheck',
 'CA_CERTIFICATE_KEY_QUALITY_CHECK':'CaCertificateKeyQualityCheck',
 'CONFLICTING_CLIENT_IDS_CHECK':'ConflictingClientIdsCheck',
 'DEVICE_CERTIFICATE_AGE_CHECK':'DeviceCertificateAgeCheck',
 'DEVICE_CERTIFICATE_EXPIRING_CHECK':'DeviceCertificateExpiringCheck',
 'DEVICE_CERTIFICATE_KEY_QUALITY_CHECK':'DeviceCertificateKeyQualityCheck',
 'DEVICE_CERTIFICATE_SHARED_CHECK':'DeviceCertificateSharedCheck',
 'INTERMEDIATE_CA_REVOKED_FOR_ACTIVE_DEVICE_CERTIFICATES_CHECK':'IntermediateCaRevokedForActiveDeviceCertificatesCheck',
 'IOT_POLICY_OVERLY_PERMISSIVE_CHECK':'IotPolicyOverlyPermissiveCheck',
 'IOT_POLICY_POTENTIAL_MISCONFIGURATION_CHECK':'IoTPolicyPotentialMisConfigurationCheck',
 'IOT_ROLE_ALIAS_ALLOWS_ACCESS_TO_UNUSED_SERVICES_CHECK':'IotRoleAliasAllowsAccessToUnusedServicesCheck',
 'IOT_ROLE_ALIAS_OVERLY_PERMISSIVE_CHECK':'IotRoleAliasOverlyPermissiveCheck',
 'LOGGING_DISABLED_CHECK':'LoggingDisabledCheck',
 'REVOKED_CA_CERTIFICATE_STILL_ACTIVE_CHECK':'RevokedCaCertificateStillActiveCheck',
 'REVOKED_DEVICE_CERTIFICATE_STILL_ACTIVE_CHECK':'RevokedDeviceCertificateStillActiveCheck',
 'UNAUTHENTICATED_COGNITO_ROLE_OVERLY_PERMISSIVE_CHECK':'UnauthenticatedCognitoRoleOverlyPermissiveCheck',
}


def configuration(ctx,r):
    if not resolved(r):return None
    candidates=[x for x in ctx.design.resources if x.type=='AWS::IoT::AccountAuditConfiguration' and x.scope==r.scope]
    if len(candidates)!=1 or not resolved(candidates[0]):return None
    selected=candidates[0]
    return selected if value(ctx,selected,'/properties/AccountId')==r.scope.account else None


def check_enabled(ctx,config,name):
    key=CHECKS.get(name) if isinstance(name,str) else None
    if key is None:return None
    root='/properties/AuditCheckConfigurations/'+key
    # CloudFormation explicitly documents omitted checks as disabled.
    if value(ctx,config,root) is ABSENT:return False
    flag=value(ctx,config,root+'/Enabled')
    return flag if type(flag) is bool else None


def schedule(ctx,r,config):
    if not resolved(r) or config is None:return 'NEEDS_REVIEW'
    raw=value(ctx,r,'/properties/TargetCheckNames')
    if not isinstance(raw,list) or not 0<len(raw)<=1000:return 'NEEDS_REVIEW'
    flags=[check_enabled(ctx,config,value(ctx,r,'/properties/TargetCheckNames/'+str(i))) for i in range(len(raw))]
    return 'FAIL' if False in flags else 'PASS' if all(f is True for f in flags) else 'NEEDS_REVIEW'


@resource_check('AWS::IoT::ScheduledAudit', 'AWS::IoT::AccountAuditConfiguration')
def evaluate_iot_audit_enabled(design,resource):
    if resource.type not in ('AWS::IoT::ScheduledAudit','AWS::IoT::AccountAuditConfiguration'):return []
    ctx=_Context(design,resource);config=configuration(ctx,resource)
    if resource.type=='AWS::IoT::ScheduledAudit':
        rule='IOT_SCHEDULED_AUDIT_ENABLED_CHECKS';path='/properties/TargetCheckNames';verdict=schedule(ctx,resource,config)
    else:
        rule='IOT_ACCOUNT_AUDIT_USED_CHECKS';path='/properties/AuditCheckConfigurations';verdict='NEEDS_REVIEW'
        if config is resource:
            for other in design.resources:
                if other.type=='AWS::IoT::ScheduledAudit' and other.scope==resource.scope and schedule(ctx,other,config)=='FAIL':verdict='FAIL';break
    f=ctx.finding(rule,path,verdict,'Known scheduled check names must be enabled in the unique explicit account audit configuration in the same account, Region and environment. Documented omitted checks are disabled. Unknown names are not rejected as a closed enum. No absence of external scheduled usage, live enablement or audit delivery is certified.')
    f['source_checked_at']='2026-10-04'
    return [f]
