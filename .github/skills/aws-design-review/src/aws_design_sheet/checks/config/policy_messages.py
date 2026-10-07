"""Checks for AWS::Config::ConfigRule, AWS::Config::OrganizationConfigRule."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

SOURCES = {
    'CONFIG_POLICY_MESSAGES': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-config-configrule-source.html',
    ],
    'CONFIG_ORG_POLICY_MESSAGES': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-config-organizationconfigrule-organizationcustompolicyrulemetadata.html',
    ],
}
MESSAGES=('ConfigurationItemChangeNotification','OversizedConfigurationItemChangeNotification')


@resource_check('AWS::Config::ConfigRule','AWS::Config::OrganizationConfigRule')
def evaluate_config_policy_messages(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type in ('AWS::Config::ConfigRule','AWS::Config::OrganizationConfigRule'):
  org=resource.type.endswith('::OrganizationConfigRule')
  pattern='/properties/OrganizationCustomPolicyRuleMetadata/OrganizationConfigRuleTriggerTypes/*' if org else '/properties/Source/SourceDetails/*/MessageType'
  owner='CUSTOM_POLICY' if org else get('/properties/Source/Owner')
  for p in expand(ctx,resource,pattern):
   raw=get(p);v='NOT_APPLICABLE' if owner in ('AWS','CUSTOM_LAMBDA') else 'NEEDS_REVIEW' if owner!='CUSTOM_POLICY' or not literal(raw) else 'PASS' if raw in MESSAGES else 'FAIL'
   emit('CONFIG_ORG_POLICY_MESSAGES' if org else 'CONFIG_POLICY_MESSAGES',p,v,'custom policy supports only change and oversized-change notifications; unknown owner/message held')
 return results
