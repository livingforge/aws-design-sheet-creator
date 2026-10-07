"""Checks for AWS::SES::MailManagerAddonSubscription."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SES_ADDON_NAME_VALUES': [CF+'aws-resource-ses-mailmanageraddonsubscription.html'],
}
ADDONS=('TRENDMICRO_VSAPI','SPAMHAUS_DBL','ABUSIX_MAIL_INTELLIGENCE','VADE_ADVANCED_EMAIL_SECURITY')


@resource_check('AWS::SES::MailManagerAddonSubscription')
def evaluate_ses_addon_name_values(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::SES::MailManagerAddonSubscription':
        path='/properties/AddonName';raw=value(ctx,resource,path)
        if raw is not ABSENT:emit('SES_ADDON_NAME_VALUES',path,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in ADDONS else 'FAIL','explicit documented add-on names only; unknown/default names, subscription uniqueness and actual service state remain held')
    return results
