"""Checks for AWS::CodeStarNotifications::NotificationRule."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CODESTAR_NOTIFICATION_TAG_KEYS': [CF+'aws-resource-codestarnotifications-notificationrule.html'],
}


@resource_check('AWS::CodeStarNotifications::NotificationRule')
def evaluate_codestarnotifications_notification_tag_keys(design,resource):
    ctx=_Context(design,resource); results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::CodeStarNotifications::NotificationRule':
        path='/properties/Tags'; raw=value(ctx,resource,path)
        if raw is not ABSENT:
            pending=not isinstance(raw,dict);invalid=False
            for key in raw if isinstance(raw,dict) else ():
                if not literal(key):pending=True
                elif key.startswith('aws'):invalid=True
                elif key.lower().startswith('aws'):pending=True
            emit('CODESTAR_NOTIFICATION_TAG_KEYS',path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','tag keys cannot start with literal lowercase aws; case variants and unresolved keys are held')
    return results
