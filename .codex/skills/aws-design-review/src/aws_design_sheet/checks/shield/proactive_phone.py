"""Checks for AWS::Shield::ProactiveEngagement."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SHIELD_PROACTIVE_PHONE': [CF+'aws-resource-shield-proactiveengagement.html'],
}


@resource_check('AWS::Shield::ProactiveEngagement')
def evaluate_shield_proactive_phone(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Shield::ProactiveEngagement':
        path='/properties/EmergencyContactList';status=get('/properties/ProactiveEngagementStatus')
        if status!='DISABLED':
            contacts=get(path);pending=contacts is not ABSENT and not isinstance(contacts,list);found=False
            for i in range(len(contacts)) if isinstance(contacts,list) else ():
                phone=get(path+'/'+str(i)+'/PhoneNumber')
                if literal(phone):found=True
                elif phone is not ABSENT:pending=True
            verdict='NEEDS_REVIEW' if status!='ENABLED' else 'PASS' if found else 'NEEDS_REVIEW' if pending else 'FAIL'
            emit('SHIELD_PROACTIVE_PHONE',path,verdict,'enabled proactive engagement needs at least one explicit nonempty phone number; number syntax/reachability, unknown status/contact values and account subscriptions remain separate')
    return results
