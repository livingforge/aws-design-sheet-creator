"""Checks for AWS::SSMContacts::Rotation."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.literals import expand
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SSM_ROTATION_PERSONAL_CONTACT': [CF+'aws-resource-ssmcontacts-rotation.html'],
}


def personal_contact(ctx,r,path):
    if not resolved(r):return 'NEEDS_REVIEW'
    contact=linked(ctx,r,path,'AWS::SSMContacts::Contact')
    if not resolved(contact):return 'NEEDS_REVIEW'
    kind=value(ctx,contact,'/properties/Type')
    return 'PASS' if kind=='PERSONAL' else 'FAIL' if kind in ('ESCALATION','ONCALL_SCHEDULE') else 'NEEDS_REVIEW'


@resource_check('AWS::SSMContacts::Rotation')
def evaluate_ssmcontacts_rotation_personal_contact(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::SSMContacts::Rotation':
        for path in expand(ctx,resource,'/properties/ContactIds/*'):
            emit('SSM_ROTATION_PERSONAL_CONTACT',path,personal_contact(ctx,resource,path),'linked explicit PERSONAL contacts are supported; ESCALATION/ONCALL_SCHEDULE are not; unknown types/references and actual contact state remain held')
    return results
