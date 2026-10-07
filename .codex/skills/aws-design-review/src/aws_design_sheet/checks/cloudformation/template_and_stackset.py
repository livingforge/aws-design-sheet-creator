"""Checks for AWS::CloudFormation::Stack, AWS::CloudFormation::StackSet."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.literals import expand

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'STACKSET_PERMISSION_TARGETS': [CF+'aws-properties-cloudformation-stackset-deploymenttargets.html'],
    'CLOUDFORMATION_TEMPLATE_BODY_BYTES': [CF+'aws-resource-cloudformation-stack.html'],
}


def stackset_targets(ctx,resource,path):
    mode=value(ctx,resource,'/properties/PermissionModel')
    if mode=='SERVICE_MANAGED':
        units=value(ctx,resource,path+'/OrganizationalUnitIds')
        return 'FAIL' if units is ABSENT else 'PASS' if isinstance(units,list) and units else 'FAIL' if units==[] else 'NEEDS_REVIEW'
    if mode=='SELF_MANAGED':
        parts=[value(ctx,resource,path+'/'+k) for k in ('Accounts','AccountsUrl')]
        known=sum(x is not ABSENT and x is not UNKNOWN for x in parts)
        if known>1 or all(x is ABSENT for x in parts):return 'FAIL'
        return 'NEEDS_REVIEW' if any(x is UNKNOWN for x in parts) else 'PASS'
    return 'NEEDS_REVIEW'


@resource_check('AWS::CloudFormation::StackSet', 'AWS::CloudFormation::Stack')
def evaluate_cloudformation_template_and_stackset(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::CloudFormation::StackSet':
        for path in expand(ctx,resource,'/properties/StackInstancesGroup/*/DeploymentTargets'):
            emit('STACKSET_PERMISSION_TARGETS',path,stackset_targets(ctx,resource,path),'SERVICE_MANAGED requires nonempty OrganizationalUnitIds; SELF_MANAGED requires exactly one of Accounts/AccountsUrl; unknown PermissionModel and target presence are held; account filters, permissions and target existence are separate')
    if resource.type=='AWS::CloudFormation::Stack':
        path='/properties/TemplateBody';body=get(path)
        if body is not ABSENT:
            verdict='NEEDS_REVIEW'
            if isinstance(body,str) and '${' not in body and '{{' not in body:
                try:verdict='PASS' if 1<=len(body.encode('utf8'))<=51200 else 'FAIL'
                except UnicodeError:pass
            emit('CLOUDFORMATION_TEMPLATE_BODY_BYTES',path,verdict,'explicit text TemplateBody must be 1..51200 UTF-8 bytes; object serialization, unresolved substitutions and invalid Unicode remain held; template content, Cloud Control applicability and external TemplateURL are separate')
    return results
