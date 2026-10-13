"""Checks for AWS::CloudFormation::GuardHook."""
from ..registry import resource_check
from ..common.context_values import _Context
from ..common.string_lists import strings

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'GUARDHOOK_CHANGESET_ACTIONS': [CF+'aws-properties-cloudformation-guardhook-targetfiltersitems.html',CF+'aws-resource-cloudformation-guardhook.html'],
}


@resource_check('AWS::CloudFormation::GuardHook')
def evaluate_cloudformation_guardhook_changeset_actions(design,resource):
    ctx=_Context(design,resource); results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::CloudFormation::GuardHook':
        operations,pending=strings(ctx,resource,'/properties/TargetOperations')
        if 'CHANGE_SET' in operations or pending:
            path='/properties/TargetFilters/Actions'; actions,unknown=strings(ctx,resource,path)
            # Mixed target operations and the alternative Targets shape require separate semantics.
            single=not pending and operations==['CHANGE_SET']
            verdict='FAIL' if single and any(a in ('UPDATE','DELETE') for a in actions) else 'PASS' if single and not unknown and actions and all(a=='CREATE' for a in actions) else 'NEEDS_REVIEW'
            emit('GUARDHOOK_CHANGESET_ACTIONS',path,verdict,'CHANGE_SET-only hooks may target CREATE actions only; mixed operations, omitted actions, Targets form and unresolved values remain under review')
    return results
