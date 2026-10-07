"""Checks for AWS::VpcLattice::Listener, AWS::VpcLattice::Rule."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

API='https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/'
CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'VPCLATTICE_LISTENER_ACTION_EXCLUSION': [API+'API_RuleAction.html',API+'API_CreateListener.html',CF+'aws-resource-vpclattice-listener.html'],
    'VPCLATTICE_RULE_ACTION_EXCLUSION': [API+'API_RuleAction.html',CF+'aws-resource-vpclattice-rule.html'],
}


def action_exclusion(ctx,r,path):
    a=value(ctx,r,path+'/Forward');b=value(ctx,r,path+'/FixedResponse')
    known=lambda x:isinstance(x,dict) and '$state' not in x
    if known(a) and known(b):return 'FAIL'
    if known(a) and b is ABSENT or known(b) and a is ABSENT:return 'PASS'
    return 'NEEDS_REVIEW'


@resource_check('AWS::VpcLattice::Listener','AWS::VpcLattice::Rule')
def evaluate_vpclattice_actions(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    for kind,rule,path in (
        ('AWS::VpcLattice::Listener','VPCLATTICE_LISTENER_ACTION_EXCLUSION','/properties/DefaultAction'),
        ('AWS::VpcLattice::Rule','VPCLATTICE_RULE_ACTION_EXCLUSION','/properties/Action')):
        if resource.type==kind and value(ctx,resource,path) is not ABSENT:
            emit(rule,path,action_exclusion(ctx,resource,path),'Forward and FixedResponse are exclusive union members; PASS covers exclusion only; empty/unknown action, member contents, protocol compatibility and deployed behavior remain held')
    return results
