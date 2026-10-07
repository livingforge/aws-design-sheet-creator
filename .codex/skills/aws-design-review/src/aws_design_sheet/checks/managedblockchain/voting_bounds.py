"""Checks for AWS::ManagedBlockchain::Member."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'MANAGEDBLOCKCHAIN_VOTING_BOUNDS': [CF+'aws-properties-managedblockchain-member-approvalthresholdpolicy.html'],
}


@resource_check('AWS::ManagedBlockchain::Member')
def evaluate_managedblockchain_voting_bounds(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::ManagedBlockchain::Member':
        base='/properties/NetworkConfiguration'
        for key,low,high in [('ThresholdPercentage',0,100),('ProposalDurationInHours',1,168)]:
            path=base+'/VotingPolicy/ApprovalThresholdPolicy/'+key
            raw=value(ctx,resource,path)
            if raw is ABSENT:continue
            applies=value(ctx,resource,base+'/Framework')=='HYPERLEDGER_FABRIC'
            verdict='NEEDS_REVIEW' if not applies or type(raw) is not int else 'PASS' if low<=raw<=high else 'FAIL'
            emit('MANAGEDBLOCKCHAIN_VOTING_BOUNDS',path,verdict,'explicit Hyperledger Fabric voting percentage is 0..100 and proposal duration 1..168 hours; unknown framework/values, defaults, names, enums and other missing leaf constraints remain held')
    return results
