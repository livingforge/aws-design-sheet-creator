"""SageMaker user-profile security groups inherited from a linked domain."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'SAGEMAKER_PROFILE_VPC_GROUPS':[CF+'aws-properties-sagemaker-userprofile-usersettings.html',CF+'aws-resource-sagemaker-domain.html']}


def presence(raw):
    if raw is ABSENT or raw==[]:return False
    if isinstance(raw,list) and 1<=len(raw)<=5:return True
    return None


def groups(ctx,r):
    if not resolved(r) or read(ctx,r,'/properties/DomainId') is not ABSENT:return 'NEEDS_REVIEW'
    domain=linked(ctx,r,'/properties/DomainId','AWS::SageMaker::Domain')
    if not resolved(domain):return 'NEEDS_REVIEW'
    access=value(ctx,domain,'/properties/AppNetworkAccessType')
    if access=='PublicInternetOnly':return 'NOT_APPLICABLE'
    if access!='VpcOnly':return 'NEEDS_REVIEW'
    states=[presence(value(ctx,r,'/properties/UserSettings/SecurityGroups')),presence(value(ctx,domain,'/properties/DefaultUserSettings/SecurityGroups'))]
    if True in states:return 'PASS'
    return 'FAIL' if states==[False,False] else 'NEEDS_REVIEW'


@resource_check('AWS::SageMaker::UserProfile')
def evaluate_sagemaker_profile_groups(design,resource):
    if resource.type!='AWS::SageMaker::UserProfile':return []
    ctx=_Context(design,resource)
    f=ctx.finding('SAGEMAKER_PROFILE_VPC_GROUPS','/properties/UserSettings/SecurityGroups',groups(ctx,resource),'A profile in an explicitly linked VpcOnly domain requires a nonempty security-group list on the profile or the domain DefaultUserSettings. Security groups aggregate rather than override. PASS covers declaration presence only; group identities, effective aggregate bounds, connectivity and live domain state are separate. Unknown domain, network mode or collection shape remains reviewable.')
    f['source_checked_at']='2026-10-04';return [f]
