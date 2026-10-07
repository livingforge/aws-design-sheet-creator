"""PCS instance-profile role naming, separate from effective IAM permissions."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved

SOURCES={'PCS_INSTANCE_PROFILE_ROLE_IDENTITY':['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-pcs-computenodegroup.html','https://docs.aws.amazon.com/pcs/latest/userguide/security-instance-profiles.html']}


def role_identity(ctx,r):
    if not resolved(r) or read(ctx,r,'/properties/IamInstanceProfileArn') is not ABSENT:return 'NEEDS_REVIEW'
    profile=linked(ctx,r,'/properties/IamInstanceProfileArn','AWS::IAM::InstanceProfile')
    if not resolved(profile):return 'NEEDS_REVIEW'
    roles=value(ctx,profile,'/properties/Roles')
    if not isinstance(roles,list) or len(roles)!=1:return 'NEEDS_REVIEW'
    role=linked(ctx,profile,'/properties/Roles/0','AWS::IAM::Role')
    if not resolved(role):return 'NEEDS_REVIEW'
    name=value(ctx,role,'/properties/RoleName');raw=read(ctx,profile,'/properties/Roles/0')
    if raw is not ABSENT and (not literal(raw) or raw!=name):return 'NEEDS_REVIEW'
    path=value(ctx,role,'/properties/Path')
    if path is ABSENT:path='/'
    valid_name=literal(name) and re.fullmatch(r'[\w+=,.@-]{1,64}',name,flags=re.ASCII)
    if valid_name and name.startswith('AWSPCS'):return 'PASS'
    if path=='/aws-pcs/':return 'PASS'
    if not valid_name or not literal(path) or not re.fullmatch(r'/|/[!-~]+/',path):return 'NEEDS_REVIEW'
    # The guide says "in its path"; only the exact documented path is positive.
    if '/aws-pcs/' in path:return 'NEEDS_REVIEW'
    return 'FAIL'


@resource_check('AWS::PCS::ComputeNodeGroup')
def evaluate_pcs_role_identity(design,resource):
    if resource.type!='AWS::PCS::ComputeNodeGroup':return []
    ctx=_Context(design,resource)
    f=ctx.finding('PCS_INSTANCE_PROFILE_ROLE_IDENTITY','/properties/IamInstanceProfileArn',role_identity(ctx,resource),'Resolve the instance profile and its single role. The role name starts with AWSPCS or its path is /aws-pcs/. Nested paths with ambiguous service matching, generated names, unknown references and literal profile ARNs remain reviewable. PASS only covers the naming alternative, not pcs:RegisterComputeNodeGroupInstance permission, trust policies or effective IAM authorization.')
    f['source_checked_at']='2026-10-04';return [f]
