"""Checks for AWS::LakeFormation::Permissions, AWS::LakeFormation::PrincipalPermissions."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.string_lists import strings

GRANTS={kind:'LAKEFORMATION_'+label+'_GRANT_SUBSET' for kind,label in (
    ('Permissions','PERMISSIONS'),('PrincipalPermissions','PRINCIPAL'))}
SOURCES = {
    'LAKEFORMATION_PERMISSIONS_GRANT_SUBSET': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lakeformation-permissions.html',
    ],
    'LAKEFORMATION_PRINCIPAL_GRANT_SUBSET': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lakeformation-principalpermissions.html',
    ],
}


@resource_check(*('AWS::LakeFormation::'+kind for kind in GRANTS))
def evaluate_lakeformation_permission_grants(design,resource):
    ctx=_Context(design,resource);results=[];kind=resource.type.split('::')[-1]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    path='/properties/PermissionsWithGrantOption'
    if get(path) is not ABSENT:
        granted,grant_pending=strings(ctx,resource,'/properties/Permissions')
        delegable,pending=strings(ctx,resource,path);missing=set(delegable)-set(granted)
        # ALL can imply permissions whose expansion depends on the resource kind.
        complete=not grant_pending and 'ALL' not in granted and 'ALL' not in delegable
        verdict='FAIL' if complete and missing else 'PASS' if not pending and not missing else 'NEEDS_REVIEW'
        emit(GRANTS[kind],path,verdict,'grant-option permissions must be a subset of explicitly granted names; ALL expansion, omitted/unknown permissions and external grant state remain under review')
    return results
