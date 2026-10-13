"""Checks for AWS::CleanRoomsML::TrainingDataset."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CLEANROOMSML_TRAINING_ROLE_ACCOUNT': [CF+'aws-resource-cleanroomsml-trainingdataset.html'],
}


@resource_check('AWS::CleanRoomsML::TrainingDataset')
def evaluate_cleanroomsml_training_role_account(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):
        result=ctx.finding(rule,p,v,reason);result['source_checked_at']='2026-10-04';results.append(result)
    def enum(rule,p,allowed):
        raw=get(p)
        if raw is not ABSENT:emit(rule,p,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL','literal value checked against current explicit CF allowed values; no omitted values inferred')
    if resource.type=='AWS::CleanRoomsML::TrainingDataset':
        p='/properties/RoleArn';raw=get(p);v='NEEDS_REVIEW'
        match=re.fullmatch(r'arn:aws[-a-z]*:iam::([0-9]{12}):role/[^\s]+',raw) if literal(raw) else None
        if match and re.fullmatch('[0-9]{12}',resource.scope.account):v='PASS' if match[1]==resource.scope.account else 'FAIL'
        emit('CLEANROOMSML_TRAINING_ROLE_ACCOUNT',p,v,'explicit role ARN account equals deployment account; read access, trust and actual caller/account provenance remain external')
    return results
