"""Checks for AWS::CodePipeline::CustomActionType."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CODEPIPELINE_CUSTOM_PUBLIC_VALUES': [CF+'aws-resource-codepipeline-customactiontype.html', CF+'aws-properties-codepipeline-customactiontype-artifactdetails.html'],
}


@resource_check('AWS::CodePipeline::CustomActionType')
def evaluate_codepipeline_custom_public_values(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(p):
        return value(ctx, resource, p)
    def emit(rule, p, verdict, reason):
        f = ctx.finding(rule, p, verdict, reason)
        f['source_checked_at'] = '2026-10-04'
        results.append(f)
    def enum(rule, p, allowed):
        raw = get(p)
        if raw is not ABSENT:
            emit(rule, p, 'NEEDS_REVIEW' if not (literal(raw) or (resource.type=='AWS::CodePipeline::CustomActionType' and raw=='')) else 'PASS' if raw in allowed else 'FAIL', 'documented explicit value only; applicability and service state remain separate')
    if resource.type == 'AWS::CodePipeline::CustomActionType':
        rule = 'CODEPIPELINE_CUSTOM_PUBLIC_VALUES'
        enum(rule,'/properties/Category',('Source','Build','Deploy','Test','Invoke','Approval','Compute'))
        for field, maximum in (('Provider',35), ('Version',9)):
            p = '/properties/'+field
            raw = get(p)
            if raw is not ABSENT:
                verdict = 'NEEDS_REVIEW' if not (literal(raw) or raw=='') else 'PASS' if len(raw)<=maximum and re.fullmatch(r'[0-9A-Za-z_-]+',raw) else 'FAIL'
                emit(rule,p,verdict,'documented literal name/version syntax and length; external provider registration remains separate')
        p = '/properties/ConfigurationProperties'
        raw = get(p)
        if raw is not ABSENT:
            emit(rule,p,'NEEDS_REVIEW' if not isinstance(raw,list) else 'PASS' if len(raw)<=10 else 'FAIL','at most ten explicit configuration entries; entries and template references checked separately')
        for side in ('InputArtifactDetails','OutputArtifactDetails'):
            for bound in ('MinimumCount','MaximumCount'):
                p = '/properties/'+side+'/'+bound
                raw = get(p)
                if raw is not ABSENT:
                    emit(rule,p,'NEEDS_REVIEW' if type(raw) is not int else 'PASS' if 0<=raw<=5 else 'FAIL','documented artifact count range; min/max relationship and missing required fields remain separate')
    return results
