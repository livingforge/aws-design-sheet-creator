"""Checks for AWS::CodePipeline::CustomActionType."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CODEPIPELINE_TEMPLATE_CONFIG_REFERENCE': ['https://docs.aws.amazon.com/codepipeline/latest/userguide/actions-create-custom-action.html', CF+'aws-properties-codepipeline-customactiontype-settings.html'],
}


def template_verdict(ctx, resource, path):
    raw = value(ctx, resource, path)
    if not literal(raw) or len(raw) > 10000:
        return 'NEEDS_REVIEW'
    refs = re.findall(r'\{Config:([^{}]+)\}', raw)
    residual = re.sub(r'\{Config:[^{}]+\}', '', raw)
    if '{Config:' in residual:
        return 'NEEDS_REVIEW'
    if not refs:
        return 'PASS'
    base = '/properties/ConfigurationProperties'
    props = value(ctx, resource, base)
    if props is ABSENT:props=[]
    if not isinstance(props, list) or len(props) > 1000:
        return 'NEEDS_REVIEW'
    names = [value(ctx, resource, base+'/'+str(i)+'/Name') for i in range(len(props))]
    if any(not literal(n) for n in names):
        return 'NEEDS_REVIEW'
    pending = False
    for name in refs:
        if name not in names and name!='JobList':return 'FAIL'
        if names.count(name) != 1:
            pending = True
            continue
        p = base+'/'+str(names.index(name))
        required = value(ctx, resource, p+'/Required')
        secret = value(ctx, resource, p+'/Secret')
        if required is False or secret is True:
            return 'FAIL'
        if required is not True or secret is not False:
            pending = True
    return 'NEEDS_REVIEW' if pending else 'PASS'


@resource_check('AWS::CodePipeline::CustomActionType')
def evaluate_codepipeline_template_config_reference(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(p):
        return value(ctx, resource, p)
    def emit(rule, p, verdict, reason):
        f = ctx.finding(rule, p, verdict, reason)
        f['source_checked_at'] = '2026-10-04'
        results.append(f)
    if resource.type == 'AWS::CodePipeline::CustomActionType':
        for field in ('EntityUrlTemplate','ExecutionUrlTemplate'):
            p = '/properties/Settings/'+field
            if get(p) is not ABSENT:
                emit('CODEPIPELINE_TEMPLATE_CONFIG_REFERENCE', p, template_verdict(ctx, resource, p), 'Config references require unique explicit Required=true and Secret=false properties; unknown/duplicate references and the service-added JobList property remain reviewable; supported Entity/Execution templates only, with other template grammar separate')
    return results
