"""Checks for AWS::CodePipeline::Webhook."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CODEPIPELINE_WEBHOOK_FIRST_STAGE': [CF+'aws-resource-codepipeline-webhook.html'],
}


def webhook_target(ctx, resource):
    pipeline = linked(ctx, resource, '/properties/TargetPipeline', 'AWS::CodePipeline::Pipeline')
    name = value(ctx, resource, '/properties/TargetAction')
    if not resolved(resource) or not resolved(pipeline) or not literal(name):
        return 'NEEDS_REVIEW'
    raw=read(ctx,resource,'/properties/TargetPipeline')
    if raw is not ABSENT and (not literal(raw) or raw!=value(ctx,pipeline,'/properties/Name')):
        return 'NEEDS_REVIEW'
    stages = value(ctx, pipeline, '/properties/Stages')
    if not isinstance(stages, list) or not stages:
        return 'NEEDS_REVIEW'
    actions = value(ctx, pipeline, '/properties/Stages/0/Actions')
    if not isinstance(actions, list):
        return 'NEEDS_REVIEW'
    names = [value(ctx, pipeline, '/properties/Stages/0/Actions/'+str(i)+'/Name') for i in range(len(actions))]
    if any(not literal(n) for n in names) or names.count(name) > 1:
        return 'NEEDS_REVIEW'
    return 'PASS' if name in names else 'FAIL'


@resource_check('AWS::CodePipeline::Webhook')
def evaluate_codepipeline_webhook_first_stage(design, resource):
    ctx = _Context(design, resource)
    results = []

    def emit(rule, path, verdict, reason):
        f = ctx.finding(rule, path, verdict, reason)
        f['source_checked_at'] = '2026-10-04'
        results.append(f)

    def enum(rule, path, allowed):
        raw = value(ctx, resource, path)
        if raw is not ABSENT:
            emit(rule, path, 'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL', 'checks documented literal enum; conditional applicability, defaults and external service state remain separate')

    if resource.type == 'AWS::CodePipeline::Webhook':
        emit('CODEPIPELINE_WEBHOOK_FIRST_STAGE', '/properties/TargetAction', webhook_target(ctx, resource), 'target action must be in first stage of a unique same-scope linked pipeline; unknown or duplicate names held; pipeline version identity and provider compatibility remain separate')
    return results
