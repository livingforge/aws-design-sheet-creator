"""Checks for AWS::ResilienceHub::App."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.json_verdict import json_verdict

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'RESILIENCEHUB_APP_JSON_SYNTAX': [CF+'aws-resource-resiliencehub-app.html'],
}


@resource_check('AWS::ResilienceHub::App')
def evaluate_resiliencehub_app_json_syntax(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::ResilienceHub::App':
        path='/properties/AppTemplateBody';raw=value(ctx,resource,path)
        if raw is not ABSENT:emit('RESILIENCEHUB_APP_JSON_SYNTAX',path,json_verdict(raw),'bounded JSON syntax only; excluded-resource variants, failover account/Region cardinality, full schema and dynamic/oversize documents remain held')
    return results
