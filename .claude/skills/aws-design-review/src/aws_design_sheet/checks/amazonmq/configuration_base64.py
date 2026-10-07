"""Checks for AWS::AmazonMQ::Configuration."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.key_types_and_base64 import base64_syntax

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'AMAZONMQ_CONFIGURATION_BASE64': [CF+'aws-resource-amazonmq-configuration.html'],
}


def _emitter(ctx,results):
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    return emit


def _base64_config(design,resource,rule,path):
    ctx=_Context(design,resource)
    results=[]
    emit=_emitter(ctx,results)
    raw=value(ctx,resource,path)
    if raw is not ABSENT:
        emit(rule,path,base64_syntax(raw),'bounded canonical Base64 syntax only; Fn::Base64, dynamic/oversized input, decoder variants and decoded properties/XML/Cuttlefish content semantics remain held')
    return results


@resource_check('AWS::AmazonMQ::Configuration')
def evaluate_amazonmq_configuration_base64(design,resource):
    return _base64_config(design,resource,'AMAZONMQ_CONFIGURATION_BASE64','/properties/Data')
