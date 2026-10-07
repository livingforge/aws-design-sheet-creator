"""Bounded YAML source/sink cardinality; plugin validation remains external."""
from ..registry import resource_check
from ..common.bounded_yaml import bounded_yaml
from ..common.context_values import _Context, value
from ..common.literals import literal
from ..common.scoped_resolution import resolved

SOURCES={'TELEMETRY_PIPELINE_SOURCE_SINK':['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-observabilityadmin-telemetrypipelines-telemetrypipelineconfiguration.html','https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-observabilityadmin-telemetrypipelines.html','https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Creating-pipelines.html']}


def structure(ctx,r):
    if not resolved(r):return 'NEEDS_REVIEW'
    raw=value(ctx,r,'/properties/Configuration/Body')
    if not literal(raw) or len(raw)>24000:return 'NEEDS_REVIEW'
    verdict,data=bounded_yaml(raw)
    if data is None:return verdict
    if not isinstance(data,dict) or not isinstance(data.get('pipeline'),dict):return 'NEEDS_REVIEW'
    pipeline=data['pipeline'];source=pipeline.get('source');sink=pipeline.get('sink')
    if source is None or sink is None:return 'FAIL'
    if not isinstance(source,dict) or not isinstance(sink,list):return 'NEEDS_REVIEW'
    if len(source)!=1 or len(sink)!=1:return 'FAIL'
    if not isinstance(sink[0],dict):return 'NEEDS_REVIEW'
    if len(sink[0])!=1:return 'FAIL'
    if any(not isinstance(v,dict) for v in [*source.values(),*sink[0].values()]):return 'NEEDS_REVIEW'
    return 'PASS'


@resource_check('AWS::ObservabilityAdmin::TelemetryPipelines')
def evaluate_observabilityadmin_telemetry_pipeline_structure(design,resource):
    if resource.type!='AWS::ObservabilityAdmin::TelemetryPipelines':return []
    ctx=_Context(design,resource)
    f=ctx.finding('TELEMETRY_PIPELINE_SOURCE_SINK','/properties/Configuration/Body',structure(ctx,resource),'A telemetry pipeline requires exactly one source and one sink. Parse the inline YAML as bounded data and verify source/sink cardinality in the documented pipeline structure. PASS covers this structure only; supported plugins, processor schemas, credentials and full service validation remain unresolved. Dynamic content, YAML aliases, duplicate keys and custom tags are held without execution.')
    f['source_checked_at']='2026-10-04';return [f]
