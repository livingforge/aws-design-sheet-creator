"""Serverless individual query metrics and WLM JSON are mutually exclusive."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

SOURCES={'REDSHIFT_SERVERLESS_MONITORING_MODE':['https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_CreateWorkgroup.html','https://docs.aws.amazon.com/redshift/latest/dg/cm-c-wlm-query-monitoring-rules.html']}
METRICS=set('max_query_blocks_read max_scan_row_count max_query_execution_time max_query_queue_time max_query_temp_blocks_to_disk max_join_row_count max_nested_loop_join_row_count max_io_skew max_query_cpu_usage_percent'.split())
OTHER=set('auto_mv datestyle enable_case_sensitive_identifier enable_user_activity_logging query_group search_path require_ssl use_fips_ssl'.split())


def monitoring(ctx,r):
    if not resolved(r):return 'NEEDS_REVIEW'
    rows=value(ctx,r,'/properties/ConfigParameters')
    if rows is ABSENT:return 'NOT_APPLICABLE'
    if not isinstance(rows,list) or len(rows)>1000:return 'NEEDS_REVIEW'
    keys=set();pending=False
    for i in range(len(rows)):
        key=value(ctx,r,f'/properties/ConfigParameters/{i}/ParameterKey')
        if not literal(key) or key not in METRICS|OTHER|{'wlm_json_configuration'}:pending=True
        else:keys.add(key)
    if 'wlm_json_configuration' in keys and keys&METRICS:return 'FAIL'
    if pending:return 'NEEDS_REVIEW'
    return 'PASS' if 'wlm_json_configuration' in keys or keys&METRICS else 'NOT_APPLICABLE'


@resource_check('AWS::RedshiftServerless::Workgroup')
def evaluate_redshiftserverless_monitoring_mode(design,resource):
    if resource.type!='AWS::RedshiftServerless::Workgroup':return []
    ctx=_Context(design,resource)
    f=ctx.finding('REDSHIFT_SERVERLESS_MONITORING_MODE','/properties/ConfigParameters',monitoring(ctx,resource),'Individual query-monitoring metrics cannot be supplied together with wlm_json_configuration. Check all declared parameter entries, including metrics listed in the Serverless documentation notes. Unknown parameter keys remain reviewable. Values, WLM JSON validation and existing deployed configuration are outside this mutual-exclusion check.')
    f['source_checked_at']='2026-10-04';return [f]
