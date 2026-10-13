"""Checks for AWS::CleanRooms::ConfiguredTable, AWS::CleanRooms::IntermediateTable."""
from ..registry import resource_check
from ..common.context_values import _Context
from ..common.literals import expand
from ..common.policy_maps import unique_items

CLEAN={k:'CLEANROOMS_'+v+'_OUTPUT_COLUMNS' for k,v in [('ConfiguredTable','CONFIGURED'),('IntermediateTable','INTERMEDIATE')]}
SOURCES = {
    'CLEANROOMS_CONFIGURED_OUTPUT_COLUMNS': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cleanrooms-configuredtable-outputcolumnthreshold.html',
    ],
    'CLEANROOMS_INTERMEDIATE_OUTPUT_COLUMNS': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cleanrooms-intermediatetable-outputcolumnthreshold.html',
    ],
}


@resource_check('AWS::CleanRooms::ConfiguredTable','AWS::CleanRooms::IntermediateTable')
def evaluate_cleanrooms_output_columns(design,resource):
    ctx=_Context(design,resource); results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    kind=resource.type.split('::')[-1]
    if resource.type.startswith('AWS::CleanRooms::') and kind in CLEAN:
        for path in expand(ctx,resource,'/properties/AnalysisRules/*/Policy/V1/Custom/AggregationThresholds/*/OutputColumnThresholds'):
            emit(CLEAN[kind],path,unique_items(ctx,resource,path,'OutputColumnName'),'checks literal output-column uniqueness within each threshold collection; unknown names and actual query/schema correspondence remain under review')
    return results
