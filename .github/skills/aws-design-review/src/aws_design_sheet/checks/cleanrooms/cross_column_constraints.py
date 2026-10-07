"""Checks for AWS::CleanRooms::ConfiguredTable, AWS::CleanRooms::IntermediateTable."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand
from ..common.string_lists import strings

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CLEANROOMS_CONFIGURED_IDENTITY_COMPARE': [CF+'aws-properties-cleanrooms-configuredtable-comparisoncontrols.html'],
    'CLEANROOMS_INTERMEDIATE_IDENTITY_COMPARE': [CF+'aws-properties-cleanrooms-intermediatetable-comparisoncontrols.html'],
}


@resource_check('AWS::CleanRooms::ConfiguredTable','AWS::CleanRooms::IntermediateTable')
def evaluate_cleanrooms_cross_column_constraints(design,resource):
    ctx=_Context(design,resource); results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    clean={'AWS::CleanRooms::ConfiguredTable':'CLEANROOMS_CONFIGURED_IDENTITY_COMPARE','AWS::CleanRooms::IntermediateTable':'CLEANROOMS_INTERMEDIATE_IDENTITY_COMPARE'}
    if resource.type in clean:
        for base in expand(ctx,resource,'/properties/AnalysisRules/*/Policy/V1/Custom'):
            path=base+'/ComparisonControls/AllowedLiteralComparisonColumns'
            if value(ctx,resource,path) is ABSENT:continue
            allowed,pending=strings(ctx,resource,path); identities=[]
            thresholds=value(ctx,resource,base+'/AggregationThresholds')
            if thresholds is not ABSENT:
                if not isinstance(thresholds,list):pending=True
                else:
                    for i in range(len(thresholds)):
                        names,unknown=strings(ctx,resource,base+'/AggregationThresholds/'+str(i)+'/IdentityColumns')
                        identities.extend(names); pending|=unknown
            verdict='FAIL' if set(allowed)&set(identities) else 'NEEDS_REVIEW' if pending else 'PASS'
            emit(clean[resource.type],path,verdict,'literal-comparison columns cannot also be aggregation identity columns in this custom rule; unknown columns and physical/query schema remain under review')
    return results
