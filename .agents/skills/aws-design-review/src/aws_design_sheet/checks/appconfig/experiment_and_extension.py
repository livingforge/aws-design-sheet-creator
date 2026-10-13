"""Checks for AWS::AppConfig::ExperimentDefinition, AWS::AppConfig::Extension."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.map_paths import map_paths

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'APPCONFIG_DYNAMIC_REQUIRED': [CF+'aws-properties-appconfig-extension-parameter.html'],
    'APPCONFIG_ATTRIBUTE_UNION': [CF+'aws-properties-appconfig-experimentdefinition-attributevalue.html'],
}


@resource_check('AWS::AppConfig::Extension', 'AWS::AppConfig::ExperimentDefinition')
def evaluate_appconfig_experiment_and_extension(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::AppConfig::Extension':
        root='/properties/Parameters';paths=map_paths(ctx,resource,root)
        if paths is None:
            emit('APPCONFIG_DYNAMIC_REQUIRED',root,'NEEDS_REVIEW','parameter map is unresolved')
        for path in paths or []:
            dynamic=value(ctx,resource,path+'/Dynamic');required=value(ctx,resource,path+'/Required')
            verdict=('FAIL' if dynamic is True and required is True else 'PASS'
                     if dynamic is False or required is False else 'NEEDS_REVIEW')
            emit('APPCONFIG_DYNAMIC_REQUIRED',path,verdict,'dynamic parameters cannot also be Required=true; unknown flags are not defaulted')
    if resource.type=='AWS::AppConfig::ExperimentDefinition':
        roots=['/properties/Control/AttributeValues']
        treatments=value(ctx,resource,'/properties/Treatments')
        if isinstance(treatments,list):roots.extend('/properties/Treatments/'+str(i)+'/AttributeValues' for i in range(len(treatments)))
        elif treatments is not ABSENT:emit('APPCONFIG_ATTRIBUTE_UNION','/properties/Treatments','NEEDS_REVIEW','treatments are unresolved')
        for root in roots:
            paths=map_paths(ctx,resource,root)
            if paths is None:emit('APPCONFIG_ATTRIBUTE_UNION',root,'NEEDS_REVIEW','attribute map is unresolved')
            for path in paths or []:
                raw=value(ctx,resource,path)
                members=[value(ctx,resource,path+'/'+k) for k in ('StringValue','NumberValue','BooleanValue','StringArray','NumberArray')]
                known=sum(v is not ABSENT and v is not UNKNOWN for v in members)
                verdict=('FAIL' if known>1 else 'NEEDS_REVIEW' if not isinstance(raw,dict) or any(v is UNKNOWN for v in members)
                         or set(raw)-{'StringValue','NumberValue','BooleanValue','StringArray','NumberArray'} else 'PASS')
                emit('APPCONFIG_ATTRIBUTE_UNION',path,verdict,'at most one documented attribute member may be set; empty objects do not imply a required member, and value types are checked separately')
    return results
