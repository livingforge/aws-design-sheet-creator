"""Checks for AWS::CodeBuild::Project."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CODEBUILD_FILTER_EVENT_REQUIRED': [CF+'aws-properties-codebuild-project-projecttriggers.html'],
}


@resource_check('AWS::CodeBuild::Project')
def evaluate_codebuild_filter_event_required(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
    if resource.type=='AWS::CodeBuild::Project':
        root='/properties/Triggers/FilterGroups';raw=get(root)
        if raw is not ABSENT:
            all_event=isinstance(raw,list) and bool(raw);any_event=False;pending=not isinstance(raw,list)
            for p in expand(ctx,resource,root+'/*'):
                group=get(p);types=[get(p+'/'+str(i)+'/Type') for i in range(len(group))] if isinstance(group,list) else []
                event='EVENT' in types;any_event|=event;all_event&=event
                if not isinstance(group,list) or any(not literal(x) for x in types):pending=True
            v='PASS' if all_event else 'FAIL' if not any_event and not pending else 'NEEDS_REVIEW'
            emit('CODEBUILD_FILTER_EVENT_REQUIRED',root,v,'passes if every explicit group contains EVENT, fails only if fully known groups contain no EVENT anywhere; mixed groups held because current prose says in the array without disambiguating nesting')
    return results
