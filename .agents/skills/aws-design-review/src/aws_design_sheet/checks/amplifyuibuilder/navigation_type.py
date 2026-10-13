"""Checks for AWS::AmplifyUIBuilder::Component."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'AMPLIFYUI_NAVIGATION_TYPE': [CF+'aws-properties-amplifyuibuilder-component-actionparameters.html', CF+'aws-properties-amplifyuibuilder-component-componentchild.html', 'https://raw.githubusercontent.com/aws-amplify/amplify-codegen-ui/main/packages/codegen-ui/lib/types/actions.ts'],
}


def navigation(ctx,r):
    results=[];pending=[('/properties',0)];count=0
    while pending:
        base,depth=pending.pop();count+=1
        if depth>32 or count>1000:
            results.append((base,'NEEDS_REVIEW'));break
        events=value(ctx,r,base+'/Events')
        if events is not ABSENT:
            if not isinstance(events,dict):results.append((base+'/Events','NEEDS_REVIEW'))
            else:
                for key in events:
                    if not isinstance(key,str) or '/' in key or '~' in key or key=='$state':
                        results.append((base+'/Events','NEEDS_REVIEW'));continue
                    path=base+'/Events/'+key
                    action=value(ctx,r,path+'/Action')
                    if action=='Amplify.Navigation':
                        raw=value(ctx,r,path+'/Parameters/Type')
                        params=value(ctx,r,path+'/Parameters')
                        verdict='FAIL' if raw is ABSENT and (params is ABSENT or isinstance(params,dict) and '$state' not in params) else 'PASS' if isinstance(raw,dict) and '$state' not in raw else 'NEEDS_REVIEW'
                        results.append((path+'/Parameters/Type',verdict))
                    elif not literal(action):results.append((path+'/Action','NEEDS_REVIEW'))
        children=value(ctx,r,base+'/Children')
        if children is ABSENT:continue
        if not isinstance(children,list):results.append((base+'/Children','NEEDS_REVIEW'));continue
        pending.extend((base+'/Children/'+str(i),depth+1) for i in range(len(children)))
    return list(dict.fromkeys(results))


@resource_check('AWS::AmplifyUIBuilder::Component')
def evaluate_amplifyuibuilder_navigation_type(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::AmplifyUIBuilder::Component':
        for path,verdict in navigation(ctx,resource):emit('AMPLIFYUI_NAVIGATION_TYPE',path,verdict,'explicit Amplify.Navigation event requires Parameters.Type in bounded Children traversal; Type content, escaped map keys, unknown actions and oversized trees held')
    return results
