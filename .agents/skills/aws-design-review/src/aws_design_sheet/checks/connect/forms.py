"""Checks for AWS::Connect::EvaluationForm, AWS::Connect::TaskTemplate."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.policy_maps import unique_items

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CONNECT_FORM_COUNTS': [CF+'aws-resource-connect-evaluationform.html'],
    'CONNECT_FORM_IDS': [CF+'aws-properties-connect-evaluationform-evaluationformsection.html',CF+'aws-properties-connect-evaluationform-evaluationformquestion.html',CF+'aws-properties-connect-evaluationform-evaluationformsingleselectquestionoption.html'],
    'CONNECT_TASK_NAME_FIELD': [CF+'aws-resource-connect-tasktemplate.html',CF+'aws-properties-connect-tasktemplate-field.html'],
}


@resource_check('AWS::Connect::EvaluationForm', 'AWS::Connect::TaskTemplate')
def evaluate_connect_forms(design,resource):
    ctx=_Context(design,resource); results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Connect::EvaluationForm':
        root='/properties/Items'; stack=[root]; counts={'Section':0,'Question':0}; seen=set(); duplicate=False; pending=False; id_pending=False
        while stack:
            path=stack.pop(); items=value(ctx,resource,path)
            if not isinstance(items,list):pending=True;continue
            for i in range(len(items)):
                base=path+'/'+str(i); item=value(ctx,resource,base)
                if not isinstance(item,dict):pending=True;continue
                types=[t for t in ('Section','Question') if value(ctx,resource,base+'/'+t) is not ABSENT]
                if len(types)!=1:pending=True;continue
                kind=types[0]; node=base+'/'+kind
                if not isinstance(value(ctx,resource,node),dict):pending=True;continue
                counts[kind]+=1; ref=value(ctx,resource,node+'/RefId')
                if not literal(ref):id_pending=True
                elif ref in seen:duplicate=True
                else:seen.add(ref)
                if kind=='Section':
                    if value(ctx,resource,node+'/Items') is not ABSENT:stack.append(node+'/Items')
                else:
                    options=node+'/QuestionTypeProperties/SingleSelect/Options'
                    if value(ctx,resource,options) is not ABSENT:
                        verdict=unique_items(ctx,resource,options,'RefId')
                        emit('CONNECT_FORM_IDS',options,verdict,'SingleSelect option RefIds must be unique within this question; other question kinds and unresolved options remain separate')
                    if value(ctx,resource,node+'/QuestionTypeProperties/MultiSelect') is not ABSENT:id_pending=True
        emit('CONNECT_FORM_COUNTS',root,'FAIL' if max(counts.values())>100 else 'NEEDS_REVIEW' if pending else 'PASS','counts sections and questions separately across nested Items; each total <=100; unknown/ambiguous nodes are held and depth/schema legality is separate')
        emit('CONNECT_FORM_IDS',root,'FAIL' if duplicate else 'NEEDS_REVIEW' if pending or id_pending else 'PASS','section/question RefIds share form-wide uniqueness; unresolved nodes and MultiSelect option uniqueness remain under review')
    if resource.type=='AWS::Connect::TaskTemplate':
        path='/properties/Fields'; raw=value(ctx,resource,path); types=[]; pending=not isinstance(raw,list)
        for i in range(len(raw)) if isinstance(raw,list) else ():
            kind=value(ctx,resource,path+'/'+str(i)+'/Type')
            if not literal(kind):pending=True
            types.append(kind)
        emit('CONNECT_TASK_NAME_FIELD',path,'PASS' if 'NAME' in types else 'NEEDS_REVIEW' if pending else 'FAIL','declared template fields need at least one NAME type; omitted/unresolved fields remain under review')
    return results
