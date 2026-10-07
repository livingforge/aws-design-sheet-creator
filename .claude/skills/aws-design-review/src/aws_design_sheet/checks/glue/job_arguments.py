"""Checks for AWS::Glue::DevEndpoint, AWS::Glue::Job."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.numbers import number

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'GLUE_ENDPOINT_ARGUMENTS': [CF+'aws-resource-glue-devendpoint.html'],
    'GLUE_JOB_INTEGER_DPU': [CF+'aws-resource-glue-job.html'],
}


@resource_check('AWS::Glue::DevEndpoint', 'AWS::Glue::Job')
def evaluate_glue_job_arguments(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Glue::DevEndpoint':
        path='/properties/Arguments';raw=get(path)
        if raw is not ABSENT:
            pending=not isinstance(raw,dict);invalid=False
            for key in raw if isinstance(raw,dict) else ():
                if not literal(key) or key in ('$state','Ref') or key.startswith('Fn::'):pending=True;continue
                if key not in ('--enable-glue-datacatalog','GLUE_PYTHON_VERSION'):invalid=True;continue
                v=get(path+'/'+key)
                if not isinstance(v,str) or '${' in v or '{{' in v:pending=True
                elif key=='GLUE_PYTHON_VERSION' and v not in ('2','3'):invalid=True
                elif key=='--enable-glue-datacatalog' and v!='':pending=True
            emit('GLUE_ENDPOINT_ARGUMENTS',path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','checks documented argument keys and Python versions 2/3; nonempty datacatalog flag values, nonstrings and unresolved arguments remain under review')
    if resource.type=='AWS::Glue::Job':
        path='/properties/MaxCapacity';raw=get(path)
        if raw is not ABSENT:
            command=get('/properties/Command/Name');n=number(raw);verdict='NEEDS_REVIEW'
            if command=='glueetl' and n is not None:verdict='PASS' if n==n.to_integral_value() else 'FAIL'
            elif command in ('pythonshell','gluestreaming','glueray'):verdict='NOT_APPLICABLE'
            emit('GLUE_JOB_INTEGER_DPU',path,verdict,'explicit glueetl MaxCapacity must be integral; bounds, worker compatibility and other job types are separate checks')
    return results
