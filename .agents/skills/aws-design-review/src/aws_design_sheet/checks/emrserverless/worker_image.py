"""Creation-time image presence for explicit EMR Serverless worker map entries."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'EMRSERVERLESS_WORKER_IMAGE_URI_REQUIRED':[
    CF+'aws-properties-emrserverless-application-imageconfigurationinput.html',
    CF+'aws-properties-emrserverless-application-workertypespecificationinput.html']}


@resource_check('AWS::EMRServerless::Application')
def evaluate_emrserverless_worker_image(design,resource):
    ctx=_Context(design,resource);base='/properties/WorkerTypeSpecifications'
    raw=value(ctx,resource,base);results=[]
    if raw is ABSENT:return []
    def emit(path,verdict):
        f=ctx.finding('EMRSERVERLESS_WORKER_IMAGE_URI_REQUIRED',path,verdict,
            'Under the repository creation-design contract, each supplied worker ImageConfiguration requires ImageUri. Omitted image configuration uses the service image. Update-time removal, registry access and image compatibility are outside this presence check; unresolved map entries and escaped keys remain reviewable.')
        f['source_checked_at']='2026-10-04';results.append(f)
    if not isinstance(raw,dict) or '$state' in raw or len(raw)>1000:
        emit(base,'NEEDS_REVIEW');return results
    for key in raw:
        if not literal(key) or '/' in key or '~' in key or key.startswith('$'):
            emit(base,'NEEDS_REVIEW');continue
        path=base+'/'+key+'/ImageConfiguration'
        config=value(ctx,resource,path)
        entry=value(ctx,resource,base+'/'+key)
        if not isinstance(entry,dict) or '$state' in entry:
            emit(path,'NEEDS_REVIEW');continue
        if config is ABSENT:continue
        verdict='NEEDS_REVIEW'
        if isinstance(config,dict) and '$state' not in config:
            uri=value(ctx,resource,path+'/ImageUri')
            verdict='FAIL' if uri is ABSENT or uri=='' else 'PASS' if literal(uri) else 'NEEDS_REVIEW'
        if resource.template is not None and resource.template.state.value!='KNOWN':verdict='NEEDS_REVIEW'
        emit(path+'/ImageUri',verdict)
    return results
