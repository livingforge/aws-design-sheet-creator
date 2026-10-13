"""Checks for AWS::CleanRoomsML::ConfiguredModelAlgorithmAssociation."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.literals import expand

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CLEANROOMSML_CUSTOM_REDACTION': [CF+'aws-properties-cleanroomsml-configuredmodelalgorithmassociation-'+s+'.html' for s in ('logredactionconfiguration','customentityconfig')],
}


@resource_check('AWS::CleanRoomsML::ConfiguredModelAlgorithmAssociation')
def evaluate_cleanroomsml_custom_redaction(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::CleanRoomsML::ConfiguredModelAlgorithmAssociation':
        bases=(base for policy in ('TrainedModels','TrainedModelInferenceJobs')
               for base in expand(ctx,resource,'/properties/PrivacyConfiguration/Policies/'+policy+'/ContainerLogs/*/LogRedactionConfiguration'))
        for base in bases:
            raw=get(base+'/EntitiesToRedact');custom=get(base+'/CustomEntityConfig');pending=not isinstance(raw,list);found=False
            for i in range(len(raw)) if isinstance(raw,list) else ():
                entity=get(base+'/EntitiesToRedact/'+str(i))
                if entity=='CUSTOM':found=True
                elif entity not in ('NUMBERS','ALL_PERSONALLY_IDENTIFIABLE_INFORMATION'):pending=True
            verdict='NEEDS_REVIEW'
            if found:verdict='FAIL' if custom is ABSENT else 'PASS' if isinstance(custom,dict) else 'NEEDS_REVIEW'
            elif not pending:verdict='PASS' if custom is ABSENT else 'NEEDS_REVIEW' if custom is UNKNOWN else 'FAIL'
            emit('CLEANROOMSML_CUSTOM_REDACTION',base,verdict,'CUSTOM redaction and CustomEntityConfig must accompany each other; unknown entities/configuration presence are held; custom pattern contents and effectiveness are separate')
    return results
