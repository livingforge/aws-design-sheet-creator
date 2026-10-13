"""Checks for AWS::PCAConnectorAD::Template."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'PCACONNECTORAD_SUBJECT_PRESENT': [CF+'aws-properties-pcaconnectorad-template-subjectnameflagsv'+str(v)+'.html' for v in (2,3,4)],
}
FLAGS=('RequireCommonName','RequireDirectoryPath','RequireDnsAsCn','RequireEmail','SanRequireDirectoryGuid','SanRequireDns','SanRequireDomainDns','SanRequireEmail','SanRequireSpn','SanRequireUpn')


@resource_check('AWS::PCAConnectorAD::Template')
def evaluate_pcaconnectorad_subject_present(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 for version in (2,3,4):
  p='/properties/Definition/TemplateV'+str(version)+'/SubjectNameFlags'
  raw=get(p)
  if raw is ABSENT:continue
  flags=[get(p+'/'+key) for key in FLAGS]
  verdict='PASS' if any(x is True for x in flags) else 'FAIL' if all(x is False for x in flags) and isinstance(raw,dict) and not set(raw)-set(FLAGS) else 'NEEDS_REVIEW'
  emit('PCACONNECTORAD_SUBJECT_PRESENT',p,verdict,'at least one explicit subject/SAN flag must be true; all ten false fails; missing/unknown flags are not assumed false; directory values and issuance remain external')
 return results
