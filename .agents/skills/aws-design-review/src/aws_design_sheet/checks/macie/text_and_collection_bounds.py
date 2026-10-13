"""Checks for AWS::Macie::AllowList, AWS::Macie::CustomDataIdentifier, AWS::Macie::FindingsFilter."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

MACIE={k:'MACIE_'+label+'_BOUNDS' for k,label in (
    ('AllowList','ALLOW_LIST'),('CustomDataIdentifier','CUSTOM_IDENTIFIER'),('FindingsFilter','FINDINGS_FILTER'))}
SOURCES = {
    'MACIE_ALLOW_LIST_BOUNDS': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-macie-allowlist.html',
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-macie-allowlist-criteria.html',
    ],
    'MACIE_CUSTOM_IDENTIFIER_BOUNDS': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-macie-customdataidentifier.html',
    ],
    'MACIE_FINDINGS_FILTER_BOUNDS': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-macie-findingsfilter.html',
    ],
}


def text(raw):
    return isinstance(raw,str) and '${' not in raw and '{{' not in raw


@resource_check(*('AWS::Macie::'+kind for kind in MACIE))
def evaluate_macie_text_and_collection_bounds(design,resource):
    ctx=_Context(design,resource);results=[];kind=resource.type.split('::')[-1]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    rule=MACIE[kind]
    bounds=[('Name',3 if kind=='FindingsFilter' else 1,64 if kind=='FindingsFilter' else 128),('Description',1,512)]
    if kind=='AllowList':bounds.append(('Criteria/Regex',1,512))
    if kind=='CustomDataIdentifier':bounds.append(('Regex',1,512))
    for key,low,high in bounds:
        path='/properties/'+key;raw=get(path)
        if raw is not ABSENT:
            emit(rule,path,'NEEDS_REVIEW' if not text(raw) else 'PASS' if low<=len(raw)<=high else 'FAIL','checks documented character-count bounds of explicit strings; unresolved values, regex semantics and external Macie session state remain separate')
    if kind=='CustomDataIdentifier':
        for key,limit,minimum in (('Keywords',50,3),('IgnoreWords',10,4)):
            path='/properties/'+key;raw=get(path)
            if raw is ABSENT:continue
            known=0;pending=not isinstance(raw,list);invalid=isinstance(raw,list) and not raw
            for i in range(len(raw)) if isinstance(raw,list) else ():
                item=get(path+'/'+str(i))
                if not text(item):pending=True
                else:
                    known+=1
                    if not minimum<=len(item)<=90:invalid=True
            emit(rule,path,'FAIL' if invalid or known>limit else 'NEEDS_REVIEW' if pending else 'PASS','checks keyword/ignore-word collection counts and per-string character lengths; unknown entries remain under review; regex matching behavior is not inferred')
        path='/properties/MaximumMatchDistance';raw=get(path)
        if raw is not ABSENT:
            emit(rule,path,'NEEDS_REVIEW' if type(raw) is not int else 'PASS' if 1<=raw<=300 else 'FAIL','explicit integer maximum match distance must be 1..300; omitted default and unresolved values remain separate')
    return results
