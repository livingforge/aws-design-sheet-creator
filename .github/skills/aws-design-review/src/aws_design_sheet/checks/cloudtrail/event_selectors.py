"""Checks for AWS::CloudTrail::EventDataStore, AWS::CloudTrail::Trail."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.literals import expand, literal
from ..common.string_lists import strings

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CLOUDTRAIL_DATASTORE_SELECTORS': [CF+'aws-properties-cloudtrail-eventdatastore-advancedfieldselector.html'],
    'CLOUDTRAIL_TRAIL_VALUE_LIMIT': [CF+'aws-resource-cloudtrail-trail.html'],
}
OPS=('Equals','NotEquals','StartsWith','NotStartsWith','EndsWith','NotEndsWith')
CATEGORIES={'Management','Data','NetworkActivity','Insight','ConfigurationItem','Evidence','ActivityAuditLog'}


@resource_check('AWS::CloudTrail::EventDataStore','AWS::CloudTrail::Trail')
def evaluate_cloudtrail_event_selectors(design,resource):
    ctx=_Context(design,resource); results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::CloudTrail::EventDataStore':
        for path in expand(ctx,resource,'/properties/AdvancedEventSelectors/*/FieldSelectors'):
            raw=value(ctx,resource,path); fields=[]; pending=not isinstance(raw,list); invalid=False
            for i in range(len(raw)) if isinstance(raw,list) else ():
                base=path+'/'+str(i); name=value(ctx,resource,base+'/Field')
                if not literal(name):pending=True
                fields.append((name,base))
            category_rows=[b for n,b in fields if n=='eventCategory']
            known_fields=all(literal(n) for n,b in fields) and isinstance(raw,list)
            if not category_rows and known_fields:invalid=True
            category=None
            if len(category_rows)==1:
                cats,unknown=strings(ctx,resource,category_rows[0]+'/Equals')
                if not unknown and len(cats)==1 and cats[0] in CATEGORIES:category=cats[0]
                elif not unknown and any(c not in CATEGORIES for c in cats):invalid=True
                else:pending=True
            elif category_rows:pending=True
            resources=[b for n,b in fields if n=='resources.type']
            if len(resources)>1:invalid=True
            required='resources.type' if category=='Data' else 'eventSource' if category=='NetworkActivity' else None
            if required and not any(n==required for n,b in fields):
                if known_fields:invalid=True
                else:pending=True
            for name,base in fields:
                equals_only=name in ('eventCategory','resources.type','readOnly') or category=='NetworkActivity' and name=='eventSource'
                if not equals_only:continue
                equal=value(ctx,resource,base+'/Equals')
                if equal is ABSENT:invalid=True
                elif not isinstance(equal,list):pending=True
                elif not equal:invalid=True
                else:
                    _,unknown=strings(ctx,resource,base+'/Equals');pending|=unknown
                for op in OPS[1:]:
                    raw_op=value(ctx,resource,base+'/'+op)
                    if raw_op is UNKNOWN:pending=True
                    elif raw_op is not ABSENT:invalid=True
            if category is None:pending=True
            emit('CLOUDTRAIL_DATASTORE_SELECTORS',path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','checks category Equals, Data resource type, NetworkActivity event source, Equals-only fields and resource-type field count; mixed categories, allowed field catalogs and external resources remain separate')
    if resource.type=='AWS::CloudTrail::Trail':
        path='/properties/AdvancedEventSelectors'; selectors=value(ctx,resource,path)
        if selectors is not ABSENT:
            count=0;pending=not isinstance(selectors,list)
            for i in range(len(selectors)) if isinstance(selectors,list) else ():
                fields_path=path+'/'+str(i)+'/FieldSelectors';fields=value(ctx,resource,fields_path)
                if not isinstance(fields,list):pending=True;continue
                for j in range(len(fields)):
                    base=fields_path+'/'+str(j)
                    if not isinstance(value(ctx,resource,base),dict):pending=True
                    for op in OPS:
                        op_path=base+'/'+op
                        if value(ctx,resource,op_path) is ABSENT:continue
                        vals,unknown=strings(ctx,resource,op_path);count+=len(vals);pending|=unknown
            emit('CLOUDTRAIL_TRAIL_VALUE_LIMIT',path,'FAIL' if count>500 else 'NEEDS_REVIEW' if pending else 'PASS','at most 500 condition values across all advanced selectors; duplicates count as entries; unresolved collections/values remain under review')
    return results
