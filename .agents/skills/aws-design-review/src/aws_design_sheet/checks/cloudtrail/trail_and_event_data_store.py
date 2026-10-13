"""CloudTrail collection checks with conservative unknown handling."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={
 'CLOUDTRAIL_WIDGET_PARAMETERS':[CF+'aws-properties-cloudtrail-dashboard-widget.html'],
 'CLOUDTRAIL_INSIGHTS_DESTINATION':[CF+'aws-resource-cloudtrail-eventdatastore.html'],
 'CLOUDTRAIL_DATA_RESOURCE_TOTAL':[CF+'aws-properties-cloudtrail-trail-dataresource.html'],
 'CLOUDTRAIL_ADVANCED_FIELD_REQUIREMENTS':[CF+'aws-properties-cloudtrail-trail-advancedfieldselector.html',CF+'aws-properties-cloudtrail-trail-advancedeventselector.html'],
}
OTHER_OPS=('NotEquals','StartsWith','EndsWith','NotStartsWith','NotEndsWith')


def fields(ctx,resource,base):
    raw=value(ctx,resource,base)
    paths=[base+'/'+str(i) for i in range(len(raw))] if isinstance(raw,list) else []
    names=[value(ctx,resource,p+'/Field') for p in paths]
    return paths,names,isinstance(raw,list) and all(literal(n) for n in names)


@resource_check('AWS::CloudTrail::Dashboard', 'AWS::CloudTrail::EventDataStore', 'AWS::CloudTrail::Trail')
def evaluate_cloudtrail_trail_and_event_data_store(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):
        f=ctx.finding(rule,p,v,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::CloudTrail::Dashboard':
        for p in expand(ctx,resource,'/properties/Widgets/*/QueryParameters/*'):
            raw=get(p)
            emit('CLOUDTRAIL_WIDGET_PARAMETERS',p,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in ('$StartTime$','$EndTime$','$Period$') else 'FAIL','checks literal widget parameter names; query substitution semantics and service eligibility remain external')
    if resource.type=='AWS::CloudTrail::EventDataStore':
        p='/properties/InsightsDestination'
        if get(p) is not ABSENT:
            dest=linked(ctx,resource,p,resource.type);found=False;pending=dest is None;observed=False
            if dest:
                root='/properties/AdvancedEventSelectors';raw=value(ctx,dest,root)
                if not isinstance(raw,list) or not raw:pending=True
                for selector in expand(ctx,dest,root+'/*'):
                    paths,names,known=fields(ctx,dest,selector+'/FieldSelectors');pending|=not known
                    if not paths:pending=True
                    for path,name in zip(paths,names):
                        if name!='eventCategory':pending=True;continue
                        vals=value(ctx,dest,path+'/Equals')
                        no_other=all(value(ctx,dest,path+'/'+op) is ABSENT for op in OTHER_OPS)
                        if no_other and isinstance(vals,list) and len(vals)==1 and literal(value(ctx,dest,path+'/Equals/0')):
                            category=value(ctx,dest,path+'/Equals/0');observed=True
                            if category=='Insight':found=True
                            elif category not in ('Management','Data','NetworkActivity','ConfigurationItem','Evidence','ActivityAuditLog'):pending=True
                        else:pending=True
            emit('CLOUDTRAIL_INSIGHTS_DESTINATION',p,'PASS' if found else 'FAIL' if observed and not pending else 'NEEDS_REVIEW','linked destination explicitly selects Insight; negative result requires fully known recognized categories; external destinations, missing selectors and other predicates held')
    if resource.type=='AWS::CloudTrail::Trail':
        root='/properties/EventSelectors';raw=get(root)
        if raw is not ABSENT:
            values=[];pending=not isinstance(raw,list)
            for selector in expand(ctx,resource,root+'/*'):
                data=get(selector+'/DataResources')
                if data is ABSENT:continue
                if not isinstance(data,list):pending=True;continue
                for i in range(len(data)):
                    p=selector+'/DataResources/'+str(i)+'/Values';items=get(p)
                    if not isinstance(items,list):pending=True;continue
                    for j in range(len(items)):
                        arn=get(p+'/'+str(j))
                        # Broad all-resource prefixes and malformed/unknown values are held.
                        if literal(arn) and re.fullmatch(r'arn:aws(?:-cn|-us-gov)?:(?:s3:::[^:*?]+/[^*?]*|lambda:[a-z0-9-]+:[0-9]{12}:function:[^*?]+|dynamodb:[a-z0-9-]+:[0-9]{12}:table/[^*?]+)',arn):values.append(arn)
                        else:pending=True
            v='NEEDS_REVIEW' if pending else 'FAIL' if len(set(values))>250 else 'PASS' if len(values)<=250 else 'NEEDS_REVIEW'
            emit('CLOUDTRAIL_DATA_RESOURCE_TOTAL',root,v,'checks aggregate explicit specific resource ARNs across basic selectors; all-resource prefixes, unknown values and ambiguous duplicate counting above 250 held; conditional DataResources requirement separate')
        for selector in expand(ctx,resource,'/properties/AdvancedEventSelectors/*'):
            p=selector+'/FieldSelectors';paths,names,known=fields(ctx,resource,p);bad=False;pending=not known
            categories=[x for x,n in zip(paths,names) if n=='eventCategory']
            if not categories and known:bad=True
            if len(categories)!=1:pending=True
            category=None
            for path in categories:
                vals=get(path+'/Equals')
                if vals is ABSENT:bad=True
                elif isinstance(vals,list) and len(vals)==1 and literal(get(path+'/Equals/0')):
                    category=get(path+'/Equals/0')
                    if category not in ('Management','Data','NetworkActivity'):bad=True
                else:pending=True
                for op in OTHER_OPS:
                    raw=get(path+'/'+op)
                    if isinstance(raw,list):bad=True
                    elif raw is not ABSENT:pending=True
            if len(categories)!=1:category=None
            if names.count('resources.type')>1:bad=True
            required='resources.type' if category=='Data' else 'eventSource' if category=='NetworkActivity' else None
            if required and required not in names:
                if known:bad=True
                else:pending=True
            if category=='NetworkActivity':
                for path,name in zip(paths,names):
                    if name!='eventSource':continue
                    eq=get(path+'/Equals')
                    if eq is ABSENT:bad=True
                    elif not isinstance(eq,list) or not eq:pending=True
                    for op in OTHER_OPS:
                        raw=get(path+'/'+op)
                        if isinstance(raw,list):bad=True
                        elif raw is not ABSENT:pending=True
            emit('CLOUDTRAIL_ADVANCED_FIELD_REQUIREMENTS',p,'FAIL' if bad else 'NEEDS_REVIEW' if pending else 'PASS','checks required category, Data resource type, NetworkActivity eventSource Equals and unique resources.type field; other field semantics, values and service catalogs remain separate')
    return results
