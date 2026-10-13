"""Documented enum checks shared by WAF Classic and Pinpoint."""
from .context_values import _Context, value
from .literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SPECS={
 'AWS::WAF::SizeConstraintSet':('WAF_SIZE_FIELD_TYPE','SizeConstraints','waf-sizeconstraintset'),
 'AWS::WAF::XssMatchSet':('WAF_XSS_FIELD_TYPE','XssMatchTuples','waf-xssmatchset'),
 'AWS::WAFRegional::SqlInjectionMatchSet':('WAFREGIONAL_SQL_FIELD_TYPE','SqlInjectionMatchTuples','wafregional-sqlinjectionmatchset'),
}
SOURCES={rule:[CF+'aws-properties-'+page+'-fieldtomatch.html'] for rule,_,page in SPECS.values()}
SOURCES['PINPOINT_SEGMENT_SET_DIMENSION']=[CF+'aws-properties-pinpoint-segment-'+page+'.html' for page in ('setdimension','demographic','location')]
FIELDS=('URI','QUERY_STRING','HEADER','METHOD','BODY','SINGLE_QUERY_ARG','ALL_QUERY_ARGS')
DIMENSIONS=tuple('Demographic/'+key for key in ('AppVersion','Channel','DeviceType','Make','Model','Platform'))+('Location/Country',)


def enum_findings(design,resource):
    ctx=_Context(design,resource);specs=[];results=[];seen=set()
    if resource.type in SPECS:
        rule,key,_=SPECS[resource.type]
        specs.append((rule,'/properties/'+key+'/*/FieldToMatch/Type',FIELDS))
    if resource.type=='AWS::Pinpoint::Segment':
        for root in ('/properties/Dimensions','/properties/SegmentGroups/Groups/*/Dimensions/*'):
            specs.extend(('PINPOINT_SEGMENT_SET_DIMENSION',root+'/'+key+'/DimensionType',('INCLUSIVE','EXCLUSIVE')) for key in DIMENSIONS)
    for rule,pattern,allowed in specs:
        for path in expand(ctx,resource,pattern):
            if (rule,path) in seen:continue
            seen.add((rule,path));raw=value(ctx,resource,path)
            verdict='NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL'
            f=ctx.finding(rule,path,verdict,'Documented literal enum only; unknown values remain reviewable. PASS does not establish runtime availability, actual segment membership or overall resource validity.')
            f['source_checked_at']='2026-10-04';results.append(f)
    return results
