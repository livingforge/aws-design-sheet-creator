"""Checks for AWS::CustomerProfiles::Domain, AWS::CustomerProfiles::ObjectType."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal
from ..common.string_lists import strings

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CUSTOMERPROFILES_CANONICAL_ATTRIBUTES': [CF+'aws-properties-customerprofiles-domain-attributetypesselector.html'],
    'CUSTOMERPROFILES_UNIQUE_KEY': [CF+'aws-properties-customerprofiles-objecttype-objecttypekey.html'],
}


@resource_check('AWS::CustomerProfiles::Domain', 'AWS::CustomerProfiles::ObjectType')
def evaluate_customerprofiles_object_type_keys(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::CustomerProfiles::Domain':
        base='/properties/RuleBasedMatching'; selector=base+'/AttributeTypesSelector'
        if value(ctx,resource,selector) is not ABSENT:
            aliases={'Address':{'BusinessAddress','ShippingAddress'},'EmailAddress':{'BusinessEmailAddress','PersonalEmailAddress'},'PhoneNumber':{'HomePhoneNumber','MobilePhoneNumber'}}
            forbidden=set();pending=False
            for group,names in aliases.items():
                raw=value(ctx,resource,selector+'/'+group)
                if raw is ABSENT:continue
                selected,unknown=strings(ctx,resource,selector+'/'+group);pending|=unknown
                if selected:forbidden.update(names)
                if any(s not in names|{group} for s in selected):pending=True
            model=value(ctx,resource,selector+'/AttributeMatchingModel')
            if model not in ('ONE_TO_ONE','MANY_TO_MANY'):pending=True
            for path in expand(ctx,resource,base+'/MatchingRules/*/Rule'):
                attrs,unknown=strings(ctx,resource,path);invalid=any(a.split('.')[0] in forbidden for a in attrs)
                ambiguous=any(a.split('.')[0] in ('MailingAddress','MaillingAddress','Phone','HomePhone') for a in attrs)
                emit('CUSTOMERPROFILES_CANONICAL_ATTRIBUTES',path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending or unknown or ambiguous else 'PASS','selected address/email/phone variants must use canonical matching-rule types; spelling discrepancies, unknown selectors and complete attribute catalog remain separate')
    if resource.type=='AWS::CustomerProfiles::ObjectType':
        path='/properties/Keys'; raw=value(ctx,resource,path)
        if raw is not ABSENT:
            pending=not isinstance(raw,list);unique_names=set();seen=set()
            for i in range(len(raw)) if isinstance(raw,list) else ():
                base=path+'/'+str(i);name=value(ctx,resource,base+'/Name');items=value(ctx,resource,base+'/ObjectTypeKeyList')
                if not literal(name):pending=True
                elif name in seen:pending=True
                else:seen.add(name)
                marks=0
                if not isinstance(items,list):pending=True;continue
                for j in range(len(items)):
                    ids_path=base+'/ObjectTypeKeyList/'+str(j)+'/StandardIdentifiers'
                    if value(ctx,resource,ids_path) is ABSENT:continue
                    identifiers,unknown=strings(ctx,resource,ids_path);pending|=unknown
                    if 'UNIQUE' in identifiers:marks+=1
                if marks>1:pending=True
                if marks and literal(name):unique_names.add(name)
            emit('CUSTOMERPROFILES_UNIQUE_KEY',path,'FAIL' if len(unique_names)>1 else 'NEEDS_REVIEW' if pending else 'PASS','at most one distinct named key may carry UNIQUE; repeated definitions within one key, unknown names/identifiers and mapping semantics remain under review')
    return results
