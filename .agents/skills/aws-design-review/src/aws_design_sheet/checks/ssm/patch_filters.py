"""Documented patch-filter OS properties and static upper bounds."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

API='https://docs.aws.amazon.com/systems-manager/latest/APIReference/'
CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={
    'SSM_PATCH_FILTER_OS_PROPERTY':[API+'DescribePatchProperties.html',API+'PatchFilter.html',CF+'aws-resource-ssm-patchbaseline.html'],
    'SSM_PATCH_FILTER_VALUE_BOUNDS':[API+'PatchFilter.html',CF+'aws-properties-ssm-patchbaseline-patchfilter.html'],
    'SSM_PATCH_LIST_WILDCARDS':['https://docs.aws.amazon.com/systems-manager/latest/userguide/patch-manager-approved-rejected-package-name-formats.html'],
}
RPM={'PRODUCT','CLASSIFICATION','SEVERITY'}
OS_PROPERTIES={**{os:RPM for os in ('AMAZON_LINUX','AMAZON_LINUX_2','AMAZON_LINUX_2023','CENTOS','ORACLE_LINUX','REDHAT_ENTERPRISE_LINUX','SUSE')},
    'DEBIAN':{'PRODUCT','PRIORITY'},'UBUNTU':{'PRODUCT','PRIORITY'},
    'MACOS':{'PRODUCT','CLASSIFICATION'},'WINDOWS':{'PRODUCT','PRODUCT_FAMILY','CLASSIFICATION','MSRC_SEVERITY'}}
LISTED_PROPERTIES={'PRODUCT','PRODUCT_FAMILY','CLASSIFICATION','MSRC_SEVERITY','PRIORITY','SEVERITY'}


@resource_check('AWS::SSM::PatchBaseline')
def patch_filters(design,resource):
    ctx=_Context(design,resource)
    os=value(ctx,resource,'/properties/OperatingSystem')
    if os is ABSENT:os='WINDOWS'
    paths=['/properties/GlobalFilters/PatchFilters']
    rules=value(ctx,resource,'/properties/ApprovalRules/PatchRules')
    results=patch_list_wildcards(ctx,resource,os)
    if rules is not ABSENT and not isinstance(rules,list):
        results.append(ctx.finding('SSM_PATCH_FILTER_OS_PROPERTY','/properties/ApprovalRules/PatchRules','NEEDS_REVIEW','approval rules are unresolved'))
    for i in range(len(rules) if isinstance(rules,list) else 0):
        paths.append(f'/properties/ApprovalRules/PatchRules/{i}/PatchFilterGroup/PatchFilters')
    for path in paths:
        filters=value(ctx,resource,path)
        if filters is ABSENT:continue
        if not isinstance(filters,list):
            results.append(ctx.finding('SSM_PATCH_FILTER_OS_PROPERTY',path,'NEEDS_REVIEW','patch filters are unresolved'))
            continue
        for i in range(len(filters)):
            base=path+f'/{i}'
            key=value(ctx,resource,base+'/Key')
            allowed=OS_PROPERTIES.get(os) if isinstance(os,str) else None
            verdict='NEEDS_REVIEW'
            if isinstance(key,str) and key in LISTED_PROPERTIES and allowed is not None:
                verdict='PASS' if key in allowed else 'FAIL'
            elif key=='PATCH_SET' and os=='WINDOWS':
                verdict='PASS'  # Explicitly listed by PatchFilter; not part of DescribePatchProperties.Property.
            results.append(ctx.finding('SSM_PATCH_FILTER_OS_PROPERTY',base+'/Key',verdict,
                'checks the documented OS matrix for six property keys and Windows PATCH_SET; other keys/OSs and dynamic property values require review'))
            values=value(ctx,resource,base+'/Values')
            bad=isinstance(values,list) and len(values)>20
            pending=not isinstance(values,list) or not values
            for j in range(len(values) if isinstance(values,list) else 0):
                item=value(ctx,resource,base+f'/Values/{j}')
                known=isinstance(item,str) and '{{' not in item and '${' not in item
                if known and len(item)>64:bad=True
                elif not known or item=='':pending=True
            results.append(ctx.finding('SSM_PATCH_FILTER_VALUE_BOUNDS',base+'/Values',
                'FAIL' if bad else 'NEEDS_REVIEW' if pending else 'PASS',
                'at most 20 values and 64 characters per known value; empty forms and actual OS-specific catalogs require separate review'))
    return results


def patch_list_wildcards(ctx,resource,os):
    limits={'MACOS':0,'AMAZON_LINUX_2':1,'AMAZON_LINUX_2023':1,
            'ORACLE_LINUX':1,'REDHAT_ENTERPRISE_LINUX':1,'SUSE':1}
    limit=limits.get(os) if isinstance(os,str) else None
    results=[]
    for key in ('ApprovedPatches','RejectedPatches'):
        path='/properties/'+key
        items=value(ctx,resource,path)
        if items is ABSENT:continue
        if not isinstance(items,list):
            results.append(ctx.finding('SSM_PATCH_LIST_WILDCARDS',path,'NEEDS_REVIEW','patch list is unresolved'))
            continue
        for i in range(len(items)):
            item=value(ctx,resource,path+f'/{i}')
            verdict='NEEDS_REVIEW'
            if limit is not None and isinstance(item,str) and '{{' not in item and '${' not in item:
                verdict='FAIL' if item.count('*')>limit else 'NEEDS_REVIEW' if any(c in item for c in '?[]') else 'PASS'
            results.append(ctx.finding('SSM_PATCH_LIST_WILDCARDS',path+f'/{i}',verdict,
                'macOS forbids wildcards; the listed Linux package formats support a single asterisk; this does not validate package existence or the complete name grammar'))
    return results
