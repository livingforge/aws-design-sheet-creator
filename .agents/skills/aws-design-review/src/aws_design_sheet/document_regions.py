"""Bounded checks on declared placement, independent of live account identity."""


def inspect_placement(document):
    resources={r.id:r for r in document.design.resources}
    env=next(e for e in document.design.environments if e.id==document.environment_id)
    rows=[]
    for item in document.items:
        resource=resources[item.resource_id]
        if resource.type not in ('AWS::WAFv2::WebACL','AWS::WAFv2::IPSet','AWS::WAFv2::RegexPatternSet','AWS::WAFv2::RuleGroup'):continue
        setting=item.expected
        if item.name!='Scope' or setting.status!='DECIDED' or setting.mode!='LITERAL' or setting.value!='CLOUDFRONT':continue
        region=getattr(resource,'region',None) or env.region
        rows.append({'rule_id':'DOCUMENT_WAF_CLOUDFRONT_REGION','rule_version':'1.0','resource_id':resource.id,
            'path':'/properties/Scope','verdict':'PASS' if region=='us-east-1' else 'FAIL','severity':'ERROR',
            'authority':'AWS_SPEC','expected':'us-east-1','actual':region,'evidence_ids':[],
            'reason':'Explicit CLOUDFRONT Scope requires declared region us-east-1; no account, deployment or other WAF conditions verified',
            'source_checked_at':'2026-10-13','source_urls':[
                'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-wafv2-webacl.html']})
    return rows+literal_arn_regions(document,resources,env)


ARN_SOURCES=['https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html',
             'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cnames-and-https-requirements.html']


def literal_arn_regions(document,resources,env):
    """Decided literal ARNs whose region or partition differs from their resource's declared region."""
    from .document_bindings import FIXED_REGION,region_check,token
    from .document_v11 import SchemaSetting
    rows=[]

    def leaves(value,path):
        if isinstance(value,dict):
            if set(value)=={'$design'}:
                inner=SchemaSetting.model_validate(value['$design'])
                if inner.status=='DECIDED' and inner.mode=='LITERAL':yield from leaves(inner.value,path)
                return
            for k,v in value.items():yield from leaves(v,path+'/'+token(k))
        elif isinstance(value,list):
            for i,v in enumerate(value):yield from leaves(v,path+'/'+str(i))
        elif isinstance(value,str):yield path,value

    for item in document.items:
        setting=item.expected
        if item.origin=='cfn_only' or setting.status!='DECIDED' or setting.mode not in ('LITERAL','COMPOSITE'):continue
        resource=resources[item.resource_id];region=getattr(resource,'region',None) or env.region
        for path,text in leaves(setting.value,'/properties/'+token(item.name)):
            pattern='/'+'/'.join('*' if p.isdigit() else p for p in path.split('/')[2:])
            fixed=(resource.type,pattern) in FIXED_REGION
            found=region_check(resource.type,path,text,region)
            if found is None and not fixed:continue
            if found is None:verdict,reason='PASS',f"ARN is in the region this property requires ({FIXED_REGION[(resource.type,pattern)]})"
            elif found['cross_region_by_design']:verdict,reason='PASS','ARN is in another region, which this property points to by design'
            elif fixed:verdict,reason='FAIL',f"This property requires an ARN in {found['expected_region']}"
            else:verdict,reason='NEEDS_REVIEW',('ARN region or partition differs from the resource region; '
                                                'confirm the cross-region reference is intended and supported')
            rows.append({'rule_id':'DOCUMENT_ARN_REGION','rule_version':'1.0','resource_id':resource.id,'path':path,
                'verdict':verdict,'severity':'ERROR' if fixed else 'WARNING','authority':'AWS_SPEC',
                'expected':found['expected_region'] if found else FIXED_REGION[(resource.type,pattern)],
                'actual':', '.join(f"{f['arn_partition']}:{f['arn_region'] or '-'}" for f in found['found']) if found else region,
                'evidence_ids':[],'reason':reason+'; existence and account are not verified','source_checked_at':'2026-10-22',
                'source_urls':ARN_SOURCES})
    return rows
