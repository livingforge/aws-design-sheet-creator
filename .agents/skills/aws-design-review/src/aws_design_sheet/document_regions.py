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
    return rows
