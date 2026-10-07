"""Checks for AWS::SES::ReceiptRule."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SES_RECEIPT_ENUMS': [CF+'aws-properties-ses-receiptrule-rule.html',CF+'aws-properties-ses-receiptrule-lambdaaction.html',CF+'aws-properties-ses-receiptrule-snsaction.html','https://docs.aws.amazon.com/ses/latest/APIReference/API_SNSAction.html'],
}


@resource_check('AWS::SES::ReceiptRule')
def evaluate_ses_receipt_enums(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::SES::ReceiptRule':
        specs=[('/properties/Rule/TlsPolicy',('Require','Optional')),
               ('/properties/Rule/Actions/*/LambdaAction/InvocationType',('Event','RequestResponse')),
               ('/properties/Rule/Actions/*/SNSAction/Encoding',('UTF-8','Base64'))]
        seen=set()
        for pattern,allowed in specs:
            for path in expand(ctx,resource,pattern):
                if path in seen:continue
                seen.add(path)
                raw=get(path)
                pending=not literal(raw) or allowed==('UTF-8','Base64') and raw=='BASE64'
                emit('SES_RECEIPT_ENUMS',path,'NEEDS_REVIEW' if pending else 'PASS' if raw in allowed else 'FAIL','checks explicit documented receipt-rule enums; omitted defaults are not inferred; BASE64 prose spelling conflicts with Base64 enum and remains under review')
    return results
