"""Checks for AWS::Lex::Bot."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'LEX_INLINE_FALLBACK': [CF+'aws-resource-lex-bot.html','https://docs.aws.amazon.com/lexv2/latest/dg/built-in-intent-fallback.html'],
    'LEX_MULTIVALUE_LOCALE': [CF+'aws-properties-lex-bot-multiplevaluessetting.html',CF+'aws-resource-lex-bot.html'],
}


@resource_check('AWS::Lex::Bot')
def evaluate_lex_bot_locales(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Lex::Bot':
        root='/properties/BotLocales';locales=get(root)
        applicable=get('/properties/BotType')=='Bot' and get('/properties/BotFileS3Location') is ABSENT and isinstance(locales,list) and len(locales)==1
        for base in expand(ctx,resource,root+'/*'):
            path=base+'/Intents';intents=get(path);found=False;pending=not isinstance(intents,list)
            for i in range(len(intents)) if isinstance(intents,list) else ():
                p=path+'/'+str(i)+'/ParentIntentSignature';signature=get(p)
                if signature=='AMAZON.FallbackIntent':found=True
                elif signature is not ABSENT and not literal(signature):pending=True
            verdict='NEEDS_REVIEW' if not applicable else 'PASS' if found else 'NEEDS_REVIEW' if pending else 'FAIL'
            emit('LEX_INLINE_FALLBACK',path,verdict,'single explicit Bot locale must contain AMAZON.FallbackIntent; imports, multiple locales, omitted/other BotType and unknown intent collections remain under review')
            locale=get(base+'/LocaleId')
            for path in expand(ctx,resource,base+'/Intents/*/Slots/*/MultipleValuesSetting/AllowMultipleValues'):
                raw=get(path);verdict='NEEDS_REVIEW'
                if raw is False:verdict='NOT_APPLICABLE'
                elif raw is True:
                    if locale=='en_US':verdict='PASS'
                    elif isinstance(locale,str) and re.fullmatch(r'[a-z]{2}_[A-Z]{2}',locale):verdict='FAIL'
                emit('LEX_MULTIVALUE_LOCALE',path,verdict,'true multivalue slots require en_US; compare with enclosing locale; unknown/noncanonical locale IDs and nonboolean values remain under review')
    return results
