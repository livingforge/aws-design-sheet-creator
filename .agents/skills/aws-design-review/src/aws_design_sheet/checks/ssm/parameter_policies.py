"""Literal policy declarations, with example-only schema variants left open."""
import json
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

GUIDE='https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-policies.html'
API='https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_PutParameter.html'
SOURCES={rule:[GUIDE,API] for rule in ('SSM_POLICY_TYPE','SSM_POLICY_DOCUMENTED_SHAPE','SSM_POLICY_EXPIRATION_UNIQUE','SSM_POLICY_ADVANCED_TIER')}
ATTRIBUTES={'Expiration':{'Timestamp'},'ExpirationNotification':{'Before','Unit'},'NoChangeNotification':{'After','Unit'}}


def literal(value):
    return isinstance(value,str) and '{{' not in value and '${' not in value


@resource_check('AWS::SSM::Parameter')
def parameter_policies(design,resource):
    ctx=_Context(design,resource)
    path='/properties/Policies'
    raw=value(ctx,resource,path)
    if raw is ABSENT:return []
    duplicate=False
    def pairs(items):
        nonlocal duplicate
        result={}
        for key,val in items:
            duplicate |= key in result
            result[key]=val
        return result
    def invalid_constant(value):raise ValueError(value)
    parsed=None
    if literal(raw):
        try:parsed=json.loads(raw,object_pairs_hook=pairs,parse_constant=invalid_constant)
        except (ValueError,RecursionError):pass
    if duplicate or not isinstance(parsed,list):
        return [ctx.finding('SSM_POLICY_DOCUMENTED_SHAPE',path,'NEEDS_REVIEW',
            'policy JSON is unresolved, has duplicate object keys or is not an array; array syntax is checked separately')]
    if parsed==[] or parsed==[{}]:return []  # Empty/remove forms; no effective policy inferred.
    results=[]
    known_types=[]
    uncertain=False
    for i,policy in enumerate(parsed):
        item_path=path+f'/{i}'
        kind=policy.get('Type') if isinstance(policy,dict) else None
        recognized=literal(kind) and kind in ATTRIBUTES
        verdict='PASS' if recognized else 'FAIL' if literal(kind) else 'NEEDS_REVIEW'
        results.append(ctx.finding('SSM_POLICY_TYPE',item_path+'/Type',verdict,
            'Parameter Store supports Expiration, ExpirationNotification and NoChangeNotification'))
        if recognized:known_types.append(kind)
        else:uncertain=True
        verdict='NEEDS_REVIEW'
        if recognized and set(policy)=={'Type','Version','Attributes'} and policy['Version']=='1.0':
            attrs=policy['Attributes']
            if isinstance(attrs,dict) and set(attrs)==ATTRIBUTES[kind] and all(literal(v) for v in attrs.values()):
                if kind=='Expiration':
                    # Recognize the example's structure only; do not certify ISO grammar or dates.
                    verdict='PASS' if attrs['Timestamp'] else 'NEEDS_REVIEW'
                else:
                    amount=attrs['Before' if kind=='ExpirationNotification' else 'After']
                    if re.fullmatch(r'[0-9]{1,12}',amount) and attrs['Unit'] in ('Days','Hours'):
                        verdict='PASS'
        results.append(ctx.finding('SSM_POLICY_DOCUMENTED_SHAPE',item_path,verdict,
            'matches the documented Version 1.0 object/attribute shape only; other versions/attributes, duration bounds and timestamp validity require review'))
    count=known_types.count('Expiration')
    results.append(ctx.finding('SSM_POLICY_EXPIRATION_UNIQUE',path,
        'FAIL' if count>1 else 'NEEDS_REVIEW' if uncertain else 'PASS',
        'a parameter cannot have two Expiration policies; other policy compatibility is checked separately'))
    tier=value(ctx,resource,'/properties/Tier')
    verdict='NEEDS_REVIEW'
    if known_types:
        verdict='FAIL' if tier=='Standard' else 'PASS' if tier in ('Advanced','Intelligent-Tiering') else 'NEEDS_REVIEW'
    results.append(ctx.finding('SSM_POLICY_ADVANCED_TIER','/properties/Tier',verdict,
        'effective policies require advanced parameters; Intelligent-Tiering selects advanced when a policy is present, and omitted account defaults remain unknown'))
    return results
