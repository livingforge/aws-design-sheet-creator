"""Field-index document constraints explicitly stated by PutAccountPolicy."""
from ..common.field_reads import UNKNOWN

URL='https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutAccountPolicy.html'
SOURCES={rule:[URL] for rule in ('LOGS_INDEX_POLICY_MINIMUM','LOGS_INDEX_POLICY_FIELDS_EXCLUSIVE','LOGS_INDEX_POLICY_FIELD_TYPE')}


def field_name(raw):
    return isinstance(raw,str) and bool(raw) and not any(token in raw for token in ('${','{{'))


def index_policy(ctx,path,body):
    fields=body.get('Fields',[]) if isinstance(body,dict) else UNKNOWN
    v2=body.get('FieldsV2',{}) if isinstance(body,dict) else UNKNOWN
    if isinstance(v2,dict) and any(k.startswith('Fn::') or k in ('Ref','$state') for k in v2):
        v2=UNKNOWN
    known=isinstance(body,dict) and set(body)<= {'Fields','FieldsV2'} and isinstance(fields,list) and isinstance(v2,dict)
    left=[name for name in fields if field_name(name)] if isinstance(fields,list) else []
    right=[name for name in v2 if field_name(name)] if isinstance(v2,dict) else []
    complete=known and len(left)==len(fields) and len(right)==len(v2)
    minimum='PASS' if left or right else 'FAIL' if complete else 'NEEDS_REVIEW'
    exclusive='FAIL' if set(left)&set(right) else 'PASS' if complete else 'NEEDS_REVIEW'
    rows=[ctx.finding('LOGS_INDEX_POLICY_MINIMUM',path,minimum,'a field index policy must declare at least one index; unresolved or future document shapes need review'),
          ctx.finding('LOGS_INDEX_POLICY_FIELDS_EXCLUSIVE',path,exclusive,'field names in Fields and FieldsV2 must be mutually exclusive; field-name validity is separate')]
    for name in right:
        config=v2[name]
        kind=config.get('type') if isinstance(config,dict) else None
        verdict='PASS' if kind in ('FIELD_INDEX','FACET') else 'FAIL' if isinstance(kind,str) and '${' not in kind and '{{' not in kind else 'NEEDS_REVIEW'
        if isinstance(config,dict) and any(k.startswith('Fn::') or k in ('Ref','$state') for k in config):verdict='NEEDS_REVIEW'
        rows.append(ctx.finding('LOGS_INDEX_POLICY_FIELD_TYPE',path+'/FieldsV2/'+name.replace('~','~0').replace('/','~1')+'/type',verdict,
            'FieldsV2 types are FIELD_INDEX or FACET; unresolved type expressions require review'))
    return rows
