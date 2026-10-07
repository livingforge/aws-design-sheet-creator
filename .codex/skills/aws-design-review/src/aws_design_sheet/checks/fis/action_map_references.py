"""Checks for AWS::FIS::ExperimentTemplate."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'FIS_ACTION_MAP_REFERENCES': [CF+'aws-properties-fis-experimenttemplate-experimenttemplateaction.html','https://docs.aws.amazon.com/fis/latest/userguide/action-sequence.html'],
}


def fis_references(ctx,resource):
    actions = value(ctx,resource,'/properties/Actions')
    targets = value(ctx,resource,'/properties/Targets')
    def known_map(raw):
        return isinstance(raw,dict) and len(raw)<=1000 and all(literal(k) and "/" not in k and "~" not in k for k in raw)
    if not known_map(actions):
        return 'NEEDS_REVIEW'
    pending = False
    invalid = False
    def escape(s):
        return s.replace('~','~0').replace('/','~1')
    for name in actions:
        base = '/properties/Actions/'+escape(name)
        if not isinstance(value(ctx,resource,base),dict):
            pending = True
            continue
        after = value(ctx,resource,base+'/StartAfter')
        if after is not ABSENT:
            if not isinstance(after,list) or len(after)>1000:
                pending = True
            else:
                for i in range(len(after)):
                    ref = value(ctx,resource,base+'/StartAfter/'+str(i))
                    if not literal(ref):pending = True
                    elif ref not in actions or ref==name:invalid = True
        assigned = value(ctx,resource,base+'/Targets')
        if assigned is not ABSENT:
            if not known_map(assigned):
                pending = True
            else:
                for key in assigned:
                    ref = value(ctx,resource,base+'/Targets/'+escape(key))
                    if not literal(ref) or not known_map(targets):pending = True
                    elif ref not in targets:invalid = True
    return 'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS'


@resource_check('AWS::FIS::ExperimentTemplate')
def evaluate_fis_action_map_references(design,resource):
    ctx = _Context(design,resource)
    results = []
    def emit(rule,path,verdict,reason):
        finding = ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    if resource.type == 'AWS::FIS::ExperimentTemplate' and value(ctx,resource,'/properties/Actions') is not ABSENT:
        emit('FIS_ACTION_MAP_REFERENCES','/properties/Actions',fis_references(ctx,resource),'explicit StartAfter names must refer to other actions and target values to top-level target keys; bounded map traversal; slash/tilde keys held; multi-action cycles, action catalogs and target contents remain separate')
    return results
