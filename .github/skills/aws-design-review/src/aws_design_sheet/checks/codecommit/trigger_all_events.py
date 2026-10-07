"""Checks for AWS::CodeCommit::Repository."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CODECOMMIT_TRIGGER_ALL_EVENTS': [CF+'aws-properties-codecommit-repository-repositorytrigger.html'],
}


@resource_check('AWS::CodeCommit::Repository')
def evaluate_codecommit_trigger_all_events(design, resource):
    ctx = _Context(design, resource)
    results = []

    def emit(rule, path, verdict, reason):
        finding = ctx.finding(rule, path, verdict, reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)

    if resource.type == 'AWS::CodeCommit::Repository':
        for path in expand(ctx, resource, '/properties/Triggers/*/Events'):
            raw = value(ctx, resource, path)
            entries = [value(ctx, resource, path+'/'+str(i)) for i in range(len(raw))] if isinstance(raw, list) else []
            known = [entry for entry in entries if literal(entry)]
            conflict = 'all' in known and any(entry != 'all' for entry in known)
            pending = not isinstance(raw, list) or len(known) != len(entries)
            # Repeated 'all' has no other value; duplicate policy is separate.
            verdict = 'FAIL' if conflict else 'NEEDS_REVIEW' if pending else 'PASS'
            emit('CODECOMMIT_TRIGGER_ALL_EVENTS', path, verdict, 'checks all versus other values across the complete events array; duplicate validity, allowed events and required fields remain separate')
    return results
