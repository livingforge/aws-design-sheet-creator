"""Checks for AWS::CodeBuild::ReportGroup."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CODEBUILD_REPORT_VALUES': [CF+'aws-resource-codebuild-reportgroup.html', CF+'aws-properties-codebuild-reportgroup-reportexportconfig.html', CF+'aws-properties-codebuild-reportgroup-s3reportexportconfig.html'],
}


@resource_check('AWS::CodeBuild::ReportGroup')
def evaluate_codebuild_report_values(design, resource):
    ctx = _Context(design, resource)
    results = []

    def emit(rule, path, verdict, reason):
        finding = ctx.finding(rule, path, verdict, reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)

    if resource.type == 'AWS::CodeBuild::ReportGroup':
        for suffix, allowed in (
            ('Type', ('TEST', 'CODE_COVERAGE')),
            ('ExportConfig/ExportConfigType', ('S3', 'NO_EXPORT')),
            ('ExportConfig/S3Destination/Packaging', ('ZIP', 'NONE')),
        ):
            path = '/properties/'+suffix
            raw = value(ctx, resource, path)
            if raw is ABSENT:
                continue
            verdict = 'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL'
            emit('CODEBUILD_REPORT_VALUES', path, verdict, 'checks documented literal enum only; required fields, export applicability and destination permissions remain separate')
    return results
