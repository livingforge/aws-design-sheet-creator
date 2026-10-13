"""Checks for AWS::Lambda::Function."""
import io
import zipfile
from ..registry import resource_check
from ..common.artifact_values import value
from ..common.context_values import CFN, _Context
from ..common.field_reads import ABSENT

SOURCES = {
    'LAMBDA_INLINE_ZIP_ESTIMATE': [CFN + 'aws-properties-lambda-function-code.html'],
}


@resource_check('AWS::Lambda::Function')
def inline_zip(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/Code/ZipFile'
    content = value(ctx, resource, path)
    if content is ABSENT:
        return []
    verdict = 'NEEDS_REVIEW'
    if isinstance(content, str):
        try:
            # CloudFormation's compression settings are unspecified. This is
            # an advisory estimate, never an ERROR about the deployment archive.
            data = io.BytesIO()
            with zipfile.ZipFile(data, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('index.py', content.encode('utf-8'))
            verdict = 'PASS' if data.tell() <= 4 * 1024 * 1024 else 'FAIL'
        except UnicodeError:
            verdict = 'NEEDS_REVIEW'
    return [{**ctx.finding('LAMBDA_INLINE_ZIP_ESTIMATE', path, verdict,
        'local DEFLATE ZIP estimate against 4 MiB; CloudFormation archive settings and MB unit are unspecified, so verify the actual deployment package'),
        'severity': 'WARNING'}]
