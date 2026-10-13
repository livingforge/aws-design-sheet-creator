"""AWS account ID evidence from explicit values and linked resources."""
import re
from .literals import literal


def account_id(raw):
    if not literal(raw):return 'NEEDS_REVIEW'
    return 'PASS' if re.fullmatch(r'[0-9]{12}',raw) else 'FAIL'
