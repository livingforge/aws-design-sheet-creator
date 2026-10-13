"""Literal field/index JSONPath subset, without evaluating any payload."""
import re

STEP = r'(?:\.[A-Za-z_][A-Za-z0-9_]*|\[(?:0|[1-9][0-9]*)\])'


def literal_path_suffix(suffix):
    return isinstance(suffix, str) and len(suffix) <= 4096 and re.fullmatch(STEP + '*', suffix) is not None


def prohibited_http_selector(suffix):
    # Only inspect operators after proven steps. Punctuation inside unparsed
    # quoted keys is not a recursive-descent/filter operator.
    return (isinstance(suffix, str) and len(suffix) <= 4096
            and re.match('^' + STEP + r'*(?:\.\.|\[\?\()', suffix) is not None)
