"""IANA time zone names from the pinned tzdata package."""
from functools import lru_cache
from importlib.resources import files


@lru_cache(maxsize=1)
def timezone_names():
    try:
        import tzdata
        if tzdata.__version__ != '2026.4':
            return None
        return frozenset(files('tzdata').joinpath('zones').read_text(encoding='utf-8').splitlines())
    except (ImportError, OSError):
        return None
