"""Finite number test."""
import math
from decimal import Decimal


def number(raw):
    if type(raw) not in (int,float) or (isinstance(raw,float) and not math.isfinite(raw)):return None
    return Decimal(str(raw))
