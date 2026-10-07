"""Decimal-precision helpers for Greengrass and IoT job values."""
from decimal import Decimal


def decimal_places(raw,places):
    if type(raw) not in (int,float) or not -10**12<=raw<=10**12:
        return 'NEEDS_REVIEW'
    # Interpret the serialized decimal number, not its binary float expansion.
    number=Decimal(str(raw)).normalize()
    return 'PASS' if number.as_tuple().exponent>=-places else 'FAIL'
