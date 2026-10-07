"""Rejection of constant JSON values that the services do not accept."""


def reject_constant(value):
    raise ValueError(value)
