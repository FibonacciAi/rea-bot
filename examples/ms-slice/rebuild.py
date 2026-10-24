"""Finite duration slice for parity cases against the published `ms` package.

A year is 365.25 days. Rounding matches JavaScript Math.round (half toward +infinity).
This is not a full port.
"""
import math
import re

_S = 1000
_M = _S * 60
_H = _M * 60
_D = _H * 24
_W = _D * 7
_Y = _D * 365.25

_PARSE = re.compile(
    r'^(-?(?:\d+)?\.?\d+) *(milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)?$',
    re.IGNORECASE)


def _round(value):
    return math.floor(value + 0.5)


def _whole(value):
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _scale(unit):
    return {
        'y': _Y, 'yr': _Y, 'yrs': _Y, 'year': _Y, 'years': _Y,
        'w': _W, 'week': _W, 'weeks': _W,
        'd': _D, 'day': _D, 'days': _D,
        'h': _H, 'hr': _H, 'hrs': _H, 'hour': _H, 'hours': _H,
        'm': _M, 'min': _M, 'mins': _M, 'minute': _M, 'minutes': _M,
        's': _S, 'sec': _S, 'secs': _S, 'second': _S, 'seconds': _S,
        'ms': 1, 'msec': 1, 'msecs': 1, 'millisecond': 1, 'milliseconds': 1,
    }[unit]


def parse_duration(text):
    if len(text) > 100:
        return None
    match = _PARSE.fullmatch(text)
    if not match:
        return None
    number = float(match.group(1))
    unit = (match.group(2) or 'ms').lower()
    return _whole(number * _scale(unit))


def format_short(value):
    absolute = abs(value)
    if absolute >= _D:
        return str(_round(value / _D)) + 'd'
    if absolute >= _H:
        return str(_round(value / _H)) + 'h'
    if absolute >= _M:
        return str(_round(value / _M)) + 'm'
    if absolute >= _S:
        return str(_round(value / _S)) + 's'
    return str(value) + 'ms'


def format_long(value):
    absolute = abs(value)
    for size, name in ((_D, 'day'), (_H, 'hour'), (_M, 'minute'), (_S, 'second')):
        if absolute >= size:
            count = _round(value / size)
            plural = absolute >= size * 1.5
            return str(count) + ' ' + name + ('s' if plural else '')
    return str(value) + ' ms'


def convert(val, long=False):
    if isinstance(val, str) and val:
        return parse_duration(val)
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise ValueError('not a duration')
    if isinstance(val, float) and (val != val or abs(val) == float('inf')):
        raise ValueError('not a duration')
    return format_long(val) if long else format_short(val)
