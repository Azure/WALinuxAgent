# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
import datetime


def create_timestamp():
    """
    Returns a string with current UTC time in iso format
    """
    return datetime.datetime.utcnow().isoformat()


def create_null_timestamp():
    return "0000-00-00T00:00:00.000000"


def datetime_to_ticks(dt):
    """
    Converts 'dt', a datetime, to the number of ticks (1 tick == 1/10000000 sec) since datetime.min (0001-01-01 00:00:00).

    Note that the resolution of a datetime goes only to microseconds.
    """
    return 10 ** 7 * (dt - datetime.datetime.min).total_seconds()
