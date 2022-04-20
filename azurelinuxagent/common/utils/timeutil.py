# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
import datetime


def create_timestamp(dt=None, timespec='auto'):
    """
    Returns a string with the given datetime in iso format. If no datetime is given as parameter, it
    uses datetime.utcnow(). The 'timespec' parameter is passed as argument to datetime.isoformat()
    """
    if dt is None:
        dt = datetime.datetime.utcnow()
    return dt.isoformat(timespec=timespec)


def create_history_timestamp(dt=None):
    """
    Returns a string with the given datetime formatted as a timestamp for the agent's history folder
    """
    if dt is None:
        dt = datetime.datetime.utcnow()
    return dt.isoformat(timespec='seconds').replace(":", "-")


def datetime_to_ticks(dt):
    """
    Converts 'dt', a datetime, to the number of ticks (1 tick == 1/10000000 sec) since datetime.min (0001-01-01 00:00:00).

    Note that the resolution of a datetime goes only to microseconds.
    """
    return int(10 ** 7 * total_seconds(dt - datetime.datetime.min))


def total_seconds(dt):
    """
    Compute the total_seconds for timedelta 'td'. Used instead timedelta.total_seconds() because 2.6 does not implement total_seconds.
    """
    return ((24.0 * 60 * 60 * dt.days + dt.seconds) * 10 ** 6 + dt.microseconds) / 10 ** 6

