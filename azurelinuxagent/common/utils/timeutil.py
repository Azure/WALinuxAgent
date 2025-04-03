# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.

import datetime

def create_utc_timestamp(dt):
    """
    Formats the given datetime, which must be timezone-aware and in UTC, as "YYYY-MM-DDTHH:MM:SS.ffffffZ".
    This is basically ISO-8601, but using "Z" (Zero offset) to represent the timezone offset (instead of "+00:00").
    The corresponding format for strftime/strptime is "%Y-%m-%dT%H:%M:%S.%fZ".
    """
    if dt.tzinfo is None:
        raise ValueError("The datetime must be timezone-aware")
    if dt.utcoffset() != datetime.timedelta(0):
        raise ValueError("The datetime must be in UTC")

    # We use isoformat() instead of strftime() since the later is limited to years >= 1900 in Python < 3.2.  We remove the
    # timezone information since we are using "Z" to represent UTC, and we force the microseconds to be 000000 when it is 0.
    return dt.replace(tzinfo=None).isoformat() + (".000000Z" if dt.microsecond == 0 else "Z")

