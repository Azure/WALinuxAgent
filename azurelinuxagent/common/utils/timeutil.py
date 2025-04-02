# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.

# This format is based on ISO-8601, with Z representing UTC (Zero offset)
UTCTimestampFormat = u'%Y-%m-%dT%H:%M:%S.%fZ'


def create_utc_timestamp(dt):
    """
    Returns a string with the given datetime formatted according to UTCTimestampFormat.
    """
    return dt.strftime(UTCTimestampFormat)

