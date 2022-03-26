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
