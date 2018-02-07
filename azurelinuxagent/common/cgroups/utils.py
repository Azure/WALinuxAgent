#! /usr/bin/env python
# -*- coding:utf-8 -*-

from __future__ import unicode_literals
from __future__ import print_function

import os
import getpass

BASE_CGROUPS_DIR = '/sys/fs/cgroup'

CGROUPS_DIRS = [
    'cpu',
    'memory',
]

def get_user_cgroups():
    user = getpass.getuser()
    user_cgroups = {}
    for cgroup in CGROUPS_DIRS:
        user_cgroup = os.path.join(BASE_CGROUPS_DIR, cgroup, user)
        # if not os.path.exists(user_cgroup):
        #     os.mkdir(user_cgroup)
        user_cgroups[cgroup] = user_cgroup
    return user_cgroups
