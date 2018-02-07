#! /usr/bin/env python
# -*- coding:utf-8 -*-

from __future__ import unicode_literals
from __future__ import print_function

import os
import logging
from pwd import getpwnam

from .common import BASE_CGROUPS, CgroupsException

logger = logging.getLogger(__name__)


def get_user_info(user):
    try:
        user_system = getpwnam(user)
    except KeyError:
        raise CgroupsException("User %s doesn't exists" % user)
    else:
        uid = user_system.pw_uid
        gid = user_system.pw_gid
    return uid, gid


def create_user_cgroups(user, script=True):
    logger.info('Creating cgroups sub-directories for user %s' % user)
    # Get hierarchies and create cgroups sub-directories
    try:
        hierarchies = os.listdir(BASE_CGROUPS)
    except OSError as e:
        if e.errno == 2:
            raise CgroupsException(
                "cgroups filesystem is not mounted on %s" % BASE_CGROUPS)
        else:
            raise OSError(e)
    logger.debug('Hierarchies availables: %s' % hierarchies)
    for hierarchy in hierarchies:
        user_cgroup = os.path.join(BASE_CGROUPS, hierarchy, user)
        if not os.path.exists(user_cgroup):
            try:
                os.mkdir(user_cgroup)
            except OSError as e:
                if e.errno == 13:
                    if script:
                        raise CgroupsException(
                            "Permission denied, you don't have root privileges")
                    else:
                        raise CgroupsException(
                            "Permission denied. If you want to use cgroups " +
                            "without root priviliges, please execute first " +
                            "the 'user_cgroups' command (as root or sudo).")
                elif e.errno == 17:
                    pass
                else:
                    raise OSError(e)
            else:
                uid, gid = get_user_info(user)
                os.chown(user_cgroup, uid, gid)
    logger.warn('cgroups sub-directories created for user %s' % user)

