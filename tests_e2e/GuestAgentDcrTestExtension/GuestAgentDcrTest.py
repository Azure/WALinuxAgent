#!/usr/bin/env python
from __future__ import print_function

from Utils.WAAgentUtil import waagent
import Utils.HandlerUtil as Util
import sys
import re
import traceback
import os
import datetime

ExtensionShortName = "GADcrTestExt"
OperationFileName = "operations-{0}.log"


def install():
    operation = "install"
    status = "success"
    msg = "Installed successfully"

    hutil = parse_context(operation)
    hutil.log("Start to install.")
    hutil.log(msg)
    hutil.do_exit(0, operation, status, '0', msg)


def enable():
    # Global Variables definition
    operation = "enable"
    status = "success"
    msg = "Enabled successfully."

    # Operations.append(operation)
    hutil = parse_context(operation)
    hutil.log("Start to enable.")
    public_settings = hutil.get_public_settings()
    name = public_settings.get("name")
    if name:
        name = "Name: {0}".format(name)
        hutil.log(name)
        msg = "{0} {1}".format(msg, name)
        print(name)
    else:
        hutil.error("The name in public settings is not provided.")
    # msg = msg % ','.join(Operations)
    hutil.log(msg)
    hutil.do_exit(0, operation, status, '0', msg)


def disable():
    operation = "disable"
    status = "success"
    msg = "Disabled successfully."

    # Operations.append(operation)
    hutil = parse_context(operation)
    hutil.log("Start to disable.")
    # msg % ','.join(Operations)
    hutil.log(msg)
    hutil.do_exit(0, operation, status, '0', msg)


def uninstall():
    operation = "uninstall"
    status = "success"
    msg = "Uninstalled successfully."

    # Operations.append(operation)
    hutil = parse_context(operation)
    hutil.log("Start to uninstall.")
    # msg % ','.join(Operations)
    hutil.log(msg)
    hutil.do_exit(0, operation, status, '0', msg)


def update():
    operation = "update"
    status = "success"
    msg = "Updated successfully."

    # Operations.append(operation)
    hutil = parse_context(operation)
    hutil.log("Start to update.")
    # msg % ','.join(Operations)
    hutil.log(msg)
    hutil.do_exit(0, operation, status, '0', msg)


def parse_context(operation):
    hutil = Util.HandlerUtility(waagent.Log, waagent.Error)
    hutil.do_parse_context(operation)
    op_log = os.path.join(hutil.get_log_dir(), OperationFileName.format(hutil.get_extension_version()))
    with open(op_log, 'a+') as oplog_handler:
        oplog_handler.write("Date:{0}; Operation:{1}; SeqNo:{2}\n"
                            .format(datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                                    operation, hutil.get_seq_no()))
    return hutil


def main():
    waagent.LoggerInit('/var/log/waagent.log', '/dev/stdout')
    waagent.Log("%s started to handle." % (ExtensionShortName))

    try:
        for a in sys.argv[1:]:
            if re.match("^([-/]*)(disable)", a):
                disable()
            elif re.match("^([-/]*)(uninstall)", a):
                uninstall()
            elif re.match("^([-/]*)(install)", a):
                install()
            elif re.match("^([-/]*)(enable)", a):
                enable()
            elif re.match("^([-/]*)(update)", a):
                update()
    except Exception as e:
        err_msg = "Failed with error: {0}, {1}".format(e, traceback.format_exc())
        waagent.Error(err_msg)


if __name__ == '__main__':
    main()
