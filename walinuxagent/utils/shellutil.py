# Windows Azure Linux Agent
#
# Copyright 2014 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Requires Python 2.4+ and Openssl 1.0+
#

import platform
import os
import subprocess
import walinuxagent.logger as logger

"""
Shell command util functions
"""
def Run(cmd, chk_err=True):
    """
    Calls RunGetOutput on 'cmd', returning only the return code.
    If chk_err=True then errors will be reported in the log.
    If chk_err=False then errors will be suppressed from the log.
    """
    retcode,out=RunGetOutput(cmd,chk_err)
    return retcode

def RunGetOutput(cmd, chk_err=True):
    """
    Wrapper for subprocess.check_output.
    Execute 'cmd'.  Returns return code and STDOUT, trapping expected exceptions.
    Reports exceptions to Error if chk_err parameter is True
    """
    logger.Verbose("Run cmd '{0}'", cmd)
    try:                                     
        output=subprocess.check_output(cmd,stderr=subprocess.STDOUT,shell=True)
    except subprocess.CalledProcessError,e :
        if chk_err :
            logger.Error("Run cmd '{0}' failed", e.cmd)
            logger.Error("Error Code:{0}", e.returncode)
            logger.Error("Result:{0}", e.output[:-1].decode('latin-1'))
        return e.returncode, e.output.decode('latin-1')
    return 0, output

def RunSendStdin(cmd, input, chk_err=True):
    """
    Wrapper for subprocess.Popen.
    Execute 'cmd', sending 'input' to STDIN of 'cmd'.
    Returns return code and STDOUT, trapping expected exceptions.
    Reports exceptions to Error if chk_err parameter is True
    """
    logger.Verbose("Run cmd '{0}'", cmd)
    try:                                     
        me=subprocess.Popen([cmd], shell=True, stdin=subprocess.PIPE,
                            stderr=subprocess.STDOUT,stdout=subprocess.PIPE)
        output=me.communicate(input)
    except OSError , e :
        if chk_err :
            logger.Error("Run cmd '{0}' failed", e.cmd)
            logger.Error("Error Code:{0}", e.returncode)
            logger.Error("Result:{0}", e.output[:-1].decode('latin-1'))
        return e.returncode, e.output.decode('latin-1')
    if me.returncode is not 0 and chk_err is True:
        logger.Error("Run cmd '{0}' failed", cmd)
        logger.Error("Error Code:{0}", me.returncode)
        logger.Error("Result:{0}", output[0].decode('latin-1'))
    return me.returncode, output[0].decode('latin-1')

#End shell command util functions
