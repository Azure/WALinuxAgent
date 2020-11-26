#######################################################################
# check_debian_plain - if distro appears to be debian, re-check
# to see if it's actually devuan
#######################################################################
# 2020-10-21 : changes to fix travis build failures
#######################################################################
import sys
import platform
import os
import re
# need io for file read compatibility between python v2 and v3
import io
# for some reason this breaks travis builds (works in local builds)
# move to inside check_debian_plain() - seems to work then.
# from azurelinuxagent.common import logger

def check_debian_plain(distinfo={}):
# objectives:
#   - figure out whether we're in debian or devuan
#   - python-version-agnostic
#   - only use basic python facilities (as few
#     external modules/libraries as possible
# modus operandi:
# - if anything goes wrong
#     just return what we were given
# - if platform.linux_distribution has been run,
#     pass the info via distinfo
# - first read /etc/issue to get the dist id
# - read /etc/apt/sources.list:
#   - find the first non-commented line
#   - construct the base filename for the list
#   - search in /var/lib/apt/lists for [base_filename]*Release
#     (Q: why _Release in debian and _InRelease in devuan?)
#   - take the first file found
#   - extract the required info from the top of the file
# TODO:
#   - what if we can't find the files? Need to return something
#     which won't break what comes after.
#   - possible problem with initial-capitalization of ID
#     for now, stick with whatever we get from the files (which
#     in itself is inconsistent)
#   - general robustification:
#     - dodge cdrom lines in /etc/apt/sources.list
#     - pre-check existence of all files which we need to use
#       (don't assume anything)
#     - figure out how to report an error (waagent has a module to do this)
#   - need to figure out how to alert to / log an error condition
######################################################################
#  moving logger import here (travis build problem otherwise)
    import azurelinuxagent.common.logger as logger
    logger.info("check_debian_plain: entered")
    localdistinfo={
        'ID' : '',
        'RELEASE' : '',
        'CODENAME' : '',
        'DESCRIPTION' : '',
    }
# copy in any data which have already been ascertained:
    for k in localdistinfo.keys():
        if k in distinfo:
            logger.info("check_debian_plain: distinfo."+k+"="+distinfo[k])
#           localdistinfo['ID']=distinfo[k]
# fixed bug in above line:
            localdistinfo[k]=distinfo[k]
    aptdir="/var/lib/apt/lists/"
# (Original intention was to get distid from /etc/issue - but it was
# decided that /etc/dpkg/origins/default would be safer)
    distid=""
#
# 1) Get the distribution ID from /etc/dpkg/origins/default
#
    if not os.path.isfile("/etc/dpkg/origins/default"):
# can't find the file - give up
# (REVISIT: need to report an error here?)
        return localdistinfo
#   originsfile=open("/etc/dpkg/origins/default","r")
# use io.open() for python v2/v3 compatibility:
    originsfile=io.open("/etc/dpkg/origins/default","r")
    sline=""
    for line in originsfile:
        if re.search("^Vendor:",line):
            sline=line
            break
    sline=sline.strip()
    if sline=="":
# didn't find a "Vendor:" line - give up
        logger.error("check_debian_plain: did not find a vendor")
        return localdistinfo
    originsfile.close()
    distid=sline.split()[1]
    logger.info("check_debian_plain: distid="+distid)
#
# 2) Get the release file from /etc/apt/sources.list
# (use the first line starting with "deb")
#
    if not os.path.isfile("/etc/apt/sources.list"):
# no sources.list file - just return what we were given
#
        logger.error("check_debian_plain: WARNING: did not find sources.list file")
        return localdistinfo
# FIXME: some tests throw up "unclosed file" warnings here. Apparently,
# in python3, this use of open() is deprecated in favour of "with ..."
# substitute io.open() for open() to give python v2/v3 compatibility:
#   slfile=open("/etc/apt/sources.list","r")
    slfile=io.open("/etc/apt/sources.list","r")
    sline=""
    for line in slfile:
# skip lines relating to a cdrom
        if re.search("cdrom:",line):
            continue
# NB following will only work for non-commented lines:
        if re.search("^deb",line):
            sline=line
            break

#   slfile.close
#  fix missing parentheses after above call
# (why was a syntax error not being flagged up for this?)
# Maybe this will fix the unclosed file error?
    slfile.close()
    sline=sline.strip();
    if sline=="":
# couldn't find an appropriate line - give up
        logger.error("check_debian_plain: unable to find useful line in sources.list")
        return localdistinfo
#   deb,url,codename,domain=sline.split(' ')
# Above breaks travis test - apparently because travis runs under ubuntu
# xenial, and the lines in the sources.list file have more fields than
# under devuan.
# Make the parsing more robust:
    tokenlist=sline.split(' ')
    url=tokenlist[1]
    codename=tokenlist[2]
    domain=tokenlist[3]
# extract the host and dir from the url:
    parts=re.search('^http:\/\/(.*?)\/(.*)',url)
    host=parts.group(1)
    section=parts.group(2)
    if re.search('\/$',section):
        section=section[:-1]
# assemble the speculative filename
# apparently if it's devuan, the file will end in _InRelease,
# if debian, _Release. Currently unsure why.
#
# 3) Get the release from the apt list file
#
    filename=host+'_'+section+'_dists_'+codename+'_'
    if distid=="Devuan":
        filename=filename+'InRelease'
    else:
        filename=filename+'Release'
# initialise version before the following condition - avoid possibility
# of trying to use it uninitialised
    version=""
    if os.path.isfile(aptdir+filename):
# now examine the file to get the release.
# Should be in the first few lines - need a test to avoid having
# to rummage needlessly through what might be a very big file:
# - once we've got the line starting "Version:" - stop reading
# - if we see a line which ends with "Packages" - stop reading
# REVISIT: this test may not work in all cases.
        relfile=open(aptdir+filename,"r")
        for line in relfile:
            if re.search('Packages$',line):
                break
            parts = re.search('Version: (.*)',line)
            if parts:
                version=parts.group(1)
                break
        relfile.close()
        if version == "":
            logger.error("check_debian_plain: unable to find version")
        else:
            logger.info("check_debian_plain: Version = '"+version+"'")
    else:
#       logger.error("check_debian_plain: cannot find file "+relfile)
# fixed bug in above - trying to output a file handle
        logger.error("check_debian_plain: cannot find file ",aptdir+filename)
#  Update localdistinfo with the results found:
#  REVISIT: what if our search didn't retrieve information, and
#  a key in distinfo was already populated?
    localdistinfo['ID']=distid
    localdistinfo['RELEASE']=version
    localdistinfo['CODENAME']=codename
    localdistinfo['DESCRIPTION']=distid+' GNU/Linux '+version+' ('+codename+')'
    return localdistinfo

def test():
# need to do this using the actual output from platform.linux_distribution
    distinfo_proto={
        'ID' : "",
        'RELEASE' : "",
        'CODENAME' : "",
    }
# (format of result is (distname,version,id))
# NB: platform.linux_distribution is deprecated (and will be removed in
# python 3.8. Suggestion is to use the distro package)
    platforminfo=platform.linux_distribution()
    print("platforminfo:")
    print(platforminfo)
# if we got anything vaguely useful, copy it into distinfo_proto
    if platforminfo[0]!='':
        distinfo_proto['ID']=platforminfo[0]
    if platforminfo[1]!='':
        distinfo_proto['RELEASE']=platforminfo[1]
# what about the third element?
    print("(before ***** start ******)")
    print(distinfo_proto)
    print("(before ***** end ******)")
# NB: for actual use, we can construct the dictionary in the
# function call (no need to use a pre-constructed dictionary)
    distinfo_actual=check_debian_plain(distinfo_proto)
    print("(after ***** start ******)")
    print(distinfo_actual)
    print("(after ***** end ******)")

if __name__ == "__main__":
    test()
