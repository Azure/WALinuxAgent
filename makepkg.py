#!/usr/bin/env python

import glob
import os
import os.path
import shutil
import subprocess
import sys

from azurelinuxagent.common.version import AGENT_NAME, AGENT_VERSION, \
    AGENT_LONG_VERSION
from azurelinuxagent.ga.update import AGENT_MANIFEST_FILE

MANIFEST = '''[{{
    "name": "{0}",
    "version": 1.0,
    "handlerManifest": {{
        "installCommand": "",
        "uninstallCommand": "",
        "updateCommand": "",
        "enableCommand": "python -u {1} -run-exthandlers",
        "disableCommand": "",
        "rebootAfterInstall": false,
        "reportHeartbeat": false
    }}
}}]'''

PUBLISH_MANIFEST = '''<?xml version="1.0" encoding="utf-8" ?>
<ExtensionImage xmlns="http://schemas.microsoft.com/windowsazure"  xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
  <!-- WARNING: Ordering of fields matter in this file. -->
  <ProviderNameSpace>Microsoft.OSTCLinuxAgent</ProviderNameSpace>
  <Type>{1}</Type>
  <Version>{0}</Version>
  <Label>Microsoft Azure Guest Agent for Linux IaaS</Label>
  <HostingResources>VmRole</HostingResources>
  <MediaLink></MediaLink>
  <Description>Microsoft Azure Guest Agent for Linux IaaS</Description>
  <IsInternalExtension>true</IsInternalExtension>
  <Eula>https://github.com/Azure/WALinuxAgent/blob/2.1/LICENSE.txt</Eula>
  <PrivacyUri>https://github.com/Azure/WALinuxAgent/blob/2.1/LICENSE.txt</PrivacyUri>
  <HomepageUri>https://github.com/Azure/WALinuxAgent</HomepageUri>
  <IsJsonExtension>true</IsJsonExtension>
  <CompanyName>Microsoft</CompanyName>
  <SupportedOS>Linux</SupportedOS>
  <!--%REGIONS%-->
</ExtensionImage>
'''

PUBLISH_MANIFEST_FILE = 'manifest.xml'

output_path = os.path.join(os.getcwd(), "eggs")
target_path = os.path.join(output_path, AGENT_LONG_VERSION)
bin_path = os.path.join(target_path, "bin")
egg_path = os.path.join(bin_path, AGENT_LONG_VERSION + ".egg")
manifest_path = os.path.join(target_path, AGENT_MANIFEST_FILE)
publish_manifest_path = os.path.join(target_path, PUBLISH_MANIFEST_FILE)
pkg_name = os.path.join(output_path, AGENT_LONG_VERSION + ".zip")

family = 'Test'
if len(sys.argv) > 1:
    family = sys.argv[1]

def do(*args):
    try:
        subprocess.check_output(args, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print("ERROR: {0}".format(str(e)))
        print("\t{0}".format(" ".join(args)))
        print(e.output)
        sys.exit(1)


if os.path.isdir(target_path):
    shutil.rmtree(target_path)
elif os.path.isfile(target_path):
    os.remove(target_path)
if os.path.isfile(pkg_name):
    os.remove(pkg_name)
os.makedirs(bin_path)
print("Created {0} directory".format(target_path))

args = ["python", "setup.py", "bdist_egg", "--dist-dir={0}".format(bin_path)]

print("Creating egg {0}".format(egg_path))
do(*args)

egg_name = os.path.join("bin", os.path.basename(
    glob.glob(os.path.join(bin_path, "*"))[0]))

print("Writing {0}".format(manifest_path))
with open(manifest_path, mode='w') as manifest:
    manifest.write(MANIFEST.format(AGENT_NAME, egg_name))

print("Writing {0}".format(publish_manifest_path))
with open(publish_manifest_path, mode='w') as publish_manifest:
    publish_manifest.write(PUBLISH_MANIFEST.format(AGENT_VERSION,
                                                   family))


cwd = os.getcwd()
os.chdir(target_path)
print("Creating package {0}".format(pkg_name))
do("zip", "-r", pkg_name, egg_name)
do("zip", "-j", pkg_name, AGENT_MANIFEST_FILE)
do("zip", "-j", pkg_name, PUBLISH_MANIFEST_FILE)
os.chdir(cwd)

print("Package {0} successfully created".format(pkg_name))
sys.exit(0)
