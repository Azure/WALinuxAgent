#!/usr/bin/env python3

import argparse
import glob
import logging
import os.path
import shutil
import subprocess
import sys

from azurelinuxagent.common.version import AGENT_NAME, AGENT_VERSION, \
    AGENT_LONG_VERSION
from azurelinuxagent.ga.guestagent import AGENT_MANIFEST_FILE

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


def do(*args):
    try:
        return subprocess.check_output(args, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:  # pylint: disable=C0103
        raise Exception("[{0}] failed:\n{1}\n{2}".format(" ".join(args), str(e), e.output))


def run(agent_family, output_directory, log):
    output_path = os.path.join(output_directory, "eggs")
    target_path = os.path.join(output_path, AGENT_LONG_VERSION)
    bin_path = os.path.join(target_path, "bin")
    egg_path = os.path.join(bin_path, AGENT_LONG_VERSION + ".egg")
    manifest_path = os.path.join(target_path, AGENT_MANIFEST_FILE)
    publish_manifest_path = os.path.join(target_path, PUBLISH_MANIFEST_FILE)
    pkg_name = os.path.join(output_path, AGENT_LONG_VERSION + ".zip")

    if os.path.isdir(target_path):
        shutil.rmtree(target_path)
    elif os.path.isfile(target_path):
        os.remove(target_path)
    if os.path.isfile(pkg_name):
        os.remove(pkg_name)
    os.makedirs(bin_path)
    log.info("Created {0} directory".format(target_path))

    setup_path = os.path.join(os.path.dirname(__file__), "setup.py")
    args = ["python3", setup_path, "bdist_egg", "--dist-dir={0}".format(bin_path)]

    log.info("Creating egg {0}".format(egg_path))
    do(*args)

    egg_name = os.path.join("bin", os.path.basename(
        glob.glob(os.path.join(bin_path, "*"))[0]))

    log.info("Writing {0}".format(manifest_path))
    with open(manifest_path, mode='w') as manifest:
        manifest.write(MANIFEST.format(AGENT_NAME, egg_name))

    log.info("Writing {0}".format(publish_manifest_path))
    with open(publish_manifest_path, mode='w') as publish_manifest:
        publish_manifest.write(PUBLISH_MANIFEST.format(AGENT_VERSION, agent_family))

    cwd = os.getcwd()
    os.chdir(target_path)
    try:
        log.info("Creating package {0}".format(pkg_name))
        do("zip", "-r", pkg_name, egg_name)
        do("zip", "-j", pkg_name, AGENT_MANIFEST_FILE)
        do("zip", "-j", pkg_name, PUBLISH_MANIFEST_FILE)
    finally:
        os.chdir(cwd)

    log.info("Package {0} successfully created".format(pkg_name))


if __name__ == "__main__":
    logging.basicConfig(format='%(message)s', level=logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument('family', metavar='family', nargs='?', default='Test', help='Agent family')
    parser.add_argument('-o', '--output', default=os.getcwd(), help='Output directory')

    arguments = parser.parse_args()

    try:

        run(arguments.family, arguments.output, logging)

    except Exception as exception:
        logging.error(str(exception))
        sys.exit(1)

    sys.exit(0)
