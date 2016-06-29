#!/usr/bin/env python

import glob
import os
import os.path
import shutil
import subprocess
import sys

from azurelinuxagent.common.version import AGENT_NAME, AGENT_VERSION, AGENT_LONG_VERSION
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


output_path = os.path.join(os.getcwd(), "eggs")
target_path = os.path.join(output_path, AGENT_LONG_VERSION)
bin_path = os.path.join(target_path, "bin")
egg_path = os.path.join(bin_path, AGENT_LONG_VERSION + ".egg")
manifest_path = os.path.join(target_path, AGENT_MANIFEST_FILE)
pkg_name = os.path.join(output_path, AGENT_LONG_VERSION + ".zip")

def do(*args):
    try:
        subprocess.check_output(args, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print "ERROR: {0}".format(str(e))
        print "\t{0}".format(" ".join(args))
        print e.output
        sys.exit(1)

if os.path.isdir(target_path):
    shutil.rmtree(target_path)
elif os.path.isfile(target_path):
    os.remove(target_path)
if os.path.isfile(pkg_name):
    os.remove(pkg_name)
os.makedirs(bin_path)
print "Created {0} directory".format(target_path)

args = ["python", "setup.py"]
args.append("bdist_egg")
args.append("--dist-dir={0}".format(bin_path))

print "Creating egg {0}".format(egg_path)
do(*args)

egg_name = os.path.join("bin", os.path.basename(glob.glob(os.path.join(bin_path, "*"))[0]))

print "Writing {0}".format(manifest_path)
with open(manifest_path, mode='w') as manifest:
    manifest.write(MANIFEST.format(AGENT_NAME, egg_name))

cwd = os.getcwd()
os.chdir(target_path)
print "Creating package {0}".format(pkg_name)
do("zip", "-r", pkg_name, egg_name)
do("zip", "-j", pkg_name, AGENT_MANIFEST_FILE)
os.chdir(cwd)

print "Package {0} successfully created".format(pkg_name)
sys.exit(0)
