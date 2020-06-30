# Copyright 2020 Microsoft Corporation
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
# Requires Python 2.6+ and Openssl 1.0+
#

# TODO: Check the licensing; it was copy-pasted from another file.

DATA_FILE = {
        "version_info": "wire/version_info.xml",
        "goal_state": "wire/goal_state.xml",
        "hosting_env": "wire/hosting_env.xml",
        "shared_config": "wire/shared_config.xml",
        "certs": "wire/certs.xml",
        "ext_conf": "wire/ext_conf.xml",
        "manifest": "wire/manifest.xml",
        "ga_manifest": "wire/ga_manifest.xml",
        "trans_prv": "wire/trans_prv",
        "trans_cert": "wire/trans_cert",
        "test_ext": "ext/sample_ext-1.3.0.zip",
        "remote_access": None,
        "in_vm_artifacts_profile": None
}

DATA_FILE_IN_VM_ARTIFACTS_PROFILE = DATA_FILE.copy()
DATA_FILE_IN_VM_ARTIFACTS_PROFILE["ext_conf"] = "wire/ext_conf_in_vm_artifacts_profile.xml"
DATA_FILE_IN_VM_ARTIFACTS_PROFILE["in_vm_artifacts_profile"] = "wire/in_vm_artifacts_profile.json"

DATA_FILE_NO_EXT = DATA_FILE.copy()
DATA_FILE_NO_EXT["goal_state"] = "wire/goal_state_no_ext.xml"
DATA_FILE_NO_EXT["ext_conf"] = None

DATA_FILE_EXT_NO_SETTINGS = DATA_FILE.copy()
DATA_FILE_EXT_NO_SETTINGS["ext_conf"] = "wire/ext_conf_no_settings.xml"

DATA_FILE_EXT_NO_PUBLIC = DATA_FILE.copy()
DATA_FILE_EXT_NO_PUBLIC["ext_conf"] = "wire/ext_conf_no_public.xml"

DATA_FILE_EXT_AUTOUPGRADE = DATA_FILE.copy()
DATA_FILE_EXT_AUTOUPGRADE["ext_conf"] = "wire/ext_conf_autoupgrade.xml"

DATA_FILE_EXT_INTERNALVERSION = DATA_FILE.copy()
DATA_FILE_EXT_INTERNALVERSION["ext_conf"] = "wire/ext_conf_internalversion.xml"

DATA_FILE_EXT_AUTOUPGRADE_INTERNALVERSION = DATA_FILE.copy()
DATA_FILE_EXT_AUTOUPGRADE_INTERNALVERSION["ext_conf"] = "wire/ext_conf_autoupgrade_internalversion.xml"

DATA_FILE_EXT_ROLLINGUPGRADE = DATA_FILE.copy()
DATA_FILE_EXT_ROLLINGUPGRADE["ext_conf"] = "wire/ext_conf_upgradeguid.xml"

DATA_FILE_EXT_SEQUENCING = DATA_FILE.copy()
DATA_FILE_EXT_SEQUENCING["ext_conf"] = "wire/ext_conf_sequencing.xml"

DATA_FILE_EXT_DELETION = DATA_FILE.copy()
DATA_FILE_EXT_DELETION["manifest"] = "wire/manifest_deletion.xml"

DATA_FILE_EXT_SINGLE = DATA_FILE.copy()
DATA_FILE_EXT_SINGLE["manifest"] = "wire/manifest_deletion.xml"

DATA_FILE_MULTIPLE_EXT = DATA_FILE.copy()
DATA_FILE_MULTIPLE_EXT["ext_conf"] = "wire/ext_conf_multiple_extensions.xml"

DATA_FILE_NO_CERT_FORMAT = DATA_FILE.copy()
DATA_FILE_NO_CERT_FORMAT["certs"] = "wire/certs_no_format_specified.xml"

DATA_FILE_CERT_FORMAT_NOT_PFX = DATA_FILE.copy()
DATA_FILE_CERT_FORMAT_NOT_PFX["certs"] = "wire/certs_format_not_pfx.xml"

DATA_FILE_REMOTE_ACCESS = DATA_FILE.copy()
DATA_FILE_REMOTE_ACCESS["goal_state"] = "wire/goal_state_remote_access.xml"
DATA_FILE_REMOTE_ACCESS["remote_access"] = "wire/remote_access_single_account.xml"

DATA_FILE_PLUGIN_SETTINGS_MISMATCH = DATA_FILE.copy()
DATA_FILE_PLUGIN_SETTINGS_MISMATCH["ext_conf"] = "wire/ext_conf_plugin_settings_version_mismatch.xml"