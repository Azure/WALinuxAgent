# Copyright 2018 Microsoft Corporation
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

import errno
import os

from azurelinuxagent.common import conf
from azurelinuxagent.common.exception import OSUtilError
from azurelinuxagent.common.osutil import sshkey
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.osutil.gaia import GaiaOSUtil
from azurelinuxagent.common.osutil.nsbsd import NSBSDOSUtil
from azurelinuxagent.common.utils import fileutil, shellutil
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from tests.lib.tools import AgentTestCase, Mock, load_data, patch


class DefaultOsUtilTestCase(AgentTestCase):
    def test_default_service_name(self):
        self.assertEqual(DefaultOSUtil().get_service_name(), "waagent")


class TestSSHKeyPath(AgentTestCase):
    def setUp(self):
        super(TestSSHKeyPath, self).setUp()
        self.home = os.path.join(self.tmp_dir, "alice")
        os.mkdir(self.home)
        self.account = Mock(pw_name="alice", pw_dir=self.home, pw_uid=os.getuid(), pw_gid=os.getgid())
        self.util = DefaultOSUtil()
        self.util.selinux = False
        self.util.get_userentry = Mock(return_value=self.account)

    def test_public_key_requires_an_absolute_file_path_under_the_accounts_ssh_directory(self):
        other_key = os.path.join(self.tmp_dir, "bob", ".ssh", "key")
        os.makedirs(os.path.dirname(other_key))
        for path in (os.path.relpath(self.home + "/.ssh/key"), self.home + "/.ssh",
                     self.home + "/key", self.home + "/.ssh-old/key", other_key):
            with self.assertRaises(OSUtilError):
                self.util.deploy_ssh_pubkey("alice", (path, None, "ssh-rsa test"))
        self.assertEqual([], os.listdir(self.home))
        self.assertFalse(os.path.exists(other_key))

    def test_legacy_home_path_appends_in_place_and_labeling_is_best_effort(self):
        directory = os.path.join(self.home, ".ssh")
        os.mkdir(directory)
        path = os.path.join(directory, "custom_keys")
        fileutil.write_file(path, "existing\n")
        inode = os.stat(path).st_ino
        home_alias = os.path.join(self.tmp_dir, "home-base")
        os.symlink(self.tmp_dir, home_alias)
        with patch.object(conf, "get_home_dir", return_value=home_alias):
            with patch.object(self.util, "set_selinux_context", return_value=1):
                self.util.deploy_ssh_pubkey("alice", ("$HOME/alice/.ssh/custom_keys", None, "ssh-rsa test"))
                self.util.deploy_ssh_pubkey("alice", (home_alias + "/alice/.ssh/custom_keys", None, "ssh-rsa alias"))
        self.assertEqual(inode, os.stat(path).st_ino)
        self.assertEqual("existing\nssh-rsa test\nssh-rsa alias\n", fileutil.read_file(path))

    def test_user_controlled_symlinks_in_ssh_or_above_the_home_leave_the_target_untouched(self):
        target = os.path.join(self.tmp_dir, "custom-home")
        os.mkdir(target)
        mode = os.stat(target).st_mode
        os.symlink(target, os.path.join(self.home, ".ssh"))

        shared = os.path.join(self.tmp_dir, "shared")
        os.mkdir(shared)
        os.chmod(shared, 0o770)
        alias = os.path.join(shared, "homes")
        os.symlink(self.tmp_dir, alias)
        for home in (self.home, os.path.join(alias, "custom-home")):
            self.account.pw_dir = home
            with self.assertRaises(OSUtilError):
                self.util.deploy_ssh_pubkey("alice", (home + "/.ssh/key", None, "ssh-rsa test"))
            self.assertEqual([], os.listdir(target), home)
            self.assertEqual(mode, os.stat(target).st_mode, home)

    def test_keypair_only_overwrites_keys_when_both_destinations_are_safe(self):
        path = self.home + "/.ssh/key"
        fingerprint = "A" * 40
        source = os.path.join(self.tmp_dir, fingerprint + ".prv")
        fileutil.write_file(source, "original private key")
        with patch("azurelinuxagent.common.osutil.default.CryptUtil.get_pubkey_from_prv", return_value="public"):
            self.util.deploy_ssh_keypair("alice", (path, fingerprint))
            self.assertEqual("public", fileutil.read_file(path + ".pub"))

            fileutil.write_file(source, "replacement private key")
            with self.assertRaises(OSUtilError):
                self.util.deploy_ssh_keypair("alice", (self.home + "/.ssh/../outside_key", fingerprint))
            for link in (os.symlink, os.link):
                os.unlink(path + ".pub")
                link(path, path + ".pub")
                with self.assertRaises(OSUtilError):
                    self.util.deploy_ssh_keypair("alice", (path, fingerprint))
        self.assertEqual([".ssh"], os.listdir(self.home))
        self.assertEqual("original private key", fileutil.read_file(path))

    def test_failed_certificate_conversion_leaves_a_fresh_account_retryable(self):
        fingerprint = "A" * 40
        fileutil.write_file(os.path.join(self.tmp_dir, fingerprint + ".crt"), "certificate fixture")
        path = self.home + "/.ssh/authorized_keys"
        outputs = iter((b"partial", b"ssh-rsa converted\n"))

        def convert(command, stdout, log_error):  # pylint: disable=unused-argument
            key = next(outputs)
            stdout.write(key)
            if key == b"partial":
                raise shellutil.CommandError(command, 1, "", "conversion failed")

        with patch("azurelinuxagent.common.osutil.default.CryptUtil.get_pubkey_from_crt", return_value="PEM"):
            with patch.object(shellutil, "run_command", side_effect=convert):
                # Exercise the separate-owner path without changing the test process's credentials.
                with patch.object(os, "geteuid", return_value=self.account.pw_uid + 1):
                    with self.assertRaises(OSUtilError) as failure:
                        self.util.deploy_ssh_pubkey("alice", (path, fingerprint, None))
                    self.assertIn("conversion failed", str(failure.exception))
                    self.assertEqual([], os.listdir(self.home))
                    self.util.deploy_ssh_pubkey("alice", (path, fingerprint, None))
        self.assertEqual("ssh-rsa converted\n", fileutil.read_file(path))
        self.assertEqual(self.account.pw_uid, os.stat(path).st_uid)

    def test_gaia_replaces_for_certificates_but_appends_inline_keys(self):
        gaia = GaiaOSUtil()
        gaia.selinux = False
        self.account.pw_name = "admin"
        gaia.get_userentry = self.util.get_userentry
        os.mkdir(self.home + "/.ssh")
        path = self.home + "/.ssh/authorized_keys"
        fileutil.write_file(path, "old key\n")
        inode = os.stat(path).st_ino
        fingerprint = "A" * 40
        fileutil.write_file(os.path.join(self.tmp_dir, fingerprint + ".crt"), load_data("wire/trans_cert"))
        expected = CryptUtil(conf.get_openssl_cmd()).asn1_to_ssh(load_data("wire/trans_pub"))
        with patch.object(gaia, "_replace_user", return_value=path):
            gaia.deploy_ssh_pubkey("ovf-user", (path, fingerprint, None))
            gaia.deploy_ssh_pubkey("ovf-user", (path, None, "ssh-rsa inline"))
        self.assertEqual(expected + "ssh-rsa inline\n", fileutil.read_file(path))
        self.assertEqual(inode, os.stat(path).st_ino)

    def test_nsbsd_uses_its_fixed_home_for_admin_public_keys_only(self):
        with patch.object(NSBSDOSUtil, "resolver"):
            nsbsd = NSBSDOSUtil()
        self.account.pw_name = "admin"
        nsbsd.get_userentry = Mock(return_value=self.account)
        with patch("azurelinuxagent.common.osutil.default.key_files", side_effect=OSUtilError("stop before open")) as files:
            with self.assertRaises(OSUtilError):
                nsbsd.deploy_ssh_pubkey("ovf-user", ("/ignored", None, "ssh-rsa test"))
            files.assert_called_once_with("/usr/Firewall", ("authorized_keys",), self.account, keypair=False)
            files.reset_mock()
            with self.assertRaises(OSUtilError):
                nsbsd.deploy_ssh_keypair("admin", (self.home + "/.ssh/key", "A" * 40))
            files.assert_called_once_with(self.home, ("key",), self.account, keypair=True)

    def test_concurrently_created_directory_is_validated_not_replaced(self):
        directory = self.home + "/.ssh"
        created = []
        real_at = sshkey._at

        def create_before_mkdir(operation, parent, name, *args):
            if operation is os.mkdir and name == ".ssh" and not created:
                os.mkdir(directory, 0o700)
                created.append(os.stat(directory).st_ino)
            return real_at(operation, parent, name, *args)

        with patch.object(sshkey, "_at", side_effect=create_before_mkdir):
            self.util.deploy_ssh_pubkey("alice", (directory + "/keys", None, "ssh-rsa test"))
        self.assertEqual([os.stat(directory).st_ino], created)

    def test_creation_without_pass_fds_leaves_an_existing_directory_alone(self):
        parent = os.open(self.home, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with patch.object(sshkey, "_HAS_PASS_FDS", False):
                self.assertTrue(sshkey._create_as_account(parent, ".ssh", self.account, "directory"))
                inode = os.stat(self.home + "/.ssh").st_ino
                self.assertFalse(sshkey._create_as_account(parent, ".ssh", self.account, "directory"))
                self.assertEqual(inode, os.stat(self.home + "/.ssh").st_ino)
        finally:
            os.close(parent)

    def test_keypair_close_failure_does_not_skip_the_companion(self):
        private, public = Mock(), Mock()
        private.close.side_effect = IOError(errno.ENOSPC, "delayed write failed")
        with self.assertRaises(IOError):
            with sshkey._key_streams() as files:
                files.extend((private, public))
        public.close.assert_called_once_with()
