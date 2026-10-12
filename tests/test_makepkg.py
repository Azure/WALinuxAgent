# Copyright 2026 Microsoft Corporation
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

import os
import shutil
import tempfile
import unittest
import zipfile

import makepkg


class TestMakePackage(unittest.TestCase):
    def setUp(self):
        self.test_directory = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_directory)

    def test_add_zip_directory_entries_adds_namespace_package_directories(self):
        archive_path = os.path.join(self.test_directory, "agent.egg")
        with zipfile.ZipFile(archive_path, mode="w") as archive:
            archive.writestr(
                "azurelinuxagent/vendor/site-packages/opentelemetry/sdk/trace/__init__.py",
                b""
            )

        makepkg.add_zip_directory_entries(archive_path)

        with zipfile.ZipFile(archive_path) as archive:
            entries = archive.namelist()

        self.assertIn("azurelinuxagent/vendor/site-packages/opentelemetry/", entries)
        self.assertIn("azurelinuxagent/vendor/site-packages/opentelemetry/sdk/", entries)

    def test_add_zip_directory_entries_is_idempotent(self):
        archive_path = os.path.join(self.test_directory, "agent.egg")
        with zipfile.ZipFile(archive_path, mode="w") as archive:
            archive.writestr("package/module.py", b"")

        makepkg.add_zip_directory_entries(archive_path)
        makepkg.add_zip_directory_entries(archive_path)

        with zipfile.ZipFile(archive_path) as archive:
            entries = archive.namelist()

        self.assertEqual(1, entries.count("package/"))

    def test_remove_vendor_bytecode_keeps_sources_and_agent_bytecode(self):
        archive_path = os.path.join(self.test_directory, "agent.egg")
        vendor_source = "azurelinuxagent/vendor/site-packages/opentelemetry/trace/__init__.py"
        vendor_bytecode = "azurelinuxagent/vendor/site-packages/opentelemetry/trace/__pycache__/__init__.pyc"
        agent_bytecode = "azurelinuxagent/common/__pycache__/version.pyc"

        with zipfile.ZipFile(archive_path, mode="w") as archive:
            archive.writestr(vendor_source, b"source")
            archive.writestr(vendor_bytecode, b"vendor bytecode")
            archive.writestr(agent_bytecode, b"agent bytecode")

        makepkg.remove_vendor_bytecode(archive_path)

        with zipfile.ZipFile(archive_path) as archive:
            entries = archive.namelist()

        self.assertIn(vendor_source, entries)
        self.assertNotIn(vendor_bytecode, entries)
        self.assertIn(agent_bytecode, entries)


if __name__ == "__main__":
    unittest.main()
