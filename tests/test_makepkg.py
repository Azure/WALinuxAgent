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


if __name__ == "__main__":
    unittest.main()
