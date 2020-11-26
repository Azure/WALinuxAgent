"""
# test_debian_recheck.py - test the DebianRecheck class
# by running it against files collected from the following environments:
# - debian stretch (v9)
# - devuan ascii (v2.1 - derived from debian stretch)
# - debian buster (v10)
# - devuan beowulf (v3.0 - derived from debian buster)
# Test by modifying the variables SOURCES_LIST and ORIGINS_FILENAME
# to access specific files rather than the defaults, re-run __init__, and then
# check the values retrieved by the access methods
"""
# pylint: disable=line-too-long
# import platform
import os
# import io
# import sys
import unittest

from azurelinuxagent.common.extralib.debian_recheck import DebianRecheck

class TestDebianRecheck(unittest.TestCase):
    """ class for testing DebianRecheck """

# from tests/tools.py:

    test_dir = os.path.dirname(os.path.abspath(__file__))  # pylint: disable=invalid-name
    data_dir = os.path.join(test_dir, "..", "..", "data", "devuan_support")  # pylint: disable=invalid-name

    def test_file_read_successful_debian_stretch(self): # pylint: disable=invalid-name
        """
        test if the files for debian stretch are read successfully
        start with blank distinfo - we're only interested in how our code processes the files
        """
        distinfo = {
            'ID' : '',
            'RELEASE' : '',
            'CODENAME' : '',
            'DESCRIPTION' : '',
        }
        testdr = DebianRecheck(distinfo)
# better to construct these variables from predefined components?
# (rather than repeating things?)
        testdr.SOURCES_LIST = os.path.join(self.data_dir, "debian_stretch", "etc", "apt", "sources.list")
        testdr.ORIGINS_FILENAME = os.path.join(self.data_dir, "debian_stretch", "etc", "dpkg", "origins", "default")
# (last component needs to be empty to ensure that the path ends with / )
        testdr.LISTS_BASE = os.path.join(self.data_dir, "debian_stretch", "var", "lib", "apt", "lists", "")
# enable local debugging:
        testdr.debugfl = 1
# re-run __init__ to read new files
        testdr.__init__(distinfo)
# now retrieve and check attributes
        self.assertEqual(testdr.get_codename(), "stretch")
        self.assertEqual(testdr.get_release(), "9.12")
        self.assertEqual(testdr.get_id(), "Debian")
# others?

    def test_file_read_successful_devuan_ascii(self): # pylint: disable=invalid-name
        """ test if the files for devuan ascii are read successfully """
        distinfo = {
            'ID' : '',
            'RELEASE' : '',
            'CODENAME' : '',
            'DESCRIPTION' : '',
        }
        testdr = DebianRecheck(distinfo)
# better to construct these variables from predefined components?
# (rather than repeating things?)
        testdr.SOURCES_LIST = os.path.join(self.data_dir, "devuan_ascii", "etc", "apt", "sources.list")
        testdr.ORIGINS_FILENAME = os.path.join(self.data_dir, "devuan_ascii", "etc", "dpkg", "origins", "default")
        testdr.LISTS_BASE = os.path.join(self.data_dir, "devuan_ascii", "var", "lib", "apt", "lists", "")
# enable local debugging:
        testdr.debugfl = 1
# re-run __init__ to read new files
        testdr.__init__(distinfo)
# now retrieve and check attributes
        self.assertEqual(testdr.get_codename(), "ascii")
        self.assertEqual(testdr.get_release(), "2.1")
        self.assertEqual(testdr.get_id(), "Devuan")


    def test_file_read_successful_debian_buster(self): # pylint: disable=invalid-name
        """ test if the files for debian buster are read successfully """
        distinfo = {
            'ID' : '',
            'RELEASE' : '',
            'CODENAME' : '',
            'DESCRIPTION' : '',
        }
        testdr = DebianRecheck(distinfo)
# better to construct these variables from predefined components?
# (rather than repeating things?)
        testdr.SOURCES_LIST = os.path.join(self.data_dir, "debian_buster", "etc", "apt", "sources.list")
        testdr.ORIGINS_FILENAME = os.path.join(self.data_dir, "debian_buster", "etc", "dpkg", "origins", "default")
        testdr.LISTS_BASE = os.path.join(self.data_dir, "debian_buster", "var", "lib", "apt", "lists", "")
# enable local debugging:
        testdr.debugfl = 1
# re-run __init__ to read new files
        testdr.__init__(distinfo)
# now retrieve and check attributes
        self.assertEqual(testdr.get_codename(), "buster")
        self.assertEqual(testdr.get_release(), "10.5")
        self.assertEqual(testdr.get_id(), "Debian")


    def test_file_read_successful_devuan_beowulf(self): # pylint: disable=invalid-name
        """ test if the files for devuan beowulf are read successfully """
        distinfo = {
            'ID' : '',
            'RELEASE' : '',
            'CODENAME' : '',
            'DESCRIPTION' : '',
        }
        testdr = DebianRecheck(distinfo)
# better to construct these variables from predefined components?
# (rather than repeating things?)
        testdr.SOURCES_LIST = os.path.join(self.data_dir, "devuan_beowulf", "etc", "apt", "sources.list")
        testdr.ORIGINS_FILENAME = os.path.join(self.data_dir, "devuan_beowulf", "etc", "dpkg", "origins", "default")
        testdr.LISTS_BASE = os.path.join(self.data_dir, "devuan_beowulf", "var", "lib", "apt", "lists", "")
# enable local debugging:
        testdr.debugfl = 1
# re-run __init__ to read new files
        testdr.__init__(distinfo)
# now retrieve and check attributes
        self.assertEqual(testdr.get_codename(), "beowulf")
        self.assertEqual(testdr.get_release(), "3.0")
        self.assertEqual(testdr.get_id(), "Devuan")

if __name__ == '__main__':
    unittest.main()
