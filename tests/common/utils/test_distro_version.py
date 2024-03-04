import os
import unittest

from tests.lib.tools import AgentTestCase, data_dir

from azurelinuxagent.common.utils.distro_version import DistroVersion
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion


class TestDistroVersion(AgentTestCase):

    def test_it_should_implement_all_comparison_operators(self):
        self.assertTrue(DistroVersion("1.0.0") < DistroVersion("1.1.0"))
        self.assertTrue(DistroVersion("1.0.0") <= DistroVersion("1.0.0"))
        self.assertTrue(DistroVersion("1.0.0") <= DistroVersion("1.1.0"))

        self.assertTrue(DistroVersion("1.1.0") > DistroVersion("1.0.0"))
        self.assertTrue(DistroVersion("1.1.0") >= DistroVersion("1.1.0"))
        self.assertTrue(DistroVersion("1.1.0") >= DistroVersion("1.0.0"))

        self.assertTrue(DistroVersion("1.1.0") != DistroVersion("1.0.0"))
        self.assertTrue(DistroVersion("1.1.0") == DistroVersion("1.1.0"))

    def test_it_should_compare_digit_sequences_numerically(self):
        self.assertTrue(DistroVersion("2.0.0") < DistroVersion("10.0.0"))
        self.assertTrue(DistroVersion("1.2.0") < DistroVersion("1.10.0"))
        self.assertTrue(DistroVersion("1.0.2") < DistroVersion("1.0.10"))
        self.assertTrue(DistroVersion("2.0.rc.2") < DistroVersion("2.0.rc.10"))
        self.assertTrue(DistroVersion("2.0.rc2") < DistroVersion("2.0.rc10"))

    def test_it_should_compare_non_digit_sequences_lexicographically(self):
        self.assertTrue(DistroVersion("2.0.alpha") < DistroVersion("2.0.beta"))
        self.assertTrue(DistroVersion("2.0.alpha.2") < DistroVersion("2.0.beta.1"))
        self.assertTrue(DistroVersion("alpha") < DistroVersion("beta"))
        self.assertTrue(DistroVersion("<1.0.0>") < DistroVersion(">1.0.0>"))

    def test_it_should_parse_common_distro_versions(self):
        """
        Test that DistroVersion can parse the versions given by azurelinuxagent.common.version.DISTRO_VERSION
        (the values in distro_versions.txt are current values from telemetry.)
        """
        data_file = os.path.join(data_dir, "distro_versions.txt")

        with open(data_file, "r") as f:
            for line in f:
                line = line.rstrip()
                version = DistroVersion(line)
                self.assertNotEqual([], version._fragments)

        self.assertEqual([], DistroVersion("")._fragments)

    def test_it_should_compare_commonly_used_versions(self):
        """
        Test that DistroVersion does some common comparisons correctly.
        """
        self.assertTrue(DistroVersion("1.0.0") < DistroVersion("2.0.0."))
        self.assertTrue(DistroVersion("1.0.0") < DistroVersion("1.1.0"))
        self.assertTrue(DistroVersion("1.0.0") < DistroVersion("1.0.1"))

        self.assertTrue(DistroVersion("1.0.0") == DistroVersion("1.0.0"))
        self.assertTrue(DistroVersion("1.0.0") != DistroVersion("2.0.0"))

        self.assertTrue(DistroVersion("13") != DistroVersion("13.0"))
        self.assertTrue(DistroVersion("13") < DistroVersion("13.0"))
        self.assertTrue(DistroVersion("13") < DistroVersion("13.1"))

        ubuntu_version = DistroVersion("16.10")
        self.assertTrue(ubuntu_version in [DistroVersion('16.04'), DistroVersion('16.10'), DistroVersion('17.04')])

        ubuntu_version = DistroVersion("20.10")
        self.assertTrue(DistroVersion('18.04') <= ubuntu_version <= DistroVersion('24.04'))

        redhat_version = DistroVersion("7.9")
        self.assertTrue(DistroVersion('7') <= redhat_version <= DistroVersion('9'))

        self.assertTrue(DistroVersion("1.0") < DistroVersion("1.1"))
        self.assertTrue(DistroVersion("1.9") < DistroVersion("1.10"))
        self.assertTrue(DistroVersion("1.9.9") < DistroVersion("1.10.0"))
        self.assertTrue(DistroVersion("1.0.0.0") < DistroVersion("1.2.0.0"))

        self.assertTrue(DistroVersion("1.0") <= DistroVersion("1.1"))
        self.assertTrue(DistroVersion("1.1") > DistroVersion("1.0"))
        self.assertTrue(DistroVersion("1.1") >= DistroVersion("1.0"))

        self.assertTrue(DistroVersion("1.0") == DistroVersion("1.0"))
        self.assertTrue(DistroVersion("1.0") >= DistroVersion("1.0"))
        self.assertTrue(DistroVersion("1.0") <= DistroVersion("1.0"))

    def test_uncommon_versions(self):
        self.assertTrue(DistroVersion("2") != DistroVersion("2.0"))
        self.assertTrue(DistroVersion("2") < DistroVersion("2.0"))

        self.assertTrue(DistroVersion("10.0_RC2") != DistroVersion("10.0RC2"))
        self.assertTrue(DistroVersion("10.0_RC2")._fragments == [10, 0, '_', 'RC', 2])
        self.assertTrue(DistroVersion("10.0RC2")._fragments == [10, 0, 'RC', 2])

        self.assertTrue(DistroVersion("1.4-rolling") < DistroVersion("1.4-rolling-202402090309"))

        self.assertTrue(DistroVersion("2023") < DistroVersion("2023.02.1"))

        self.assertTrue(DistroVersion("2.1-systemd-alpha") < DistroVersion("2.1-systemd-rc"))
        self.assertTrue(DistroVersion("2308a") < DistroVersion("2308beta"))
        self.assertTrue(DistroVersion("6.0.0.beta4") < DistroVersion("6.0.0.beta5"))
        self.assertTrue(DistroVersion("9.13.1P8X1") < DistroVersion("9.13.1RC1"))
        self.assertTrue(DistroVersion("a") < DistroVersion("rc"))
        self.assertTrue(DistroVersion("Clawhammer__9.14.0"), DistroVersion("Clawhammer__9.14.1"))
        self.assertTrue(DistroVersion("FFFF") < DistroVersion("h"))
        self.assertTrue(DistroVersion("None") < DistroVersion("n/a"))

        # TypeError: '<' not supported between instances of 'int' and 'str'
        with self.assertRaises(TypeError):
            _ = DistroVersion("3.11.2-rc.1") < DistroVersion("3.11.2-rc.a")

        # AttributeError: 'FlexibleVersion' object has no attribute '_fragments'
        with self.assertRaises(AttributeError):
            _ = DistroVersion("1.0.0.0") == FlexibleVersion("1.0.0.0")


if __name__ == '__main__':
    unittest.main()
