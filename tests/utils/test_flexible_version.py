import random # pylint: disable=unused-import
import re
import unittest

from azurelinuxagent.common.utils.flexible_version import FlexibleVersion

class TestFlexibleVersion(unittest.TestCase):

    def setUp(self):
        self.v = FlexibleVersion() # pylint: disable=invalid-name

    def test_compile_separator(self): # pylint: disable=useless-return
        tests = [
            '.',
            '',
            '-'
        ]
        for t in tests: # pylint: disable=invalid-name
            t_escaped = re.escape(t)
            t_re = re.compile(t_escaped)
            self.assertEqual((t_escaped, t_re), self.v._compile_separator(t)) # pylint: disable=protected-access
        self.assertEqual(('', re.compile('')),  self.v._compile_separator(None)) # pylint: disable=protected-access
        return

    def test_compile_pattern(self): # pylint: disable=useless-return
        self.v._compile_pattern() # pylint: disable=protected-access
        tests = {
            '1': True,
            '1.2': True,
            '1.2.3': True,
            '1.2.3.4': True,
            '1.2.3.4.5': True,

            '1alpha': True,
            '1.alpha': True,
            '1-alpha': True,
            '1alpha0': True,
            '1.alpha0': True,
            '1-alpha0': True,
            '1.2alpha': True,
            '1.2.alpha': True,
            '1.2-alpha': True,
            '1.2alpha0': True,
            '1.2.alpha0': True,
            '1.2-alpha0': True,

            '1beta': True,
            '1.beta': True,
            '1-beta': True,
            '1beta0': True,
            '1.beta0': True,
            '1-beta0': True,
            '1.2beta': True,
            '1.2.beta': True,
            '1.2-beta': True,
            '1.2beta0': True,
            '1.2.beta0': True,
            '1.2-beta0': True,

            '1rc': True,
            '1.rc': True,
            '1-rc': True,
            '1rc0': True,
            '1.rc0': True,
            '1-rc0': True,
            '1.2rc': True,
            '1.2.rc': True,
            '1.2-rc': True,
            '1.2rc0': True,
            '1.2.rc0': True,
            '1.2-rc0': True,

            '1.2.3.4alpha5': True,

            ' 1': False,
            'beta': False,
            '1delta0': False,
            '': False
        }
        for test in iter(tests):
            expectation = tests[test]
            self.assertEqual(
                expectation,
                self.v.version_re.match(test) is not None,
                "test: {0} expected: {1} ".format(test, expectation))
        return

    def test_compile_pattern_sep(self): # pylint: disable=useless-return
        self.v.sep = '-'
        self.v._compile_pattern() # pylint: disable=protected-access
        tests = { 
            '1': True,
            '1-2': True,
            '1-2-3': True,
            '1-2-3-4': True,
            '1-2-3-4-5': True,

            '1alpha': True,
            '1-alpha': True,
            '1alpha0': True,
            '1-alpha0': True,
            '1-2alpha': True,
            '1-2.alpha': True,
            '1-2-alpha': True,
            '1-2alpha0': True,
            '1-2.alpha0': True,
            '1-2-alpha0': True,

            '1beta': True,
            '1-beta': True,
            '1beta0': True,
            '1-beta0': True,
            '1-2beta': True,
            '1-2.beta': True,
            '1-2-beta': True,
            '1-2beta0': True,
            '1-2.beta0': True,
            '1-2-beta0': True,

            '1rc': True,
            '1-rc': True,
            '1rc0': True,
            '1-rc0': True,
            '1-2rc': True,
            '1-2.rc': True,
            '1-2-rc': True,
            '1-2rc0': True,
            '1-2.rc0': True,
            '1-2-rc0': True,

            '1-2-3-4alpha5': True,

            ' 1': False,
            'beta': False,
            '1delta0': False,
            '': False
        }
        for test in iter(tests):
            expectation = tests[test]
            self.assertEqual(
                expectation,
                self.v.version_re.match(test) is not None,
                "test: {0} expected: {1} ".format(test, expectation))
        return

    def test_compile_pattern_prerel(self): # pylint: disable=useless-return
        self.v.prerel_tags = ('a', 'b', 'c')
        self.v._compile_pattern() # pylint: disable=protected-access
        tests = {
            '1': True,
            '1.2': True,
            '1.2.3': True,
            '1.2.3.4': True,
            '1.2.3.4.5': True,

            '1a': True,
            '1.a': True,
            '1-a': True,
            '1a0': True,
            '1.a0': True,
            '1-a0': True,
            '1.2a': True,
            '1.2.a': True,
            '1.2-a': True,
            '1.2a0': True,
            '1.2.a0': True,
            '1.2-a0': True,

            '1b': True,
            '1.b': True,
            '1-b': True,
            '1b0': True,
            '1.b0': True,
            '1-b0': True,
            '1.2b': True,
            '1.2.b': True,
            '1.2-b': True,
            '1.2b0': True,
            '1.2.b0': True,
            '1.2-b0': True,

            '1c': True,
            '1.c': True,
            '1-c': True,
            '1c0': True,
            '1.c0': True,
            '1-c0': True,
            '1.2c': True,
            '1.2.c': True,
            '1.2-c': True,
            '1.2c0': True,
            '1.2.c0': True,
            '1.2-c0': True,

            '1.2.3.4a5': True,

            ' 1': False,
            '1.2.3.4alpha5': False,
            'beta': False,
            '1delta0': False,
            '': False
        }
        for test in iter(tests):
            expectation = tests[test]
            self.assertEqual(
                expectation,
                self.v.version_re.match(test) is not None,
                "test: {0} expected: {1} ".format(test, expectation))
        return

    def test_ensure_compatible_separators(self): # pylint: disable=useless-return
        v1 = FlexibleVersion('1.2.3') # pylint: disable=invalid-name
        v2 = FlexibleVersion('1-2-3', sep='-') # pylint: disable=invalid-name
        try:
            v1 == v2 # pylint: disable=pointless-statement
            self.assertTrue(False, "Incompatible separators failed to raise an exception") # pylint: disable=redundant-unittest-assert
        except ValueError:
            pass
        except Exception as e: # pylint: disable=invalid-name
            t = e.__class__.__name__ # pylint: disable=invalid-name
            # pylint: disable=redundant-unittest-assert
            self.assertTrue(False, "Incompatible separators raised an unexpected exception: {0}" \
                .format(t))
            # pylint: enable=redundant-unittest-assert
        return

    def test_ensure_compatible_prerel(self): # pylint: disable=useless-return
        v1 = FlexibleVersion('1.2.3', prerel_tags=('alpha', 'beta', 'rc')) # pylint: disable=invalid-name
        v2 = FlexibleVersion('1.2.3', prerel_tags=('a', 'b', 'c')) # pylint: disable=invalid-name
        try:
            v1 == v2 # pylint: disable=pointless-statement
            self.assertTrue(False, "Incompatible prerel_tags failed to raise an exception") # pylint: disable=redundant-unittest-assert
        except ValueError:
            pass
        except Exception as e: # pylint: disable=invalid-name
            t = e.__class__.__name__ # pylint: disable=invalid-name
            # pylint: disable=redundant-unittest-assert
            self.assertTrue(False, "Incompatible prerel_tags raised an unexpected exception: {0}" \
                .format(t))
            # pylint: enable=redundant-unittest-assert
        return

    def test_ensure_compatible_prerel_length(self): # pylint: disable=useless-return
        v1 = FlexibleVersion('1.2.3', prerel_tags=('a', 'b', 'c')) # pylint: disable=invalid-name
        v2 = FlexibleVersion('1.2.3', prerel_tags=('a', 'b')) # pylint: disable=invalid-name
        try:
            v1 == v2 # pylint: disable=pointless-statement
            self.assertTrue(False, "Incompatible prerel_tags failed to raise an exception") # pylint: disable=redundant-unittest-assert
        except ValueError:
            pass
        except Exception as e: # pylint: disable=invalid-name
            t = e.__class__.__name__ # pylint: disable=invalid-name
            # pylint: disable=redundant-unittest-assert
            self.assertTrue(False, "Incompatible prerel_tags raised an unexpected exception: {0}" \
                .format(t))
            # pylint: enable=redundant-unittest-assert
        return

    def test_ensure_compatible_prerel_order(self): # pylint: disable=useless-return
        v1 = FlexibleVersion('1.2.3', prerel_tags=('a', 'b')) # pylint: disable=invalid-name
        v2 = FlexibleVersion('1.2.3', prerel_tags=('b', 'a')) # pylint: disable=invalid-name
        try:
            v1 == v2 # pylint: disable=pointless-statement
            self.assertTrue(False, "Incompatible prerel_tags failed to raise an exception") # pylint: disable=redundant-unittest-assert
        except ValueError:
            pass
        except Exception as e: # pylint: disable=invalid-name
            t = e.__class__.__name__ # pylint: disable=invalid-name
            # pylint: disable=redundant-unittest-assert
            self.assertTrue(False, "Incompatible prerel_tags raised an unexpected exception: {0}" \
                .format(t))
            # pylint: enable=redundant-unittest-assert
        return

    def test_major(self): # pylint: disable=useless-return
        tests = {
            '1' : 1,
            '1.2' : 1,
            '1.2.3' : 1,
            '1.2.3.4' : 1
        }
        for test in iter(tests):
            expectation = tests[test]
            self.assertEqual(
                expectation,
                FlexibleVersion(test).major)
        return

    def test_minor(self): # pylint: disable=useless-return
        tests = {
            '1' : 0,
            '1.2' : 2,
            '1.2.3' : 2,
            '1.2.3.4' : 2
        }
        for test in iter(tests):
            expectation = tests[test]
            self.assertEqual(
                expectation,
                FlexibleVersion(test).minor)
        return

    def test_patch(self): # pylint: disable=useless-return
        tests = {
            '1' : 0,
            '1.2' : 0,
            '1.2.3' : 3,
            '1.2.3.4' : 3
        }
        for test in iter(tests):
            expectation = tests[test]
            self.assertEqual(
                expectation,
                FlexibleVersion(test).patch)
        return

    def test_parse(self): # pylint: disable=useless-return
        tests = {
            "1.2.3.4": ((1, 2, 3, 4), None),
            "1.2.3.4alpha5": ((1, 2, 3, 4), ('alpha', 5)),
            "1.2.3.4-alpha5": ((1, 2, 3, 4), ('alpha', 5)),
            "1.2.3.4.alpha5": ((1, 2, 3, 4), ('alpha', 5))
        }
        for test in iter(tests):
            expectation = tests[test]
            self.v._parse(test) # pylint: disable=protected-access
            self.assertEqual(expectation, (self.v.version, self.v.prerelease))
        return

    def test_decrement(self): # pylint: disable=useless-return
        src_v = FlexibleVersion('1.0.0.0.10')
        dst_v = FlexibleVersion(str(src_v))
        for i in range(1,10):
            dst_v -= 1
            self.assertEqual(i, src_v.version[-1] - dst_v.version[-1])
        return

    def test_decrement_disallows_below_zero(self): # pylint: disable=useless-return
        try:
            FlexibleVersion('1.0') - 1 # pylint: disable=expression-not-assigned
            self.assertTrue(False, "Decrement failed to raise an exception") # pylint: disable=redundant-unittest-assert
        except ArithmeticError:
            pass
        except Exception as e: # pylint: disable=invalid-name
            t = e.__class__.__name__ # pylint: disable=invalid-name
            self.assertTrue(False, "Decrement raised an unexpected exception: {0}".format(t)) # pylint: disable=redundant-unittest-assert
        return

    def test_increment(self): # pylint: disable=useless-return
        src_v = FlexibleVersion('1.0.0.0.0')
        dst_v = FlexibleVersion(str(src_v))
        for i in range(1,10):
            dst_v += 1
            self.assertEqual(i, dst_v.version[-1] - src_v.version[-1])
        return

    def test_str(self): # pylint: disable=useless-return
        tests = [
            '1',
            '1.2',
            '1.2.3',
            '1.2.3.4',
            '1.2.3.4.5',

            '1alpha',
            '1.alpha',
            '1-alpha',
            '1alpha0',
            '1.alpha0',
            '1-alpha0',
            '1.2alpha',
            '1.2.alpha',
            '1.2-alpha',
            '1.2alpha0',
            '1.2.alpha0',
            '1.2-alpha0',

            '1beta',
            '1.beta',
            '1-beta',
            '1beta0',
            '1.beta0',
            '1-beta0',
            '1.2beta',
            '1.2.beta',
            '1.2-beta',
            '1.2beta0',
            '1.2.beta0',
            '1.2-beta0',

            '1rc',
            '1.rc',
            '1-rc',
            '1rc0',
            '1.rc0',
            '1-rc0',
            '1.2rc',
            '1.2.rc',
            '1.2-rc',
            '1.2rc0',
            '1.2.rc0',
            '1.2-rc0',

            '1.2.3.4alpha5',
        ]
        for test in tests:
            self.assertEqual(test, str(FlexibleVersion(test)))
        return

    def test_creation_from_flexible_version(self): # pylint: disable=useless-return
        tests = [
            '1',
            '1.2',
            '1.2.3',
            '1.2.3.4',
            '1.2.3.4.5',

            '1alpha',
            '1.alpha',
            '1-alpha',
            '1alpha0',
            '1.alpha0',
            '1-alpha0',
            '1.2alpha',
            '1.2.alpha',
            '1.2-alpha',
            '1.2alpha0',
            '1.2.alpha0',
            '1.2-alpha0',

            '1beta',
            '1.beta',
            '1-beta',
            '1beta0',
            '1.beta0',
            '1-beta0',
            '1.2beta',
            '1.2.beta',
            '1.2-beta',
            '1.2beta0',
            '1.2.beta0',
            '1.2-beta0',

            '1rc',
            '1.rc',
            '1-rc',
            '1rc0',
            '1.rc0',
            '1-rc0',
            '1.2rc',
            '1.2.rc',
            '1.2-rc',
            '1.2rc0',
            '1.2.rc0',
            '1.2-rc0',

            '1.2.3.4alpha5',
        ]
        for test in tests:
            v = FlexibleVersion(test) # pylint: disable=invalid-name
            self.assertEqual(test, str(FlexibleVersion(v)))
        return

    def test_repr(self):
        v = FlexibleVersion('1,2,3rc4', ',', ['lol', 'rc']) # pylint: disable=invalid-name
        expected = "FlexibleVersion ('1,2,3rc4', ',', ('lol', 'rc'))"
        self.assertEqual(expected, repr(v))

    def test_order(self): # pylint: disable=useless-return
        test0 = ["1.7.0", "1.7.0rc0", "1.11.0"]
        expected0 = ['1.7.0rc0', '1.7.0', '1.11.0']
        self.assertEqual(expected0, list(map(str, sorted([FlexibleVersion(v) for v in test0]))))

        test1 = [
            '2.0.2rc2',
            '2.2.0beta3',
            '2.0.10',
            '2.1.0alpha42',
            '2.0.2beta4',
            '2.1.1',
            '2.0.1',
            '2.0.2rc3',
            '2.2.0',
            '2.0.0',
            '3.0.1',
            '2.1.0rc1'
        ]
        expected1 = [
            '2.0.0',
            '2.0.1',
            '2.0.2beta4',
            '2.0.2rc2',
            '2.0.2rc3',
            '2.0.10',
            '2.1.0alpha42',
            '2.1.0rc1',
            '2.1.1',
            '2.2.0beta3',
            '2.2.0',
            '3.0.1'
        ]
        self.assertEqual(expected1, list(map(str, sorted([FlexibleVersion(v) for v in test1]))))

        self.assertEqual(FlexibleVersion("1.0.0.0.0.0.0.0"), FlexibleVersion("1"))

        self.assertFalse(FlexibleVersion("1.0") > FlexibleVersion("1.0"))
        self.assertFalse(FlexibleVersion("1.0") < FlexibleVersion("1.0"))
        
        self.assertTrue(FlexibleVersion("1.0") < FlexibleVersion("1.1"))
        self.assertTrue(FlexibleVersion("1.9") < FlexibleVersion("1.10"))
        self.assertTrue(FlexibleVersion("1.9.9") < FlexibleVersion("1.10.0"))
        self.assertTrue(FlexibleVersion("1.0.0.0") < FlexibleVersion("1.2.0.0"))

        self.assertTrue(FlexibleVersion("1.1") > FlexibleVersion("1.0"))
        self.assertTrue(FlexibleVersion("1.10") > FlexibleVersion("1.9"))
        self.assertTrue(FlexibleVersion("1.10.0") > FlexibleVersion("1.9.9"))
        self.assertTrue(FlexibleVersion("1.2.0.0") > FlexibleVersion("1.0.0.0"))

        self.assertTrue(FlexibleVersion("1.0") <= FlexibleVersion("1.1"))
        self.assertTrue(FlexibleVersion("1.1") > FlexibleVersion("1.0"))
        self.assertTrue(FlexibleVersion("1.1") >= FlexibleVersion("1.0"))

        self.assertTrue(FlexibleVersion("1.0") == FlexibleVersion("1.0"))
        self.assertTrue(FlexibleVersion("1.0") >= FlexibleVersion("1.0"))
        self.assertTrue(FlexibleVersion("1.0") <= FlexibleVersion("1.0"))

        self.assertFalse(FlexibleVersion("1.0") != FlexibleVersion("1.0"))
        self.assertTrue(FlexibleVersion("1.1") != FlexibleVersion("1.0"))
        return


if __name__ == '__main__':
    unittest.main()
