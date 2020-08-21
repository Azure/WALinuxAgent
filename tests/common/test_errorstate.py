import unittest
from datetime import timedelta, datetime

from azurelinuxagent.common.errorstate import ErrorState
from tests.tools import Mock, patch


class TestErrorState(unittest.TestCase):
    def test_errorstate00(self):
        """
        If ErrorState is never incremented, it will never trigger.
        """
        test_subject = ErrorState(timedelta(seconds=10000))
        self.assertFalse(test_subject.is_triggered())
        self.assertEqual(0, test_subject.count)
        self.assertEqual('unknown', test_subject.fail_time)

    def test_errorstate01(self):
        """
        If ErrorState is never incremented, and the timedelta is zero it will
        not trigger.
        """
        test_subject = ErrorState(timedelta(seconds=0))
        self.assertFalse(test_subject.is_triggered())
        self.assertEqual(0, test_subject.count)
        self.assertEqual('unknown', test_subject.fail_time)

    def test_errorstate02(self):
        """
        If ErrorState is triggered, and the current time is within timedelta
        of now it will trigger.
        """
        test_subject = ErrorState(timedelta(seconds=0))
        test_subject.incr()

        self.assertTrue(test_subject.is_triggered())
        self.assertEqual(1, test_subject.count)
        self.assertEqual('0.0 min', test_subject.fail_time)

    @patch('azurelinuxagent.common.errorstate.datetime')
    def test_errorstate03(self, mock_time):
        """
        ErrorState will not trigger until
         1. ErrorState has been incr() at least once.
         2. The timedelta from the first incr() has elapsed.
        """
        test_subject = ErrorState(timedelta(minutes=15))

        for x in range(1, 10): # pylint: disable=invalid-name
            mock_time.utcnow = Mock(return_value=datetime.utcnow() + timedelta(minutes=x))

            test_subject.incr()
            self.assertFalse(test_subject.is_triggered())

        mock_time.utcnow = Mock(return_value=datetime.utcnow() + timedelta(minutes=30))
        test_subject.incr()
        self.assertTrue(test_subject.is_triggered())
        self.assertEqual('29.0 min', test_subject.fail_time)

    def test_errorstate04(self):
        """
        If ErrorState is reset the timestamp of the last incr() is reset to
        None.
        """

        test_subject = ErrorState(timedelta(minutes=15))
        self.assertTrue(test_subject.timestamp is None)

        test_subject.incr()
        self.assertTrue(test_subject.timestamp is not None)

        test_subject.reset()
        self.assertTrue(test_subject.timestamp is None)

    def test_errorstate05(self):
        """
        Test the fail_time for various scenarios
        """

        test_subject = ErrorState(timedelta(minutes=15))
        self.assertEqual('unknown', test_subject.fail_time)

        test_subject.incr()
        self.assertEqual('0.0 min', test_subject.fail_time)

        test_subject.timestamp = datetime.utcnow() - timedelta(seconds=60)
        self.assertEqual('1.0 min', test_subject.fail_time)

        test_subject.timestamp = datetime.utcnow() - timedelta(seconds=73)
        self.assertEqual('1.22 min', test_subject.fail_time)

        test_subject.timestamp = datetime.utcnow() - timedelta(seconds=120)
        self.assertEqual('2.0 min', test_subject.fail_time)

        test_subject.timestamp = datetime.utcnow() - timedelta(seconds=60 * 59)
        self.assertEqual('59.0 min', test_subject.fail_time)

        test_subject.timestamp = datetime.utcnow() - timedelta(seconds=60 * 60)
        self.assertEqual('1.0 hr', test_subject.fail_time)

        test_subject.timestamp = datetime.utcnow() - timedelta(seconds=60 * 95)
        self.assertEqual('1.58 hr', test_subject.fail_time)

        test_subject.timestamp = datetime.utcnow() - timedelta(seconds=60 * 60 * 3)
        self.assertEqual('3.0 hr', test_subject.fail_time)
