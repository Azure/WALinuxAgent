from datetime import timedelta

from azurelinuxagent.common.errorstate import *
from tests.tools import *


class TestErrorState(unittest.TestCase):
    def test_errorstate00(self):
        """
        If ErrorState is never incremented, it will never trigger.
        """
        test_subject = ErrorState(timedelta(seconds=10000))
        self.assertFalse(test_subject.is_triggered())
        self.assertEqual(0, test_subject.count)

    def test_errorstate01(self):
        """
        If ErrorState is never incremented, and the timedelta is zero it will
        not trigger.
        """
        test_subject = ErrorState(timedelta(seconds=0))
        self.assertFalse(test_subject.is_triggered())
        self.assertEqual(0, test_subject.count)

    def test_errorstate02(self):
        """
        If ErrorState is triggered, and the current time is within timedelta
        of now it will trigger.
        """
        test_subject = ErrorState(timedelta(seconds=0))
        test_subject.incr()


        self.assertTrue(test_subject.is_triggered())
        self.assertEqual(1, test_subject.count)

    @patch('azurelinuxagent.common.errorstate.datetime')
    def test_errorstate03(self, mock_time):
        """
        ErrorState will not trigger until
         1. ErrorState has been incr() at least once.
         2. The timedelta from the first incr() has elapsed.
        """
        test_subject = ErrorState(timedelta(minutes=15))

        for x in range(1, 10):
            mock_time.utcnow = Mock(return_value=datetime.utcnow() + timedelta(minutes=x))

            test_subject.incr()
            self.assertFalse(test_subject.is_triggered())

        mock_time.utcnow = Mock(return_value=datetime.utcnow() + timedelta(minutes=30))
        test_subject.incr()
        self.assertTrue(test_subject.is_triggered())

    def test_errorstate04(self, mock_time):
        """
        If ErrorState is reset the timestamp of the last incr() is reset to
        None.
        """

        test_subject = ErrorState(timedelta(minutes=15))
        self.assertTrue(test_subject.timestamp is not None)

        test_subject.incr()
        self.assertTrue(test_subject.timestamp is None)

        test_subject.reset()
        self.assertTrue(test_subject.timestamp is None)
