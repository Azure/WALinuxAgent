from datetime import datetime, timedelta

ERROR_STATE_DELTA_DEFAULT = timedelta(minutes=15)
ERROR_STATE_DELTA_INSTALL = timedelta(minutes=5)
ERROR_STATE_HOST_PLUGIN_FAILURE = timedelta(minutes=5)


class ErrorState(object):
    def __init__(self, min_timedelta=ERROR_STATE_DELTA_DEFAULT):
        self.min_timedelta = min_timedelta

        self.count = 0
        self.timestamp = None

    def incr(self):
        if self.count == 0:
            self.timestamp = datetime.utcnow()

        self.count += 1

    def reset(self):
        self.count = 0
        self.timestamp = None

    def is_triggered(self):
        if self.timestamp is None:
            return False

        delta = datetime.utcnow() - self.timestamp
        if delta >= self.min_timedelta:
            return True

        return False

    @property
    def fail_time(self):
        if self.timestamp is None:
            return 'unknown'

        delta = round((datetime.utcnow() - self.timestamp).seconds / 60.0, 2)
        if delta < 60:
            return '{0} min'.format(delta)

        delta_hr = round(delta / 60.0, 2)
        return '{0} hr'.format(delta_hr)
